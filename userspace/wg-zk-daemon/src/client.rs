//! Client role (`docs/protocol-r1.md`, Section 5).
//!
//! One spawned task per NEED_PROOF; SET_PROOF goes out through the single sender task
//! ([`netlink::run_sender`]). Per event, in this order:
//! 1. draw the session nonce; mode `0x02`: encapsulate to the gateway's `ek`, giving `(ct, ss)`;
//! 2. prove over `S_gw = PEER_PUB` and `S_c = LOCAL_PUB` of this event;
//! 3. mode `0x02`: send `(token, nonce, ct)` over the TLS side channel (timeouts
//!    `WGZK_TLS_HANDSHAKE_MS` on connect, `WGZK_TLS_READ_MS` on the write), then install
//!    `psk` for the peer `PEER_PUB` on `WG_IFACE`;
//! 4. if any part of step 3 failed: stop; no SET_PROOF, the handshake times out;
//! 5. SET_PROOF.
//!
//! Every event produces one `[timing] side=client ...` line. Events of an interface other
//! than `WG_IFACE` (when set) are ignored, so one daemon per interface can run side by side.
//!
//! A build with the cargo feature `fault-injection` has four hooks here (lines marked
//! `#[cfg(feature = "fault-injection")]`, see module `fault`); a normal build has none.

use anyhow::Result;
use curve25519_dalek::scalar::Scalar;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Duration, Instant};
use tokio_rustls::TlsConnector;

use crate::mlkem::{self, Encapsulator, CT_LEN};
use crate::mlkem_channel;
use crate::netlink::{self, IfaceFilter, NeedProofEvent, Request, SetProof, WgzkCmd};
use crate::peers::{self, PeerInstaller, PeerUpdate};
use crate::settings::ClientConfig;
use crate::zk::{self, Mode, Transcript};

/// Capacity of the SET_PROOF channel.
const REQUEST_QUEUE: usize = 1024;

/// Mode `0x02` state: the gateway's ML-KEM key and side-channel endpoint.
pub struct ClientPq {
    pub encap: Encapsulator,
    pub server_addr: String,
    pub connector: TlsConnector,
    /// Interface on which the PSK is installed.
    pub iface: String,
}

pub struct Client {
    epoch: u32,
    sk: Scalar,
    pk: [u8; 32],
    pq: Option<ClientPq>,
    installer: Arc<dyn PeerInstaller>,
    tls_connect: Duration,
    tls_write: Duration,
    /// Tokens of NEED_PROOF events being handled; a duplicate event is skipped.
    inflight: Mutex<HashSet<u32>>,
    #[cfg(feature = "fault-injection")]
    fault: Option<crate::fault::Fault>,
}

/// Phase durations of one handshake, and the nonce prefix for the log.
#[derive(Default, Debug)]
pub struct Timings {
    pub encap: Duration,
    pub zk: Duration,
    pub tls: Duration,
    pub write: Duration,
    pub psk: Duration,
    pub nonce_prefix: Option<[u8; 4]>,
}

/// Removes a token from the in-flight set when the handling task ends.
struct InflightToken<'a> {
    set: &'a Mutex<HashSet<u32>>,
    token: u32,
}

impl Drop for InflightToken<'_> {
    fn drop(&mut self) {
        self.set.lock().unwrap_or_else(PoisonError::into_inner).remove(&self.token);
    }
}

impl Client {
    pub fn new(
        epoch: u32,
        sk: Scalar,
        pq: Option<ClientPq>,
        installer: Arc<dyn PeerInstaller>,
        tls_connect: Duration,
        tls_write: Duration,
    ) -> Self {
        Client {
            epoch,
            pk: zk::public_key(&sk),
            sk,
            pq,
            installer,
            tls_connect,
            tls_write,
            inflight: Mutex::new(HashSet::new()),
            #[cfg(feature = "fault-injection")]
            fault: None,
        }
    }

    /// Select the fault this client injects (fault-injection builds only).
    #[cfg(feature = "fault-injection")]
    pub fn with_fault(mut self, fault: Option<crate::fault::Fault>) -> Self {
        self.fault = fault;
        self
    }

    pub fn mode(&self) -> Mode {
        if self.pq.is_some() {
            Mode::ZkPq
        } else {
            Mode::ZkOnly
        }
    }

    /// Steps 1 to 4. `Ok` carries the SET_PROOF to send; `Err` the reason for not sending one.
    pub async fn prepare(&self, ev: &NeedProofEvent, tm: &mut Timings) -> Result<SetProof, &'static str> {
        // 1. Nonce; mode 0x02: encapsulation.
        let t = Instant::now();
        let nonce = zk::gen_session_nonce().map_err(|_| "rng")?;
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&nonce[..4]);
        tm.nonce_prefix = Some(prefix);
        let kem = self.pq.as_ref().map(|pq| (pq, pq.encap.encap()));
        tm.encap = t.elapsed();

        // 2. Proof over S_gw = PEER_PUB and S_c = LOCAL_PUB as delivered in this event.
        let t = Instant::now();
        let h_ct = match &kem {
            Some((_, (ct, _))) => zk::ct_hash(ct),
            None => zk::H_CT_NONE,
        };
        let transcript = Transcript {
            mode: self.mode(),
            epoch: self.epoch,
            pk: self.pk,
            s_gw: ev.peer_pub,
            s_c: ev.local_pub,
            nonce,
            h_ct,
        };
        #[cfg(feature = "fault-injection")]
        let transcript = crate::fault::transcript(self.fault, transcript)?;
        let (r, s) = zk::prove(&self.sk, &transcript).map_err(|_| "rng")?;
        #[cfg(feature = "fault-injection")]
        let s = crate::fault::response(self.fault, s);
        tm.zk = t.elapsed();

        // 3. Mode 0x02: side channel, then the PSK. 4. Any failure stops here.
        if let Some((pq, (ct, ss))) = kem {
            self.send_ciphertext(pq, ev.token.unwrap_or(0), nonce, ct, tm).await?;
            self.install_psk(pq, ev.peer_pub, &ss, tm).await?;
        }

        Ok(SetProof {
            peer_id: ev.peer_id,
            ifindex: ev.ifindex,
            r,
            s,
            session_nonce: nonce,
            token: ev.token,
        })
    }

    /// Step 3, first half: the side-channel message, with timeouts on connect and on write.
    async fn send_ciphertext(
        &self,
        pq: &ClientPq,
        token: u32,
        nonce: [u8; 32],
        ct: [u8; CT_LEN],
        tm: &mut Timings,
    ) -> Result<(), &'static str> {
        #[cfg(feature = "fault-injection")]
        let Some((nonce, ct)) = crate::fault::side_channel(self.fault, nonce, ct)? else {
            return Ok(());
        };
        let t = Instant::now();
        let mut tls = match timeout(self.tls_connect, mlkem_channel::connect_tls(&pq.connector, &pq.server_addr)).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => {
                eprintln!("[client] side channel: {e:#}");
                return Err("tls_connect");
            }
            Err(_) => return Err("tls_timeout"),
        };
        tm.tls = t.elapsed();

        let t = Instant::now();
        match timeout(self.tls_write, mlkem_channel::send_on(&mut tls, token, &nonce, &ct)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!("[client] side channel: {e:#}");
                return Err("send");
            }
            Err(_) => return Err("send_timeout"),
        }
        tm.write = t.elapsed();
        Ok(())
    }

    /// Step 3, second half: the PSK for the gateway peer `PEER_PUB`.
    async fn install_psk(&self, pq: &ClientPq, peer: [u8; 32], ss: &[u8; 32], tm: &mut Timings) -> Result<(), &'static str> {
        #[cfg(feature = "fault-injection")]
        if !crate::fault::installs_psk(self.fault) {
            return Ok(());
        }
        let t = Instant::now();
        let update = PeerUpdate {
            iface: &pq.iface,
            key: peer,
            psk: Some(mlkem::derive_psk(ss)),
            allowed_ip: None,
        };
        if let Err(e) = self.installer.set_peer(&update).await {
            eprintln!("[client] PSK installation failed: {e:#}");
            return Err("psk");
        }
        tm.psk = t.elapsed();
        Ok(())
    }

    /// Steps 1 to 5 for one event, then the timing line.
    async fn handle(self: Arc<Self>, ev: NeedProofEvent, t0: Instant, requests: mpsc::Sender<Request>) {
        let _inflight = match ev.token {
            Some(token) => {
                if !self.inflight.lock().unwrap_or_else(PoisonError::into_inner).insert(token) {
                    return; // the same NEED_PROOF is already being handled
                }
                Some(InflightToken { set: &self.inflight, token })
            }
            None => None,
        };

        let mut tm = Timings::default();
        let prepared = self.prepare(&ev, &mut tm).await;
        let t_tail = Instant::now();
        let result = match prepared {
            // 5. SET_PROOF, through the sender task.
            Ok(p) => requests.send(Request::SetProof(p)).await.map_err(|_| "queue"),
            Err(reason) => Err(reason),
        };
        let tail = t_tail.elapsed();
        let status = match result {
            Ok(()) => "result=ok".to_string(),
            Err(reason) => format!("result=fail reason={reason}"),
        };
        // ` fault=<name>` follows `side=client` in a fault-injection build with a fault selected.
        #[cfg(not(feature = "fault-injection"))]
        let fault = "";
        #[cfg(feature = "fault-injection")]
        let fault = crate::fault::log_field(self.fault);
        eprintln!(
            "[timing] side=client{fault} token={} nonce_prefix={} {status} zk_us={} encap_us={} tls_us={} write_us={} psk_us={} tail_us={} total_us={}",
            ev.token.map_or_else(|| "-".to_string(), |t| t.to_string()),
            tm.nonce_prefix.map_or_else(|| "-".to_string(), hex::encode),
            tm.zk.as_micros(),
            tm.encap.as_micros(),
            tm.tls.as_micros(),
            tm.write.as_micros(),
            tm.psk.as_micros(),
            tail.as_micros(),
            t0.elapsed().as_micros(),
        );
    }
}

async fn event_loop(cl: &Arc<Client>, filter: Option<&IfaceFilter>, requests: &mpsc::Sender<Request>) -> Result<()> {
    let (sock, family_id) = netlink::connect_events().await?;
    if let Ok(ns) = std::fs::read_link("/proc/self/ns/net") {
        eprintln!("[client] joined wgzk events, ns={}", ns.display());
    }
    loop {
        for genl in netlink::recv_events(&sock, family_id).await? {
            let t0 = Instant::now();
            if *genl.cmd() != WgzkCmd::NeedProof as u8 {
                continue;
            }
            let ev = match netlink::parse_need_proof(&genl) {
                Ok(ev) => ev,
                Err(e) => {
                    eprintln!("[client] dropping NEED_PROOF: {e}");
                    continue;
                }
            };
            if let Some(f) = filter {
                if !f.matches(ev.ifindex) {
                    eprintln!("[client] ignoring NEED_PROOF of ifindex {}", ev.ifindex);
                    continue;
                }
            }
            tokio::spawn(cl.clone().handle(ev, t0, requests.clone()));
        }
    }
}

pub async fn run(cfg: ClientConfig) -> Result<()> {
    let pq = match &cfg.pq {
        Some(pq) => Some(ClientPq {
            encap: Encapsulator::new(&pq.server_ek)?,
            server_addr: pq.server_addr.clone(),
            connector: mlkem_channel::make_connector(pq.cert_fp)?,
            iface: pq.iface.clone(),
        }),
        None => None,
    };
    let client = Client::new(
        cfg.epoch,
        cfg.sk,
        pq,
        peers::installer(cfg.installer),
        cfg.bounds.tls_handshake,
        cfg.bounds.tls_read,
    );
    #[cfg(feature = "fault-injection")]
    let client = client.with_fault(cfg.fault);
    let client = Arc::new(client);
    eprintln!(
        "[client] mode=0x{:02x} epoch={} iface={} installer={}",
        cfg.mode().byte(),
        cfg.epoch,
        cfg.iface.as_deref().unwrap_or("(any)"),
        cfg.installer.name()
    );
    #[cfg(feature = "fault-injection")]
    if let Some(f) = cfg.fault {
        eprintln!("[client] FAULT INJECTION ACTIVE: {}", f.name());
    }

    let (requests, rx) = mpsc::channel(REQUEST_QUEUE);
    tokio::spawn(netlink::run_sender(rx, "client"));

    let filter = cfg.iface.as_deref().map(IfaceFilter::new);
    loop {
        if let Err(e) = event_loop(&client, filter.as_ref(), &requests).await {
            eprintln!("[client] event loop error: {e:#} (retrying in 1s)");
            sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
pub mod testing {
    //! Clients and kernel events for tests.
    use super::*;
    use crate::netlink::NeedVerifyEvent;
    use crate::peers::testing::FakeInstaller;

    /// A client in mode 0x02 talking to the side channel at `addr` pinned to `fp`.
    pub fn pq_client(
        ek: &[u8; mlkem::EK_LEN],
        addr: &str,
        fp: [u8; 32],
        sk: Scalar,
        epoch: u32,
        installer: Arc<FakeInstaller>,
    ) -> Client {
        let pq = ClientPq {
            encap: Encapsulator::new(ek).expect("ek"),
            server_addr: addr.to_string(),
            connector: mlkem_channel::make_connector(fp).expect("connector"),
            iface: "wgc0".into(),
        };
        Client::new(epoch, sk, Some(pq), installer, Duration::from_secs(2), Duration::from_secs(1))
    }

    /// A client in mode 0x01.
    pub fn zk_client(sk: Scalar, epoch: u32, installer: Arc<FakeInstaller>) -> Client {
        Client::new(epoch, sk, None, installer, Duration::from_secs(2), Duration::from_secs(1))
    }

    pub fn need_proof(s_gw: [u8; 32], s_c: [u8; 32]) -> NeedProofEvent {
        NeedProofEvent { ifindex: 4, peer_id: 11, peer_pub: s_gw, local_pub: s_c, token: Some(31337) }
    }

    /// The kernel of the gateway turns the client's SET_PROOF into a NEED_VERIFY.
    pub fn as_need_verify(p: &SetProof, s_gw: [u8; 32], s_c: [u8; 32]) -> NeedVerifyEvent {
        NeedVerifyEvent {
            ifindex: 1,
            pending_id: 77,
            peer_index: 5,
            peer_pub: s_c,
            local_pub: s_gw,
            r: p.r,
            s: p.s,
            session_nonce: p.session_nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::ctbuf::CtBuffer;
    use crate::gateway::testing::{fixture, random32};
    use crate::mlkem_channel::testing::{ensure_provider, self_signed, spawn_gateway};
    use crate::peers::testing::{Call, FakeInstaller};

    /// Client and gateway code end to end, without a kernel: TLS side channel, proof, both
    /// PSK installations. The two sides must install the same PSK.
    #[tokio::test]
    async fn client_and_gateway_agree() {
        ensure_provider();
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let (cert, key, fp) = self_signed();
        let addr = spawn_gateway(&cert, &key, f.ctbuf.clone()).await;

        let client_inst = Arc::new(FakeInstaller::default());
        let ek = f.ek_bytes.as_deref().expect("mode 0x02 fixture has ek");
        let client = pq_client(ek, &addr, fp, f.sk, f.epoch, client_inst.clone());
        let s_c = random32();
        let ev = need_proof(f.s_gw, s_c);
        let mut tm = Timings::default();
        let sp = client.prepare(&ev, &mut tm).await.expect("client steps 1-4");
        assert_eq!((sp.peer_id, sp.ifindex, sp.token), (11, 4, Some(31337)));

        let [Call::Set { iface, key, psk: Some(client_psk), allowed_ip: None }] = &client_inst.calls()[..] else {
            panic!("client must install exactly one PSK: {:?}", client_inst.calls());
        };
        assert_eq!((iface.as_str(), *key), ("wgc0", f.s_gw), "PSK for the gateway peer PEER_PUB");

        let out = f.gw.decide(&as_need_verify(&sp, f.s_gw, s_c)).await;
        assert_eq!(out.result, Ok(()));
        assert_eq!(out.token, Some(31337), "token travelled over the side channel");
        let gw_calls = f.installer.calls();
        let [Call::Set { key, psk: Some(gw_psk), .. }] = &gw_calls[..] else {
            panic!("gateway must install exactly one peer: {gw_calls:?}");
        };
        assert_eq!(*key, s_c);
        assert_eq!(gw_psk, client_psk, "both sides derive the same PSK");
    }

    /// Step 4: a failed side channel means no SET_PROOF and no PSK.
    #[tokio::test]
    async fn unreachable_gateway_aborts_without_set_proof() {
        ensure_provider();
        let (_, ek) = mlkem::keygen();
        let (_, _, fp) = self_signed();
        // A port with nothing listening.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = l.local_addr().expect("addr").to_string();
        drop(l);
        let inst = Arc::new(FakeInstaller::default());
        let client = pq_client(&ek, &addr, fp, Scalar::from(7u64), 0, inst.clone());
        let mut tm = Timings::default();
        let r = client.prepare(&need_proof(random32(), random32()), &mut tm).await;
        assert_eq!(r, Err("tls_connect"));
        assert!(inst.calls().is_empty(), "no PSK installed");
    }

    /// Step 4: a gateway with the wrong certificate means no SET_PROOF.
    #[tokio::test]
    async fn wrong_gateway_certificate_aborts() {
        ensure_provider();
        let (_, ek) = mlkem::keygen();
        let (cert, key, _) = self_signed();
        let (_, _, other_fp) = self_signed();
        let buf = Arc::new(CtBuffer::new(4, Duration::from_secs(5)));
        let addr = spawn_gateway(&cert, &key, buf.clone()).await;
        let inst = Arc::new(FakeInstaller::default());
        let client = pq_client(&ek, &addr, other_fp, Scalar::from(7u64), 0, inst.clone());
        let r = client.prepare(&need_proof(random32(), random32()), &mut Timings::default()).await;
        assert_eq!(r, Err("tls_connect"));
        assert!(inst.calls().is_empty());
    }

    /// Step 4: a failed local PSK installation means no SET_PROOF.
    #[tokio::test]
    async fn failed_psk_installation_aborts() {
        ensure_provider();
        let (_, ek) = mlkem::keygen();
        let (cert, key, fp) = self_signed();
        let buf = Arc::new(CtBuffer::new(4, Duration::from_secs(5)));
        let addr = spawn_gateway(&cert, &key, buf).await;
        let inst = Arc::new(FakeInstaller::default());
        inst.set_failing(true);
        let client = pq_client(&ek, &addr, fp, Scalar::from(7u64), 0, inst);
        let r = client.prepare(&need_proof(random32(), random32()), &mut Timings::default()).await;
        assert_eq!(r, Err("psk"));
    }

    /// Mode 0x01: proof only, no side channel, no PSK; the proof verifies at a ZK-only gateway.
    #[tokio::test(start_paused = true)]
    async fn zk_only_client() {
        let f = fixture(Mode::ZkOnly, false, 16, 16);
        let inst = Arc::new(FakeInstaller::default());
        let client = zk_client(f.sk, f.epoch, inst.clone());
        let s_c = random32();
        let sp = client.prepare(&need_proof(f.s_gw, s_c), &mut Timings::default()).await.expect("prepare");
        assert!(inst.calls().is_empty());
        // The proof is bound to S_c: the same proof in an initiation with another session key
        // fails (tried first, since afterwards the nonce would be refused as a replay).
        let other = as_need_verify(&sp, f.s_gw, random32());
        assert_eq!(f.gw.decide(&other).await.result, Err("proof"));
        assert_eq!(f.gw.decide(&as_need_verify(&sp, f.s_gw, s_c)).await.result, Ok(()));
        assert_eq!(f.gw.decide(&other).await.result, Err("replay"));
    }

    #[tokio::test]
    async fn set_proof_only_after_success_and_duplicates_skipped() {
        let f = fixture(Mode::ZkOnly, false, 16, 16);
        let client = Arc::new(zk_client(f.sk, f.epoch, Arc::new(FakeInstaller::default())));
        let (tx, mut rx) = mpsc::channel(4);
        let ev = need_proof(f.s_gw, random32());
        client.clone().handle(ev.clone(), Instant::now(), tx.clone()).await;
        assert!(matches!(rx.try_recv(), Ok(Request::SetProof(p)) if p.token == Some(31337)));
        // A token that is still in flight is not handled twice.
        client.inflight.lock().expect("lock").insert(31337);
        client.clone().handle(ev, Instant::now(), tx).await;
        assert!(rx.try_recv().is_err());
    }
}
