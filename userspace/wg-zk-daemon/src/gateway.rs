//! Gateway role (`docs/protocol-r1.md`, Section 6).
//!
//! Tasks:
//! - side channel (mode `0x02`): [`mlkem_channel::serve`] stores ciphertexts, nothing else;
//! - netlink event loop: one spawned task per NEED_VERIFY of `WG_IFACE`;
//! - verdict sender: the only writer of SET_VERIFY ([`netlink::run_sender`]);
//! - housekeeping: purge of expired ciphertexts, removal of idle peers.
//!
//! At start, with `WGZK_ADOPT_PEERS=1` (the default), the peers that `WG_IFACE` already has
//! are adopted into the peer table as if verified at that moment: they count against
//! `WGZK_PEER_MAX` and are removed after `WGZK_PEER_IDLE_SECS` unless a handshake refreshes
//! them. The interface is then reserved for peers created by the daemon; a manually
//! configured peer is removed when idle. A failure to list the peers is logged, not fatal.
//!
//! At most `WGZK_VERIFY_MAX` decisions are in progress at one time; an event beyond that is
//! rejected at once (`overload`). So is an event whose nonce is being decided (`busy`):
//! copies of one initiation do not queue up behind each other.
//!
//! Per NEED_VERIFY, in this order and holding the nonce's lock throughout (step 3):
//! 1. reject if the nonce is in the replay cache, or if the cache is full;
//! 2. mode `0x02`: look up the ciphertext for the nonce, waiting at most `WGZK_CT_WAIT_MS`;
//!    reject if absent (the lookup does not remove it);
//! 3. verify the proof for the current epoch, then for the previous one if configured;
//! 4. mode `0x02`: decapsulate, derive the PSK;
//! 5. create or update the peer `{S_c, psk, allowed-ips addr/128}` (refused when
//!    `WGZK_PEER_MAX` peers exist and `S_c` is new);
//! 6. insert the nonce into the replay cache, drop the ciphertext.
//!
//! Then `SET_VERIFY(PENDING_ID, 1)`. Any failure: `SET_VERIFY(PENDING_ID, 0)`, and no peer,
//! no key and no replay entry has been created. Every event produces one
//! `[timing] side=gateway ...` line.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::{interval, sleep, Duration, Instant, MissedTickBehavior};

use crate::addr;
use crate::ctbuf::CtBuffer;
use crate::mlkem::{self, Decapsulator, CT_LEN};
use crate::mlkem_channel::{self, Limits};
use crate::netlink::{self, IfaceFilter, NeedVerifyEvent, Request, WgzkCmd};
use crate::peers::{self, PeerError, PeerInstaller, PeerTable, PeerUpdate};
use crate::replay::ReplayCache;
use crate::settings::GatewayConfig;
use crate::zk::{self, Mode, Transcript};

/// Capacity of the verdict channel (one entry per kernel pending-table slot).
const VERDICT_QUEUE: usize = 1024;
/// Upper bound on the interval of the idle-peer collection.
const PEER_GC_MAX_INTERVAL: Duration = Duration::from_secs(30);

pub struct Gateway {
    /// Credential public keys to try, current epoch first: `(epoch, pk_e)`.
    epochs: Vec<(u32, [u8; 32])>,
    iface: String,
    addr_prefix: [u8; 8],
    ct_wait: Duration,
    /// Mode `0x02` exactly when present.
    dk: Option<Decapsulator>,
    ctbuf: Arc<CtBuffer>,
    replay: ReplayCache,
    peers: PeerTable,
    installer: Arc<dyn PeerInstaller>,
    adopt_peers: bool,
    /// One permit per decision in progress.
    in_progress: Arc<Semaphore>,
}

/// Phase durations of one decision.
#[derive(Default, Debug)]
pub struct Timings {
    pub wait_ct: Duration,
    pub verify: Duration,
    pub decap: Duration,
    pub peer: Duration,
}

/// Result of one decision: the verdict (or the reason for rejecting) and what the timing
/// line reports.
#[derive(Debug)]
pub struct Outcome {
    pub result: Result<(), &'static str>,
    /// Side-channel token of the ciphertext, when one was found.
    pub token: Option<u32>,
    pub timings: Timings,
}

impl Gateway {
    pub fn new(
        cfg: &GatewayConfig,
        dk: Option<Decapsulator>,
        ctbuf: Arc<CtBuffer>,
        installer: Arc<dyn PeerInstaller>,
    ) -> Self {
        let mut epochs = vec![(cfg.epoch, cfg.pk)];
        if let Some(prev) = cfg.pk_prev {
            // settings guarantees epoch >= 1 when a previous key is configured.
            epochs.push((cfg.epoch.saturating_sub(1), prev));
        }
        Gateway {
            epochs,
            iface: cfg.iface.clone(),
            addr_prefix: cfg.addr_prefix,
            ct_wait: cfg.bounds.ct_wait,
            dk,
            ctbuf,
            replay: ReplayCache::new(cfg.bounds.replay_max),
            peers: PeerTable::new(cfg.bounds.peer_max),
            installer,
            adopt_peers: cfg.adopt_peers,
            in_progress: Arc::new(Semaphore::new(cfg.bounds.verify_max)),
        }
    }

    /// At start: adopt the peers the interface already has (`WGZK_ADOPT_PEERS`). Returns how
    /// many were adopted; a listing failure is logged and adopts nothing.
    pub async fn adopt_existing_peers(&self) -> usize {
        if !self.adopt_peers {
            return 0;
        }
        match self.installer.list_peers(&self.iface).await {
            Ok(keys) => {
                let n = self.peers.adopt(&keys);
                let (now, max) = (self.peers.len(), self.peers.max());
                eprintln!("[gateway] adopted {n} existing peer(s) of {}; {now} in the table, WGZK_PEER_MAX={max}", self.iface);
                if now >= max {
                    eprintln!(
                        "[gateway] the peer table is at or above WGZK_PEER_MAX ({now} >= {max}): handshakes for new session keys are refused until idle removals bring it below"
                    );
                }
                n
            }
            Err(e) => {
                eprintln!("[gateway] listing the peers of {} failed, none adopted: {e:#}", self.iface);
                0
            }
        }
    }

    /// Whether a handshake with this nonce has been accepted (tests only).
    #[cfg(test)]
    pub fn has_accepted(&self, nonce: &[u8; 32]) -> bool {
        self.replay.contains(nonce)
    }

    pub fn mode(&self) -> Mode {
        if self.dk.is_some() {
            Mode::ZkPq
        } else {
            Mode::ZkOnly
        }
    }

    /// Section 6 step 3 for one NEED_VERIFY.
    pub async fn decide(&self, ev: &NeedVerifyEvent) -> Outcome {
        let mut timings = Timings::default();
        let mut token = None;
        let result = self.decide_steps(ev, &mut timings, &mut token).await;
        Outcome { result, token, timings }
    }

    async fn decide_steps(
        &self,
        ev: &NeedVerifyEvent,
        tm: &mut Timings,
        token: &mut Option<u32>,
    ) -> Result<(), &'static str> {
        let nonce = ev.session_nonce;
        // Two events with the same nonce never decide concurrently, and the second does
        // not wait for the first.
        let Some(_nonce_lock) = self.replay.try_lock_nonce(nonce) else {
            return Err("busy");
        };

        // 3.1 Replay cache. Room for step 3.6 is reserved now, so that step cannot fail
        // after a peer has been created.
        if self.replay.contains(&nonce) {
            return Err("replay");
        }
        let replay_slot = self.replay.reserve().ok_or("replay_full")?;

        // 3.2 Ciphertext for this nonce (mode 0x02).
        let pq: Option<(&Decapsulator, Arc<[u8; CT_LEN]>)> = match &self.dk {
            Some(dk) => {
                let t = Instant::now();
                let entry = self.ctbuf.lookup(&nonce, self.ct_wait).await;
                tm.wait_ct = t.elapsed();
                let entry = entry.ok_or("no_ct")?;
                *token = Some(entry.token);
                Some((dk, entry.ct))
            }
            None => None,
        };

        // 3.3 Proof, current epoch first.
        let t = Instant::now();
        let h_ct = match &pq {
            Some((_, ct)) => zk::ct_hash(&ct[..]),
            None => zk::H_CT_NONE,
        };
        let valid = self.epochs.iter().any(|(epoch, pk)| {
            let transcript = Transcript {
                mode: self.mode(),
                epoch: *epoch,
                pk: *pk,
                s_gw: ev.local_pub,
                s_c: ev.peer_pub,
                nonce,
                h_ct,
            };
            zk::verify(&transcript, &ev.r, &ev.s)
        });
        tm.verify = t.elapsed();
        if !valid {
            return Err("proof");
        }

        // 3.4 Decapsulation (mode 0x02).
        let psk = match &pq {
            Some((dk, ct)) => {
                let t = Instant::now();
                let psk = mlkem::derive_psk(&dk.decap(ct));
                tm.decap = t.elapsed();
                Some(psk)
            }
            None => None,
        };

        // 3.5 Peer {S_c, psk, allowed-ips addr/128}.
        let t = Instant::now();
        let update = PeerUpdate {
            iface: &self.iface,
            key: ev.peer_pub,
            psk,
            allowed_ip: Some(addr::derive_addr(&self.addr_prefix, &ev.peer_pub)),
        };
        let installed = self.peers.install(&*self.installer, &update).await;
        tm.peer = t.elapsed();
        match installed {
            Ok(()) => {}
            Err(PeerError::Full) => return Err("peer_full"),
            Err(PeerError::Install(e)) => {
                eprintln!("[gateway] peer installation failed pending_id={}: {e:#}", ev.pending_id);
                return Err("peer_install");
            }
        }

        // 3.6 Replay cache; the ciphertext has served its purpose.
        replay_slot.insert(nonce);
        if pq.is_some() {
            self.ctbuf.remove(&nonce);
        }
        Ok(())
    }

    /// One NEED_VERIFY: a task that decides, or a rejection at once when `WGZK_VERIFY_MAX`
    /// decisions are in progress.
    pub fn dispatch(self: &Arc<Self>, ev: NeedVerifyEvent, t0: Instant, verdicts: &mpsc::Sender<Request>) {
        match self.in_progress.clone().try_acquire_owned() {
            Ok(permit) => {
                tokio::spawn(self.clone().handle(ev, t0, verdicts.clone(), permit));
            }
            Err(_) => {
                // Not awaited: a full verdict queue must not stall the event loop. Without
                // a verdict the kernel entry times out, which rejects as well.
                let queued = verdicts.try_send(Request::SetVerify { pending_id: ev.pending_id, result: 0 }).is_ok();
                eprintln!(
                    "[timing] side=gateway pending_id={} token=- nonce_prefix={} result=fail reason={} wait_ct_us=0 verify_us=0 decap_us=0 peer_us=0 total_us={}",
                    ev.pending_id,
                    hex::encode(&ev.session_nonce[..4]),
                    if queued { "overload" } else { "overload_verdict_lost" },
                    t0.elapsed().as_micros(),
                );
            }
        }
    }

    /// Decide, queue the verdict, log the timing line.
    async fn handle(
        self: Arc<Self>,
        ev: NeedVerifyEvent,
        t0: Instant,
        verdicts: mpsc::Sender<Request>,
        _in_progress: OwnedSemaphorePermit,
    ) {
        let out = self.decide(&ev).await;
        let result = u8::from(out.result.is_ok());
        let queued = verdicts
            .send(Request::SetVerify { pending_id: ev.pending_id, result })
            .await
            .is_ok();
        let total = t0.elapsed();
        let status = match (out.result, queued) {
            (Ok(()), true) => "result=ok".to_string(),
            (Ok(()), false) => "result=fail reason=verdict_lost".to_string(),
            (Err(reason), _) => format!("result=fail reason={reason}"),
        };
        let tm = &out.timings;
        eprintln!(
            "[timing] side=gateway pending_id={} token={} nonce_prefix={} {status} wait_ct_us={} verify_us={} decap_us={} peer_us={} total_us={}",
            ev.pending_id,
            out.token.map_or_else(|| "-".to_string(), |t| t.to_string()),
            hex::encode(&ev.session_nonce[..4]),
            tm.wait_ct.as_micros(),
            tm.verify.as_micros(),
            tm.decap.as_micros(),
            tm.peer.as_micros(),
            total.as_micros(),
        );
    }
}

async fn event_loop(gw: &Arc<Gateway>, filter: &IfaceFilter, verdicts: &mpsc::Sender<Request>) -> Result<()> {
    let (sock, family_id) = netlink::connect_events().await?;
    if let Ok(ns) = std::fs::read_link("/proc/self/ns/net") {
        eprintln!("[gateway] joined wgzk events, ns={}", ns.display());
    }
    loop {
        for genl in netlink::recv_events(&sock, family_id).await? {
            let t0 = Instant::now();
            if *genl.cmd() != WgzkCmd::NeedVerify as u8 {
                continue;
            }
            let ev = match netlink::parse_need_verify(&genl) {
                Ok(ev) => ev,
                Err(e) => {
                    eprintln!("[gateway] dropping NEED_VERIFY: {e}");
                    continue;
                }
            };
            if !filter.matches(ev.ifindex) {
                eprintln!("[gateway] ignoring NEED_VERIFY of ifindex {} (not {})", ev.ifindex, gw.iface);
                continue;
            }
            gw.dispatch(ev, t0, verdicts);
        }
    }
}

pub async fn run(cfg: GatewayConfig) -> Result<()> {
    let installer = peers::installer(cfg.installer);
    let ctbuf = Arc::new(CtBuffer::new(cfg.bounds.ct_buffer_max, cfg.bounds.ct_ttl));

    let dk = match &cfg.pq {
        Some(pq) => {
            let acceptor = mlkem_channel::make_acceptor(&pq.cert_pem, &pq.key_pem)?;
            let listener = mlkem_channel::bind(pq.port).await?;
            let limits = Limits {
                max_conn: cfg.bounds.tls_max_conn,
                handshake: cfg.bounds.tls_handshake,
                read: cfg.bounds.tls_read,
            };
            tokio::spawn(mlkem_channel::serve(listener, acceptor, ctbuf.clone(), limits));
            let (buf, ttl) = (ctbuf.clone(), cfg.bounds.ct_ttl);
            tokio::spawn(async move {
                let mut tick = interval(ttl);
                tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    buf.purge_expired();
                }
            });
            Some(Decapsulator::from_seed(&pq.dk_seed))
        }
        None => None,
    };

    let gw = Arc::new(Gateway::new(&cfg, dk, ctbuf, installer));
    eprintln!(
        "[gateway] mode=0x{:02x} epoch={} previous_epoch={} iface={} installer={}",
        cfg.mode().byte(),
        cfg.epoch,
        if cfg.pk_prev.is_some() { "yes" } else { "no" },
        cfg.iface,
        cfg.installer.name()
    );
    gw.adopt_existing_peers().await;

    let (gc_gw, idle) = (gw.clone(), cfg.bounds.peer_idle);
    tokio::spawn(async move {
        let mut tick = interval(idle.min(PEER_GC_MAX_INTERVAL));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let n = gc_gw.peers.collect_idle(&*gc_gw.installer, &gc_gw.iface, idle).await;
            if n > 0 {
                eprintln!("[gateway] removed {n} idle peer(s), {} remain", gc_gw.peers.len());
            }
        }
    });

    let (verdicts, rx) = mpsc::channel(VERDICT_QUEUE);
    tokio::spawn(netlink::run_sender(rx, "gateway"));

    let filter = IfaceFilter::new(&cfg.iface);
    loop {
        if let Err(e) = event_loop(&gw, &filter, &verdicts).await {
            eprintln!("[gateway] event loop error: {e:#} (retrying in 1s)");
            sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
pub mod testing {
    //! Builds a gateway with a fake installer and produces client-side proofs for it.
    use super::*;
    use crate::mlkem::Encapsulator;
    use crate::peers::testing::FakeInstaller;
    use crate::settings::Bounds;
    use curve25519_dalek::scalar::Scalar;

    pub struct Fixture {
        pub gw: Arc<Gateway>,
        pub installer: Arc<FakeInstaller>,
        pub ctbuf: Arc<CtBuffer>,
        pub sk: Scalar,
        pub sk_prev: Scalar,
        pub epoch: u32,
        pub ek: Option<Encapsulator>,
        /// The encapsulation key of the gateway, for building a client (mode 0x02).
        pub ek_bytes: Option<Box<[u8; mlkem::EK_LEN]>>,
        pub s_gw: [u8; 32],
    }

    pub fn random32() -> [u8; 32] {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("rng");
        b
    }

    pub fn random_sk() -> Scalar {
        Scalar::from_bytes_mod_order(random32())
    }

    pub fn fixture(mode: Mode, with_prev: bool, peer_max: usize, replay_max: usize) -> Fixture {
        fixture_with(mode, with_prev, peer_max, replay_max, true)
    }

    pub fn fixture_with(mode: Mode, with_prev: bool, peer_max: usize, replay_max: usize, adopt_peers: bool) -> Fixture {
        let (sk, sk_prev, epoch) = (random_sk(), random_sk(), 5);
        let (dk, ek, ek_bytes) = match mode {
            Mode::ZkPq => {
                let (seed, ek) = mlkem::keygen();
                let encap = Encapsulator::new(&ek).expect("ek");
                (Some(Decapsulator::from_seed(&seed)), Some(encap), Some(Box::new(ek)))
            }
            Mode::ZkOnly => (None, None, None),
        };
        let bounds = Bounds { peer_max, replay_max, ..Bounds::from_env(&std::collections::HashMap::new()).expect("defaults") };
        let cfg = GatewayConfig {
            epoch,
            pk: zk::public_key(&sk),
            pk_prev: with_prev.then(|| zk::public_key(&sk_prev)),
            iface: "wg0".into(),
            addr_prefix: addr::DEFAULT_PREFIX,
            bounds,
            adopt_peers,
            installer: crate::settings::Installer::Netlink,
            pq: None,
        };
        let ctbuf = Arc::new(CtBuffer::new(bounds.ct_buffer_max, bounds.ct_ttl));
        let installer = Arc::new(FakeInstaller::default());
        let gw = Arc::new(Gateway::new(&cfg, dk, ctbuf.clone(), installer.clone()));
        Fixture { gw, installer, ctbuf, sk, sk_prev, epoch, ek, ek_bytes, s_gw: random32() }
    }

    /// What an honest client produces for one handshake.
    pub struct ClientSide {
        pub ev: NeedVerifyEvent,
        pub ct: Option<Arc<[u8; CT_LEN]>>,
        pub psk: Option<[u8; 32]>,
    }

    impl Fixture {
        /// A handshake of session key `s_c`, proven with `sk` for `epoch` in `mode`.
        pub fn client(&self, s_c: [u8; 32], sk: &Scalar, epoch: u32, mode: Mode) -> ClientSide {
            let nonce = zk::gen_session_nonce().expect("rng");
            let (ct, psk) = match &self.ek {
                Some(ek) => {
                    let (ct, ss) = ek.encap();
                    (Some(Arc::new(ct)), Some(mlkem::derive_psk(&ss)))
                }
                None => (None, None),
            };
            let h_ct = ct.as_ref().map_or(zk::H_CT_NONE, |c| zk::ct_hash(&c[..]));
            let t = Transcript { mode, epoch, pk: zk::public_key(sk), s_gw: self.s_gw, s_c, nonce, h_ct };
            let (r, s) = zk::prove(sk, &t).expect("prove");
            let ev = NeedVerifyEvent {
                ifindex: 1,
                pending_id: u64::from_le_bytes(random32()[..8].try_into().expect("8")),
                peer_index: 1,
                peer_pub: s_c,
                local_pub: self.s_gw,
                r,
                s,
                session_nonce: nonce,
            };
            ClientSide { ev, ct, psk }
        }

        /// An honest handshake for the current epoch and the gateway's mode.
        pub fn honest(&self) -> ClientSide {
            self.client(random32(), &self.sk, self.epoch, self.gw.mode())
        }

        /// The side channel delivers the client's ciphertext.
        pub fn deliver(&self, c: &ClientSide, token: u32) {
            if let Some(ct) = &c.ct {
                self.ctbuf.insert(c.ev.session_nonce, ct.clone(), token).expect("buffer");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::peers::testing::Call;
    use crate::settings::Bounds;
    use tokio::time::advance;

    fn set_calls(f: &Fixture) -> Vec<Call> {
        f.installer.calls().into_iter().filter(|c| matches!(c, Call::Set { .. })).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn accepts_valid_pq_handshake() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let c = f.honest();
        f.deliver(&c, 4242);
        let out = f.gw.decide(&c.ev).await;
        assert_eq!(out.result, Ok(()));
        assert_eq!(out.token, Some(4242));
        assert_eq!(
            set_calls(&f),
            vec![Call::Set {
                iface: "wg0".into(),
                key: c.ev.peer_pub,
                psk: c.psk,
                allowed_ip: Some(addr::derive_addr(&addr::DEFAULT_PREFIX, &c.ev.peer_pub)),
            }],
            "peer = {{S_c, the client's psk, derived address/128}}"
        );
        assert!(f.gw.has_accepted(&c.ev.session_nonce));
        assert!(f.ctbuf.lookup(&c.ev.session_nonce, Duration::ZERO).await.is_none(), "ciphertext consumed on acceptance");
    }

    #[tokio::test(start_paused = true)]
    async fn replayed_initiation_is_rejected() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let c = f.honest();
        f.deliver(&c, 1);
        assert_eq!(f.gw.decide(&c.ev).await.result, Ok(()));
        // The same initiation again, and even with its ciphertext sent again.
        assert_eq!(f.gw.decide(&c.ev).await.result, Err("replay"));
        f.deliver(&c, 1);
        assert_eq!(f.gw.decide(&c.ev).await.result, Err("replay"));
        assert_eq!(set_calls(&f).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn missing_ciphertext_is_rejected_after_the_wait() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let c = f.honest();
        let start = Instant::now();
        let out = f.gw.decide(&c.ev).await;
        assert_eq!(out.result, Err("no_ct"));
        assert_eq!(start.elapsed(), Duration::from_millis(250), "waits WGZK_CT_WAIT_MS");
        assert!(set_calls(&f).is_empty());
        assert!(!f.gw.has_accepted(&c.ev.session_nonce));
    }

    #[tokio::test(start_paused = true)]
    async fn ciphertext_arriving_during_the_wait_is_used() {
        let f = Arc::new(fixture(Mode::ZkPq, false, 16, 16));
        let c = f.honest();
        let (ct, nonce) = (c.ct.clone().expect("ct"), c.ev.session_nonce);
        let buf = f.ctbuf.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            buf.insert(nonce, ct, 9).expect("late ciphertext");
        });
        let out = f.gw.decide(&c.ev).await;
        assert_eq!(out.result, Ok(()));
        assert_eq!(out.timings.wait_ct, Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn copied_nonce_does_not_use_up_the_ciphertext() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let victim = f.honest();
        f.deliver(&victim, 1);
        // An attacker copies (R, s, nonce) into an initiation carrying its own session key.
        let mut forged = victim.ev.clone();
        forged.peer_pub = random32();
        forged.pending_id += 1;
        assert_eq!(f.gw.decide(&forged).await.result, Err("proof"));
        assert!(set_calls(&f).is_empty(), "nothing created for the forgery");
        assert_eq!(f.gw.decide(&victim.ev).await.result, Ok(()), "the victim still succeeds");
    }

    #[tokio::test(start_paused = true)]
    async fn proof_bound_to_another_ciphertext_is_rejected() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let c = f.honest();
        // The gateway holds a different ciphertext for this nonce.
        let (other_ct, _) = f.ek.as_ref().expect("ek").encap();
        f.ctbuf.insert(c.ev.session_nonce, Arc::new(other_ct), 1).expect("insert");
        assert_eq!(f.gw.decide(&c.ev).await.result, Err("proof"));
        assert!(set_calls(&f).is_empty());
        assert!(!f.gw.has_accepted(&c.ev.session_nonce));
    }

    #[tokio::test(start_paused = true)]
    async fn epochs_current_then_previous() {
        let f = fixture(Mode::ZkPq, true, 16, 16);
        let prev = f.client(random32(), &f.sk_prev, f.epoch - 1, Mode::ZkPq);
        f.deliver(&prev, 1);
        assert_eq!(f.gw.decide(&prev.ev).await.result, Ok(()), "previous epoch accepted");

        let older = f.client(random32(), &f.sk_prev, f.epoch - 2, Mode::ZkPq);
        f.deliver(&older, 2);
        assert_eq!(f.gw.decide(&older.ev).await.result, Err("proof"), "two epochs back");

        let wrong_key = f.client(random32(), &f.sk_prev, f.epoch, Mode::ZkPq);
        f.deliver(&wrong_key, 3);
        assert_eq!(f.gw.decide(&wrong_key.ev).await.result, Err("proof"), "previous key, current epoch");

        let g = fixture(Mode::ZkPq, false, 16, 16);
        let prev = g.client(random32(), &g.sk_prev, g.epoch - 1, Mode::ZkPq);
        g.deliver(&prev, 1);
        assert_eq!(g.gw.decide(&prev.ev).await.result, Err("proof"), "no previous epoch configured");
    }

    #[tokio::test(start_paused = true)]
    async fn mode_is_bound() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let c = f.client(random32(), &f.sk, f.epoch, Mode::ZkOnly);
        f.deliver(&c, 1);
        assert_eq!(f.gw.decide(&c.ev).await.result, Err("proof"));
    }

    #[tokio::test(start_paused = true)]
    async fn zk_only_mode_installs_without_psk() {
        let f = fixture(Mode::ZkOnly, false, 16, 16);
        let c = f.honest();
        assert!(c.ct.is_none());
        let out = f.gw.decide(&c.ev).await;
        assert_eq!(out.result, Ok(()));
        assert_eq!(out.token, None);
        assert!(matches!(&set_calls(&f)[..], [Call::Set { psk: None, allowed_ip: Some(_), .. }]));
    }

    #[tokio::test(start_paused = true)]
    async fn full_peer_table_refuses_new_session_keys() {
        let f = fixture(Mode::ZkPq, false, 1, 16);
        let a = f.honest();
        f.deliver(&a, 1);
        assert_eq!(f.gw.decide(&a.ev).await.result, Ok(()));
        let b = f.honest();
        f.deliver(&b, 2);
        assert_eq!(f.gw.decide(&b.ev).await.result, Err("peer_full"));
        assert!(!f.gw.has_accepted(&b.ev.session_nonce), "no replay entry for a refused handshake");
        // A re-key of the installed session key still works.
        let rekey = f.client(a.ev.peer_pub, &f.sk, f.epoch, Mode::ZkPq);
        f.deliver(&rekey, 3);
        assert_eq!(f.gw.decide(&rekey.ev).await.result, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn installer_failure_rejects_and_records_nothing() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let c = f.honest();
        f.deliver(&c, 1);
        f.installer.set_failing(true);
        assert_eq!(f.gw.decide(&c.ev).await.result, Err("peer_install"));
        assert!(!f.gw.has_accepted(&c.ev.session_nonce));
        // The same initiation, delivered again (e.g. after a transient failure), can pass.
        f.installer.set_failing(false);
        assert_eq!(f.gw.decide(&c.ev).await.result, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn full_replay_cache_refuses_new_handshakes() {
        let f = fixture(Mode::ZkPq, false, 16, 1);
        let a = f.honest();
        f.deliver(&a, 1);
        assert_eq!(f.gw.decide(&a.ev).await.result, Ok(()));
        let b = f.honest();
        f.deliver(&b, 2);
        assert_eq!(f.gw.decide(&b.ev).await.result, Err("replay_full"));
        assert_eq!(set_calls(&f).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_duplicates_pass_once() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let c = f.honest();
        f.deliver(&c, 1);
        let mut dup = c.ev.clone();
        dup.pending_id += 1;
        let (g1, g2) = (f.gw.clone(), f.gw.clone());
        let (e1, e2) = (c.ev.clone(), dup);
        let a = tokio::spawn(async move { g1.decide(&e1).await.result });
        let b = tokio::spawn(async move { g2.decide(&e2).await.result });
        let mut results = [a.await.expect("a"), b.await.expect("b")];
        results.sort();
        // The copy is refused as busy while the first is being decided and as a replay
        // after that; which of the two it meets is a matter of scheduling.
        assert_eq!(results[0], Ok(()));
        assert!(matches!(results[1], Err("busy" | "replay")), "{results:?}");
        assert_eq!(set_calls(&f).len(), 1);
    }

    /// Copies of an initiation whose decision waits for the ciphertext do not wait behind
    /// it: each is refused at once, and the first still decides.
    #[tokio::test(start_paused = true)]
    async fn copies_do_not_queue_behind_a_waiting_decision() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let c = f.honest(); // no ciphertext delivered: the decision waits WGZK_CT_WAIT_MS
        let (gw, ev) = (f.gw.clone(), c.ev.clone());
        let first = tokio::spawn(async move { gw.decide(&ev).await.result });
        sleep(Duration::from_millis(10)).await;
        let start = Instant::now();
        for i in 0..100 {
            let mut copy = c.ev.clone();
            copy.pending_id += 1 + i;
            assert_eq!(f.gw.decide(&copy).await.result, Err("busy"));
        }
        assert_eq!(start.elapsed(), Duration::ZERO, "no copy waited");
        assert_eq!(first.await.expect("first"), Err("no_ct"));
    }

    /// With WGZK_VERIFY_MAX decisions in progress, the next event is rejected at once.
    #[tokio::test(start_paused = true)]
    async fn overload_is_rejected_at_once() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let bounds = Bounds { verify_max: 2, ..Bounds::from_env(&std::collections::HashMap::<&str, &str>::new()).expect("defaults") };
        let cfg = GatewayConfig {
            epoch: f.epoch,
            pk: zk::public_key(&f.sk),
            pk_prev: None,
            iface: "wg0".into(),
            addr_prefix: addr::DEFAULT_PREFIX,
            bounds,
            adopt_peers: false,
            installer: crate::settings::Installer::Netlink,
            pq: None,
        };
        let (seed, _) = mlkem::keygen();
        let gw = Arc::new(Gateway::new(&cfg, Some(Decapsulator::from_seed(&seed)), f.ctbuf.clone(), f.installer.clone()));
        let (tx, mut rx) = mpsc::channel(8);
        // Three events with different nonces and no ciphertext: two decisions wait, the
        // third finds no room.
        let events: Vec<NeedVerifyEvent> = (0..3).map(|_| f.honest().ev).collect();
        for ev in &events {
            gw.dispatch(ev.clone(), Instant::now(), &tx);
        }
        assert_eq!(
            rx.try_recv(),
            Ok(Request::SetVerify { pending_id: events[2].pending_id, result: 0 }),
            "rejected without waiting"
        );
        assert_eq!(gw.in_progress.available_permits(), 0);
        // The two decisions end after the wait for the ciphertext; room is free again.
        let mut late = vec![rx.recv().await.expect("verdict"), rx.recv().await.expect("verdict")];
        late.sort_by_key(|r| match r {
            Request::SetVerify { pending_id, .. } => *pending_id,
            Request::SetProof(_) => 0,
        });
        let mut expected: Vec<u64> = events[..2].iter().map(|e| e.pending_id).collect();
        expected.sort();
        assert_eq!(
            late,
            expected.iter().map(|id| Request::SetVerify { pending_id: *id, result: 0 }).collect::<Vec<_>>()
        );
        tokio::task::yield_now().await;
        assert_eq!(gw.in_progress.available_permits(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn verdicts_and_timing_for_every_event() {
        let f = fixture(Mode::ZkPq, false, 16, 16);
        let (tx, mut rx) = mpsc::channel(4);
        let ok = f.honest();
        f.deliver(&ok, 1);
        f.gw.dispatch(ok.ev.clone(), Instant::now(), &tx);
        let bad = f.honest(); // no ciphertext delivered
        f.gw.dispatch(bad.ev.clone(), Instant::now(), &tx);
        assert_eq!(rx.recv().await, Some(Request::SetVerify { pending_id: ok.ev.pending_id, result: 1 }));
        assert_eq!(rx.recv().await, Some(Request::SetVerify { pending_id: bad.ev.pending_id, result: 0 }));
    }

    const IDLE: Duration = Duration::from_secs(300);

    async fn collect(f: &Fixture) -> usize {
        f.gw.peers.collect_idle(&*f.gw.installer, &f.gw.iface, IDLE).await
    }

    #[tokio::test(start_paused = true)]
    async fn adopted_peers_count_against_the_bound() {
        let f = fixture(Mode::ZkPq, false, 2, 16);
        let (a, b) = (random32(), random32());
        f.installer.set_listed(&[a, b]);
        assert_eq!(f.gw.adopt_existing_peers().await, 2);
        let new = f.honest();
        f.deliver(&new, 1);
        assert_eq!(f.gw.decide(&new.ev).await.result, Err("peer_full"), "the adopted peers fill the table");
        let rekey = f.client(a, &f.sk, f.epoch, Mode::ZkPq);
        f.deliver(&rekey, 2);
        assert_eq!(f.gw.decide(&rekey.ev).await.result, Ok(()), "an adopted key can still be verified");
    }

    #[tokio::test(start_paused = true)]
    async fn more_peers_than_the_bound_are_all_adopted() {
        let f = fixture(Mode::ZkOnly, false, 2, 16);
        f.installer.set_listed(&[random32(), random32(), random32()]);
        assert_eq!(f.gw.adopt_existing_peers().await, 3);
        assert_eq!(f.gw.peers.len(), 3);
        let c = f.honest();
        assert_eq!(f.gw.decide(&c.ev).await.result, Err("peer_full"));
        advance(IDLE).await;
        assert_eq!(collect(&f).await, 3);
        let c = f.honest();
        assert_eq!(f.gw.decide(&c.ev).await.result, Ok(()), "below the bound again");
    }

    #[tokio::test(start_paused = true)]
    async fn adopted_peers_are_collected_when_idle() {
        let f = fixture(Mode::ZkOnly, false, 16, 16);
        let (a, b) = (random32(), random32());
        f.installer.set_listed(&[a, b]);
        f.gw.adopt_existing_peers().await;
        advance(IDLE - Duration::from_secs(1)).await;
        assert_eq!(collect(&f).await, 0);
        advance(Duration::from_secs(1)).await;
        assert_eq!(collect(&f).await, 2);
        let removed: Vec<Call> = f.installer.calls();
        assert!(removed.contains(&Call::Remove { iface: "wg0".into(), key: a }));
        assert!(removed.contains(&Call::Remove { iface: "wg0".into(), key: b }));
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_refreshes_an_adopted_peer() {
        let f = fixture(Mode::ZkOnly, false, 16, 16);
        let (a, b) = (random32(), random32());
        f.installer.set_listed(&[a, b]);
        f.gw.adopt_existing_peers().await;
        advance(Duration::from_secs(250)).await;
        let rekey = f.client(a, &f.sk, f.epoch, Mode::ZkOnly);
        assert_eq!(f.gw.decide(&rekey.ev).await.result, Ok(()));
        advance(Duration::from_secs(100)).await;
        assert_eq!(collect(&f).await, 1, "only b, idle for 350 s, is removed");
        assert_eq!(f.installer.calls().last(), Some(&Call::Remove { iface: "wg0".into(), key: b }));
        assert_eq!(f.gw.peers.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn adoption_can_be_switched_off() {
        let f = fixture_with(Mode::ZkOnly, false, 16, 16, false);
        f.installer.set_listed(&[random32()]);
        assert_eq!(f.gw.adopt_existing_peers().await, 0);
        assert_eq!(f.installer.list_calls(), 0, "the interface is not even listed");
        assert_eq!(f.gw.peers.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn listing_failure_is_survived() {
        let f = fixture(Mode::ZkOnly, false, 16, 16);
        f.installer.set_list_failing(true);
        assert_eq!(f.gw.adopt_existing_peers().await, 0);
        assert_eq!(f.installer.list_calls(), 1);
        let c = f.honest();
        assert_eq!(f.gw.decide(&c.ev).await.result, Ok(()), "the gateway works on");
    }
}
