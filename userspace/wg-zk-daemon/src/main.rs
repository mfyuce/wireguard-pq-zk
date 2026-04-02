use futures::future::pending;
use anyhow::Result;
use tokio::time::{sleep, Duration};
use std::collections::HashSet;
use tokio::sync::{Mutex, OnceCell};

mod netlink;
mod zk;
mod mlkem;
mod mlkem_channel;
use dotenvy::dotenv;

use curve25519_dalek::scalar::Scalar;
use netlink::*;
use zk::{parse_pk_hex, parse_sk_hex};

static SK: OnceCell<Scalar> = OnceCell::const_new();
static PK: OnceCell<[u8; 32]> = OnceCell::const_new();
static IN_FLIGHT: OnceCell<Mutex<HashSet<u64>>> = OnceCell::const_new();

// ── ML-KEM config (loaded from env) ──────────────────────────────────────────

/// ML-KEM config shared across tasks.
#[derive(Clone)]
struct MlKemConfig {
    /// Gateway: 64-byte seed (hex) for DecapsulationKey
    dk_seed: Option<[u8; mlkem::SEED_LEN]>,
    /// Gateway: TLS cert PEM
    cert_pem: Option<String>,
    /// Gateway: TLS key PEM
    key_pem: Option<String>,
    /// Gateway: WireGuard interface name (for `wg set`)
    wg_iface: Option<String>,
    /// Gateway: peer's WireGuard public key (base64, for `wg set ... preshared-key`)
    wg_peer_pubkey: Option<String>,
    /// Client: gateway ML-KEM encapsulation key (hex, 1184 bytes)
    server_ek: Option<[u8; mlkem::EK_LEN]>,
    /// Client: gateway TLS server address ("host:port")
    server_addr: Option<String>,
    /// Client: expected TLS cert fingerprint (hex SHA-256)
    cert_fp: Option<String>,
    /// TCP port for ML-KEM channel (default 51821)
    port: u16,
}

impl MlKemConfig {
    fn from_env() -> Self {
        let dk_seed = std::env::var("MLKEM_DK_SEED").ok().and_then(|h| {
            let b = hex::decode(h.trim()).ok()?;
            b.try_into().ok()
        });
        let server_ek = std::env::var("MLKEM_SERVER_EK").ok().and_then(|h| {
            let b = hex::decode(h.trim()).ok()?;
            b.try_into().ok()
        });
        let port = std::env::var("MLKEM_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(mlkem_channel::DEFAULT_PORT);
        MlKemConfig {
            dk_seed,
            cert_pem: std::env::var("MLKEM_CERT_PEM").ok(),
            key_pem: std::env::var("MLKEM_KEY_PEM").ok(),
            wg_iface: std::env::var("WG_IFACE").ok(),
            wg_peer_pubkey: std::env::var("WG_PEER_PUBKEY").ok(),
            server_ek,
            server_addr: std::env::var("MLKEM_SERVER_ADDR").ok(),
            cert_fp: std::env::var("MLKEM_CERT_FP").ok(),
            port,
        }
    }

    fn is_gateway_ready(&self) -> bool {
        self.dk_seed.is_some()
            && self.cert_pem.is_some()
            && self.key_pem.is_some()
            && self.wg_iface.is_some()
            && self.wg_peer_pubkey.is_some()
    }

    fn is_client_ready(&self) -> bool {
        self.server_ek.is_some()
            && self.server_addr.is_some()
            && self.cert_fp.is_some()
    }
}


async fn inflight() -> &'static Mutex<HashSet<u64>> {
    IN_FLIGHT.get_or_init(|| async { Mutex::new(HashSet::new()) }).await
}

async fn load_keys() -> Result<()> {
    if let Ok(sk_hex) = std::env::var("WGZK_SK_HEX") {
        SK.get_or_try_init(|| async move {
            // DİKKAT: sadece parse_*’ı döndür, Ok(...) yapma
            parse_sk_hex(&sk_hex)
        }).await?;
    }
    if let Ok(pk_hex) = std::env::var("WGZK_PK_HEX") {
        PK.get_or_try_init(|| async move {
            parse_pk_hex(&pk_hex)
        }).await?;
    }
    Ok(())
}

// 2) Decide mode robustly
fn decide_mode() -> &'static str {
    if let Ok(m) = std::env::var("WGZK_MODE") {
        return if m.eq_ignore_ascii_case("client") { "client" } else { "gateway" };
    }
    // default to client if nothing tells us otherwise
    "client"
}


#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {

    eprintln!( "[daemon] Starting" );
    // Load variables from .env file (if present)
    dotenv().ok();
    eprintln!( "[daemon] Env loaded" );
    load_keys().await?;
    eprintln!( "[daemon] Keys loaded" );

    inflight().await;

    eprintln!( "[daemon] Inflight loaded" );

    // // connect + resolve + join
    // let mut sock = connect_genl().await?;
    // let resolved = resolve_family_and_groups(&mut sock, "wgzk").await?;
    // let events_gid = *resolved.mcast_groups.get("events")
    //     .ok_or_else(|| anyhow::anyhow!("wgzk: 'events' multicast group missing"))?;
    // add_mcast(&sock, events_gid).await?;
    // // let family_id = resolved.family_id;

    let mode = decide_mode();
    eprintln!("[daemon] Mode = {mode}");

    let need_sk = mode == "client";
    let need_pk = mode == "gateway";

    if need_sk && SK.get().is_none() {
        eprintln!("[daemon] WARNING: WGZK_SK_HEX missing (client).");
    }
    if need_pk && PK.get().is_none() {
        eprintln!("[daemon] WARNING: WGZK_PK_HEX missing (gateway).");
    }

    // Load ML-KEM config from env
    let mlkem_cfg = MlKemConfig::from_env();

    // Optionally print generated cert info on gateway
    if mode == "gateway" && mlkem_cfg.cert_pem.is_none() {
        eprintln!("[mlkem] MLKEM_CERT_PEM not set — generating self-signed cert");
        match mlkem_channel::generate_self_signed() {
            Ok((cert, key, fp)) => {
                eprintln!("[mlkem] cert fingerprint (share with clients): {fp}");
                eprintln!("[mlkem] set MLKEM_CERT_PEM, MLKEM_KEY_PEM in .env to persist");
                eprintln!("[mlkem] MLKEM_CERT_PEM={cert}");
                let _ = (cert, key); // not stored — just printed
            }
            Err(e) => eprintln!("[mlkem] cert gen failed: {e}"),
        }
    }

    // CLIENT TASK (NEED_PROOF → ML-KEM encap + TLS send → SET_PROOF)
    let mlkem_cfg_c = mlkem_cfg.clone();
    let client_task = Some(tokio::spawn(async move {
        loop {
            match run_client_once(mlkem_cfg_c.clone()).await {
                Ok(_) => tokio::time::sleep(Duration::from_millis(500)).await,
                Err(e) => {
                    eprintln!("[client] loop error: {e:?} (retrying in 1s)");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }));

    // GATEWAY ML-KEM TLS LISTENER (background — decap CT + inject PSK)
    let mlkem_cfg_gw = mlkem_cfg.clone();
    let mlkem_listener_task = if mode == "gateway" && mlkem_cfg.is_gateway_ready() {
        Some(tokio::spawn(async move {
            loop {
                if let Err(e) = run_mlkem_gateway_listener(&mlkem_cfg_gw).await {
                    eprintln!("[mlkem-listener] error: {e:?} (retrying in 2s)");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }))
    } else {
        if mode == "gateway" {
            eprintln!("[mlkem] gateway ML-KEM disabled — set MLKEM_DK_SEED, MLKEM_CERT_PEM, MLKEM_KEY_PEM, WG_IFACE, WG_PEER_PUBKEY");
        }
        None
    };

    // GATEWAY ZK TASK (NEED_VERIFY → SET_VERIFY)
    let server_task = Some(tokio::spawn(async move {
        loop {
            match run_gateway_once().await {
                Ok(_) => tokio::time::sleep(Duration::from_millis(500)).await,
                Err(e) => {
                    eprintln!("[gateway] loop error: {e:?} (retrying in 1s)");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }));


    let client_join = async {
        if let Some(t) = client_task {
            let _ = t.await;
        } else {
            pending::<()>().await;
        }
    };

    let server_join = async {
        if let Some(t) = server_task {
            let _ = t.await;
        } else {
            pending::<()>().await;
        }
    };

    let mlkem_join = async {
        if let Some(t) = mlkem_listener_task {
            let _ = t.await;
        } else {
            pending::<()>().await;
        }
    };

    tokio::select! {
        _ = client_join => {},
        _ = server_join => {},
        _ = mlkem_join => {},
        _ = tokio::signal::ctrl_c() => { eprintln!("[daemon] shutdown"); }
    }

    // tokio::select! {
    //     _ = client_task => {},
    //     _ = server_task => {},
    //     _ = tokio::signal::ctrl_c() => {
    //         eprintln!("shutdown");
    //     }
    // }

    Ok(())
}

async fn run_gateway_once() -> Result<()> {
    use anyhow::anyhow;
    let mut sock = connect_genl().await?;
    let resolved = resolve_family_and_groups(&mut sock, "wgzk").await?;
    let events_gid = *resolved
        .mcast_groups
        .get("events")
        .ok_or_else(|| anyhow!("wgzk: 'events' multicast group missing"))?;
    add_mcast(&sock, events_gid).await?;
    let family_id = resolved.family_id;

    // let hand_path = Path::new("/sys/kernel/debug/wireguard/zk_handshake");

    loop {
        let (_nl_type, genl) = recv_next(&mut sock).await?;
        // 1) still support NEED_PROOF (clients behind this same binary)
        if *genl.cmd() == WgzkCmd::NeedProof as u8 {
            // no change to your client path here
            continue;
        }
        // 2) new NEED_VERIFY → SET_VERIFY path
        if let Some(ev) = try_parse_need_verify(&genl) {
            let pk = match PK.get() {
                Some(pk) => pk,
                None => { eprintln!("[gateway] PK not set; cannot verify"); continue; }
            };
            eprintln!("[gateway] r={} s={} nonce={}",
                hex::encode(ev.r), hex::encode(ev.s), hex::encode(ev.session_nonce));
            let ok = zk::verify(pk, &ev.r, &ev.s, &ev.session_nonce);
            eprintln!("[gateway] verify result={ok} idx={}", ev.sender_index);
            if let Err(e) = send_set_verify(&mut sock, family_id, ev.sender_index, if ok { 1 } else { 0 }).await {
                eprintln!("[gateway] SET_VERIFY send error: {e:?}");
            } else {
                eprintln!("[gateway] SET_VERIFY idx={} result={}", ev.sender_index, ok);
            }
        }
    }
}

async fn run_mlkem_gateway_listener(cfg: &MlKemConfig) -> Result<()> {
    let seed = cfg.dk_seed.as_ref().unwrap();
    let cert_pem = cfg.cert_pem.as_deref().unwrap();
    let key_pem = cfg.key_pem.as_deref().unwrap();
    let wg_iface = cfg.wg_iface.as_deref().unwrap();
    let wg_peer_pubkey = cfg.wg_peer_pubkey.as_deref().unwrap();

    let acceptor = mlkem_channel::make_acceptor(cert_pem, key_pem)?;
    let listener = mlkem_channel::bind(cfg.port).await?;

    loop {
        match mlkem_channel::recv_ciphertext(&acceptor, &listener).await {
            Ok((token, _nonce, ct)) => {
                eprintln!("[mlkem-gw] received CT token={token}");
                let ss = mlkem::decap(seed, &ct);
                let psk = mlkem::derive_psk(&ss);
                match mlkem::inject_psk(wg_iface, wg_peer_pubkey, &psk) {
                    Ok(()) => eprintln!("[mlkem-gw] PSK injected for token={token}"),
                    Err(e) => eprintln!("[mlkem-gw] inject_psk error: {e:?}"),
                }
            }
            Err(e) => {
                eprintln!("[mlkem-gw] recv_ciphertext error: {e:?}");
            }
        }
    }
}

async fn run_client_once(mlkem_cfg: MlKemConfig) -> Result<()> {
    eprintln!("[daemon] Connecting to genl");

    // ESKİ: expect / unwrap zinciri
    // YENİ: hepsi `?` ve kontrollü hata
    let mut sock = connect_genl().await?;

    eprintln!("[daemon] Connecting to wgzk");
    let resolved = resolve_family_and_groups(&mut sock, "wgzk").await?;
    let events_gid = *resolved
        .mcast_groups
        .get("events")
        .ok_or_else(|| anyhow::anyhow!("wgzk: 'events' multicast group missing"))?;

    eprintln!("[daemon] Connecting to mcast");
    add_mcast(&sock, events_gid).await?;
    eprintln!("[wgzk] joined events");

    if let Ok(ns) = std::fs::read_link("/proc/self/ns/net") {
        eprintln!("[wgzk] ns={}", ns.display());
    }

    let family_id = resolved.family_id;

    eprintln!("[daemon] Connecting to family_id");
    loop {
        eprintln!("[daemon] loop");
        match recv_next(&mut sock).await {
            Ok((_nl_type, genl)) => {
                eprintln!("[daemon] Recv OK");
                if *genl.cmd() == WgzkCmd::NeedProof as u8 {
                    if let Some(ev) = try_parse_need_proof(&genl) {
                        // Use per‑initiation token for dedup (best against races)
                        let token = ev.token.unwrap_or(0) as u64;
                        let mut inflight1 = inflight().await.lock().await;
                        if !inflight1.insert(token) {
                            continue; // already in-flight
                        }
                        drop(inflight1);

                        eprintln!(
                            "[daemon] NEED_PROOF ifindex={} peer_id={} token={:?}",
                            ev.ifindex, ev.peer_id, ev.token
                        );


                        let Some(sk) = SK.get() else {
                            eprintln!("[client] SK not set; cannot produce proof yet");
                            continue;
                        };
                        // Schnorr++: fresh session nonce for transcript binding
                        let session_nonce = zk::gen_session_nonce();
                        let (r, s) = zk::prove(sk, &session_nonce);
                        eprintln!("[client] proving r={} s={} nonce={}",
                            hex::encode(r), hex::encode(s), hex::encode(session_nonce));

                        // ML-KEM hybrid: encap + send CT to gateway over TLS
                        if mlkem_cfg.is_client_ready() {
                            let server_ek = mlkem_cfg.server_ek.as_ref().unwrap();
                            let server_addr = mlkem_cfg.server_addr.as_deref().unwrap();
                            let cert_fp = mlkem_cfg.cert_fp.as_deref().unwrap();
                            match mlkem::encap(server_ek) {
                                Ok((ct, ss)) => {
                                    let psk = mlkem::derive_psk(&ss);
                                    // Inject PSK locally (for gateway-side symmetry, client also injects its half)
                                    // Note: client doesn't call inject_psk — gateway does; client just sends CT.
                                    let token_u32 = ev.token.unwrap_or(0);
                                    match mlkem_channel::make_connector(cert_fp) {
                                        Ok(connector) => {
                                            if let Err(e) = mlkem_channel::send_ciphertext(
                                                &connector, server_addr, token_u32, &session_nonce, &ct,
                                            ).await {
                                                eprintln!("[client] ML-KEM send error: {e:?}");
                                            } else {
                                                eprintln!("[client] ML-KEM CT sent token={token_u32}");
                                                let _ = psk; // gateway will derive PSK from CT
                                            }
                                        }
                                        Err(e) => eprintln!("[client] make_connector error: {e:?}"),
                                    }
                                }
                                Err(e) => eprintln!("[client] ML-KEM encap error: {e:?}"),
                            }
                        }

                        if let Err(e) = send_set_proof(&mut sock, family_id, ev.peer_id, ev.token, &r, &s, ev.ifindex, &session_nonce).await {
                            eprintln!("[daemon] send_set_proof error: {e:?}");
                        } else {
                            eprintln!(
                                "[daemon] SET_PROOF sent peer_id={} token={:?}",
                                ev.peer_id, ev.token
                            );
                        }

                        inflight().await.lock().await.remove(&token);
                    }
                }
            }
            Err(e) => {
                eprintln!("[daemon] recv error: {e:?}");
                sleep(Duration::from_millis(250)).await;
            }
        }
    }
}