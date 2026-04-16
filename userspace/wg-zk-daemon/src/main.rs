use futures::future::pending;
use anyhow::{anyhow, Result};
use tokio::time::{sleep, Duration};
use std::collections::{HashMap, HashSet};
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

/// Gateway-side pending ML-KEM shared secrets, keyed by the session nonce sent
/// by the client. Inserted by the ML-KEM TLS listener and consumed by the ZK
/// NEED_VERIFY handler, binding ZK proof ↔ ML-KEM CT via the matching nonce.
static MLKEM_PENDING: OnceCell<Mutex<HashMap<[u8; 32], ([u8; 32], u32)>>> = OnceCell::const_new();

async fn mlkem_pending() -> &'static Mutex<HashMap<[u8; 32], ([u8; 32], u32)>> {
    MLKEM_PENDING.get_or_init(|| async { Mutex::new(HashMap::new()) }).await
}

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
        // WGZK_DISABLE_MLKEM=1 forces ZK-only mode: all ML-KEM fields are None
        // so is_{client,gateway}_ready() return false and the TLS/encap paths
        // are skipped. Used by the benchmark harness for 3-config comparison.
        if std::env::var("WGZK_DISABLE_MLKEM").map(|v| v == "1").unwrap_or(false) {
            eprintln!("[mlkem] WGZK_DISABLE_MLKEM=1 — running in ZK-only mode");
            return MlKemConfig {
                dk_seed: None, cert_pem: None, key_pem: None,
                wg_iface: std::env::var("WG_IFACE").ok(),
                wg_peer_pubkey: std::env::var("WG_PEER_PUBKEY").ok(),
                server_ek: None, server_addr: None, cert_fp: None,
                port: mlkem_channel::DEFAULT_PORT,
            };
        }
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
            // NOTE: return parse_* result directly — do not wrap in Ok(...)
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
    eprintln!("[wgzk] WGZK_MODE not set; defaulting to 'client'. Set WGZK_MODE=gateway on the gateway daemon.");
    "client"
}


#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {

    eprintln!( "[daemon] Starting" );
    // Install rustls ring provider (must be called before any TLS operation)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("rustls ring provider already installed");
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
    let mlkem_disabled = std::env::var("WGZK_DISABLE_MLKEM").map(|v| v == "1").unwrap_or(false);

    // Optionally print generated cert info on gateway
    if mode == "gateway" && !mlkem_disabled && mlkem_cfg.cert_pem.is_none() {
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
    let mlkem_enabled = mode == "gateway" && mlkem_cfg.is_gateway_ready();
    let server_task = Some(tokio::spawn(async move {
        loop {
            match run_gateway_once(mlkem_enabled).await {
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

async fn run_gateway_once(mlkem_enabled: bool) -> Result<()> {
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

            // Bind ZK proof to matching ML-KEM CT (if ML-KEM is enabled).
            // The client uses the same session nonce for both; the ML-KEM listener
            // inserts (nonce → ss) before the ZK proof arrives. Absence of a match
            // means the ML-KEM CT never arrived (or carried a different nonce).
            if mlkem_enabled {
                let bound = mlkem_pending().await.lock().await.remove(&ev.session_nonce);
                match bound {
                    Some((_ss, token)) => eprintln!(
                        "[gateway] ZK↔ML-KEM bound nonce={} token={}",
                        hex::encode(ev.session_nonce), token
                    ),
                    None => eprintln!(
                        "[gateway] WARNING: ZK proof without matching ML-KEM CT for nonce={}",
                        hex::encode(ev.session_nonce)
                    ),
                }
            }

            if let Err(e) = send_set_verify(&mut sock, family_id, ev.sender_index, if ok { 1 } else { 0 }).await {
                eprintln!("[gateway] SET_VERIFY send error: {e:?}");
            } else {
                eprintln!("[gateway] SET_VERIFY idx={} result={}", ev.sender_index, ok);
            }
        }
    }
}

async fn run_mlkem_gateway_listener(cfg: &MlKemConfig) -> Result<()> {
    let seed = cfg.dk_seed.as_ref().ok_or_else(|| anyhow!("ML-KEM gateway: WGZK_MLKEM_DK_SEED missing"))?;
    let cert_pem = cfg.cert_pem.as_deref().ok_or_else(|| anyhow!("ML-KEM gateway: WGZK_MLKEM_CERT_PEM missing"))?;
    let key_pem = cfg.key_pem.as_deref().ok_or_else(|| anyhow!("ML-KEM gateway: WGZK_MLKEM_KEY_PEM missing"))?;
    let wg_iface = cfg.wg_iface.as_deref().ok_or_else(|| anyhow!("ML-KEM gateway: WGZK_WG_IFACE missing"))?;
    let wg_peer_pubkey = cfg.wg_peer_pubkey.as_deref().ok_or_else(|| anyhow!("ML-KEM gateway: WGZK_WG_PEER_PUBKEY missing"))?;

    let acceptor = mlkem_channel::make_acceptor(cert_pem, key_pem)?;
    let listener = mlkem_channel::bind(cfg.port).await?;

    let mut backoff_ms: u64 = 50;
    const BACKOFF_MAX_MS: u64 = 5_000;
    loop {
        match mlkem_channel::recv_ciphertext(&acceptor, &listener).await {
            Ok((token, nonce, ct)) => {
                backoff_ms = 50;
                eprintln!("[mlkem-gw] received CT token={token} nonce={}", hex::encode(nonce));
                let ss = mlkem::decap(seed, &ct);
                // Store pending binding keyed by the client-provided session nonce.
                // The ZK NEED_VERIFY handler looks it up by the matching nonce from
                // the ZK proof — this ties ZK ↔ ML-KEM for the same session.
                mlkem_pending().await.lock().await.insert(nonce, (ss, token));
                let psk = mlkem::derive_psk(&ss);
                match mlkem::inject_psk(wg_iface, wg_peer_pubkey, &psk) {
                    Ok(()) => eprintln!("[mlkem-gw] PSK injected for token={token}"),
                    Err(e) => eprintln!("[mlkem-gw] inject_psk error: {e:?}"),
                }
            }
            Err(e) => {
                eprintln!("[mlkem-gw] recv_ciphertext error: {e:?} (backoff {backoff_ms}ms)");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(BACKOFF_MAX_MS);
            }
        }
    }
}

async fn run_client_once(mlkem_cfg: MlKemConfig) -> Result<()> {
    eprintln!("[daemon] Connecting to genl");

    // All genl operations use `?` with proper error propagation — no expect/unwrap.
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
                        // Per-initiation token dedup (best against races). Skip dedup
                        // if kernel omitted the token — better to handle a duplicate
                        // than to drop every tokenless initiation after the first.
                        if let Some(t) = ev.token {
                            let mut inflight1 = inflight().await.lock().await;
                            if !inflight1.insert(t as u64) {
                                continue; // already in-flight
                            }
                            drop(inflight1);
                        } else {
                            eprintln!("[daemon] NEED_PROOF without token; dedup skipped");
                        }

                        // Nanosecond-resolution timing anchors for the benchmark harness.
                        // These Instants bracket each daemon phase so the host-side
                        // analyzer can compute per-phase deltas below journald's
                        // microsecond-coalescing floor.
                        let t_start = std::time::Instant::now();
                        let token_log = ev.token.unwrap_or(0);

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
                        let t_zk = std::time::Instant::now();
                        eprintln!("[client] proving r={} s={} nonce={}",
                            hex::encode(r), hex::encode(s), hex::encode(session_nonce));

                        let mut t_encap = t_zk;
                        let mut t_tls = t_zk;
                        let mut t_mlkem = t_zk;
                        let mut t_psk = t_zk;

                        // ML-KEM hybrid: encap + send CT to gateway over TLS
                        if let (Some(server_ek), Some(server_addr), Some(cert_fp)) = (
                            mlkem_cfg.server_ek.as_ref(),
                            mlkem_cfg.server_addr.as_deref(),
                            mlkem_cfg.cert_fp.as_deref(),
                        ) {
                            match mlkem::encap(server_ek) {
                                Ok((ct, ss)) => {
                                    t_encap = std::time::Instant::now();
                                    let psk = mlkem::derive_psk(&ss);
                                    let token_u32 = ev.token.unwrap_or(0);
                                    match mlkem_channel::make_connector(cert_fp) {
                                        Ok(connector) => {
                                            match mlkem_channel::connect_tls(&connector, server_addr).await {
                                                Ok(mut tls) => {
                                                    t_tls = std::time::Instant::now();
                                                    if let Err(e) = mlkem_channel::send_on(
                                                        &mut tls, token_u32, &session_nonce, &ct,
                                                    ).await {
                                                        eprintln!("[client] ML-KEM send error: {e:?}");
                                                    } else {
                                                        t_mlkem = std::time::Instant::now();
                                                        eprintln!("[client] ML-KEM CT sent token={token_u32}");
                                                        if let (Some(iface), Some(peer_pubkey)) = (
                                                            mlkem_cfg.wg_iface.as_deref(),
                                                            mlkem_cfg.wg_peer_pubkey.as_deref(),
                                                        ) {
                                                            match mlkem::inject_psk(iface, peer_pubkey, &psk) {
                                                                Ok(()) => eprintln!("[client] PSK injected locally"),
                                                                Err(e) => eprintln!("[client] inject_psk error: {e:?}"),
                                                            }
                                                        }
                                                        t_psk = std::time::Instant::now();
                                                    }
                                                }
                                                Err(e) => eprintln!("[client] TLS connect error: {e:?}"),
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
                        let t_end = std::time::Instant::now();
                        eprintln!(
                            "[timing] token={} total_us={} zk_us={} mlkem_us={} psk_us={} tail_us={} encap_us={} tls_us={} write_us={}",
                            token_log,
                            t_end.duration_since(t_start).as_micros(),
                            t_zk.duration_since(t_start).as_micros(),
                            t_mlkem.duration_since(t_zk).as_micros(),
                            t_psk.duration_since(t_mlkem).as_micros(),
                            t_end.duration_since(t_psk).as_micros(),
                            t_encap.duration_since(t_zk).as_micros(),
                            t_tls.duration_since(t_encap).as_micros(),
                            t_mlkem.duration_since(t_tls).as_micros(),
                        );

                        if let Some(t) = ev.token {
                            inflight().await.lock().await.remove(&(t as u64));
                        }
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