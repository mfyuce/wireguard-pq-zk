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
/// Aynı peer_id için birden fazla eşzamanlı üretimi engelle.
static IN_FLIGHT: OnceCell<Mutex<HashSet<u64>>> = OnceCell::const_new();


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

    // Do not exit; just warn (so you can start and later inject keys)
    if need_sk && SK.get().is_none() {
        eprintln!("[daemon] WARNING: WGZK_SK_HEX missing (client). Will retry proof only when SK set.");
    }
    if need_pk && PK.get().is_none() {
        eprintln!("[daemon] WARNING: WGZK_PK_HEX missing (gateway). Verify will fail until set.");
    }


    // CLIENT TASK (NEED_PROOF → SET_PROOF)
    let client_task =
        Some(tokio::spawn(async move {
            loop {
                match run_client_once().await {
                    Ok(_) => {
                        // run_client_once returns only on controlled shutdown; keep alive
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        eprintln!("[client] loop error: {e:?} (retrying in 1s)");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                };
            }
        })) ;

    // GATEWAY TASK (NEED_VERIFY → SET_VERIFY)
    let server_task =
        Some(tokio::spawn(async move {
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

    tokio::select! {
        _ = client_join => {},
        _ = server_join => {},
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

async fn run_client_once()  -> Result<()>{
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