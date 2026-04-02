/// gen-mlkem: generate ML-KEM-768 keypair + self-signed TLS cert for gateway.
///
/// Output (shell-sourceable):
///   MLKEM_DK_SEED=<hex64>      gateway decapsulation key seed
///   MLKEM_EK=<hex1184>         client-side encapsulation key
///   MLKEM_CERT_PEM=<pem>       gateway TLS cert (single-line, \n escaped)
///   MLKEM_KEY_PEM=<pem>        gateway TLS private key
///   MLKEM_CERT_FP=<hex64>      SHA-256 fingerprint (pin on client)

use anyhow::Result;
use ml_kem::{
    kem::{KeyExport, Kem},
    MlKem768, Seed,
};
use sha2::{Digest, Sha256};

fn main() -> Result<()> {
    // ── ML-KEM-768 keypair ───────────────────────────────────────────────────
    let (dk, ek) = MlKem768::generate_keypair();
    let seed: Seed = dk.to_seed().expect("fresh key must have seed");
    let seed_bytes: [u8; 64] = seed.into();
    let ek_bytes: [u8; 1184] = ek.to_bytes().into();

    // ── Self-signed TLS cert ─────────────────────────────────────────────────
    let cert = rcgen::generate_simple_self_signed(vec!["wgzk-gateway".to_string()])?;
    let cert_pem = cert.cert.pem();
    let key_pem  = cert.key_pair.serialize_pem();
    let fp = {
        let mut h = Sha256::new();
        h.update(cert.cert.der());
        hex::encode(h.finalize())
    };

    // ── Print shell-sourceable vars ──────────────────────────────────────────
    // PEM values: escape newlines so they fit on one line for env files
    let cert_pem_esc = cert_pem.replace('\n', "\\n");
    let key_pem_esc  = key_pem.replace('\n', "\\n");

    println!("MLKEM_DK_SEED={}", hex::encode(seed_bytes));
    println!("MLKEM_EK={}", hex::encode(ek_bytes));
    println!("MLKEM_CERT_PEM={cert_pem_esc}");
    println!("MLKEM_KEY_PEM={key_pem_esc}");
    println!("MLKEM_CERT_FP={fp}");

    Ok(())
}
