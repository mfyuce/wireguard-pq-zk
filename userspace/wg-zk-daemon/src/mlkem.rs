/// ML-KEM-768 (FIPS 203) key encapsulation for PQ hybrid handshake.
///
/// Flow:
///   keygen() → (seed[64B], ek_bytes[1184B])
///   Client: encap(ek_bytes) → (ct[1088B], ss[32B])
///   Server: decap(seed, ct) → ss[32B]
///   Both:   psk = derive_psk(ss) = SHA-256("wgzk-mlkem-psk-v1" || ss)
///
/// Inject PSK into WireGuard before Noise handshake via `wg set ... preshared-key`.

use hybrid_array::Array;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, KeyExport, Kem},
    DecapsulationKey, EncapsulationKey, MlKem768, Seed,
};
use sha2::{Digest, Sha256};

pub const CT_LEN: usize = 1088; // ML-KEM-768 ciphertext (FIPS 203 §7)
pub const EK_LEN: usize = 1184; // ML-KEM-768 encapsulation key
pub const SEED_LEN: usize = 64; // DecapsulationKey seed (compact serialization)

/// Generate a fresh ML-KEM-768 keypair.
/// Returns (seed[64B], ek_bytes[1184B]).
pub fn keygen() -> ([u8; SEED_LEN], [u8; EK_LEN]) {
    let (dk, ek) = MlKem768::generate_keypair();
    let seed: Seed = dk.to_seed().expect("freshly generated key must have seed");
    let seed_bytes: [u8; SEED_LEN] = seed.into();
    let ek_bytes: [u8; EK_LEN] = ek.to_bytes().into();
    (seed_bytes, ek_bytes)
}

/// Client: encapsulate shared secret to server's encapsulation key.
/// Returns (ciphertext[1088B], shared_secret[32B]).
pub fn encap(server_ek_bytes: &[u8; EK_LEN]) -> anyhow::Result<([u8; CT_LEN], [u8; 32])> {
    let ek_arr: Array<u8, _> = (*server_ek_bytes).into();
    let ek = EncapsulationKey::<MlKem768>::new(&ek_arr)
        .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 encapsulation key"))?;
    let (ct, ss) = ek.encapsulate();
    let ct_bytes: [u8; CT_LEN] = ct.into();
    let ss_bytes: [u8; 32] = ss.into();
    Ok((ct_bytes, ss_bytes))
}

/// Server: decapsulate ciphertext using the 64-byte seed.
pub fn decap(seed: &[u8; SEED_LEN], ct_bytes: &[u8; CT_LEN]) -> [u8; 32] {
    let seed_arr: Seed = (*seed).into();
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed_arr);
    let ct: ml_kem::kem::Ciphertext<MlKem768> = (*ct_bytes).into();
    let ss = dk.decapsulate(&ct);
    ss.into()
}

/// Derive 32-byte WireGuard PSK from ML-KEM shared secret.
/// PSK = SHA-256("wgzk-mlkem-psk-v1" || shared_secret)
pub fn derive_psk(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"wgzk-mlkem-psk-v1");
    h.update(shared_secret);
    h.finalize().into()
}

/// Inject PSK into WireGuard peer via `wg set`.
/// peer_wg_pubkey: base64-encoded WireGuard Curve25519 public key.
pub fn inject_psk(ifname: &str, peer_wg_pubkey: &str, psk: &[u8; 32]) -> anyhow::Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use std::io::Write;
    use std::process::{Command, Stdio};
    let psk_b64 = STANDARD.encode(psk);
    let mut child = Command::new("wg")
        .args(["set", ifname, "peer", peer_wg_pubkey, "preshared-key", "/dev/stdin"])
        .stdin(Stdio::piped())
        .spawn()?;
    child.stdin.as_mut().unwrap().write_all(psk_b64.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("wg set preshared-key failed: {status}");
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encap_decap_roundtrip() {
        let (seed, ek_bytes) = keygen();
        let (ct, ss_client) = encap(&ek_bytes).expect("encap");
        let ss_server = decap(&seed, &ct);
        assert_eq!(ss_client, ss_server, "shared secrets must match");
    }

    #[test]
    fn psk_deterministic() {
        let ss = [0xab_u8; 32];
        assert_eq!(derive_psk(&ss), derive_psk(&ss));
    }

    #[test]
    fn correct_sizes() {
        let (seed, ek_bytes) = keygen();
        assert_eq!(seed.len(), SEED_LEN);
        assert_eq!(ek_bytes.len(), EK_LEN);
        let (ct, _) = encap(&ek_bytes).expect("encap");
        assert_eq!(ct.len(), CT_LEN);
    }
}
