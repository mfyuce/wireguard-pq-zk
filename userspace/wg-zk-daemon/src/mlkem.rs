//! ML-KEM-768 (FIPS 203) for the post-quantum pre-shared key of mode `0x02`
//! (`docs/protocol-r1.md`, Sections 3.2 and 3.4).
//!
//! ```text
//! Client:  (ct[1088], ss[32]) = Encaps(ek)            Encapsulator::encap
//! Gateway: ss = Decaps(dk, ct)                          Decapsulator::decap
//! Both:    psk = SHA-256("wgzk-mlkem-psk-v1" || ss)     derive_psk
//! ```
//!
//! Keys are parsed once at startup: the gateway expands its 64-byte seed into the
//! decapsulation key, the client validates the 1184-byte encapsulation key. Installing the
//! PSK into WireGuard is the job of the installer in `peers.rs`.

use hybrid_array::Array;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    DecapsulationKey, EncapsulationKey, MlKem768, Seed,
};
use sha2::{Digest, Sha256};

pub const CT_LEN: usize = 1088; // ML-KEM-768 ciphertext (FIPS 203 §7)
pub const EK_LEN: usize = 1184; // ML-KEM-768 encapsulation key
pub const SEED_LEN: usize = 64; // DecapsulationKey seed (compact serialization)

/// Client side: the gateway's validated encapsulation key.
pub struct Encapsulator {
    ek: EncapsulationKey<MlKem768>,
}

impl Encapsulator {
    pub fn new(server_ek_bytes: &[u8; EK_LEN]) -> anyhow::Result<Self> {
        let ek_arr: Array<u8, _> = (*server_ek_bytes).into();
        let ek = EncapsulationKey::<MlKem768>::new(&ek_arr)
            .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 encapsulation key"))?;
        Ok(Encapsulator { ek })
    }

    /// Encapsulate a fresh shared secret. Returns (ciphertext[1088B], shared_secret[32B]).
    pub fn encap(&self) -> ([u8; CT_LEN], [u8; 32]) {
        let (ct, ss) = self.ek.encapsulate();
        (ct.into(), ss.into())
    }
}

/// Gateway side: the decapsulation key, expanded once from the 64-byte seed.
pub struct Decapsulator {
    dk: DecapsulationKey<MlKem768>,
}

impl Decapsulator {
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let seed_arr: Seed = (*seed).into();
        Decapsulator { dk: DecapsulationKey::<MlKem768>::from_seed(seed_arr) }
    }

    /// Decapsulate. ML-KEM decapsulation never fails: a malformed ciphertext yields an
    /// unrelated (implicit-rejection) secret, so the PSKs of the two sides then differ.
    pub fn decap(&self, ct_bytes: &[u8; CT_LEN]) -> [u8; 32] {
        let ct: ml_kem::kem::Ciphertext<MlKem768> = (*ct_bytes).into();
        self.dk.decapsulate(&ct).into()
    }
}

/// Derive 32-byte WireGuard PSK from ML-KEM shared secret.
/// PSK = SHA-256("wgzk-mlkem-psk-v1" || shared_secret)
pub fn derive_psk(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"wgzk-mlkem-psk-v1");
    h.update(shared_secret);
    h.finalize().into()
}

/// Generate a fresh ML-KEM-768 keypair: (seed[64B], ek_bytes[1184B]). Test fixtures only;
/// production keys come from the enrolment channel.
#[cfg(test)]
pub fn keygen() -> ([u8; SEED_LEN], [u8; EK_LEN]) {
    use ml_kem::kem::{Kem, KeyExport};
    let (dk, ek) = MlKem768::generate_keypair();
    let seed: Seed = dk.to_seed().expect("freshly generated key must have seed");
    (seed.into(), ek.to_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encap_decap_roundtrip() {
        let (seed, ek_bytes) = keygen();
        let (ct, ss_client) = Encapsulator::new(&ek_bytes).expect("ek").encap();
        let ss_server = Decapsulator::from_seed(&seed).decap(&ct);
        assert_eq!(ss_client, ss_server, "shared secrets must match");
        assert_eq!(derive_psk(&ss_client), derive_psk(&ss_server));
    }

    #[test]
    fn psk_known_answer() {
        // SHA-256("wgzk-mlkem-psk-v1" || 32 x 0xab), computed independently with hashlib.
        assert_eq!(
            hex::encode(derive_psk(&[0xab_u8; 32])),
            "2f1ae5715671518c26330069d6d1cac51e28aed10d135a9644d86c698b0f5be0"
        );
    }

    #[test]
    fn rejects_malformed_encapsulation_key() {
        // Coefficients must be < q = 3329; all-0xff encodes 4095.
        assert!(Encapsulator::new(&[0xff; EK_LEN]).is_err());
    }

    #[test]
    fn tampered_ciphertext_gives_other_secret() {
        let (seed, ek_bytes) = keygen();
        let (mut ct, ss_client) = Encapsulator::new(&ek_bytes).expect("ek").encap();
        ct[100] ^= 0x01;
        assert_ne!(Decapsulator::from_seed(&seed).decap(&ct), ss_client);
    }
}
