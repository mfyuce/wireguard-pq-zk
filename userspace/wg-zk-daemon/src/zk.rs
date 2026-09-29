//! Schnorr++ proof of knowledge of the group credential `sk_e` over Ristretto255,
//! challenge version 2 (`docs/protocol-r1.md`, Section 3.3).
//!
//! ```text
//! R = [r]G         r = HMAC-SHA512(sk_e, "WGZK-v1/hedged-nonce" || 64 random bytes) mod l
//! c = SHA-512(T || mode || epoch || pk_e || S_gw || S_c || R || nonce || h_ct) mod l
//! s = r + c * sk_e mod l
//! ```
//!
//! `T` is the 28-byte ASCII tag `WGZK-v2/schnorr-ristretto255`, `mode` one byte, `epoch` a
//! u32 in little endian, every other field 32 bytes. `mod l` reduces the 64-byte SHA-512
//! digest, read as a little-endian integer, modulo the group order. The proof on the wire
//! is `(R, s, nonce)`; everything else in the transcript is known to both sides.
//!
//! Binding `S_c` makes a proof useless in any initiation other than the one it was made
//! for: the proof travels in clear, and an unbound proof could be copied into an attacker's
//! initiation. Binding `h_ct = SHA-256(ct)` (mode `0x02`) ties the proof to the ML-KEM
//! ciphertext the gateway holds for the same nonce; in mode `0x01` `h_ct` is 32 zero bytes.
//!
//! Verification rejects non-canonical encodings of `pk_e`, `R` and `s`, and compares the
//! group elements in constant time.

use anyhow::{anyhow, bail};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use getrandom::fill;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

type HmacSha512 = Hmac<Sha512>;

/// Domain tag of challenge version 2 (28 bytes, no terminator).
pub const CHALLENGE_TAG: &[u8; 28] = b"WGZK-v2/schnorr-ristretto255";

/// `h_ct` in mode `0x01` (no ciphertext).
pub const H_CT_NONE: [u8; 32] = [0u8; 32];

/// Operating mode of a gateway, and of the clients that talk to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `0x01`: proof only.
    ZkOnly,
    /// `0x02`: proof plus ML-KEM-768 pre-shared key.
    ZkPq,
}

impl Mode {
    /// Wire value of the mode, as hashed into the challenge.
    pub fn byte(self) -> u8 {
        match self {
            Mode::ZkOnly => 0x01,
            Mode::ZkPq => 0x02,
        }
    }
}

/// Everything the challenge binds except the commitment `R`, which is produced by the
/// prover and travels with the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transcript {
    pub mode: Mode,
    pub epoch: u32,
    /// Credential public key `pk_e`, compressed Ristretto255.
    pub pk: [u8; 32],
    /// Gateway WireGuard static public key.
    pub s_gw: [u8; 32],
    /// Client session (per-connection) WireGuard public key.
    pub s_c: [u8; 32],
    /// Session nonce.
    pub nonce: [u8; 32],
    /// `SHA-256(ct)` in mode `0x02`, [`H_CT_NONE`] in mode `0x01`.
    pub h_ct: [u8; 32],
}

/// `h_ct = SHA-256(ct)`.
pub fn ct_hash(ct: &[u8]) -> [u8; 32] {
    Sha256::digest(ct).into()
}

/// Fiat-Shamir challenge, version 2. Field order and lengths are those of Section 3.3.
fn challenge(t: &Transcript, r_enc: &[u8; 32]) -> Scalar {
    let mut h = Sha512::new();
    h.update(CHALLENGE_TAG);
    h.update([t.mode.byte()]);
    h.update(t.epoch.to_le_bytes());
    h.update(t.pk);
    h.update(t.s_gw);
    h.update(t.s_c);
    h.update(r_enc);
    h.update(t.nonce);
    h.update(t.h_ct);
    Scalar::from_hash(h)
}

/// Schnorr++ measure 2: hedged nonce.
/// r = HMAC-SHA512(sk_bytes, "WGZK-v1/hedged-nonce" ‖ OSRAND_64) mod ℓ
///
/// Combining secret-key material with fresh OS randomness provides resilience
/// against both RNG failures (deterministic component) and fault attacks
/// (random component). A failing OS RNG is an error, never a fallback.
fn hedged_nonce(sk_bytes: &[u8; 32]) -> anyhow::Result<Scalar> {
    const SALT: &[u8] = b"WGZK-v1/hedged-nonce";
    let mut osrand = [0u8; 64];
    fill(&mut osrand).map_err(|e| anyhow!("OS RNG failure: {e}"))?;

    let mut mac = <HmacSha512 as Mac>::new_from_slice(sk_bytes)
        .map_err(|_| anyhow!("HMAC key rejected"))?;
    mac.update(SALT);
    mac.update(&osrand);
    let tag = mac.finalize().into_bytes();

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&tag);
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

/// Generate a fresh 32-byte session nonce.
pub fn gen_session_nonce() -> anyhow::Result<[u8; 32]> {
    let mut n = [0u8; 32];
    fill(&mut n).map_err(|e| anyhow!("OS RNG failure: {e}"))?;
    Ok(n)
}

/// Credential public key `pk_e = [sk_e]G`, compressed.
pub fn public_key(sk: &Scalar) -> [u8; 32] {
    (G * sk).compress().to_bytes()
}

/// Schnorr++ prove over the transcript `t`. Returns `(R, s)`.
///
/// `t.pk` must be the public key of `sk_x`; otherwise the proof does not verify.
pub fn prove(sk_x: &Scalar, t: &Transcript) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let sk_bytes: [u8; 32] = sk_x.to_bytes();
    let r = hedged_nonce(&sk_bytes)?;
    Ok(prove_with_r(sk_x, &r, t))
}

/// The prover's arithmetic for a given commitment scalar `r`. Private on purpose: outside
/// this module `r` is always the hedged nonce. The known-answer test calls it directly.
fn prove_with_r(sk_x: &Scalar, r: &Scalar, t: &Transcript) -> ([u8; 32], [u8; 32]) {
    let r_enc = (G * r).compress().to_bytes();
    let c = challenge(t, &r_enc);
    let s = r + c * sk_x;
    (r_enc, s.to_bytes())
}

/// Schnorr++ verify: `[s]G == R + [c]pk` for the transcript `t`, with canonical
/// encoding validation (measure 7) and a constant-time comparison (measure 8).
pub fn verify(t: &Transcript, r_bytes: &[u8; 32], s_bytes: &[u8; 32]) -> bool {
    // Ristretto canonical decoding — rejects non-canonical encodings (measure 7)
    let Some(x_point) = CompressedRistretto(t.pk).decompress() else { return false; };
    let Some(r_point) = CompressedRistretto(*r_bytes).decompress() else { return false; };

    // Canonical scalar — reject malleable inputs (measure 7)
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(*s_bytes)) else { return false; };

    // `r_bytes` decoded, so it is the unique encoding of `r_point`: hashing it equals
    // hashing `r_point.compress()` as the prover did.
    let c = challenge(t, r_bytes);

    // Constant-time equality check via Ristretto (measure 8)
    (G * s) == (r_point + c * x_point)
}

/// Decode `WGZK_SK_HEX`: 32 bytes of hex, reduced modulo the group order. Error messages
/// never contain the input.
pub fn parse_sk_hex(hex32: &str) -> anyhow::Result<Scalar> {
    let b = hex::decode(hex32.trim()).map_err(|_| anyhow!("secret key is not valid hex"))?;
    let arr: [u8; 32] = b
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("secret key must be 32 bytes hex"))?;
    let sk = Scalar::from_bytes_mod_order(arr);
    if sk == Scalar::ZERO {
        bail!("secret key reduces to zero");
    }
    Ok(sk)
}

/// Decode `WGZK_PK_HEX` / `WGZK_PK_PREV_HEX`: a canonical compressed Ristretto255 point
/// other than the identity.
pub fn parse_pk_hex(hex32: &str) -> anyhow::Result<[u8; 32]> {
    let b = hex::decode(hex32.trim()).map_err(|_| anyhow!("public key is not valid hex"))?;
    let arr: [u8; 32] = b
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes hex (Ristretto255 compressed)"))?;
    let Some(point) = CompressedRistretto(arr).decompress() else {
        bail!("public key is not a canonical Ristretto255 encoding");
    };
    if point == RistrettoPoint::identity() {
        bail!("public key is the identity element");
    }
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_sk() -> Scalar {
        let mut seed = [0u8; 32];
        fill(&mut seed).expect("rng");
        Scalar::from_bytes_mod_order(seed)
    }

    fn random_bytes() -> [u8; 32] {
        let mut b = [0u8; 32];
        fill(&mut b).expect("rng");
        b
    }

    fn transcript_for(sk: &Scalar) -> Transcript {
        Transcript {
            mode: Mode::ZkPq,
            epoch: 3,
            pk: public_key(sk),
            s_gw: random_bytes(),
            s_c: random_bytes(),
            nonce: gen_session_nonce().expect("rng"),
            h_ct: ct_hash(b"some ciphertext"),
        }
    }

    #[test]
    fn prove_verify_roundtrip() {
        let sk = random_sk();
        let t = transcript_for(&sk);
        let (r, s) = prove(&sk, &t).expect("prove");
        assert!(verify(&t, &r, &s), "verify should succeed");
    }

    #[test]
    fn roundtrip_zk_only_mode() {
        let sk = random_sk();
        let t = Transcript { mode: Mode::ZkOnly, h_ct: H_CT_NONE, ..transcript_for(&sk) };
        let (r, s) = prove(&sk, &t).expect("prove");
        assert!(verify(&t, &r, &s));
    }

    /// Prove over `t`, then verify over `t` with exactly one field changed by `mutate`.
    fn fails_when_changed(mutate: impl Fn(&mut Transcript)) {
        let sk = random_sk();
        let t = transcript_for(&sk);
        let (r, s) = prove(&sk, &t).expect("prove");
        assert!(verify(&t, &r, &s), "unchanged transcript must verify");
        let mut t2 = t;
        mutate(&mut t2);
        assert_ne!(t, t2, "the mutation must change the transcript");
        assert!(!verify(&t2, &r, &s), "changed transcript must not verify");
    }

    #[test]
    fn changed_mode_fails() {
        fails_when_changed(|t| t.mode = Mode::ZkOnly);
    }

    #[test]
    fn changed_epoch_fails() {
        fails_when_changed(|t| t.epoch += 1);
    }

    #[test]
    fn changed_pk_fails() {
        // A different, valid credential public key.
        let other = public_key(&random_sk());
        fails_when_changed(move |t| t.pk = other);
    }

    #[test]
    fn changed_s_gw_fails() {
        fails_when_changed(|t| t.s_gw[0] ^= 0x01);
    }

    #[test]
    fn changed_s_c_fails() {
        fails_when_changed(|t| t.s_c[31] ^= 0x80);
    }

    #[test]
    fn changed_nonce_fails() {
        fails_when_changed(|t| t.nonce[7] ^= 0x10);
    }

    #[test]
    fn changed_h_ct_fails() {
        fails_when_changed(|t| t.h_ct = ct_hash(b"another ciphertext"));
    }

    #[test]
    fn wrong_key_fails() {
        let sk1 = random_sk();
        let sk2 = random_sk();
        let t1 = transcript_for(&sk1);
        let (r, s) = prove(&sk1, &t1).expect("prove");
        let t2 = Transcript { pk: public_key(&sk2), ..t1 };
        assert!(!verify(&t2, &r, &s), "wrong key must fail");
    }

    #[test]
    fn non_canonical_s_fails() {
        let sk = random_sk();
        let t = transcript_for(&sk);
        let (r, s) = prove(&sk, &t).expect("prove");
        // s + l has the same value mod l but is not the canonical encoding.
        let l_le: [u8; 32] = hex::decode(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        )
        .expect("hex")
        .try_into()
        .expect("32 bytes");
        let mut sum = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = s[i] as u16 + l_le[i] as u16 + carry;
            sum[i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "s + l fits in 32 bytes because s < l < 2^253");
        assert!(!verify(&t, &r, &sum), "non-canonical s must be rejected");
    }

    #[test]
    fn parse_keys() {
        let sk = random_sk();
        let pk = public_key(&sk);
        assert_eq!(parse_pk_hex(&hex::encode(pk)).expect("pk"), pk);
        assert_eq!(parse_sk_hex(&hex::encode(sk.to_bytes())).expect("sk"), sk);
        assert!(parse_sk_hex(&"00".repeat(32)).is_err(), "zero secret");
        assert!(parse_sk_hex("abcd").is_err(), "short secret");
        assert!(parse_pk_hex(&"00".repeat(32)).is_err(), "identity public key");
        assert!(parse_pk_hex(&"ff".repeat(32)).is_err(), "non-canonical public key");
    }

    // ── Known-answer test, challenge version 2 ──────────────────────────────────
    //
    // Inputs: the scalars below are canonical little-endian encodings. `KAT_R_SCALAR`
    // stands in for the hedged nonce; `KAT_H_CT` is SHA-256("wgzk-kat-v2/ct"). The expected
    // values were produced by this module and checked independently in Python: c and s with
    // hashlib and integer arithmetic (c = int.from_bytes(SHA-512(...), "little") mod l,
    // s = r + c * sk mod l), pk_e and R with a separate Ristretto255 encoder that reproduces
    // the RFC 9496 generator vectors.
    const KAT_SK: &str = "4731bcefd3f3791c92a34f200ba53d34ec23fba43359c942acc6de359f62c50c";
    const KAT_R_SCALAR: &str = "6c27bb2c8a257a0be64da3c84e2d9725f25a1612eb9f4ff1b172711c724d4b0b";
    const KAT_MODE: Mode = Mode::ZkPq;
    const KAT_EPOCH: u32 = 7;
    const KAT_S_GW: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const KAT_S_C: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const KAT_NONCE: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    const KAT_H_CT: &str = "d2dfb433e44bc0fc6a37d766483f400f0fc5f9ad6214293de880733a6534e359";
    // Expected: pk_e = [sk]G, the challenge c, and the proof (R, s).
    const KAT_PK: &str = "c866f2598183d9bbc4b3958828184f9e53537da7c4f39d85361124a50e6eb10b";
    const KAT_C: &str = "f211b548717869fb97f33dcf77c97e2eee4962e32f371f06ad4eba62066c0502";
    const KAT_R: &str = "8cd9e4d0e4dbe42ff4e87a05057f109bf357a068126543c927e64286f9410302";
    const KAT_S: &str = "77ed96eea8500f23de7ee536351e65069f1d95ba45a5472fac504659d9be5608";

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("hex").try_into().expect("32 bytes")
    }

    fn kat_scalar(s: &str) -> Scalar {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(h32(s))).expect("canonical scalar")
    }

    fn kat_transcript() -> Transcript {
        Transcript {
            mode: KAT_MODE,
            epoch: KAT_EPOCH,
            pk: public_key(&kat_scalar(KAT_SK)),
            s_gw: h32(KAT_S_GW),
            s_c: h32(KAT_S_C),
            nonce: h32(KAT_NONCE),
            h_ct: h32(KAT_H_CT),
        }
    }

    #[test]
    fn known_answer_v2() {
        let sk = kat_scalar(KAT_SK);
        let r = kat_scalar(KAT_R_SCALAR);
        let t = kat_transcript();
        let (r_enc, s) = prove_with_r(&sk, &r, &t);
        let c = challenge(&t, &r_enc);
        assert_eq!(hex::encode(t.pk), KAT_PK, "pk_e");
        assert_eq!(hex::encode(c.to_bytes()), KAT_C, "challenge");
        assert_eq!(hex::encode(r_enc), KAT_R, "R");
        assert_eq!(hex::encode(s), KAT_S, "s");
        assert!(verify(&t, &r_enc, &s), "the vector must verify");
    }

    #[test]
    fn challenge_input_is_225_bytes() {
        // 28 + 1 + 4 + 6 * 32: a changed field length or order would show up here.
        let t = kat_transcript();
        let mut buf = Vec::new();
        buf.extend_from_slice(CHALLENGE_TAG);
        buf.push(t.mode.byte());
        buf.extend_from_slice(&t.epoch.to_le_bytes());
        buf.extend_from_slice(&t.pk);
        buf.extend_from_slice(&t.s_gw);
        buf.extend_from_slice(&t.s_c);
        buf.extend_from_slice(&[0x55; 32]);
        buf.extend_from_slice(&t.nonce);
        buf.extend_from_slice(&t.h_ct);
        assert_eq!(buf.len(), 225);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&Sha512::digest(&buf));
        assert_eq!(challenge(&t, &[0x55; 32]), Scalar::from_bytes_mod_order_wide(&wide));
    }
}
