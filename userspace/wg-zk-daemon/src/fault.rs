//! Fault injection for the negative acceptance tests: cargo feature `fault-injection`, off by
//! default. `main.rs` declares this module only under the feature, so none of it exists in a
//! normal build; there a non-empty `WGZK_FAULT` stops the daemon at startup (`settings.rs`).
//!
//! A client daemon built with the feature misbehaves in the one way that `WGZK_FAULT`
//! selects, so that the test bed can show that the gateway refuses. Faults exist for the
//! client role only. The hooks sit at four places in `client.rs`: the transcript before
//! proving, the response after proving, the side-channel message, the local PSK.
//!
//! ```text
//! WGZK_FAULT      mode  the client ...                                          gateway
//! skip_ct         0x02  opens no side-channel connection; PSK, proof (bound to  no_ct
//!                       the hash of the unsent ciphertext) and SET_PROOF as usual
//! other_nonce_ct  0x02  sends the ciphertext under another, random nonce;       no_ct
//!                       proof and SET_PROOF carry the real nonce
//! flip_ct         0x02  sends the ciphertext with one bit flipped under the     proof
//!                       real nonce; the proof is bound to the original
//! bad_proof       any   flips one bit of s after proving                        proof
//! other_key       any   proves over a random S_c instead of LOCAL_PUB           proof
//! other_gw        any   proves over a random S_gw instead of PEER_PUB           proof
//! other_epoch     any   proves for epoch + 7 (wrapping)                         proof
//! no_psk          0x02  skips the local PSK installation                        accepts
//! ```
//!
//! With `no_psk` the gateway accepts and installs its PSK; the WireGuard handshake itself
//! then fails on the PSK mismatch, which only the test bed can show.

use anyhow::{bail, Result};

use crate::mlkem::CT_LEN;
use crate::settings::Env;
use crate::zk::{self, Transcript};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    SkipCt,
    OtherNonceCt,
    FlipCt,
    BadProof,
    OtherKey,
    OtherGw,
    OtherEpoch,
    NoPsk,
}

impl Fault {
    pub const ALL: [Fault; 8] = [
        Fault::SkipCt,
        Fault::OtherNonceCt,
        Fault::FlipCt,
        Fault::BadProof,
        Fault::OtherKey,
        Fault::OtherGw,
        Fault::OtherEpoch,
        Fault::NoPsk,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Fault::SkipCt => "skip_ct",
            Fault::OtherNonceCt => "other_nonce_ct",
            Fault::FlipCt => "flip_ct",
            Fault::BadProof => "bad_proof",
            Fault::OtherKey => "other_key",
            Fault::OtherGw => "other_gw",
            Fault::OtherEpoch => "other_epoch",
            Fault::NoPsk => "no_psk",
        }
    }

    /// Faults that act on the side channel or the PSK, which exist in mode 0x02 only.
    fn needs_pq(self) -> bool {
        matches!(self, Fault::SkipCt | Fault::OtherNonceCt | Fault::FlipCt | Fault::NoPsk)
    }
}

/// `WGZK_FAULT` of the client role. `pq`: the client runs in mode 0x02. Unset or empty: no
/// fault; an unknown name, or a mode-0x02 fault in mode 0x01, is a startup error.
pub fn from_env(env: &dyn Env, pq: bool) -> Result<Option<Fault>> {
    let Some(v) = env.var("WGZK_FAULT")? else { return Ok(None) };
    let Some(fault) = Fault::ALL.into_iter().find(|f| f.name() == v) else {
        let names: Vec<&str> = Fault::ALL.iter().map(|f| f.name()).collect();
        bail!("WGZK_FAULT={v:?}: unknown fault, expected one of {}", names.join(", "));
    };
    if fault.needs_pq() && !pq {
        bail!("WGZK_FAULT={v}: this fault needs mode 0x02, but WGZK_DISABLE_MLKEM=1");
    }
    Ok(Some(fault))
}

fn random32() -> Result<[u8; 32], &'static str> {
    zk::gen_session_nonce().map_err(|_| "rng")
}

/// Step 2, before proving: `other_key`, `other_gw` and `other_epoch` change what the proof
/// is bound to.
pub fn transcript(fault: Option<Fault>, mut t: Transcript) -> Result<Transcript, &'static str> {
    match fault {
        Some(Fault::OtherKey) => t.s_c = random32()?,
        Some(Fault::OtherGw) => t.s_gw = random32()?,
        Some(Fault::OtherEpoch) => t.epoch = t.epoch.wrapping_add(7),
        _ => {}
    }
    Ok(t)
}

/// Step 2, after proving: `bad_proof` flips one bit of `s`.
pub fn response(fault: Option<Fault>, mut s: [u8; 32]) -> [u8; 32] {
    if fault == Some(Fault::BadProof) {
        s[0] ^= 0x01;
    }
    s
}

/// A side-channel message: session nonce and ciphertext.
pub type Message = ([u8; 32], [u8; CT_LEN]);

/// Step 3, side channel: the message to send, or `None` for no connection at all.
pub fn side_channel(fault: Option<Fault>, nonce: [u8; 32], ct: [u8; CT_LEN]) -> Result<Option<Message>, &'static str> {
    Ok(match fault {
        Some(Fault::SkipCt) => None,
        Some(Fault::OtherNonceCt) => Some((random32()?, ct)),
        Some(Fault::FlipCt) => {
            let mut flipped = ct;
            flipped[0] ^= 0x01;
            Some((nonce, flipped))
        }
        _ => Some((nonce, ct)),
    })
}

/// Step 3, PSK: `false` when the local installation is skipped.
pub fn installs_psk(fault: Option<Fault>) -> bool {
    fault != Some(Fault::NoPsk)
}

/// ` fault=<name>` for the client timing line; empty without a fault.
pub fn log_field(fault: Option<Fault>) -> String {
    fault.map_or_else(String::new, |f| format!(" fault={}", f.name()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::testing::{as_need_verify, need_proof, pq_client, zk_client};
    use crate::client::Timings;
    use crate::gateway::testing::{fixture, random32 as random_key, Fixture};
    use crate::mlkem_channel::testing::{ensure_provider, self_signed, spawn_gateway};
    use crate::peers::testing::{Call, FakeInstaller};
    use crate::zk::Mode;
    use std::sync::Arc;
    use tokio::time::Duration;

    /// One handshake of a client with `fault` against the gateway fixture.
    struct Run {
        f: Fixture,
        result: Result<(), &'static str>,
        /// Nonce of the SET_PROOF.
        nonce: [u8; 32],
        client_calls: Vec<Call>,
    }

    async fn run(fault: Fault, mode: Mode) -> Run {
        let f = fixture(mode, false, 16, 16);
        let client_inst = Arc::new(FakeInstaller::default());
        let client = match mode {
            Mode::ZkPq => {
                ensure_provider();
                let (cert, key, fp) = self_signed();
                let addr = spawn_gateway(&cert, &key, f.ctbuf.clone()).await;
                let ek = f.ek_bytes.as_deref().expect("mode 0x02 fixture has ek");
                pq_client(ek, &addr, fp, f.sk, f.epoch, client_inst.clone())
            }
            Mode::ZkOnly => zk_client(f.sk, f.epoch, client_inst.clone()),
        }
        .with_fault(Some(fault));
        let s_c = random_key();
        let sp = client
            .prepare(&need_proof(f.s_gw, s_c), &mut Timings::default())
            .await
            .expect("a faulty client still sends SET_PROOF");
        let out = f.gw.decide(&as_need_verify(&sp, f.s_gw, s_c)).await;
        Run { result: out.result, nonce: sp.session_nonce, client_calls: client_inst.calls(), f }
    }

    /// Refused for `reason`, and nothing was created at the gateway.
    fn refused(r: &Run, reason: &str) {
        assert_eq!(r.result, Err(reason));
        assert!(r.f.installer.calls().is_empty(), "no peer installed at the gateway");
        assert!(!r.f.gw.has_accepted(&r.nonce), "no replay entry");
    }

    #[tokio::test]
    async fn skip_ct() {
        let r = run(Fault::SkipCt, Mode::ZkPq).await;
        refused(&r, "no_ct");
        assert_eq!(r.f.ctbuf.stored(), 0, "no side-channel message arrived");
        assert_eq!(r.client_calls.len(), 1, "the client installed its PSK as usual");
    }

    #[tokio::test]
    async fn other_nonce_ct() {
        let r = run(Fault::OtherNonceCt, Mode::ZkPq).await;
        refused(&r, "no_ct");
        assert_eq!(r.f.ctbuf.stored(), 1, "the ciphertext arrived, under another nonce");
        assert!(r.f.ctbuf.lookup(&r.nonce, Duration::ZERO).await.is_none());
    }

    #[tokio::test]
    async fn flip_ct() {
        let r = run(Fault::FlipCt, Mode::ZkPq).await;
        refused(&r, "proof");
        assert!(
            r.f.ctbuf.lookup(&r.nonce, Duration::ZERO).await.is_some(),
            "a ciphertext was found under the real nonce; its hash did not match"
        );
    }

    #[tokio::test]
    async fn proof_faults_in_both_modes() {
        for mode in [Mode::ZkPq, Mode::ZkOnly] {
            for fault in [Fault::BadProof, Fault::OtherKey, Fault::OtherGw, Fault::OtherEpoch] {
                let r = run(fault, mode).await;
                assert_eq!(r.result, Err("proof"), "{fault:?} in {mode:?}");
                refused(&r, "proof");
            }
        }
    }

    #[tokio::test]
    async fn no_psk_is_accepted_by_the_gateway() {
        let r = run(Fault::NoPsk, Mode::ZkPq).await;
        assert_eq!(r.result, Ok(()));
        assert!(r.client_calls.is_empty(), "the client installer was never called");
        assert_eq!(r.f.installer.calls().len(), 1, "the gateway installed its peer");
    }

    #[test]
    fn hooks_do_nothing_without_a_fault() {
        let t = Transcript {
            mode: Mode::ZkPq,
            epoch: 1,
            pk: [1; 32],
            s_gw: [2; 32],
            s_c: [3; 32],
            nonce: [4; 32],
            h_ct: [5; 32],
        };
        assert_eq!(transcript(None, t), Ok(t));
        assert_eq!(response(None, [9; 32]), [9; 32]);
        assert_eq!(side_channel(None, [4; 32], [7; CT_LEN]), Ok(Some(([4; 32], [7; CT_LEN]))));
        assert!(installs_psk(None));
        assert_eq!(log_field(None), "");
        assert_eq!(log_field(Some(Fault::FlipCt)), " fault=flip_ct");
        assert_eq!(transcript(Some(Fault::OtherEpoch), t).map(|t| t.epoch), Ok(8));
        let wrapped = Transcript { epoch: u32::MAX, ..t };
        assert_eq!(transcript(Some(Fault::OtherEpoch), wrapped).map(|t| t.epoch), Ok(6));
    }
}
