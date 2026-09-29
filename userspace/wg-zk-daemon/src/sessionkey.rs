//! Per-connection session key `S_c` (`docs/protocol-r1.md`, Sections 1 and 5).
//!
//! `new-connection --iface <name>` generates a fresh WireGuard (X25519) key pair, makes it the
//! interface's private key through `wg set <iface> private-key /dev/stdin` (the key goes to
//! the tool's stdin, never to the command line or to disk), and replaces the interface's
//! global IPv6 addresses by the derived tunnel address `addr/128` of Section 3.5 with `ip`.
//! The same call asks for a new UDP port (`listen-port 0`: the kernel picks one), so that two
//! connections of a client do not share a source port either.
//!
//! Key generation: 32 bytes from the OS RNG, clamped as X25519 and `wg genkey` do; the public
//! key is the clamped scalar times the Montgomery base point (curve25519-dalek, already a
//! dependency).

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use curve25519_dalek::montgomery::MontgomeryPoint;
use std::net::Ipv6Addr;

use crate::addr;
use crate::tool;

pub struct KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

/// X25519 clamping (RFC 7748, Section 5).
pub fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// X25519 public key of a private key.
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*private).to_bytes()
}

pub fn generate() -> Result<KeyPair> {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).map_err(|e| anyhow!("OS RNG failure: {e}"))?;
    let private = clamp(k);
    Ok(KeyPair { private, public: public_key(&private) })
}

/// Install a fresh session key and its tunnel address on `iface`. Returns the public key
/// and the address.
pub async fn new_connection(iface: &str, prefix: &[u8; 8]) -> Result<([u8; 32], Ipv6Addr)> {
    let kp = generate()?;
    let addr = addr::derive_addr(prefix, &kp.public);
    let private_b64 = format!("{}\n", STANDARD.encode(kp.private));
    let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let set = a(&["set", iface, "private-key", "/dev/stdin", "listen-port", "0"]);
    tool::run("wg", &set, Some(private_b64.as_bytes())).await?;
    tool::run("ip", &a(&["-6", "addr", "flush", "dev", iface, "scope", "global"]), None).await?;
    tool::run("ip", &a(&["-6", "addr", "add", &format!("{addr}/128"), "dev", iface]), None).await?;
    Ok((kp.public, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("hex").try_into().expect("32 bytes")
    }

    #[test]
    fn rfc7748_base_point_vectors() {
        // RFC 7748, Section 6.1.
        let alice = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = h32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assert_eq!(hex::encode(public_key(&alice)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(hex::encode(public_key(&bob)), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        // Clamping does not change the public key.
        assert_eq!(public_key(&clamp(alice)), public_key(&alice));
    }

    #[test]
    fn generated_keys_are_clamped_and_fresh() {
        let a = generate().expect("a");
        let b = generate().expect("b");
        assert_eq!(a.private, clamp(a.private));
        assert_eq!(a.public, public_key(&a.private));
        assert_ne!(a.private, b.private);
    }

    /// Cross-check against `wg pubkey` (reads stdin, prints; needs no privileges). Skipped
    /// when the tool is not installed.
    #[test]
    fn matches_wg_pubkey() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let kp = generate().expect("key");
        let child = Command::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            eprintln!("wg not installed; skipping the wg pubkey cross-check");
            return;
        };
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(format!("{}\n", STANDARD.encode(kp.private)).as_bytes())
            .expect("write");
        let out = child.wait_with_output().expect("wg pubkey");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), STANDARD.encode(kp.public));
    }
}
