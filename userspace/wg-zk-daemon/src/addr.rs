//! Inner tunnel address of a connection (`docs/protocol-r1.md`, Section 3.5), derived by
//! both sides from the session key:
//!
//! ```text
//! addr = prefix (8 bytes) || SHA-256("wgzk-addr-v1" || S_c)[0..8]
//! ```
//!
//! The client assigns `addr/128` to its interface, the gateway sets the peer's allowed-ips
//! to `addr/128`. Default prefix `fd57:475a:4b00:0000::/64`; `WGZK_ADDR_PREFIX` overrides it
//! and must then be the same on the gateway and on its clients.

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use std::net::Ipv6Addr;

/// fd57:475a:4b00:0000::/64
pub const DEFAULT_PREFIX: [u8; 8] = [0xfd, 0x57, 0x47, 0x5a, 0x4b, 0x00, 0x00, 0x00];

/// Tunnel address of the session key `s_c`.
pub fn derive_addr(prefix: &[u8; 8], s_c: &[u8; 32]) -> Ipv6Addr {
    let h = Sha256::new().chain_update(b"wgzk-addr-v1").chain_update(s_c).finalize();
    let mut a = [0u8; 16];
    a[..8].copy_from_slice(prefix);
    a[8..].copy_from_slice(&h[..8]);
    Ipv6Addr::from(a)
}

/// Parse a /64 prefix such as `fd57:475a:4b00::/64` (the `/64` may be omitted). The low
/// 64 bits must be zero.
pub fn parse_prefix(s: &str) -> Result<[u8; 8]> {
    let s = s.trim();
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    if let Some(l) = len {
        if l.trim() != "64" {
            bail!("address prefix must be a /64, got /{l}");
        }
    }
    let ip: Ipv6Addr = addr.trim().parse().map_err(|_| anyhow!("not an IPv6 prefix: {s}"))?;
    let o = ip.octets();
    if o[8..].iter().any(|b| *b != 0) {
        bail!("address prefix {s} has bits set beyond /64");
    }
    let mut p = [0u8; 8];
    p.copy_from_slice(&o[..8]);
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 Section 6.1, Alice's X25519 public key.
    const ALICE_PUB: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    fn alice() -> [u8; 32] {
        hex::decode(ALICE_PUB).expect("hex").try_into().expect("32 bytes")
    }

    #[test]
    fn derived_address_fixed_key() {
        // Expected values computed independently with Python hashlib/ipaddress.
        let a = derive_addr(&DEFAULT_PREFIX, &alice());
        assert_eq!(a.to_string(), "fd57:475a:4b00:0:f24:5b46:5b2e:4672");
        let other = parse_prefix("fd00:1234::/64").expect("prefix");
        assert_eq!(derive_addr(&other, &alice()).to_string(), "fd00:1234::f24:5b46:5b2e:4672");
    }

    #[test]
    fn different_keys_give_different_addresses() {
        let mut k = alice();
        k[0] ^= 1;
        assert_ne!(derive_addr(&DEFAULT_PREFIX, &k), derive_addr(&DEFAULT_PREFIX, &alice()));
    }

    #[test]
    fn prefix_parsing() {
        assert_eq!(parse_prefix("fd57:475a:4b00:0000::/64").expect("default"), DEFAULT_PREFIX);
        assert_eq!(parse_prefix("fd57:475a:4b00::").expect("no length"), DEFAULT_PREFIX);
        assert!(parse_prefix("fd57:475a:4b00::/48").is_err());
        assert!(parse_prefix("fd57:475a:4b00::1/64").is_err());
        assert!(parse_prefix("10.0.0.0/64").is_err());
    }
}
