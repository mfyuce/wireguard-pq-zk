//! WireGuard peers created by the daemon (`docs/protocol-r1.md`, Section 6 step 3.5 and
//! Section 7), and the installer boundary shared with the client (Section 5 step 3).
//!
//! [`PeerInstaller`] is the only way the daemon changes WireGuard state. [`WgTool`]
//! implements it with the `wg` tool:
//!
//! ```text
//! wg set <iface> peer <key> [preshared-key /dev/stdin] [allowed-ips <addr>/128]
//! wg set <iface> peer <key> remove
//! wg show <iface> peers
//! ```
//!
//! The PSK is written to the tool's stdin. The default implementation is
//! [`crate::wgnl::WgNetlink`], which sends the same changes over WireGuard's generic netlink
//! family without a child process; `WGZK_INSTALLER` selects one of the two ([`installer`]).
//!
//! [`PeerTable`] remembers which peers the gateway installed and when each was last
//! verified. At `WGZK_PEER_MAX` installed peers a handshake for a new key is refused (an
//! existing peer can still be updated); nothing is evicted. A periodic task removes peers
//! whose last verification is older than `WGZK_PEER_IDLE_SECS`. Installation and removal of
//! the same key never interleave.
//!
//! The table lives in memory. So that peers installed by an earlier run of the daemon are
//! still counted and collected, the gateway adopts at start every peer that `WG_IFACE`
//! already has, as if it had been verified at that moment (`WGZK_ADOPT_PEERS=1`, the
//! default; [`PeerTable::adopt`]). Adoption reserves the interface for peers created by the
//! daemon: a manually configured peer on it is removed once it has been idle for
//! `WGZK_PEER_IDLE_SECS`. If more peers exist than `WGZK_PEER_MAX`, all are adopted and new
//! keys are refused until removals bring the table below the bound.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use tokio::time::{Duration, Instant};

use crate::keylock::KeyedLocks;
use crate::settings::Installer;
use crate::tool;
use crate::wgnl::WgNetlink;

/// One `wg set ... peer ...` operation.
pub struct PeerUpdate<'a> {
    pub iface: &'a str,
    /// The peer's static public key.
    pub key: [u8; 32],
    /// Pre-shared key; `None` leaves it untouched (mode `0x01`).
    pub psk: Option<[u8; 32]>,
    /// Allowed IP, set as `<addr>/128`; `None` leaves allowed-ips untouched.
    pub allowed_ip: Option<Ipv6Addr>,
}

pub trait PeerInstaller: Send + Sync {
    /// Create or update a peer.
    fn set_peer<'a>(&'a self, u: &'a PeerUpdate<'a>) -> BoxFuture<'a, Result<()>>;
    /// Remove a peer.
    fn remove_peer<'a>(&'a self, iface: &'a str, key: &'a [u8; 32]) -> BoxFuture<'a, Result<()>>;
    /// Public keys of the peers the interface has now.
    fn list_peers<'a>(&'a self, iface: &'a str) -> BoxFuture<'a, Result<Vec<[u8; 32]>>>;
}

/// The installer selected by `WGZK_INSTALLER`.
pub fn installer(kind: Installer) -> std::sync::Arc<dyn PeerInstaller> {
    match kind {
        Installer::Netlink => std::sync::Arc::new(WgNetlink::new()),
        Installer::Tool => std::sync::Arc::new(WgTool),
    }
}

/// Parse the output of `wg show <iface> peers`: one base64 public key per line. A line that
/// is not a key fails the whole listing (the message does not repeat the line).
fn parse_peer_list(out: &str) -> Result<Vec<[u8; 32]>> {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            STANDARD
                .decode(l)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| anyhow!("unexpected line in the output of wg show ... peers"))
        })
        .collect()
}

/// [`PeerInstaller`] backed by the `wg` tool.
pub struct WgTool;

impl WgTool {
    fn set_args(u: &PeerUpdate<'_>) -> Vec<String> {
        let mut a = vec!["set".to_string(), u.iface.to_string(), "peer".to_string(), STANDARD.encode(u.key)];
        if u.psk.is_some() {
            a.extend(["preshared-key".to_string(), "/dev/stdin".to_string()]);
        }
        if let Some(ip) = u.allowed_ip {
            a.extend(["allowed-ips".to_string(), format!("{ip}/128")]);
        }
        a
    }

    fn remove_args(iface: &str, key: &[u8; 32]) -> Vec<String> {
        vec!["set".to_string(), iface.to_string(), "peer".to_string(), STANDARD.encode(key), "remove".to_string()]
    }
}

impl PeerInstaller for WgTool {
    fn set_peer<'a>(&'a self, u: &'a PeerUpdate<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let stdin = u.psk.map(|psk| format!("{}\n", STANDARD.encode(psk)));
            tool::run("wg", &Self::set_args(u), stdin.as_deref().map(str::as_bytes)).await
        })
    }

    fn remove_peer<'a>(&'a self, iface: &'a str, key: &'a [u8; 32]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { tool::run("wg", &Self::remove_args(iface, key), None).await })
    }

    fn list_peers<'a>(&'a self, iface: &'a str) -> BoxFuture<'a, Result<Vec<[u8; 32]>>> {
        Box::pin(async move {
            let args = ["show".to_string(), iface.to_string(), "peers".to_string()];
            let out = tool::output("wg", &args, None).await?;
            parse_peer_list(&String::from_utf8_lossy(&out))
        })
    }
}

#[derive(Debug)]
pub enum PeerError {
    /// `WGZK_PEER_MAX` peers installed and this key is not one of them.
    Full,
    Install(anyhow::Error),
}

struct TableInner {
    /// Installed peers and the time of their last successful verification.
    peers: HashMap<[u8; 32], Instant>,
    /// New peers being installed right now; they count against the bound.
    reserved: usize,
}

pub struct PeerTable {
    inner: Mutex<TableInner>,
    keys: KeyedLocks<[u8; 32]>,
    max: usize,
}

/// A slot for a new peer; given back unless the installation succeeded.
struct NewPeerSlot<'a> {
    table: &'a PeerTable,
    committed: bool,
}

impl NewPeerSlot<'_> {
    /// The peer is now in `t.peers`; release the reservation under the same lock.
    fn commit(mut self, t: &mut TableInner) {
        t.reserved -= 1;
        self.committed = true;
    }
}

impl Drop for NewPeerSlot<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.table.inner().reserved -= 1;
        }
    }
}

impl PeerTable {
    pub fn new(max: usize) -> Self {
        PeerTable {
            inner: Mutex::new(TableInner { peers: HashMap::new(), reserved: 0 }),
            keys: KeyedLocks::new(),
            max,
        }
    }

    fn inner(&self) -> MutexGuard<'_, TableInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Step 3.5: create or update the peer `u.key` and mark it verified now.
    pub async fn install(&self, installer: &dyn PeerInstaller, u: &PeerUpdate<'_>) -> Result<(), PeerError> {
        let _key = self.keys.lock(u.key).await;
        let slot = {
            let mut t = self.inner();
            if t.peers.contains_key(&u.key) {
                None
            } else if t.peers.len() + t.reserved >= self.max {
                return Err(PeerError::Full);
            } else {
                t.reserved += 1;
                Some(NewPeerSlot { table: self, committed: false })
            }
        };
        installer.set_peer(u).await.map_err(PeerError::Install)?;
        let mut t = self.inner();
        t.peers.insert(u.key, Instant::now());
        if let Some(slot) = slot {
            slot.commit(&mut t);
        }
        Ok(())
    }

    /// Remove every peer whose last verification is at least `idle` old. Returns how many
    /// were removed; a failed removal is logged and retried on the next round.
    pub async fn collect_idle(&self, installer: &dyn PeerInstaller, iface: &str, idle: Duration) -> usize {
        let now = Instant::now();
        let candidates: Vec<[u8; 32]> = self
            .inner()
            .peers
            .iter()
            .filter(|(_, last)| now.saturating_duration_since(**last) >= idle)
            .map(|(k, _)| *k)
            .collect();
        let mut removed = 0;
        for key in candidates {
            let _key = self.keys.lock(key).await;
            // A handshake may have refreshed it while we waited for the key.
            let still_idle = self
                .inner()
                .peers
                .get(&key)
                .is_some_and(|last| Instant::now().saturating_duration_since(*last) >= idle);
            if !still_idle {
                continue;
            }
            match installer.remove_peer(iface, &key).await {
                Ok(()) => {
                    self.inner().peers.remove(&key);
                    removed += 1;
                }
                Err(e) => eprintln!("[peers] removing an idle peer failed: {e:#}"),
            }
        }
        removed
    }

    /// Gateway start: enter peers that already exist on the interface as if verified now.
    /// The bound is not applied, since the peers exist anyway; while the table is at or above
    /// it, new keys are refused. Returns how many keys were entered. Runs before any
    /// handshake is handled, so it takes no per-key lock.
    pub fn adopt(&self, keys: &[[u8; 32]]) -> usize {
        let now = Instant::now();
        let mut t = self.inner();
        let before = t.peers.len();
        for key in keys {
            t.peers.insert(*key, now);
        }
        t.peers.len() - before
    }

    /// Installed peers.
    pub fn len(&self) -> usize {
        self.inner().peers.len()
    }

    /// `WGZK_PEER_MAX`.
    pub fn max(&self) -> usize {
        self.max
    }
}

#[cfg(test)]
pub mod testing {
    //! A recording [`PeerInstaller`] for tests.
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Call {
        Set { iface: String, key: [u8; 32], psk: Option<[u8; 32]>, allowed_ip: Option<Ipv6Addr> },
        Remove { iface: String, key: [u8; 32] },
    }

    #[derive(Default)]
    pub struct FakeInstaller {
        pub calls: Mutex<Vec<Call>>,
        pub fail: std::sync::atomic::AtomicBool,
        /// What `list_peers` returns.
        pub listed: Mutex<Vec<[u8; 32]>>,
        pub list_fail: std::sync::atomic::AtomicBool,
        pub list_calls: std::sync::atomic::AtomicUsize,
    }

    impl FakeInstaller {
        pub fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }

        pub fn set_failing(&self, fail: bool) {
            self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
        }

        /// Peers the interface "has" for `list_peers`.
        pub fn set_listed(&self, keys: &[[u8; 32]]) {
            *self.listed.lock().unwrap_or_else(PoisonError::into_inner) = keys.to_vec();
        }

        pub fn set_list_failing(&self, fail: bool) {
            self.list_fail.store(fail, std::sync::atomic::Ordering::SeqCst);
        }

        pub fn list_calls(&self) -> usize {
            self.list_calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn result(&self) -> Result<()> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("injected failure")
            }
            Ok(())
        }
    }

    impl PeerInstaller for FakeInstaller {
        fn set_peer<'a>(&'a self, u: &'a PeerUpdate<'a>) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.result()?;
                self.calls.lock().unwrap_or_else(PoisonError::into_inner).push(Call::Set {
                    iface: u.iface.to_string(),
                    key: u.key,
                    psk: u.psk,
                    allowed_ip: u.allowed_ip,
                });
                Ok(())
            })
        }

        fn remove_peer<'a>(&'a self, iface: &'a str, key: &'a [u8; 32]) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.result()?;
                self.calls
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(Call::Remove { iface: iface.to_string(), key: *key });
                Ok(())
            })
        }

        fn list_peers<'a>(&'a self, _iface: &'a str) -> BoxFuture<'a, Result<Vec<[u8; 32]>>> {
            Box::pin(async move {
                self.list_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if self.list_fail.load(std::sync::atomic::Ordering::SeqCst) {
                    anyhow::bail!("injected listing failure")
                }
                Ok(self.listed.lock().unwrap_or_else(PoisonError::into_inner).clone())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Call, FakeInstaller};
    use super::*;
    use tokio::time::advance;

    fn upd(key: u8) -> PeerUpdate<'static> {
        PeerUpdate { iface: "wg0", key: [key; 32], psk: Some([0x70 + key; 32]), allowed_ip: Some(Ipv6Addr::LOCALHOST) }
    }

    #[test]
    fn wg_arguments() {
        let key_b64 = STANDARD.encode([1u8; 32]);
        let ip: Ipv6Addr = "fd57:475a:4b00::1".parse().expect("ip");
        // Gateway, mode 0x02.
        let u = PeerUpdate { iface: "wg0", key: [1; 32], psk: Some([2; 32]), allowed_ip: Some(ip) };
        assert_eq!(
            WgTool::set_args(&u),
            ["set", "wg0", "peer", &key_b64, "preshared-key", "/dev/stdin", "allowed-ips", "fd57:475a:4b00::1/128"]
        );
        // Gateway, mode 0x01: no preshared-key argument.
        let u = PeerUpdate { psk: None, ..u };
        assert_eq!(WgTool::set_args(&u), ["set", "wg0", "peer", &key_b64, "allowed-ips", "fd57:475a:4b00::1/128"]);
        // Client: PSK for the gateway peer only.
        let u = PeerUpdate { iface: "wgc", key: [1; 32], psk: Some([2; 32]), allowed_ip: None };
        assert_eq!(WgTool::set_args(&u), ["set", "wgc", "peer", &key_b64, "preshared-key", "/dev/stdin"]);
        assert_eq!(WgTool::remove_args("wg0", &[1; 32]), ["set", "wg0", "peer", &key_b64, "remove"]);
        // The PSK never appears among the arguments.
        assert!(!WgTool::set_args(&u).iter().any(|a| a.contains(&STANDARD.encode([2u8; 32]))));
    }

    #[tokio::test(start_paused = true)]
    async fn install_new_and_update() {
        let inst = FakeInstaller::default();
        let t = PeerTable::new(4);
        t.install(&inst, &upd(1)).await.expect("new");
        t.install(&inst, &upd(1)).await.expect("update");
        assert_eq!(t.len(), 1);
        assert_eq!(inst.calls().len(), 2);
        assert!(matches!(&inst.calls()[0], Call::Set { key, psk: Some(p), .. } if *key == [1; 32] && *p == [0x71; 32]));
    }

    #[tokio::test(start_paused = true)]
    async fn full_table_refuses_new_keys_only() {
        let inst = FakeInstaller::default();
        let t = PeerTable::new(2);
        t.install(&inst, &upd(1)).await.expect("1");
        t.install(&inst, &upd(2)).await.expect("2");
        assert!(matches!(t.install(&inst, &upd(3)).await, Err(PeerError::Full)));
        assert_eq!(inst.calls().len(), 2, "no installer call for a refused key");
        t.install(&inst, &upd(2)).await.expect("existing peers can still be updated");
        assert_eq!(t.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_install_leaves_no_trace() {
        let inst = FakeInstaller::default();
        let t = PeerTable::new(1);
        inst.set_failing(true);
        assert!(matches!(t.install(&inst, &upd(1)).await, Err(PeerError::Install(_))));
        assert_eq!(t.len(), 0);
        inst.set_failing(false);
        t.install(&inst, &upd(2)).await.expect("the reserved slot was given back");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_peers_are_collected() {
        let inst = FakeInstaller::default();
        let t = PeerTable::new(8);
        let idle = Duration::from_secs(300);
        t.install(&inst, &upd(1)).await.expect("a");
        advance(Duration::from_secs(200)).await;
        t.install(&inst, &upd(2)).await.expect("b");
        advance(Duration::from_secs(99)).await;
        assert_eq!(t.collect_idle(&inst, "wg0", idle).await, 0, "a is idle for 299 s only");
        advance(Duration::from_secs(1)).await;
        assert_eq!(t.collect_idle(&inst, "wg0", idle).await, 1);
        assert_eq!(t.len(), 1);
        assert_eq!(inst.calls().last(), Some(&Call::Remove { iface: "wg0".into(), key: [1; 32] }));
    }

    #[tokio::test(start_paused = true)]
    async fn reverification_keeps_a_peer() {
        let inst = FakeInstaller::default();
        let t = PeerTable::new(8);
        let idle = Duration::from_secs(300);
        t.install(&inst, &upd(1)).await.expect("first");
        advance(Duration::from_secs(250)).await;
        t.install(&inst, &upd(1)).await.expect("re-key");
        advance(Duration::from_secs(100)).await;
        assert_eq!(t.collect_idle(&inst, "wg0", idle).await, 0);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn peer_list_parsing() {
        let (a, b) = (STANDARD.encode([1u8; 32]), STANDARD.encode([2u8; 32]));
        assert_eq!(parse_peer_list(&format!("{a}\n{b}\n")).expect("two"), vec![[1; 32], [2; 32]]);
        assert!(parse_peer_list("").expect("none").is_empty());
        assert!(parse_peer_list(&format!("{a}\nnot-a-key\n")).is_err());
        assert!(parse_peer_list(&STANDARD.encode([1u8; 16])).is_err(), "16 bytes is not a key");
    }

    #[tokio::test(start_paused = true)]
    async fn adopted_peers_count_and_age_like_installed_ones() {
        let inst = FakeInstaller::default();
        let t = PeerTable::new(2);
        assert_eq!(t.adopt(&[[1; 32], [2; 32], [3; 32], [3; 32]]), 3, "all adopted, duplicates once");
        assert_eq!(t.len(), 3);
        assert!(matches!(t.install(&inst, &upd(4)).await, Err(PeerError::Full)), "above the bound");
        t.install(&inst, &upd(1)).await.expect("an adopted key can be refreshed");
        advance(Duration::from_secs(300)).await;
        assert_eq!(t.collect_idle(&inst, "wg0", Duration::from_secs(300)).await, 3);
        t.install(&inst, &upd(4)).await.expect("below the bound again");
    }

    #[tokio::test(start_paused = true)]
    async fn failed_removal_is_retried() {
        let inst = FakeInstaller::default();
        let t = PeerTable::new(8);
        t.install(&inst, &upd(1)).await.expect("install");
        advance(Duration::from_secs(301)).await;
        inst.set_failing(true);
        assert_eq!(t.collect_idle(&inst, "wg0", Duration::from_secs(300)).await, 0);
        assert_eq!(t.len(), 1, "still tracked");
        inst.set_failing(false);
        assert_eq!(t.collect_idle(&inst, "wg0", Duration::from_secs(300)).await, 1);
        assert_eq!(t.len(), 0);
    }
}
