//! Replay cache (`docs/protocol-r1.md`, Section 6 steps 3.1 and 3.6, Section 7).
//!
//! A bounded set of the session nonces of accepted handshakes, kept for the lifetime of the
//! process (one epoch). A nonce enters the set only after every other check of step 3 has
//! passed, so the API is `contains` (step 3.1) and `insert` (step 3.6), not a combined
//! check-and-insert.
//!
//! Two concurrent events with the same nonce must not both pass. The gateway therefore
//! holds [`ReplayCache::try_lock_nonce`] across the whole decision for one nonce; decisions
//! on different nonces run in parallel. An event whose nonce is being decided is not queued
//! behind that decision but refused: copies of one initiation must not pile up as waiting
//! tasks.
//!
//! When the cache is full, new handshakes are refused; nothing is evicted. Capacity is
//! reserved at step 3.1 ([`ReplayCache::reserve`]) so that the insert at step 3.6, which
//! happens after the peer was created, cannot fail for lack of room.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::keylock::{KeyGuard, KeyedLocks};

struct Inner {
    accepted: HashSet<[u8; 32]>,
    /// Insertions promised to decisions in progress.
    reserved: usize,
}

pub struct ReplayCache {
    inner: Mutex<Inner>,
    max: usize,
    nonces: KeyedLocks<[u8; 32]>,
}

/// Room for one insertion. Dropping it unused gives the room back.
pub struct ReplaySlot<'a> {
    cache: &'a ReplayCache,
    used: bool,
}

impl ReplayCache {
    pub fn new(max: usize) -> Self {
        ReplayCache {
            inner: Mutex::new(Inner { accepted: HashSet::new(), reserved: 0 }),
            max,
            nonces: KeyedLocks::new(),
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Exclusive right to decide on `nonce` until the guard is dropped; `None` while
    /// another decision on the same nonce is in progress.
    pub fn try_lock_nonce(&self, nonce: [u8; 32]) -> Option<KeyGuard<'_, [u8; 32]>> {
        self.nonces.try_lock(nonce)
    }

    /// Step 3.1: has a handshake with this nonce been accepted already?
    pub fn contains(&self, nonce: &[u8; 32]) -> bool {
        self.inner().accepted.contains(nonce)
    }

    /// Reserve room for one insertion; `None` when the cache is full.
    pub fn reserve(&self) -> Option<ReplaySlot<'_>> {
        let mut inner = self.inner();
        if inner.accepted.len() + inner.reserved >= self.max {
            return None;
        }
        inner.reserved += 1;
        Some(ReplaySlot { cache: self, used: false })
    }

    /// Accepted nonces.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner().accepted.len()
    }
}

impl ReplaySlot<'_> {
    /// Step 3.6: record the nonce of an accepted handshake.
    pub fn insert(mut self, nonce: [u8; 32]) {
        let mut inner = self.cache.inner();
        inner.reserved -= 1;
        inner.accepted.insert(nonce);
        self.used = true;
    }
}

impl Drop for ReplaySlot<'_> {
    fn drop(&mut self) {
        if !self.used {
            self.cache.inner().reserved -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration, Instant};

    #[test]
    fn contains_after_insert() {
        let c = ReplayCache::new(8);
        assert!(!c.contains(&[1; 32]));
        c.reserve().expect("room").insert([1; 32]);
        assert!(c.contains(&[1; 32]));
        assert!(!c.contains(&[2; 32]));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn full_cache_refuses_and_keeps_entries() {
        let c = ReplayCache::new(2);
        c.reserve().expect("room").insert([1; 32]);
        c.reserve().expect("room").insert([2; 32]);
        assert!(c.reserve().is_none(), "full: new handshakes are refused");
        assert!(c.contains(&[1; 32]) && c.contains(&[2; 32]), "nothing evicted");
    }

    #[test]
    fn reservations_count_and_are_returned() {
        let c = ReplayCache::new(1);
        let slot = c.reserve().expect("room");
        assert!(c.reserve().is_none(), "the reserved slot is taken");
        drop(slot);
        assert!(c.reserve().is_some(), "an unused reservation is given back");
        assert_eq!(c.len(), 0);
    }

    /// The gateway's use: lock, check, reserve, (work), insert.
    async fn decide(c: Arc<ReplayCache>, nonce: [u8; 32]) -> &'static str {
        let Some(_g) = c.try_lock_nonce(nonce) else { return "busy" };
        if c.contains(&nonce) {
            return "replay";
        }
        let Some(slot) = c.reserve() else { return "full" };
        sleep(Duration::from_millis(100)).await; // verification, decapsulation, peer
        slot.insert(nonce);
        "accepted"
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_same_nonce_passes_once() {
        let c = Arc::new(ReplayCache::new(16));
        let a = tokio::spawn(decide(c.clone(), [7; 32]));
        let b = tokio::spawn(decide(c.clone(), [7; 32]));
        let mut out = [a.await.expect("a"), b.await.expect("b")];
        out.sort();
        assert_eq!(out, ["accepted", "busy"], "the copy is refused while the first is decided");
        assert_eq!(c.len(), 1);
        assert_eq!(decide(c.clone(), [7; 32]).await, "replay", "and as a replay afterwards");
    }

    #[tokio::test(start_paused = true)]
    async fn different_nonces_run_in_parallel() {
        let c = Arc::new(ReplayCache::new(16));
        let start = Instant::now();
        let a = tokio::spawn(decide(c.clone(), [1; 32]));
        let b = tokio::spawn(decide(c.clone(), [2; 32]));
        assert_eq!(a.await.expect("a"), "accepted");
        assert_eq!(b.await.expect("b"), "accepted");
        assert_eq!(start.elapsed(), Duration::from_millis(100), "not serialised");
    }
}
