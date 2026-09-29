//! Gateway ciphertext buffer (`docs/protocol-r1.md`, Section 6 steps 1 and 3.2, Section 7).
//!
//! The side-channel listener stores `nonce -> (ct, token, arrival)` and does nothing else.
//! The NEED_VERIFY handler looks the ciphertext up by the nonce of the proof and, if the
//! proof overtook its ciphertext, waits for it up to `WGZK_CT_WAIT_MS` (woken by the insert,
//! no polling).
//!
//! A lookup never removes the entry. The entry leaves the buffer when the handshake for its
//! nonce is accepted ([`CtBuffer::remove`]) or when it expires (`WGZK_CT_TTL_MS` after
//! arrival). Otherwise an initiation that merely copies a nonce seen on the wire could use up
//! the ciphertext of the handshake it copied from.
//!
//! Bounded (`WGZK_CT_BUFFER_MAX`): when the buffer is full of live entries a new ciphertext
//! is refused; only expired entries are dropped to make room. A second message for a nonce
//! that is already buffered is refused, so a buffered ciphertext cannot be replaced.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::Notify;
use tokio::time::{timeout_at, Duration, Instant};

use crate::mlkem::CT_LEN;

/// One buffered side-channel message.
#[derive(Clone)]
pub struct CtEntry {
    pub ct: Arc<[u8; CT_LEN]>,
    pub token: u32,
    pub arrival: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CtInsertError {
    /// The buffer holds `WGZK_CT_BUFFER_MAX` live entries.
    Full,
    /// A live entry for this nonce exists already.
    Duplicate,
}

impl std::fmt::Display for CtInsertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CtInsertError::Full => write!(f, "ciphertext buffer full"),
            CtInsertError::Duplicate => write!(f, "nonce already buffered"),
        }
    }
}

pub struct CtBuffer {
    entries: Mutex<HashMap<[u8; 32], CtEntry>>,
    arrived: Notify,
    max: usize,
    ttl: Duration,
}

impl CtBuffer {
    pub fn new(max: usize, ttl: Duration) -> Self {
        CtBuffer { entries: Mutex::new(HashMap::new()), arrived: Notify::new(), max, ttl }
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<[u8; 32], CtEntry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn live(&self, e: &CtEntry, now: Instant) -> bool {
        now.saturating_duration_since(e.arrival) < self.ttl
    }

    /// Store a ciphertext (Section 6 step 1).
    pub fn insert(&self, nonce: [u8; 32], ct: Arc<[u8; CT_LEN]>, token: u32) -> Result<(), CtInsertError> {
        let now = Instant::now();
        {
            let mut map = self.entries();
            if let Some(e) = map.get(&nonce) {
                if self.live(e, now) {
                    return Err(CtInsertError::Duplicate);
                }
                map.remove(&nonce);
            }
            if map.len() >= self.max {
                map.retain(|_, e| now.saturating_duration_since(e.arrival) < self.ttl);
                if map.len() >= self.max {
                    return Err(CtInsertError::Full);
                }
            }
            map.insert(nonce, CtEntry { ct, token, arrival: now });
        }
        self.arrived.notify_waiters();
        Ok(())
    }

    /// The live entry for `nonce`, if any, without waiting and without removing it.
    fn get(&self, nonce: &[u8; 32]) -> Option<CtEntry> {
        let now = Instant::now();
        self.entries().get(nonce).filter(|e| self.live(e, now)).cloned()
    }

    /// Section 6 step 3.2: the live entry for `nonce`. Returns at once if it is buffered,
    /// otherwise waits up to `wait` for it to arrive. Does not remove the entry.
    pub async fn lookup(&self, nonce: &[u8; 32], wait: Duration) -> Option<CtEntry> {
        let deadline = Instant::now() + wait;
        loop {
            // Register for the wake-up before checking, so an insert between the check
            // and the wait cannot be missed.
            let notified = self.arrived.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(e) = self.get(nonce) {
                return Some(e);
            }
            if timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }

    /// Drop the entry for `nonce`; called when the handshake for it is accepted.
    pub fn remove(&self, nonce: &[u8; 32]) {
        self.entries().remove(nonce);
    }

    /// Drop every expired entry. Returns how many were dropped.
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut map = self.entries();
        let before = map.len();
        map.retain(|_, e| now.saturating_duration_since(e.arrival) < self.ttl);
        before - map.len()
    }

    /// Entries currently stored, live or not yet purged.
    #[cfg(test)]
    pub fn stored(&self) -> usize {
        self.entries().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{advance, sleep};

    const TTL: Duration = Duration::from_millis(5000);
    const WAIT: Duration = Duration::from_millis(250);

    fn ct(fill: u8) -> Arc<[u8; CT_LEN]> {
        Arc::new([fill; CT_LEN])
    }

    fn nonce(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[tokio::test(start_paused = true)]
    async fn insert_and_lookup() {
        let buf = CtBuffer::new(4, TTL);
        buf.insert(nonce(1), ct(0xaa), 42).expect("insert");
        let e = buf.lookup(&nonce(1), Duration::ZERO).await.expect("buffered entry");
        assert_eq!(e.token, 42);
        assert_eq!(e.ct[0], 0xaa);
        // Non-destructive: a second lookup still finds it.
        assert!(buf.lookup(&nonce(1), Duration::ZERO).await.is_some());
        assert!(buf.lookup(&nonce(2), Duration::ZERO).await.is_none());
        buf.remove(&nonce(1));
        assert!(buf.lookup(&nonce(1), Duration::ZERO).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn entries_expire() {
        let buf = CtBuffer::new(4, TTL);
        buf.insert(nonce(1), ct(1), 1).expect("insert");
        advance(TTL - Duration::from_millis(1)).await;
        assert!(buf.lookup(&nonce(1), Duration::ZERO).await.is_some(), "still live");
        advance(Duration::from_millis(1)).await;
        assert!(buf.lookup(&nonce(1), Duration::ZERO).await.is_none(), "expired");
        assert_eq!(buf.purge_expired(), 1);
        assert_eq!(buf.stored(), 0);
        // An expired entry does not block a new message for the same nonce.
        buf.insert(nonce(1), ct(2), 2).expect("insert after expiry");
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_when_full_never_evicts_live_entries() {
        let buf = CtBuffer::new(2, TTL);
        buf.insert(nonce(1), ct(1), 1).expect("insert 1");
        advance(Duration::from_millis(10)).await;
        buf.insert(nonce(2), ct(2), 2).expect("insert 2");
        assert_eq!(buf.insert(nonce(3), ct(3), 3), Err(CtInsertError::Full));
        assert!(buf.lookup(&nonce(1), Duration::ZERO).await.is_some(), "live entry kept");
        assert!(buf.lookup(&nonce(2), Duration::ZERO).await.is_some(), "live entry kept");
        // Once the oldest expires, its slot can be reused.
        advance(TTL - Duration::from_millis(10)).await;
        buf.insert(nonce(3), ct(3), 3).expect("room after expiry");
        assert!(buf.lookup(&nonce(2), Duration::ZERO).await.is_some());
        assert!(buf.lookup(&nonce(1), Duration::ZERO).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn lookup_waits_for_later_insert() {
        let buf = Arc::new(CtBuffer::new(4, TTL));
        let b2 = buf.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            b2.insert(nonce(9), ct(9), 9).expect("late insert");
        });
        let start = Instant::now();
        let e = buf.lookup(&nonce(9), WAIT).await.expect("satisfied by the later insert");
        assert_eq!(e.token, 9);
        assert_eq!(start.elapsed(), Duration::from_millis(100), "woken by the insert, not by the deadline");
    }

    #[tokio::test(start_paused = true)]
    async fn lookup_ignores_other_nonces_and_times_out() {
        let buf = Arc::new(CtBuffer::new(4, TTL));
        let b2 = buf.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            b2.insert(nonce(8), ct(8), 8).expect("unrelated insert");
        });
        let start = Instant::now();
        assert!(buf.lookup(&nonce(9), WAIT).await.is_none());
        assert_eq!(start.elapsed(), WAIT, "gives up exactly at the deadline");
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_nonce_refused() {
        let buf = CtBuffer::new(4, TTL);
        buf.insert(nonce(5), ct(0x11), 1).expect("first");
        assert_eq!(buf.insert(nonce(5), ct(0x22), 2), Err(CtInsertError::Duplicate));
        let e = buf.lookup(&nonce(5), Duration::ZERO).await.expect("entry");
        assert_eq!((e.token, e.ct[0]), (1, 0x11), "the first message is kept");
    }
}
