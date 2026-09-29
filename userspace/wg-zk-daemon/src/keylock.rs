//! Per-key asynchronous mutual exclusion.
//!
//! `KeyedLocks::lock(k)` returns a guard; while it is held, every other `lock(k)` for the
//! same key waits, while locks on other keys proceed. `try_lock(k)` does not wait: it
//! returns `None` while the key is held or waited for. The gateway uses `try_lock` to make
//! the whole decision for one session nonce (replay check to replay insert) atomic without
//! serialising unrelated handshakes and without queueing copies of one initiation, and
//! `lock` to keep installation and idle removal of the same WireGuard peer from
//! interleaving.
//!
//! The map holds an entry only while some task holds or waits for that key, so its size is
//! bounded by the number of tasks in flight. A waiter that is cancelled releases its
//! interest in the entry.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::OwnedMutexGuard;

struct Entry {
    lock: Arc<tokio::sync::Mutex<()>>,
    /// Tasks holding or waiting for this key.
    users: usize,
}

pub struct KeyedLocks<K> {
    map: Mutex<HashMap<K, Entry>>,
}

/// Held while the key is locked. Dropping it releases the key.
pub struct KeyGuard<'a, K: Eq + Hash + Clone> {
    // Field order matters: the mutex is released before the interest is dropped.
    _held: OwnedMutexGuard<()>,
    _interest: Interest<'a, K>,
}

/// One task's interest in a key; removes the map entry when the last one goes away.
struct Interest<'a, K: Eq + Hash + Clone> {
    locks: &'a KeyedLocks<K>,
    key: K,
}

impl<K: Eq + Hash + Clone> Drop for Interest<'_, K> {
    fn drop(&mut self) {
        let mut map = self.locks.map.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(e) = map.get_mut(&self.key) {
            e.users -= 1;
            if e.users == 0 {
                map.remove(&self.key);
            }
        }
    }
}

impl<K: Eq + Hash + Clone> KeyedLocks<K> {
    pub fn new() -> Self {
        KeyedLocks { map: Mutex::new(HashMap::new()) }
    }

    /// Wait until no other task holds `key`, then hold it until the guard is dropped.
    pub async fn lock(&self, key: K) -> KeyGuard<'_, K> {
        let lock = {
            let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
            let e = map.entry(key.clone()).or_insert_with(|| Entry {
                lock: Arc::new(tokio::sync::Mutex::new(())),
                users: 0,
            });
            e.users += 1;
            e.lock.clone()
        };
        // Registered before awaiting, so a cancelled wait still gives the interest back.
        let interest = Interest { locks: self, key };
        let held = lock.lock_owned().await;
        KeyGuard { _held: held, _interest: interest }
    }

    /// Hold `key` until the guard is dropped if no task holds or waits for it; `None`
    /// otherwise. Never waits.
    pub fn try_lock(&self, key: K) -> Option<KeyGuard<'_, K>> {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if map.contains_key(&key) {
            return None;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        // A mutex that nobody else has seen is free.
        let held = lock.clone().try_lock_owned().ok()?;
        map.insert(key.clone(), Entry { lock, users: 1 });
        drop(map);
        Some(KeyGuard { _held: held, _interest: Interest { locks: self, key } })
    }

    /// Keys currently held or waited for.
    #[cfg(test)]
    pub fn active(&self) -> usize {
        self.map.lock().unwrap_or_else(PoisonError::into_inner).len()
    }
}

impl<K: Eq + Hash + Clone> Default for KeyedLocks<K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::{sleep, timeout, Duration, Instant};

    #[tokio::test(start_paused = true)]
    async fn same_key_is_exclusive() {
        let locks = Arc::new(KeyedLocks::<u32>::new());
        let first_done = Arc::new(AtomicBool::new(false));

        let g = locks.lock(7).await;
        let (l2, f2) = (locks.clone(), first_done.clone());
        let second = tokio::spawn(async move {
            let _g = l2.lock(7).await;
            // Only reachable once the first holder has finished.
            assert!(f2.load(Ordering::SeqCst));
        });
        sleep(Duration::from_millis(100)).await;
        assert!(!second.is_finished(), "second locker must wait");
        first_done.store(true, Ordering::SeqCst);
        drop(g);
        second.await.expect("second task");
        assert_eq!(locks.active(), 0, "entry removed after the last user");
    }

    #[tokio::test(start_paused = true)]
    async fn different_keys_do_not_block() {
        let locks = KeyedLocks::<u32>::new();
        let _a = locks.lock(1).await;
        let start = Instant::now();
        let b = timeout(Duration::from_millis(10), locks.lock(2)).await;
        assert!(b.is_ok(), "a different key must not wait");
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(locks.active(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn try_lock_never_waits() {
        let locks = KeyedLocks::<u32>::new();
        let g = locks.try_lock(5).expect("free key");
        assert!(locks.try_lock(5).is_none(), "held: refused at once");
        assert!(locks.try_lock(6).is_some(), "another key is free");
        drop(g);
        assert_eq!(locks.active(), 0, "entry removed with the guard");
        let _g = locks.try_lock(5).expect("free again");

        // A key that a waiting locker holds is refused as well.
        let _h = locks.lock(9).await;
        assert!(locks.try_lock(9).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_waiter_releases_interest() {
        let locks = KeyedLocks::<u32>::new();
        let g = locks.lock(3).await;
        let waited = timeout(Duration::from_millis(50), locks.lock(3)).await;
        assert!(waited.is_err(), "must time out while the key is held");
        drop(g);
        assert_eq!(locks.active(), 0, "no entry left behind by the cancelled waiter");
    }
}
