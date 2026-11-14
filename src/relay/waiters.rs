//! `/v1/pull` long polls waiting for mail. Each waiting pull registers one `Notify` under each
//! of its mailboxes, so storing a message wakes only the pulls for that mailbox. The number of
//! waiting pulls is capped per IP prefix and in total.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Notify;

const SHARDS: usize = 64;

type Shard = Mutex<HashMap<String, Vec<(u64, Arc<Notify>)>>>;

/// Why a pull may not wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitRefusal {
    /// The client's prefix has its share of waiting pulls.
    PerIp,
    /// The relay has `http_api.max_waiting` pulls waiting.
    Total,
}

/// Every waiting pull, by mailbox.
pub struct PullWaiters {
    shards: Vec<Shard>,
    /// Waiting pulls per IP prefix, and in total.
    counts: Mutex<(HashMap<String, u32>, u32)>,
    next_id: AtomicU64,
}

impl Default for PullWaiters {
    fn default() -> Self {
        Self::new()
    }
}

impl PullWaiters {
    pub fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            counts: Mutex::new((HashMap::new(), 0)),
            next_id: AtomicU64::new(1),
        }
    }

    fn shard(&self, key: &str) -> &Shard {
        &self.shards[super::shard_of(key, SHARDS)]
    }

    /// Register a pull waiting on `keys`, from IP prefix `prefix`, if it is under `per_ip` for
    /// the prefix and `total` overall. The registration ends when the guard drops.
    pub fn register(
        &self,
        keys: impl IntoIterator<Item = String>,
        prefix: String,
        per_ip: u32,
        total: u32,
    ) -> Result<WaitGuard<'_>, WaitRefusal> {
        {
            let mut c = self.counts.lock();
            if c.1 >= total {
                return Err(WaitRefusal::Total);
            }
            if c.0.get(&prefix).copied().unwrap_or(0) >= per_ip {
                return Err(WaitRefusal::PerIp);
            }
            *c.0.entry(prefix.clone()).or_insert(0) += 1;
            c.1 += 1;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let notify = Arc::new(Notify::new());
        let keys: Vec<String> = keys.into_iter().collect();
        for k in &keys {
            self.shard(k).lock().entry(k.clone()).or_default().push((id, notify.clone()));
        }
        Ok(WaitGuard { waiters: self, id, keys, prefix, notify })
    }

    /// Wake every pull waiting on `key`. A pull that is between two looks at the store keeps
    /// the wake as a permit, so it is not lost.
    pub fn wake(&self, key: &str) {
        if let Some(v) = self.shard(key).lock().get(key) {
            for (_, n) in v {
                n.notify_one();
            }
        }
    }

    /// Pulls waiting now.
    pub fn waiting(&self) -> u32 {
        self.counts.lock().1
    }
}

/// One registered pull. Dropping it removes the registration.
pub struct WaitGuard<'a> {
    waiters: &'a PullWaiters,
    id: u64,
    keys: Vec<String>,
    prefix: String,
    notify: Arc<Notify>,
}

impl WaitGuard<'_> {
    /// Resolves when mail is stored for one of the pull's mailboxes.
    pub async fn notified(&self) {
        self.notify.notified().await
    }
}

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        for k in &self.keys {
            let mut s = self.waiters.shard(k).lock();
            if let Some(v) = s.get_mut(k) {
                v.retain(|(id, _)| *id != self.id);
                if v.is_empty() {
                    s.remove(k);
                }
            }
        }
        let mut c = self.waiters.counts.lock();
        if let Some(n) = c.0.get_mut(&self.prefix) {
            *n -= 1;
            if *n == 0 {
                c.0.remove(&self.prefix);
            }
        }
        c.1 -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn wakes_only_its_mailboxes_and_keeps_the_wake() {
        let w = PullWaiters::new();
        let a = w.register(["k1".to_string(), "k2".to_string()], "p".into(), 4, 10).unwrap();
        let b = w.register(["k3".to_string()], "p".into(), 4, 10).unwrap();
        // Woken before it waits: the permit is kept.
        w.wake("k2");
        tokio::time::timeout(Duration::from_millis(100), a.notified()).await.expect("a was not woken");
        assert!(tokio::time::timeout(Duration::from_millis(50), b.notified()).await.is_err(), "b woken by k2");
        drop(a);
        drop(b);
        assert_eq!(w.waiting(), 0);
        assert!(w.shards.iter().all(|s| s.lock().is_empty()));
    }

    #[test]
    fn caps_per_prefix_and_total() {
        let w = PullWaiters::new();
        let a = w.register(["k".to_string()], "p1".into(), 1, 2).unwrap();
        assert_eq!(w.register(["k".to_string()], "p1".into(), 1, 2).err(), Some(WaitRefusal::PerIp));
        let _b = w.register(["k".to_string()], "p2".into(), 1, 2).unwrap();
        assert_eq!(w.register(["k".to_string()], "p3".into(), 1, 2).err(), Some(WaitRefusal::Total));
        drop(a);
        assert!(w.register(["k".to_string()], "p1".into(), 1, 2).is_ok());
    }
}
