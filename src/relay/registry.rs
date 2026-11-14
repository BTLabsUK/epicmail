//! Which sockets hold which mailbox. A mailbox is pushed to one socket: the mux/1 holder if there
//! is one, else the newest 3.0.0 subscriber. Older 3.0.0 sockets stay open (they still collect on
//! Subscribe) until there are more than `sockets_per_address`.

use std::collections::HashMap;

use parking_lot::Mutex;
use tokio::sync::mpsc;

const SHARDS: usize = 64;

/// Messages to a socket task.
#[derive(Debug, Clone)]
pub enum Cmd {
    /// Mail may be waiting for this mailbox.
    Wake(String),
    /// mux/1: another socket took this mailbox.
    Detached { mailbox: String, reason: &'static str },
    /// 3.1.0: a transaction this socket's mailbox takes part in was cancelled.
    Cancelled { txid: String },
    /// txcancel/1: a transaction `mailbox` takes part in was cancelled.
    MuxCancelled { mailbox: String, txid: String },
    /// Close the socket.
    Close { code: u16, reason: &'static str },
}

#[derive(Debug, Clone)]
pub struct SockHandle {
    pub id: u64,
    pub tx: mpsc::Sender<Cmd>,
    /// The socket negotiated 3.1.0 (receives TransactionCancelled).
    pub cancel: bool,
}

impl SockHandle {
    /// Queue a command for the socket's task. False when its queue is full or it has ended.
    pub fn send(&self, c: Cmd) -> bool {
        self.tx.try_send(c).is_ok()
    }
}

#[derive(Default)]
struct Entry {
    mux: Option<SockHandle>,
    /// Oldest first.
    classic: Vec<SockHandle>,
}

/// The mailbox map, split into shards so sockets on different mailboxes rarely contend.
pub struct Registry {
    shards: Vec<Mutex<HashMap<String, Entry>>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self { shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect() }
    }

    fn shard(&self, key: &str) -> &Mutex<HashMap<String, Entry>> {
        &self.shards[super::shard_of(key, SHARDS)]
    }

    /// Register a 3.0.0 subscriber as the newest. Returns sockets beyond `cap` to close.
    pub fn subscribe_classic(&self, key: &str, h: SockHandle, cap: usize) -> Vec<SockHandle> {
        let mut s = self.shard(key).lock();
        let e = s.entry(key.to_string()).or_default();
        e.classic.retain(|x| x.id != h.id);
        e.classic.push(h);
        let cap = cap.max(1);
        if e.classic.len() > cap {
            let n = e.classic.len() - cap;
            e.classic.drain(..n).collect()
        } else {
            vec![]
        }
    }

    /// Remove a 3.0.0 subscriber; the entry goes when nothing holds the mailbox.
    pub fn unsubscribe_classic(&self, key: &str, id: u64) {
        let mut s = self.shard(key).lock();
        if let Some(e) = s.get_mut(key) {
            e.classic.retain(|x| x.id != id);
            if e.mux.is_none() && e.classic.is_empty() {
                s.remove(key);
            }
        }
    }

    /// Make `h` the mux/1 holder. Returns the previous holder when it is another socket.
    pub fn attach_mux(&self, key: &str, h: SockHandle) -> Option<SockHandle> {
        let mut s = self.shard(key).lock();
        let e = s.entry(key.to_string()).or_default();
        let prev = e.mux.replace(h.clone());
        prev.filter(|p| p.id != h.id)
    }

    /// Remove `id` as mux holder. False when another socket holds it now.
    pub fn detach_mux(&self, key: &str, id: u64) -> bool {
        let mut s = self.shard(key).lock();
        let Some(e) = s.get_mut(key) else { return false };
        let held = e.mux.as_ref().map(|m| m.id == id).unwrap_or(false);
        if held {
            e.mux = None;
        }
        if e.mux.is_none() && e.classic.is_empty() {
            s.remove(key);
        }
        held
    }

    /// True when socket `id` is the mux/1 holder of `key`.
    pub fn is_mux_holder(&self, key: &str, id: u64) -> bool {
        self.shard(key).lock().get(key).and_then(|e| e.mux.as_ref()).map(|m| m.id == id).unwrap_or(false)
    }

    /// The socket that gets pushes for `key`.
    pub fn push_target(&self, key: &str) -> Option<SockHandle> {
        let s = self.shard(key).lock();
        let e = s.get(key)?;
        e.mux.clone().or_else(|| e.classic.last().cloned())
    }

    /// Wake the push target of `key`. False when nobody is listening.
    pub fn wake(&self, key: &str) -> bool {
        match self.push_target(key) {
            Some(h) => {
                h.send(Cmd::Wake(key.to_string()));
                true
            }
            None => false,
        }
    }

    /// The mux/1 socket holding `key`, when it negotiated txcancel/1.
    pub fn txcancel_holder(&self, key: &str) -> Option<SockHandle> {
        self.shard(key).lock().get(key).and_then(|e| e.mux.clone()).filter(|h| h.cancel)
    }

    /// Every 3.0.0 socket subscribed to `key`.
    pub fn classic_sockets(&self, key: &str) -> Vec<SockHandle> {
        self.shard(key).lock().get(key).map(|e| e.classic.clone()).unwrap_or_default()
    }

    /// (mailboxes with a listener, mux holders, classic sockets)
    pub fn counts(&self) -> (usize, usize, usize) {
        let (mut a, mut m, mut c) = (0, 0, 0);
        for s in &self.shards {
            let s = s.lock();
            a += s.len();
            for e in s.values() {
                m += e.mux.is_some() as usize;
                c += e.classic.len();
            }
        }
        (a, m, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(id: u64) -> (SockHandle, mpsc::Receiver<Cmd>) {
        let (tx, rx) = mpsc::channel(8);
        (SockHandle { id, tx, cancel: false }, rx)
    }

    #[test]
    fn precedence_and_caps() {
        let r = Registry::new();
        let (a, _ra) = h(1);
        let (b, _rb) = h(2);
        let (c, _rc) = h(3);
        assert!(r.subscribe_classic("k", a.clone(), 2).is_empty());
        assert!(r.subscribe_classic("k", b.clone(), 2).is_empty());
        assert_eq!(r.push_target("k").unwrap().id, 2);
        let evicted = r.subscribe_classic("k", c.clone(), 2);
        assert_eq!(evicted.iter().map(|x| x.id).collect::<Vec<_>>(), vec![1]);
        let (m1, _r1) = h(10);
        let (m2, _r2) = h(11);
        assert!(r.attach_mux("k", m1.clone()).is_none());
        assert_eq!(r.push_target("k").unwrap().id, 10);
        // A classic Subscribe never takes pushes from the mux holder.
        r.subscribe_classic("k", a.clone(), 4);
        assert_eq!(r.push_target("k").unwrap().id, 10);
        assert_eq!(r.attach_mux("k", m2.clone()).unwrap().id, 10);
        assert!(!r.detach_mux("k", 10));
        assert!(r.detach_mux("k", 11));
        assert_eq!(r.push_target("k").unwrap().id, 1);
    }
}
