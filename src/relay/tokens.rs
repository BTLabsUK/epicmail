//! mux/1 resume tokens. A token lets a reconnecting socket take back its mailboxes without
//! proving each key again. Tokens live in memory only, for a day, and are spent on use.
//!
//! Tokens outlive their socket, so their number is not bounded by the socket limits. The
//! mailboxes held by all tokens together are capped at `limits.mux_token_mailboxes`; past the
//! cap the oldest tokens are dropped. A dropped token only costs its client one signed Attach.

use std::collections::{HashMap, VecDeque};

use sha2::{Digest, Sha256};

use super::Relay;
use crate::clock::now_ms;
use crate::ids::rand_b64url;

const TOKEN_TTL_MS: i64 = 24 * 3600 * 1000;

/// The mailboxes a token resumes, and when it expires (unix ms).
struct TokenEntry {
    mailboxes: Vec<String>,
    expires_at: i64,
}

/// Live tokens by SHA-256 hash, oldest first in `order`.
pub(super) struct Tokens {
    map: HashMap<[u8; 32], TokenEntry>,
    /// Hashes in issue order. May hold hashes already spent; they are skipped on eviction and
    /// dropped by `prune`.
    order: VecDeque<([u8; 32], i64)>,
    /// Mailboxes held by every entry in `map`.
    mailboxes: usize,
    cap: usize,
}

impl Tokens {
    pub(super) fn new(cap: usize) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), mailboxes: 0, cap: cap.max(1) }
    }

    fn remove(&mut self, hash: &[u8; 32]) -> Option<TokenEntry> {
        let e = self.map.remove(hash)?;
        self.mailboxes -= e.mailboxes.len();
        Some(e)
    }

    /// Drop the oldest tokens until `extra` more mailboxes fit under the cap.
    fn make_room(&mut self, extra: usize) {
        while self.mailboxes + extra > self.cap {
            let Some((hash, expires_at)) = self.order.pop_front() else { return };
            if self.map.get(&hash).is_some_and(|e| e.expires_at == expires_at) {
                self.remove(&hash);
                metrics::counter!("epicbox_mux_tokens_evicted_total").increment(1);
            }
        }
    }

    fn insert(&mut self, hash: [u8; 32], mailboxes: Vec<String>, expires_at: i64) {
        self.make_room(mailboxes.len());
        self.mailboxes += mailboxes.len();
        self.order.push_back((hash, expires_at));
        self.map.insert(hash, TokenEntry { mailboxes, expires_at });
    }

    fn update(&mut self, hash: &[u8; 32], mailboxes: Vec<String>) {
        let Some(e) = self.map.get_mut(hash) else { return };
        let old = std::mem::take(&mut e.mailboxes);
        self.mailboxes -= old.len();
        self.make_room(mailboxes.len());
        // When this token is the oldest, making room may drop it; its session then attaches
        // with signatures on the next reconnect.
        if let Some(e) = self.map.get_mut(hash) {
            self.mailboxes += mailboxes.len();
            e.mailboxes = mailboxes;
        }
    }

    fn prune(&mut self, now: i64) {
        let expired: Vec<[u8; 32]> = self.map.iter().filter(|(_, e)| e.expires_at <= now).map(|(h, _)| *h).collect();
        for h in expired {
            self.remove(&h);
        }
        let map = &self.map;
        self.order.retain(|(h, x)| map.get(h).is_some_and(|e| e.expires_at == *x));
    }
}

impl Relay {
    /// Issue a token for `mailboxes`, ending `old`. Returns (token, hash, expires unix seconds).
    pub fn issue_token(&self, old: Option<[u8; 32]>, mailboxes: Vec<String>) -> (String, [u8; 32], i64) {
        let token = rand_b64url(32);
        let hash = sha256(token.as_bytes());
        let expires_at = now_ms() + TOKEN_TTL_MS;
        let mut t = self.tokens.lock();
        if let Some(o) = old {
            t.remove(&o);
        }
        t.insert(hash, mailboxes, expires_at);
        (token, hash, expires_at / 1000)
    }

    /// Follow Attach/Detach: the set held under a live token.
    pub fn update_token(&self, hash: &[u8; 32], mailboxes: Vec<String>) {
        self.tokens.lock().update(hash, mailboxes);
    }

    /// Spend a token. None when unknown, spent, expired or dropped for room.
    pub fn take_token(&self, token: &str) -> Option<Vec<String>> {
        let hash = sha256(token.as_bytes());
        let e = self.tokens.lock().remove(&hash)?;
        (e.expires_at > now_ms()).then_some(e.mailboxes)
    }

    /// Tokens issued and not yet spent (expired ones count until the next prune).
    pub fn tokens_live(&self) -> usize {
        self.tokens.lock().map.len()
    }

    /// Drop expired tokens. Housekeeping calls this every minute.
    pub fn prune_tokens(&self) {
        self.tokens.lock().prune(now_ms());
    }
}

/// The token map is keyed by SHA-256 of the token, so the plain token is never stored.
fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxes(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("k{i}")).collect()
    }

    #[test]
    fn oldest_tokens_go_when_the_cap_is_reached() {
        let mut t = Tokens::new(10);
        t.insert([1; 32], boxes(4), 100);
        t.insert([2; 32], boxes(4), 101);
        assert_eq!(t.mailboxes, 8);
        // 4 more do not fit: the oldest token goes.
        t.insert([3; 32], boxes(4), 102);
        assert!(!t.map.contains_key(&[1; 32]));
        assert_eq!((t.map.len(), t.mailboxes), (2, 8));
        // A spent token is skipped on eviction and does not free room twice.
        t.remove(&[2; 32]);
        t.insert([4; 32], boxes(6), 103);
        assert_eq!((t.map.len(), t.mailboxes), (2, 10));
        // Growing a token past the cap drops older ones first.
        t.update(&[4; 32], boxes(8));
        assert!(t.map.contains_key(&[4; 32]) && !t.map.contains_key(&[3; 32]));
        assert_eq!(t.mailboxes, 8);
    }

    #[test]
    fn prune_drops_expired_and_stale_order() {
        let mut t = Tokens::new(100);
        t.insert([1; 32], boxes(1), 100);
        t.insert([2; 32], boxes(2), 200);
        t.remove(&[2; 32]);
        t.insert([3; 32], boxes(3), 300);
        t.prune(150);
        assert_eq!((t.map.len(), t.mailboxes, t.order.len()), (1, 3, 1));
    }
}
