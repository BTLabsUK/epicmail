//! mux/1 resume tokens. A token lets a reconnecting socket take back its mailboxes without
//! proving each key again. Tokens live in memory only, for a day, and are spent on use.

use sha2::{Digest, Sha256};

use super::Relay;
use crate::clock::now_ms;
use crate::ids::rand_b64url;

const TOKEN_TTL_MS: i64 = 24 * 3600 * 1000;

/// The mailboxes a token resumes, and when it expires (unix ms).
pub(super) struct TokenEntry {
    mailboxes: Vec<String>,
    expires_at: i64,
}

impl Relay {
    /// Issue a token for `mailboxes`, ending `old`. Returns (token, expires unix seconds).
    pub fn issue_token(&self, old: Option<[u8; 32]>, mailboxes: Vec<String>) -> (String, [u8; 32], i64) {
        let token = rand_b64url(32);
        let hash = sha256(token.as_bytes());
        let expires_at = now_ms() + TOKEN_TTL_MS;
        let mut t = self.tokens.lock();
        if let Some(o) = old {
            t.remove(&o);
        }
        t.insert(hash, TokenEntry { mailboxes, expires_at });
        (token, hash, expires_at / 1000)
    }

    /// Follow Attach/Detach: the set held under a live token.
    pub fn update_token(&self, hash: &[u8; 32], mailboxes: Vec<String>) {
        if let Some(e) = self.tokens.lock().get_mut(hash) {
            e.mailboxes = mailboxes;
        }
    }

    /// Spend a token. None when unknown, spent or expired.
    pub fn take_token(&self, token: &str) -> Option<Vec<String>> {
        let hash = sha256(token.as_bytes());
        let e = self.tokens.lock().remove(&hash)?;
        (e.expires_at > now_ms()).then_some(e.mailboxes)
    }

    /// Tokens issued and not yet spent (expired ones count until the next prune).
    pub fn tokens_live(&self) -> usize {
        self.tokens.lock().len()
    }

    /// Drop expired tokens. Housekeeping calls this every minute.
    pub fn prune_tokens(&self) {
        let now = now_ms();
        self.tokens.lock().retain(|_, e| e.expires_at > now);
    }
}

/// The token map is keyed by SHA-256 of the token, so the plain token is never stored.
fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
