//! Random identifiers the relay makes, and the identifier formats it accepts from clients.

use base64::Engine;
use rand::RngExt;

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `n` random alphanumeric characters (message ids, random challenges).
pub fn rand_id(n: usize) -> String {
    let mut rng = rand::rng();
    (0..n).map(|_| ALNUM[rng.random_range(0..ALNUM.len())] as char).collect()
}

/// `n` random bytes as unpadded base64url (mux/1 challenges and resume tokens).
pub fn rand_b64url(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rng().fill(&mut b[..]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&b)
}

pub use epicmail_core::ids::{is_msgid, is_txid};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert_eq!(rand_id(32).len(), 32);
        assert!(is_txid(&rand_id(32)));
        assert!(!is_txid("short"));
        assert_eq!(rand_b64url(16).len(), 22);
    }
}
