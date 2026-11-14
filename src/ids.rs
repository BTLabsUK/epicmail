//! Random identifiers the relay makes, and the identifier formats it accepts from clients.

use base64::Engine;
use rand::Rng;

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `n` random alphanumeric characters (message ids, random challenges).
pub fn rand_id(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| ALNUM[rng.gen_range(0..ALNUM.len())] as char).collect()
}

/// `n` random bytes as unpadded base64url (mux/1 challenges and resume tokens).
pub fn rand_b64url(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill(&mut b[..]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&b)
}

/// `[A-Za-z0-9_-]{32}`: a 3.1.0 epicboxtxid.
pub fn is_txid(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `[A-Za-z0-9_-]{1,64}`: a message id as clients may send it.
pub fn is_msgid(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

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
