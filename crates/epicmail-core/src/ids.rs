//! The identifier formats a relay accepts from clients. Random ids stay with each platform.

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
    fn txid_and_msgid_formats() {
        assert!(is_txid(&"aZ09_-".repeat(6)[..32]));
        assert!(!is_txid("short"));
        assert!(!is_txid(&"a".repeat(33)));
        assert!(!is_txid(&format!("{}!", "a".repeat(31))));
        assert!(is_msgid("icp12"));
        assert!(is_msgid(&"a".repeat(64)));
        assert!(!is_msgid(""));
        assert!(!is_msgid(&"a".repeat(65)));
        assert!(!is_msgid("a b"));
    }
}
