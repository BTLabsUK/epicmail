//! Small helpers shared by the protocol code.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `n` random alphanumeric characters (message ids, random challenges).
pub fn rand_id(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| ALNUM[rng.gen_range(0..ALNUM.len())] as char).collect()
}

pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn rand_b64url(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill(&mut b[..]);
    b64url(&b)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The key used to group clients for per-IP limits: the network prefix.
pub fn ip_prefix(ip: IpAddr, v4: u8, v6: u8) -> String {
    let ip = match ip {
        IpAddr::V6(v6addr) => v6addr.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        other => other,
    };
    let net = match ip {
        IpAddr::V4(_) => ipnet::IpNet::new(ip, v4),
        IpAddr::V6(_) => ipnet::IpNet::new(ip, v6),
    };
    net.map(|n| n.trunc().to_string()).unwrap_or_else(|_| ip.to_string())
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
    fn prefixes() {
        assert_eq!(ip_prefix("10.1.2.3".parse().unwrap(), 24, 48), "10.1.2.0/24");
        assert_eq!(ip_prefix("::ffff:10.1.2.3".parse().unwrap(), 24, 48), "10.1.2.0/24");
        assert_eq!(ip_prefix("2001:db8:1:2::5".parse().unwrap(), 24, 48), "2001:db8:1::/48");
    }

    #[test]
    fn ids() {
        assert_eq!(rand_id(32).len(), 32);
        assert!(is_txid(&rand_id(32)));
        assert!(!is_txid("short"));
        assert_eq!(rand_b64url(16).len(), 22);
    }
}
