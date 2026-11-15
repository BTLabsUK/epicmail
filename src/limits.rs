//! Rate limits and socket counts. Clients are grouped by IP prefix (/24, /48); listed shared
//! sources (Tor exits, the onion service's loopback) get `shared_multiplier` times the budget.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::clock::now_ms;
use crate::config::Limits;
use crate::traffic::{Count, Traffic};

/// The key used to group clients for per-IP limits: the network prefix. IPv4-mapped IPv6
/// addresses count as IPv4.
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

/// A token bucket per key. `take` returns the seconds to wait when the bucket is empty.
pub struct Buckets {
    map: Mutex<HashMap<String, Bucket>>,
    per_ms: f64,
    burst: f64,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: i64,
    /// The multiplier of the last `take`, so `prune` knows this bucket's real capacity.
    mult: f64,
}

impl Buckets {
    /// `per_min` tokens a minute, holding at most `burst`. A key starts full.
    pub fn per_minute(per_min: f64, burst: f64) -> Self {
        Self { map: Mutex::new(HashMap::new()), per_ms: per_min / 60_000.0, burst: burst.max(1.0) }
    }

    fn refill(&self, b: &mut Bucket, now: i64, mult: f64) {
        let cap = self.burst * mult;
        b.tokens = (b.tokens + (now - b.at).max(0) as f64 * self.per_ms * mult).min(cap);
        b.at = now;
        b.mult = mult;
    }

    /// Take `cost` tokens from `key`; `mult` scales both the rate and the burst. Err holds the
    /// seconds until enough tokens are back.
    pub fn take(&self, key: &str, cost: f64, mult: f64) -> Result<(), u64> {
        let now = now_ms();
        let mut map = self.map.lock();
        let b = map.entry(key.to_string()).or_insert(Bucket { tokens: self.burst * mult, at: now, mult });
        self.refill(b, now, mult);
        if b.tokens >= cost {
            b.tokens -= cost;
            Ok(())
        } else {
            let missing = cost - b.tokens;
            let rate = (self.per_ms * mult).max(f64::MIN_POSITIVE);
            Err(((missing / rate) / 1000.0).ceil().max(1.0) as u64)
        }
    }

    /// Seconds until one token is available, without taking it.
    pub fn blocked(&self, key: &str, mult: f64) -> Option<u64> {
        let now = now_ms();
        let mut map = self.map.lock();
        let b = map.get_mut(key)?;
        self.refill(b, now, mult);
        if b.tokens >= 1.0 {
            None
        } else {
            let rate = (self.per_ms * mult).max(f64::MIN_POSITIVE);
            Some((((1.0 - b.tokens) / rate) / 1000.0).ceil().max(1.0) as u64)
        }
    }

    /// Drop buckets that have refilled; they hold no information. A bucket of a shared source
    /// is full only at `burst * mult`, and dropping it earlier would hand out a fresh burst.
    pub fn prune(&self) {
        let now = now_ms();
        let (per_ms, burst) = (self.per_ms, self.burst);
        self.map.lock().retain(|_, b| b.tokens + (now - b.at).max(0) as f64 * per_ms * b.mult < burst * b.mult);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.lock().len()
    }
}

/// Every rate and socket limit in `[limits]`, keyed by IP prefix or address.
pub struct Limiter {
    cfg: Limits,
    pub post_addr: Buckets,
    pub post_ip: Buckets,
    pub bytes_ip: Buckets,
    pub failed_sig_ip: Buckets,
    pub sig_check_ip: Buckets,
    pub attach_ip: Buckets,
    pub http_ip: Buckets,
    sockets: Mutex<HashMap<String, (u32, u32)>>,
    total: AtomicU32,
    /// Counts for the log summary; the relay shares it.
    pub traffic: Arc<Traffic>,
}

/// Why a socket was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketRefusal {
    /// `max_sockets` are open.
    Total,
    /// The client's prefix has `sockets_per_ip` open.
    PerIp,
}

/// Held by a socket for its life; releases its slot on drop.
pub struct SocketPermit {
    limiter: Arc<Limiter>,
    prefix: String,
    mux: bool,
}

impl Limiter {
    pub fn new(cfg: &Limits) -> Self {
        Self {
            post_addr: Buckets::per_minute(cfg.posts_per_min_per_address as f64, cfg.posts_burst_per_address as f64),
            post_ip: Buckets::per_minute(cfg.posts_per_min_per_ip as f64, cfg.posts_burst_per_ip as f64),
            bytes_ip: Buckets::per_minute(cfg.bytes_per_min_per_ip as f64, cfg.bytes_per_min_per_ip as f64),
            failed_sig_ip: Buckets::per_minute(
                cfg.failed_sigs_per_min_per_ip as f64,
                cfg.failed_sigs_per_min_per_ip as f64,
            ),
            sig_check_ip: Buckets::per_minute(
                cfg.sig_checks_per_min_per_ip as f64,
                cfg.sig_checks_per_min_per_ip as f64,
            ),
            attach_ip: Buckets::per_minute(
                cfg.mux_attach_frames_per_min as f64 * 8.0,
                cfg.mux_attach_frames_per_min as f64 * 8.0,
            ),
            http_ip: Buckets::per_minute(cfg.http_per_min_per_ip as f64, cfg.http_per_min_per_ip as f64),
            sockets: Mutex::new(HashMap::new()),
            total: AtomicU32::new(0),
            traffic: Arc::new(Traffic::new()),
            cfg: cfg.clone(),
        }
    }

    /// Prefix key and budget multiplier for a client IP.
    pub fn prefix(&self, ip: IpAddr) -> (String, f64) {
        let shared = self.cfg.shared_sources.iter().any(|n| n.contains(&ip));
        let mult = if shared { self.cfg.shared_multiplier.max(1) as f64 } else { 1.0 };
        (ip_prefix(ip, self.cfg.ipv4_prefix, self.cfg.ipv6_prefix), mult)
    }

    /// Per-IP post rate and bytes. Checked before any signature work.
    pub fn post_ip(&self, ip: IpAddr, bytes: usize) -> Result<(), u64> {
        let (p, m) = self.prefix(ip);
        self.post_ip.take(&p, 1.0, m)?;
        self.bytes_ip.take(&p, bytes as f64, m)
    }

    /// Bytes of a websocket frame that is not a PostSlate, against the prefix's byte budget.
    pub fn frame_bytes(&self, ip: IpAddr, bytes: usize) -> Result<(), u64> {
        let (p, m) = self.prefix(ip);
        self.bytes_ip.take(&p, bytes as f64, m)
    }

    /// Per-address post rate. Checked after the sender's signature verified, so a forged `from`
    /// cannot drain someone else's budget.
    pub fn post_addr(&self, key: &str) -> Result<(), u64> {
        self.post_addr.take(key, 1.0, 1.0)
    }

    /// Seconds to wait when the prefix has used up its failed-signature budget.
    pub fn sig_blocked(&self, ip: IpAddr) -> Option<u64> {
        let (p, m) = self.prefix(ip);
        self.failed_sig_ip.blocked(&p, m)
    }

    /// `n` signature checks against the prefix's budget, taken before the checks run. Counts
    /// it as a refusal in the metrics when over.
    pub fn sig_checks(&self, ip: IpAddr, n: usize) -> Result<(), u64> {
        let (p, m) = self.prefix(ip);
        self.sig_check_ip.take(&p, n.max(1) as f64, m).inspect_err(|_| self.refused("sig_checks", ip))
    }

    /// One mux/1 Attach or Resume frame against the prefix's budget.
    pub fn attach_ip(&self, ip: IpAddr) -> Result<(), u64> {
        let (p, m) = self.prefix(ip);
        self.attach_ip.take(&p, 1.0, m)
    }

    /// /v1 work against the prefix's budget: `cost` mailboxes or acks.
    pub fn http_ip(&self, ip: IpAddr, cost: usize) -> Result<(), u64> {
        let (p, m) = self.prefix(ip);
        self.http_ip.take(&p, cost.max(1) as f64, m)
    }

    /// Record a request that a limit refused: the `epicbox_limit_refusals_total` metric, the
    /// traffic summary's count, and a trace line with the client IP.
    pub fn refused(&self, limit: &'static str, ip: IpAddr) {
        metrics::counter!("epicbox_limit_refusals_total", "limit" => limit).increment(1);
        self.traffic.add(Count::LimitRefusals, 1);
        tracing::trace!(limit, ip = %ip, "limit refused a request");
    }

    /// Count a failed signature against the prefix, and for the log summary.
    pub fn sig_failed(&self, ip: IpAddr) {
        let (p, m) = self.prefix(ip);
        let _ = self.failed_sig_ip.take(&p, 1.0, m);
        self.traffic.bad_signature(&p);
    }

    /// Count a post refused as invalid, for the log summary's per-network warning.
    pub fn invalid_post(&self, ip: IpAddr) {
        self.traffic.invalid_post(&self.prefix(ip).0);
    }

    /// Reserve a socket slot for `ip`, held until the permit drops.
    pub fn open_socket(self: &Arc<Self>, ip: IpAddr) -> Result<SocketPermit, SocketRefusal> {
        let (p, m) = self.prefix(ip);
        let cap = (self.cfg.sockets_per_ip as f64 * m) as u32;
        let mut map = self.sockets.lock();
        if self.total.load(Ordering::Relaxed) >= self.cfg.max_sockets {
            return Err(SocketRefusal::Total);
        }
        let e = map.entry(p.clone()).or_insert((0, 0));
        if e.0 >= cap {
            return Err(SocketRefusal::PerIp);
        }
        e.0 += 1;
        self.total.fetch_add(1, Ordering::Relaxed);
        Ok(SocketPermit { limiter: self.clone(), prefix: p, mux: false })
    }

    /// Sockets open now, all kinds.
    pub fn sockets_open(&self) -> u32 {
        self.total.load(Ordering::Relaxed)
    }

    /// Drop full buckets. Housekeeping calls this every minute.
    pub fn prune(&self) {
        self.post_addr.prune();
        self.post_ip.prune();
        self.bytes_ip.prune();
        self.failed_sig_ip.prune();
        self.sig_check_ip.prune();
        self.attach_ip.prune();
        self.http_ip.prune();
    }
}

impl SocketPermit {
    /// Count this socket as mux/1. False when the prefix is over `mux_sockets_per_ip`.
    pub fn upgrade_mux(&mut self, mult: f64) -> bool {
        if self.mux {
            return true;
        }
        let cap = (self.limiter.cfg.mux_sockets_per_ip as f64 * mult) as u32;
        let mut map = self.limiter.sockets.lock();
        let e = map.entry(self.prefix.clone()).or_insert((0, 0));
        if e.1 >= cap {
            return false;
        }
        e.1 += 1;
        self.mux = true;
        true
    }
}

impl Drop for SocketPermit {
    fn drop(&mut self) {
        let mut map = self.limiter.sockets.lock();
        if let Some(e) = map.get_mut(&self.prefix) {
            e.0 = e.0.saturating_sub(1);
            if self.mux {
                e.1 = e.1.saturating_sub(1);
            }
            if *e == (0, 0) {
                map.remove(&self.prefix);
            }
        }
        self.limiter.total.fetch_sub(1, Ordering::Relaxed);
    }
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
    fn bucket_burst_then_refuse() {
        let b = Buckets::per_minute(60.0, 3.0);
        for _ in 0..3 {
            assert!(b.take("k", 1.0, 1.0).is_ok());
        }
        let wait = b.take("k", 1.0, 1.0).unwrap_err();
        assert!((1..=2).contains(&wait));
        assert!(b.take("other", 1.0, 1.0).is_ok());
    }

    #[test]
    fn prune_keeps_a_shared_bucket_until_it_is_full() {
        // 1 token a minute, burst 2, multiplier 16: full at 32 tokens.
        let b = Buckets::per_minute(1.0, 2.0);
        for _ in 0..20 {
            b.take("shared", 1.0, 16.0).unwrap();
        }
        b.take("plain", 1.0, 1.0).unwrap();
        b.prune();
        // 12 tokens left of 32: more than one burst, still not full, so it must stay.
        assert_eq!(b.len(), 2);
        b.take("plain", 1.0, 1.0).unwrap();
        assert!(b.take("shared", 13.0, 16.0).is_err(), "pruning gave the shared source a fresh burst");
    }

    #[test]
    fn socket_caps() {
        let cfg = Limits { sockets_per_ip: 2, mux_sockets_per_ip: 1, ..Limits::default() };
        let l = Arc::new(Limiter::new(&cfg));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut a = l.open_socket(ip).unwrap();
        let _b = l.open_socket("10.0.0.9".parse().unwrap()).unwrap();
        assert_eq!(l.open_socket(ip).err(), Some(SocketRefusal::PerIp));
        assert!(l.open_socket("10.0.1.1".parse().unwrap()).is_ok());
        assert!(a.upgrade_mux(1.0));
        drop(a);
        assert_eq!(l.sockets_open(), 1);
        let mut c = l.open_socket(ip).unwrap();
        assert!(c.upgrade_mux(1.0));
    }
}
