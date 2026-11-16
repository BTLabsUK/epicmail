//! Traffic counts for the log: a summary line at info every `log.summary_interval_s`, and a
//! warning for a network prefix that sent many bad signatures or invalid posts in that time.
//!
//! The same events feed Prometheus metrics; these counts are kept per relay so the relay can read
//! them back. The summary holds counts only, and the warning a network prefix (/24, /48), so
//! neither carries a key, address, slate, id or client IP.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::relay::Relay;

/// What the summary counts. Each is a total since start; the summary logs the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    /// Posts stored for a mailbox here.
    PostsStored,
    /// Posts queued for another relay.
    PostsForwarded,
    /// Posts refused: invalid, over a limit, store full, or for a cancelled transaction.
    PostsRefused,
    /// Messages handed to a listener (a redelivery counts again).
    Delivered,
    /// Messages acknowledged and removed.
    Acked,
    /// Transactions cancelled.
    Cancels,
    /// Mailboxes proven with a valid signature: Subscribe, mux/1 Attach, `/v1/pull`.
    LoginsOk,
    /// Signatures that did not verify, of any kind.
    BadSignatures,
    /// Frames delivered to other relays.
    ForwardsSent,
    /// Forward attempts that failed or that the peer refused.
    ForwardsFailed,
    /// Requests a limit refused.
    LimitRefusals,
    /// Accepted posts that carried an epicboxtxid.
    PostsTxid,
    /// Accepted posts without one.
    PostsNoTxid,
    /// Accepted posts by size of the slate body: up to 2560 bytes, up to 5120, up to 6144, up to
    /// 10240, larger.
    SizeLe2560,
    SizeLe5120,
    SizeLe6144,
    SizeLe10240,
    SizeOver10240,
}

const N: usize = 18;

/// A coarse size class of a slate body. Counts only; there is no finer size anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeBucket {
    Le2560,
    Le5120,
    Le6144,
    Le10240,
    Over10240,
}

pub fn size_bucket(bytes: usize) -> SizeBucket {
    match bytes {
        0..=2560 => SizeBucket::Le2560,
        2561..=5120 => SizeBucket::Le5120,
        5121..=6144 => SizeBucket::Le6144,
        6145..=10240 => SizeBucket::Le10240,
        _ => SizeBucket::Over10240,
    }
}

impl SizeBucket {
    pub fn label(self) -> &'static str {
        match self {
            SizeBucket::Le2560 => "le_2560",
            SizeBucket::Le5120 => "le_5120",
            SizeBucket::Le6144 => "le_6144",
            SizeBucket::Le10240 => "le_10240",
            SizeBucket::Over10240 => "over_10240",
        }
    }

    pub fn count(self) -> Count {
        match self {
            SizeBucket::Le2560 => Count::SizeLe2560,
            SizeBucket::Le5120 => Count::SizeLe5120,
            SizeBucket::Le6144 => Count::SizeLe6144,
            SizeBucket::Le10240 => Count::SizeLe10240,
            SizeBucket::Over10240 => Count::SizeOver10240,
        }
    }
}

/// The most network prefixes tallied between two reports, so a flood from many networks
/// cannot grow memory without bound. Prefixes past it are counted in the totals only.
const MAX_PREFIXES: usize = 10_000;

/// Counts since start, and bad requests per network prefix since the last report.
pub struct Traffic {
    counts: [AtomicU64; N],
    prefixes: Mutex<HashMap<String, BadRequests>>,
}

/// Bad requests from one network prefix.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BadRequests {
    pub bad_signatures: u64,
    pub invalid_posts: u64,
}

/// A copy of every count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts([u64; N]);

impl Counts {
    pub fn get(&self, c: Count) -> u64 {
        self.0[c as usize]
    }

    fn since(&self, earlier: &Counts) -> Counts {
        Counts(std::array::from_fn(|i| self.0[i].saturating_sub(earlier.0[i])))
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|&n| n == 0)
    }
}

/// The state the summary shows as it is now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Gauges {
    pub sockets: u64,
    pub mailboxes_waiting: u64,
    pub messages_waiting: u64,
    pub forwards_waiting: u64,
}

impl Default for Traffic {
    fn default() -> Self {
        Self::new()
    }
}

impl Traffic {
    pub fn new() -> Self {
        Self { counts: std::array::from_fn(|_| AtomicU64::new(0)), prefixes: Mutex::new(HashMap::new()) }
    }

    pub fn add(&self, c: Count, n: u64) {
        self.counts[c as usize].fetch_add(n, Relaxed);
    }

    /// A signature that did not verify, from network prefix `net`.
    pub fn bad_signature(&self, net: &str) {
        self.add(Count::BadSignatures, 1);
        self.tally(net, |b| b.bad_signatures += 1);
    }

    /// A post refused as invalid, from network prefix `net`.
    pub fn invalid_post(&self, net: &str) {
        self.tally(net, |b| b.invalid_posts += 1);
    }

    fn tally(&self, net: &str, f: impl FnOnce(&mut BadRequests)) {
        let mut m = self.prefixes.lock();
        if let Some(b) = m.get_mut(net) {
            f(b);
        } else if m.len() < MAX_PREFIXES {
            f(m.entry(net.to_string()).or_default());
        }
    }

    pub fn counts(&self) -> Counts {
        Counts(std::array::from_fn(|i| self.counts[i].load(Relaxed)))
    }

    /// The prefixes with more than `threshold` bad signatures or more than `threshold` invalid
    /// posts since the last call, most first. Starts a new tally.
    pub fn take_over(&self, threshold: u64) -> Vec<(String, BadRequests)> {
        let m = std::mem::take(&mut *self.prefixes.lock());
        let mut over: Vec<_> =
            m.into_iter().filter(|(_, b)| b.bad_signatures > threshold || b.invalid_posts > threshold).collect();
        over.sort_by_key(|(_, b)| std::cmp::Reverse(b.bad_signatures + b.invalid_posts));
        over
    }
}

/// What one summary line holds: the change in every count over the interval, the totals, and
/// the gauges as they are now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub delta: Counts,
    pub total: Counts,
    pub gauges: Gauges,
}

/// Decides when a summary is due: only when a count moved or a gauge differs from the last
/// line, so an idle relay writes nothing.
#[derive(Debug, Default)]
pub struct Reporter {
    last: Counts,
    last_gauges: Gauges,
}

impl Reporter {
    pub fn next(&mut self, total: Counts, gauges: Gauges) -> Option<Summary> {
        let delta = total.since(&self.last);
        self.last = total;
        if delta.is_zero() && gauges == self.last_gauges {
            return None;
        }
        self.last_gauges = gauges;
        Some(Summary { delta, total, gauges })
    }
}

/// Write the summary and the bad-request warnings every `log.summary_interval_s` until the
/// relay shuts down.
pub async fn run(relay: Arc<Relay>) {
    let every = Duration::from_secs(relay.cfg.log.summary_interval_s.max(1));
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown = relay.shutdown.subscribe();
    let mut reporter = Reporter::default();
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        report(&relay, &mut reporter, every.as_secs());
    }
}

fn report(relay: &Relay, reporter: &mut Reporter, interval_s: u64) {
    let stats = relay.last_stats.lock().clone().unwrap_or_default();
    let gauges = Gauges {
        sockets: u64::from(relay.limiter.sockets_open()),
        mailboxes_waiting: stats.mailboxes_waiting.max(0) as u64,
        messages_waiting: stats.messages_waiting.max(0) as u64,
        forwards_waiting: stats.forwards_waiting.max(0) as u64,
    };
    if let Some(s) = reporter.next(relay.traffic.counts(), gauges) {
        let (d, t, g) = (s.delta, s.total, s.gauges);
        tracing::info!(
            interval_s,
            posts_stored = d.get(Count::PostsStored),
            posts_forwarded = d.get(Count::PostsForwarded),
            posts_refused = d.get(Count::PostsRefused),
            delivered = d.get(Count::Delivered),
            acked = d.get(Count::Acked),
            cancels = d.get(Count::Cancels),
            logins_ok = d.get(Count::LoginsOk),
            bad_signatures = d.get(Count::BadSignatures),
            forwards_sent = d.get(Count::ForwardsSent),
            forwards_failed = d.get(Count::ForwardsFailed),
            limit_refusals = d.get(Count::LimitRefusals),
            posts_txid = d.get(Count::PostsTxid),
            posts_no_txid = d.get(Count::PostsNoTxid),
            size_le_2560 = d.get(Count::SizeLe2560),
            size_le_5120 = d.get(Count::SizeLe5120),
            size_le_6144 = d.get(Count::SizeLe6144),
            size_le_10240 = d.get(Count::SizeLe10240),
            size_over_10240 = d.get(Count::SizeOver10240),
            sockets = g.sockets,
            mailboxes_waiting = g.mailboxes_waiting,
            messages_waiting = g.messages_waiting,
            forwards_waiting = g.forwards_waiting,
            posts_stored_total = t.get(Count::PostsStored),
            posts_forwarded_total = t.get(Count::PostsForwarded),
            posts_refused_total = t.get(Count::PostsRefused),
            delivered_total = t.get(Count::Delivered),
            acked_total = t.get(Count::Acked),
            bad_signatures_total = t.get(Count::BadSignatures),
            "traffic"
        );
    }
    let threshold = relay.cfg.log.warn_bad_requests;
    for (net, b) in relay.traffic.take_over(if threshold == 0 { u64::MAX } else { threshold }) {
        crate::sampled!(
            warn,
            net = %net,
            bad_signatures = b.bad_signatures,
            invalid_posts = b.invalid_posts,
            interval_s,
            "many bad requests from one network"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(t: &Traffic) -> Counts {
        t.counts()
    }

    #[test]
    fn a_summary_is_due_only_when_something_changed() {
        let t = Traffic::new();
        let mut r = Reporter::default();
        let idle = Gauges::default();
        // A fresh, idle relay writes nothing.
        assert_eq!(r.next(counts(&t), idle), None);

        t.add(Count::PostsStored, 3);
        t.add(Count::Delivered, 2);
        t.bad_signature("198.51.100.0/24");
        let busy = Gauges { sockets: 4, mailboxes_waiting: 1, messages_waiting: 1, forwards_waiting: 0 };
        let s = r.next(counts(&t), busy).unwrap();
        assert_eq!(s.delta.get(Count::PostsStored), 3);
        assert_eq!(s.delta.get(Count::Delivered), 2);
        assert_eq!(s.delta.get(Count::BadSignatures), 1);
        assert_eq!(s.gauges, busy);

        // Nothing new and the same gauges: no line.
        assert_eq!(r.next(counts(&t), busy), None);
        // A gauge alone moving is a change; the counts' change is zero.
        let s = r.next(counts(&t), idle).unwrap();
        assert!(s.delta.is_zero());
        assert_eq!(s.total.get(Count::PostsStored), 3);

        // The next interval shows only what happened in it.
        t.add(Count::PostsStored, 1);
        let s = r.next(counts(&t), idle).unwrap();
        assert_eq!((s.delta.get(Count::PostsStored), s.total.get(Count::PostsStored)), (1, 4));
    }

    #[test]
    fn size_buckets_cover_every_size_once() {
        assert_eq!(size_bucket(0), SizeBucket::Le2560);
        assert_eq!(size_bucket(2560), SizeBucket::Le2560);
        assert_eq!(size_bucket(2561), SizeBucket::Le5120);
        assert_eq!(size_bucket(5545), SizeBucket::Le6144);
        assert_eq!(size_bucket(8800), SizeBucket::Le10240);
        assert_eq!(size_bucket(10241), SizeBucket::Over10240);
        assert_eq!(size_bucket(usize::MAX).count(), Count::SizeOver10240);
    }

    #[test]
    fn prefixes_over_the_threshold_are_reported_once_most_first() {
        let t = Traffic::new();
        for _ in 0..5 {
            t.bad_signature("198.51.100.0/24");
        }
        for _ in 0..9 {
            t.invalid_post("2001:db8:1::/48");
        }
        t.bad_signature("203.0.113.0/24");
        let over = t.take_over(4);
        assert_eq!(
            over,
            vec![
                ("2001:db8:1::/48".to_string(), BadRequests { bad_signatures: 0, invalid_posts: 9 }),
                ("198.51.100.0/24".to_string(), BadRequests { bad_signatures: 5, invalid_posts: 0 }),
            ]
        );
        // Each report starts a new tally.
        assert!(t.take_over(0).is_empty());
        assert_eq!(t.counts().get(Count::BadSignatures), 6);
    }

    #[test]
    fn the_prefix_tally_is_bounded() {
        let t = Traffic::new();
        for i in 0..MAX_PREFIXES + 10 {
            t.bad_signature(&format!("n{i}"));
        }
        assert_eq!(t.prefixes.lock().len(), MAX_PREFIXES);
        assert_eq!(t.counts().get(Count::BadSignatures), (MAX_PREFIXES + 10) as u64);
    }
}
