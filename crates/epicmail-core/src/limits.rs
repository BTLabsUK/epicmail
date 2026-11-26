//! Default limits and the order messages are offered in.

/// Messages one mailbox holds.
pub const DEFAULT_QUEUE_CAP: u32 = 2000;
/// Messages from one sender one mailbox holds.
pub const DEFAULT_PER_SENDER_CAP: u32 = 200;
/// Longest slate (`str`) in bytes.
pub const DEFAULT_MAX_STR_BYTES: usize = 128 << 10;
/// Days a message or forward is kept.
pub const DEFAULT_RETENTION_DAYS: u32 = 7;
/// Lease on a message offered to a socket or an HTTPS pull.
pub const OFFER_LEASE_MS: i64 = 60_000;
/// A message offered this many times goes after the ones offered fewer times, so one that is
/// never acknowledged cannot hold up a mailbox.
pub const LATE_AFTER_OFFERS: i64 = 3;

/// The sort key of a message in the offer order, smallest first: messages offered fewer than
/// `LATE_AFTER_OFFERS` times come first, oldest created first; the rest follow, least recently
/// offered first; the store id breaks ties.
pub fn offer_key(deliveries: i64, last_offered_at: i64, created_at: i64, id: i64) -> (u8, i64, i64) {
    if deliveries >= LATE_AFTER_OFFERS {
        (1, last_offered_at, id)
    } else {
        (0, created_at, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_relay() {
        assert_eq!(DEFAULT_QUEUE_CAP, 2000);
        assert_eq!(DEFAULT_PER_SENDER_CAP, 200);
        assert_eq!(DEFAULT_MAX_STR_BYTES, 131_072);
        assert_eq!(DEFAULT_RETENTION_DAYS, 7);
        assert_eq!(OFFER_LEASE_MS, 60_000);
    }

    #[test]
    fn a_message_offered_three_times_goes_last() {
        // (deliveries, last_offered_at, created_at, id)
        let mut v = [(3, 50, 1, 1), (0, 0, 20, 2), (2, 60, 10, 3), (5, 40, 2, 4)];
        v.sort_by_key(|&(d, l, c, i)| offer_key(d, l, c, i));
        let ids: Vec<i64> = v.iter().map(|m| m.3).collect();
        assert_eq!(ids, [3, 2, 4, 1]);
    }

    #[test]
    fn ties_break_by_id() {
        assert!(offer_key(0, 0, 5, 1) < offer_key(0, 0, 5, 2));
        assert!(offer_key(3, 5, 0, 1) < offer_key(3, 5, 0, 2));
    }
}
