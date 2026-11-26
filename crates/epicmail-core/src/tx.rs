//! Transaction rules over plain data: tombstones, participants and queue caps. The stores read
//! the facts (is the txid cancelled, who took part, how many are queued) and ask these
//! functions what to do.

/// What a transaction's state says about a new slate under its txid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxGate {
    /// The txid was cancelled: store nothing.
    Cancelled,
    /// The txid has participants and the sender is not one of them.
    NotParticipant,
    /// Go ahead. `first_of_tx`: no participant yet, so this is the first slate of the transaction.
    Proceed { first_of_tx: bool },
}

/// The gate for a slate from `sender_key` under a txid. Once a transaction has participants a
/// stranger cannot post under it, or the store would link them as a participant and let them
/// cancel it.
pub fn tx_gate(cancelled: bool, participants: &[String], sender_key: &str) -> TxGate {
    if cancelled {
        return TxGate::Cancelled;
    }
    if !participants.is_empty() && !participants.iter().any(|p| p == sender_key) {
        return TxGate::NotParticipant;
    }
    TxGate::Proceed { first_of_tx: participants.is_empty() }
}

/// A queue-cap refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapRefusal {
    QueueFull,
    SenderCapped,
}

/// Whether a mailbox holding `in_queue` messages, `from_sender` of them from this sender, takes
/// one more. The mailbox cap is checked first.
pub fn cap_gate(in_queue: i64, from_sender: i64, queue_cap: u32, per_sender_cap: u32) -> Option<CapRefusal> {
    if in_queue >= i64::from(queue_cap) {
        return Some(CapRefusal::QueueFull);
    }
    if from_sender >= i64::from(per_sender_cap) {
        return Some(CapRefusal::SenderCapped);
    }
    None
}

/// What to do with a CancelTx that passed the signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelPlan {
    /// The transaction's participants (the tombstone's when it is already cancelled).
    pub participants: Vec<String>,
    /// No tombstone yet: this cancel is the first.
    pub first: bool,
    /// The participant that is not the requester: who is told of the cancel.
    pub receiver: Option<String>,
}

/// None when the requester is not a known participant: the relay answers a plain `Ok` and reveals
/// nothing. `tombstone` is the participant list of an existing tombstone.
pub fn cancel_gate(tombstone: Option<&[String]>, participants: &[String], requester: &str) -> Option<CancelPlan> {
    let list = tombstone.unwrap_or(participants);
    if list.is_empty() || !list.iter().any(|p| p == requester) {
        return None;
    }
    Some(CancelPlan {
        participants: list.to_vec(),
        first: tombstone.is_none(),
        receiver: list.iter().find(|p| p.as_str() != requester).cloned(),
    })
}

/// Add `key` to a participant list once, keeping the order of first appearance.
pub fn add_participant(list: &mut Vec<String>, key: String) {
    if !list.contains(&key) {
        list.push(key);
    }
}

/// A participant list as a tombstone stores it: comma separated.
pub fn encode_participants(list: &[String]) -> String {
    list.join(",")
}

/// The inverse of `encode_participants`; empty entries are dropped.
pub fn decode_participants(s: &str) -> Vec<String> {
    s.split(',').filter(|p| !p.is_empty()).map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tx_gate_rules() {
        assert_eq!(tx_gate(true, &v(&["a"]), "a"), TxGate::Cancelled);
        assert_eq!(tx_gate(true, &[], "a"), TxGate::Cancelled);
        assert_eq!(tx_gate(false, &[], "a"), TxGate::Proceed { first_of_tx: true });
        assert_eq!(tx_gate(false, &v(&["a", "b"]), "b"), TxGate::Proceed { first_of_tx: false });
        assert_eq!(tx_gate(false, &v(&["a", "b"]), "m"), TxGate::NotParticipant);
    }

    #[test]
    fn cap_order_and_edges() {
        assert_eq!(cap_gate(0, 0, 3, 2), None);
        assert_eq!(cap_gate(2, 1, 3, 2), None);
        assert_eq!(cap_gate(3, 0, 3, 2), Some(CapRefusal::QueueFull));
        assert_eq!(cap_gate(2, 2, 3, 2), Some(CapRefusal::SenderCapped));
        assert_eq!(cap_gate(3, 2, 3, 2), Some(CapRefusal::QueueFull), "the mailbox cap is checked first");
        assert_eq!(cap_gate(5, 5, u32::MAX, u32::MAX), None);
    }

    #[test]
    fn cancel_rules() {
        let parts = v(&["alice", "bob"]);
        assert_eq!(cancel_gate(None, &[], "alice"), None);
        assert_eq!(cancel_gate(None, &parts, "mallory"), None);
        let p = cancel_gate(None, &parts, "alice").unwrap();
        assert!(p.first);
        assert_eq!(p.receiver.as_deref(), Some("bob"));
        assert_eq!(p.participants, parts);
        // An existing tombstone's participants win over the live ones.
        let tomb = v(&["alice", "bob"]);
        let p = cancel_gate(Some(&tomb), &v(&["x"]), "bob").unwrap();
        assert!(!p.first);
        assert_eq!(p.receiver.as_deref(), Some("alice"));
        assert_eq!(cancel_gate(Some(&[]), &parts, "alice"), None);
        // A transaction with one participant has no receiver to tell.
        assert_eq!(cancel_gate(None, &v(&["solo"]), "solo").unwrap().receiver, None);
    }

    #[test]
    fn participant_lists() {
        let mut l = v(&["a"]);
        add_participant(&mut l, "b".into());
        add_participant(&mut l, "a".into());
        assert_eq!(l, ["a", "b"]);
        assert_eq!(encode_participants(&l), "a,b");
        assert_eq!(decode_participants("a,b"), l);
        assert_eq!(decode_participants(",a,,b,"), l);
        assert!(decode_participants("").is_empty());
    }
}
