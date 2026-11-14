//! Durable state behind one trait, so a second backend (Postgres) can be added without touching
//! the protocol code. Every write call returns after its transaction has committed: callers send
//! `Ok` to a wallet only after that.
//!
//! Times are unix milliseconds. Ids:
//! - `id` is the row id, internal only.
//! - `msgid` is the 32-character `epicboxmsgid` wallets see.

pub mod sqlite;

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct NewMessage {
    /// Recipient public key (the mailbox).
    pub queue: String,
    /// `from` address exactly as posted.
    pub sender: String,
    /// Sender public key, used for the per-sender cap.
    pub sender_key: String,
    /// `to` address exactly as posted.
    pub recipient: String,
    pub body: String,
    pub signature: String,
    pub challenge: String,
    pub txid: Option<String>,
    pub txidsig: Option<String>,
    /// `domain:port` of the sender's relay when it is not this relay (3.1.0 cancel routing).
    pub remote_endpoint: Option<String>,
    pub msgid: String,
    pub created_at: i64,
    pub expires_at: i64,
    /// Deliveries already made (import only).
    pub deliveries: i64,
    pub queue_cap: u32,
    pub per_sender_cap: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    Stored {
        msgid: String,
    },
    /// The same message (queue, sender, body, signature) is already waiting.
    Duplicate {
        msgid: String,
    },
    QueueFull,
    SenderCapped,
    /// The 3.1.0 transaction was cancelled; the poster gets TransactionCancelled.
    Cancelled,
    /// The txid is known and the poster is not one of its participants.
    NotParticipant,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredMessage {
    #[serde(skip)]
    pub id: i64,
    pub msgid: String,
    pub queue: String,
    pub sender: String,
    pub body: String,
    pub signature: String,
    pub challenge: String,
    pub txid: Option<String>,
    pub deliveries: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardKind {
    PostSlate = 0,
    CancelTx = 1,
}

#[derive(Debug, Clone)]
pub struct NewForward {
    /// `domain:port`, already validated.
    pub peer: String,
    pub kind: ForwardKind,
    /// The JSON frame sent to the peer.
    pub frame: String,
    pub txid: Option<String>,
    /// Participant keys to remember for 3.1.0 (sender and recipient).
    pub tx_keys: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub attempts: i64,
}

#[derive(Debug, Clone)]
pub struct ForwardRow {
    pub id: i64,
    pub peer: String,
    pub kind: ForwardKind,
    pub frame: String,
    pub attempts: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct TxInfo {
    /// Participant public keys seen on this relay.
    pub participants: Vec<String>,
    /// Remote relays (`domain:port`) that hold states of this transaction.
    pub endpoints: Vec<String>,
    pub tombstone: Option<Tombstone>,
}

#[derive(Debug, Clone)]
pub struct Tombstone {
    pub participants: Vec<String>,
    pub receiver: Option<String>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    pub messages_waiting: i64,
    pub mailboxes_waiting: i64,
    pub oldest_waiting_ms: i64,
    pub oldest_unoffered_ms: i64,
    pub forwards_waiting: i64,
    pub forward_peers: i64,
    pub oldest_forward_ms: i64,
    pub tombstones: i64,
    pub db_bytes: i64,
    /// Bytes in pages that hold data: `db_bytes` less the free pages.
    pub used_bytes: i64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SweepStats {
    pub messages_expired: u64,
    pub forwards_expired: u64,
    pub tombstones_expired: u64,
    pub challenges_expired: u64,
    pub txlinks_expired: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimMode {
    /// Mark offered, lease until `now + lease_ms` (0: no lease).
    Offer { lease_ms: i64 },
    /// Legacy clients have no Made: delivery removes the message.
    Consume,
}

#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Store a message for a local mailbox. Checks tombstones, participants, caps and dedupe in
    /// the same transaction.
    async fn put_message(&self, m: NewMessage) -> Result<PutOutcome>;

    /// Whether `queue` has a message that may be offered now, ignoring `exclude` ids.
    async fn has_offerable(&self, queue: &str, now: i64, exclude: Vec<i64>) -> Result<bool>;

    /// Offerable messages count (Attached `waiting`).
    async fn waiting(&self, queue: &str, now: i64) -> Result<i64>;

    /// Offerable message counts for several queues in one read (mux/1 `Waiting`). Queues
    /// with nothing offerable are absent from the map.
    async fn waiting_many(&self, queues: Vec<String>, now: i64) -> Result<std::collections::HashMap<String, i64>>;

    /// Take up to `limit` offerable messages, oldest first; messages offered three times or more
    /// go after the others, so one poisoned message cannot block a mailbox.
    async fn claim(
        &self,
        queue: &str,
        now: i64,
        limit: usize,
        exclude: Vec<i64>,
        mode: ClaimMode,
    ) -> Result<Vec<StoredMessage>>;

    /// Clear the lease on messages (socket closed, Detach) so they are offered again at once.
    async fn release(&self, ids: Vec<i64>) -> Result<()>;

    /// Delay a message until `until` (mux Hold). False when unknown for this queue.
    async fn hold(&self, queue: &str, msgid: &str, until: i64) -> Result<bool>;

    /// Remove delivered messages. Returns, per msgid, whether it was removed. A message with a
    /// txid takes the other waiting states of that transaction in the queue with it.
    async fn made(&self, queue: &str, msgids: Vec<String>) -> Result<Vec<bool>>;

    /// mux/1 Ack: remove each msgid that sits in one of `queues`; others are ignored. Returns
    /// how many were removed.
    async fn made_in(&self, queues: Vec<String>, msgids: Vec<String>) -> Result<u64>;

    /// Queue a frame for a remote relay. False when the same frame is already queued.
    async fn put_forward(&self, f: NewForward) -> Result<bool>;
    /// Peers with forwards due at `now`.
    async fn forward_peers_due(&self, now: i64) -> Result<Vec<String>>;
    async fn forwards_due(&self, peer: &str, now: i64, limit: usize) -> Result<Vec<ForwardRow>>;
    async fn forward_done(&self, id: i64) -> Result<()>;
    /// Record a failed attempt. `drop` removes the row (peer refused it for good).
    async fn forward_failed(&self, id: i64, next_at: i64, error: &str, drop: bool) -> Result<()>;

    async fn tx_info(&self, txid: &str) -> Result<TxInfo>;
    /// Write the tombstone and delete every waiting state of the transaction. Returns the
    /// mailboxes that lost messages.
    async fn cancel_tx(
        &self,
        txid: &str,
        participants: Vec<String>,
        receiver: Option<String>,
        now: i64,
    ) -> Result<Vec<String>>;
    /// The oldest unacknowledged tombstone for a receiver.
    async fn pending_cancel(&self, receiver: &str) -> Result<Option<String>>;
    async fn ack_cancel(&self, receiver: &str, txid: &str) -> Result<()>;

    /// Record a /v1 challenge as used. False when it was used before (replay).
    async fn use_challenge(&self, key: &str, expires_at: i64) -> Result<bool>;

    async fn sweep(&self, now: i64, retention_ms: i64) -> Result<SweepStats>;
    async fn vacuum(&self) -> Result<()>;
    async fn stats(&self, now: i64) -> Result<Stats>;
    /// Bytes of live data as of the last commit, if the store tracks it. Cheap: no store work.
    fn used_bytes(&self) -> Option<u64> {
        None
    }
    /// A write round trip, for /ready.
    async fn check_writable(&self) -> Result<()>;
}
