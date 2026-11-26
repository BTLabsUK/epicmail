//! The relay's shared state and the protocol rules every entry point uses. Websocket 3.0.0,
//! mux/1 and HTTPS /v1 all post through `post_slate` (`post.rs`) and cancel through `cancel_tx`
//! (`cancel.rs`). `tokens.rs` keeps the mux/1 resume tokens, `registry.rs` the sockets that
//! listen on each mailbox, and `session/` runs each websocket.

mod cancel;
mod post;
pub mod registry;
pub mod session;
mod tokens;
pub mod waiters;

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::{watch, Notify};

use crate::clock::now_ms;
use crate::config::Config;
use crate::limits::Limiter;
use crate::store::Store;
use epicmail_core::refusal;

pub use registry::{Cmd, Registry, SockHandle};

pub use epicmail_core::limits::OFFER_LEASE_MS;
pub use epicmail_core::text::{ATTACH_HOST_EXT, ATTACH_SIG_PREFIX, CANCEL_SEPARATED_EXT, CANCEL_SIG_PREFIX};

/// The shard, of `shards`, that holds mailbox `key`. Keys are chosen by clients, so the hash is
/// keyed with a random seed per process: nobody can pick keys that all land on one shard.
pub(crate) fn shard_of(key: &str, shards: usize) -> usize {
    static SEED: LazyLock<RandomState> = LazyLock::new(RandomState::new);
    (SEED.hash_one(key) as usize) % shards
}

/// Everything the entry points share. One per process, behind an `Arc`.
pub struct Relay {
    pub cfg: Arc<Config>,
    pub store: Arc<dyn Store>,
    /// Which socket gets pushes for each mailbox.
    pub registry: Registry,
    /// `/v1/pull` long polls waiting for mail, by mailbox.
    pub pull_waiters: waiters::PullWaiters,
    pub limiter: Arc<Limiter>,
    /// Counts for the log summary (`traffic::run`); the limiter's.
    pub traffic: Arc<crate::traffic::Traffic>,
    /// mux/1 resume tokens by SHA-256 hash. Memory only.
    tokens: Mutex<tokens::Tokens>,
    /// Wakes the forward manager after a forward is committed.
    pub forward_notify: Notify,
    /// Test knob: mailbox key -> stalled until (ms).
    stalled: Mutex<HashMap<String, i64>>,
    /// Set on SIGTERM: new sockets are refused and `/ready` reports not ready.
    pub draining: AtomicBool,
    /// Tells every session to end; sent once when the drain starts.
    pub shutdown: watch::Sender<bool>,
    next_socket: AtomicU64,
    pub started: Instant,
    /// The result of the last store write check (`/ready` and the housekeeping gauge).
    pub store_ok: AtomicBool,
    /// When `/ready` last wrote to the store. Probes closer together reuse `store_ok`.
    pub last_ready_probe: Mutex<Option<Instant>>,
    /// Store totals from the last housekeeping round, served by `/status.json`.
    pub last_stats: Mutex<Option<crate::store::Stats>>,
    /// Random per process. Forwards carry it in [`INSTANCE_HEADER`]; a socket that arrives with
    /// our own value is this relay forwarding to itself under another name, and is refused.
    pub instance_id: String,
    /// `txid:cancelrequestid` of recent cancels, with when to forget each (unix ms).
    pub(crate) cancel_requests: Mutex<HashMap<String, i64>>,
}

/// Handshake header that carries the forwarding relay's `instance_id`.
pub const INSTANCE_HEADER: &str = "x-epicmail-instance";

pub use epicmail_core::post::PostReq;

/// Why a post or a cancel was refused. Each entry point turns it into its own reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A limit was hit; retry after the seconds given.
    RateLimited(u64),
    /// Invalid request; (kind, description) as the stock relay words them.
    Invalid(&'static str, String),
    /// The recipient's queue is full.
    Full(String),
    /// The sender's host is in `federation.deny_sender_hosts`.
    DeniedHost(String),
    /// Store error; nothing was written.
    Internal,
}

impl From<epicmail_core::post::PostRefusal> for Refusal {
    fn from(r: epicmail_core::post::PostRefusal) -> Self {
        Refusal::Invalid(r.kind(), r.text())
    }
}

/// How a websocket frame's signature checks meet the prefix limits, and what they found. The
/// session sets `first` for the first signed frame of a socket; `post_slate` and `cancel_tx` add
/// to `failed` for each failed signature, so the session can count them against the socket.
#[derive(Debug, Default, Clone, Copy)]
pub struct SigScope {
    /// The first signed frame of the socket: the prefix's block does not refuse it.
    pub first: bool,
    /// Failed signatures found in this frame.
    pub failed: u32,
}

/// What `post_slate` did with a slate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostOutcome {
    /// Committed for a local mailbox (or already there: a slate posted twice keeps one copy).
    Stored {
        msgid: String,
        txid: Option<String>,
    },
    /// Committed as a forward row for another relay.
    Forwarded {
        txid: Option<String>,
    },
    /// The 3.1.0 transaction was cancelled; nothing was stored.
    Cancelled {
        txid: String,
    },
    Refused(Refusal),
}

/// What to answer a CancelTx with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelOutcome {
    /// `TransactionCancelled` for this txid.
    Cancelled(String),
    /// Plain `Ok`: the requester is not a known participant, so nothing is revealed.
    Ok,
    Refused(Refusal),
}

/// A classic `Error` frame.
pub fn error_frame(kind: &str, description: &str) -> Value {
    json!({"type":"Error","kind":kind,"description":description})
}

impl Refusal {
    /// The 3.0.0 `Error` frame for this refusal.
    pub fn classic_frame(&self) -> Value {
        match self {
            Refusal::RateLimited(s) => error_frame(refusal::KIND_INVALID_REQUEST, &refusal::rate_limited(*s)),
            Refusal::Invalid(kind, d) => error_frame(kind, d),
            Refusal::Full(d) | Refusal::DeniedHost(d) => error_frame(refusal::KIND_INVALID_REQUEST, d),
            Refusal::Internal => error_frame(refusal::KIND_UNKNOWN, refusal::INTERNAL),
        }
    }
}

impl Relay {
    /// A relay with no sockets, not draining.
    pub fn new(cfg: Arc<Config>, store: Arc<dyn Store>) -> Arc<Self> {
        let (shutdown, _) = watch::channel(false);
        let tokens = tokens::Tokens::new(cfg.limits.mux_token_mailboxes as usize);
        let limiter = Arc::new(Limiter::new(&cfg.limits));
        Arc::new(Self {
            traffic: limiter.traffic.clone(),
            limiter,
            cfg,
            store,
            registry: Registry::new(),
            pull_waiters: waiters::PullWaiters::new(),
            tokens: Mutex::new(tokens),
            forward_notify: Notify::new(),
            stalled: Mutex::new(HashMap::new()),
            draining: AtomicBool::new(false),
            shutdown,
            next_socket: AtomicU64::new(1),
            started: Instant::now(),
            store_ok: AtomicBool::new(true),
            last_ready_probe: Mutex::new(None),
            last_stats: Mutex::new(None),
            instance_id: crate::ids::rand_id(32),
            cancel_requests: Mutex::new(HashMap::new()),
        })
    }

    /// Wake every listener of `key`: the socket that gets its pushes and the waiting pulls.
    pub fn mail_arrived(&self, key: &str) {
        self.registry.wake(key);
        self.pull_waiters.wake(key);
    }

    /// A process-unique id for a new socket.
    pub fn next_socket_id(&self) -> u64 {
        self.next_socket.fetch_add(1, Ordering::Relaxed)
    }

    /// How long a message or forward is kept: `store.retention_days` in milliseconds.
    pub fn retention_ms(&self) -> i64 {
        self.cfg.retention_secs() * 1000
    }

    /// Test knob (`test.stall_endpoint`): deliver nothing to `key` for `seconds` (0 ends it,
    /// at most a day).
    pub fn stall(&self, key: &str, seconds: u64) {
        let until = now_ms() + (seconds.min(86_400) as i64) * 1000;
        let mut s = self.stalled.lock();
        if seconds == 0 {
            s.remove(key);
        } else {
            s.insert(key.to_string(), until);
        }
    }

    /// True while `key` is stalled. Always false unless `test.stall_endpoint` is set.
    pub fn is_stalled(&self, key: &str) -> bool {
        if !self.cfg.test.stall_endpoint {
            return false;
        }
        let mut s = self.stalled.lock();
        match s.get(key) {
            Some(&until) if until > now_ms() => true,
            Some(_) => {
                s.remove(key);
                // The stall ended: let the listener collect.
                drop(s);
                self.registry.wake(key);
                false
            }
            None => false,
        }
    }
}

/// Wake the listeners of each mailbox the store reports mail for from another writer. Returns
/// at once for a store with no other writers, and when the store drops the feed.
pub async fn arrivals(relay: Arc<Relay>) {
    let Some(mut rx) = relay.store.take_arrivals() else { return };
    while let Some(key) = rx.recv().await {
        relay.mail_arrived(&key);
    }
}
