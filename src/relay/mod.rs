//! The relay's shared state and the protocol rules every entry point uses. Websocket 3.0.0,
//! mux/1 and HTTPS /v1 all post through `post_slate` (`post.rs`) and cancel through `cancel_tx`
//! (`cancel.rs`). `tokens.rs` keeps the mux/1 resume tokens, `registry.rs` the sockets that
//! listen on each mailbox, and `session/` runs each websocket.

mod cancel;
mod post;
pub mod registry;
pub mod session;
mod tokens;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::{watch, Notify};

use crate::bus::Bus;
use crate::clock::now_ms;
use crate::config::Config;
use crate::limits::Limiter;
use crate::store::Store;

pub use registry::{Cmd, Registry, SockHandle};

/// Lease on a message offered to a socket or an HTTPS pull.
pub const OFFER_LEASE_MS: i64 = 60_000;
/// Domain separation prefix for cancel signatures that may travel between relays.
pub const CANCEL_SIG_PREFIX: &str = "epicbox-cancel/1:";

/// Everything the entry points share. One per process, behind an `Arc`.
pub struct Relay {
    pub cfg: Arc<Config>,
    pub store: Arc<dyn Store>,
    /// Which socket gets pushes for each mailbox.
    pub registry: Registry,
    /// Events published after a commit.
    pub bus: Bus,
    pub limiter: Arc<Limiter>,
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
}

/// A PostSlate, from any entry point.
#[derive(Debug, Clone, Default)]
pub struct PostReq {
    pub from: Option<String>,
    pub to: Option<String>,
    pub str_: Option<String>,
    pub signature: Option<String>,
    pub txid: Option<Value>,
    pub txidsig: Option<Value>,
}

impl PostReq {
    /// Read the fields from a PostSlate frame or `/v1/post` body. Missing or mistyped fields are
    /// None; `post_slate` decides what that means.
    pub fn from_json(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
        Self {
            from: s("from"),
            to: s("to"),
            str_: s("str"),
            signature: s("signature"),
            txid: v.get("epicboxtxid").filter(|x| !x.is_null()).cloned(),
            txidsig: v.get("epicboxtxidsig").filter(|x| !x.is_null()).cloned(),
        }
    }
}

/// Why a post or a cancel was refused. Each entry point turns it into its own reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A limit was hit; retry after the seconds given.
    RateLimited(u64),
    /// Invalid request; (kind, description) as the stock relay words them.
    Invalid(&'static str, String),
    /// The recipient's queue is full.
    Full(String),
    /// Store error; nothing was written.
    Internal,
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
            Refusal::RateLimited(s) => error_frame("InvalidRequest", &format!("Rate limit exceeded; retry in {s} s.")),
            Refusal::Invalid(kind, d) => error_frame(kind, d),
            Refusal::Full(d) => error_frame("InvalidRequest", d),
            Refusal::Internal => error_frame("UnknownError", "Internal error; try again."),
        }
    }
}

impl Relay {
    /// A relay with no sockets, not draining.
    pub fn new(cfg: Arc<Config>, store: Arc<dyn Store>) -> Arc<Self> {
        let (shutdown, _) = watch::channel(false);
        let tokens = tokens::Tokens::new(cfg.limits.mux_token_mailboxes as usize);
        Arc::new(Self {
            limiter: Arc::new(Limiter::new(&cfg.limits)),
            cfg,
            store,
            registry: Registry::new(),
            bus: Bus::new(),
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
        })
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
