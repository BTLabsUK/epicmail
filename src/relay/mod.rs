//! The relay's shared state and the protocol rules every entry point uses: posting a slate
//! (websocket 3.0.0, mux/1 and HTTPS /v1 all go through `post_slate`) and cancelling a 3.1.0
//! transaction.

pub mod registry;
pub mod session;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::{watch, Notify};

use crate::address::parse_address;
use crate::bus::{Bus, Event};
use crate::config::Config;
use crate::limits::Limiter;
use crate::sig;
use crate::store::{ForwardKind, NewForward, NewMessage, PutOutcome, Store};
use crate::util::{is_txid, now_ms, rand_id, sha256};

pub use registry::{Cmd, Registry, SockHandle};

/// Lease on a message offered to a socket or an HTTPS pull.
pub const OFFER_LEASE_MS: i64 = 60_000;
/// Domain separation prefix for cancel signatures that may travel between relays.
pub const CANCEL_SIG_PREFIX: &str = "epicbox-cancel/1:";
const TOKEN_TTL_MS: i64 = 24 * 3600 * 1000;

pub struct TokenEntry {
    pub mailboxes: Vec<String>,
    pub expires_at: i64,
}

pub struct Relay {
    pub cfg: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub registry: Registry,
    pub bus: Bus,
    pub limiter: Arc<Limiter>,
    /// mux/1 resume tokens by SHA-256 hash. Memory only.
    tokens: Mutex<HashMap<[u8; 32], TokenEntry>>,
    /// Wakes the forward manager after a forward is committed.
    pub forward_notify: Notify,
    /// Test knob: mailbox key -> stalled until (ms).
    stalled: Mutex<HashMap<String, i64>>,
    pub draining: AtomicBool,
    pub shutdown: watch::Sender<bool>,
    next_socket: AtomicU64,
    pub started: Instant,
    pub store_ok: AtomicBool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostOutcome {
    Stored { msgid: String, txid: Option<String> },
    Forwarded { txid: Option<String> },
    Cancelled { txid: String },
    Refused(Refusal),
}

/// What to answer a CancelTx with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelOutcome {
    Cancelled(String),
    Ok,
    Refused(Refusal),
}

pub fn error_frame(kind: &str, description: &str) -> Value {
    json!({"type":"Error","kind":kind,"description":description})
}

impl Refusal {
    /// The 3.0.0 `Error` frame for this refusal.
    pub fn classic_frame(&self) -> Value {
        match self {
            Refusal::RateLimited(s) => {
                error_frame("InvalidRequest", &format!("Rate limit exceeded; retry in {s} s."))
            }
            Refusal::Invalid(kind, d) => error_frame(kind, d),
            Refusal::Full(d) => error_frame("InvalidRequest", d),
            Refusal::Internal => error_frame("UnknownError", "Internal error; try again."),
        }
    }
}

fn endpoint_of(domain: Option<&str>, port: Option<u16>) -> Option<String> {
    domain.map(|d| format!("{}:{}", d.to_ascii_lowercase(), port.unwrap_or(443)))
}

impl Relay {
    pub fn new(cfg: Arc<Config>, store: Arc<dyn Store>) -> Arc<Self> {
        let (shutdown, _) = watch::channel(false);
        Arc::new(Self {
            limiter: Arc::new(Limiter::new(&cfg.limits)),
            cfg,
            store,
            registry: Registry::new(),
            bus: Bus::new(),
            tokens: Mutex::new(HashMap::new()),
            forward_notify: Notify::new(),
            stalled: Mutex::new(HashMap::new()),
            draining: AtomicBool::new(false),
            shutdown,
            next_socket: AtomicU64::new(1),
            started: Instant::now(),
            store_ok: AtomicBool::new(true),
        })
    }

    pub fn next_socket_id(&self) -> u64 {
        self.next_socket.fetch_add(1, Ordering::Relaxed)
    }

    pub fn retention_ms(&self) -> i64 {
        self.cfg.retention_secs() * 1000
    }

    // ---- test knob -------------------------------------------------------------------------

    pub fn stall(&self, key: &str, seconds: u64) {
        let until = now_ms() + (seconds.min(86_400) as i64) * 1000;
        let mut s = self.stalled.lock();
        if seconds == 0 {
            s.remove(key);
        } else {
            s.insert(key.to_string(), until);
        }
    }

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

    // ---- mux/1 tokens ----------------------------------------------------------------------

    /// Issue a token for `mailboxes`, ending `old`. Returns (token, expires unix seconds).
    pub fn issue_token(&self, old: Option<[u8; 32]>, mailboxes: Vec<String>) -> (String, [u8; 32], i64) {
        let token = crate::util::rand_b64url(32);
        let hash = sha256(token.as_bytes());
        let expires_at = now_ms() + TOKEN_TTL_MS;
        let mut t = self.tokens.lock();
        if let Some(o) = old {
            t.remove(&o);
        }
        t.insert(hash, TokenEntry { mailboxes, expires_at });
        (token, hash, expires_at / 1000)
    }

    /// Follow Attach/Detach: the set held under a live token.
    pub fn update_token(&self, hash: &[u8; 32], mailboxes: Vec<String>) {
        if let Some(e) = self.tokens.lock().get_mut(hash) {
            e.mailboxes = mailboxes;
        }
    }

    /// Spend a token. None when unknown, spent or expired.
    pub fn take_token(&self, token: &str) -> Option<Vec<String>> {
        let hash = sha256(token.as_bytes());
        let e = self.tokens.lock().remove(&hash)?;
        (e.expires_at > now_ms()).then_some(e.mailboxes)
    }

    pub fn tokens_live(&self) -> usize {
        self.tokens.lock().len()
    }

    pub fn prune_tokens(&self) {
        let now = now_ms();
        self.tokens.lock().retain(|_, e| e.expires_at > now);
    }

    // ---- posting ---------------------------------------------------------------------------

    /// Validate, store or queue a slate. `allow_cancel` accepts the 3.1.0 fields.
    pub async fn post_slate(&self, ip: IpAddr, req: PostReq, allow_cancel: bool) -> PostOutcome {
        let out = self.post_slate_inner(ip, req, allow_cancel).await;
        let label = match &out {
            PostOutcome::Stored { .. } => "stored",
            PostOutcome::Forwarded { .. } => "forwarded",
            PostOutcome::Cancelled { .. } => "cancelled",
            PostOutcome::Refused(Refusal::RateLimited(_)) => "rate_limited",
            PostOutcome::Refused(Refusal::Full(_)) => "full",
            PostOutcome::Refused(Refusal::Internal) => "internal",
            PostOutcome::Refused(Refusal::Invalid(..)) => "invalid",
        };
        metrics::counter!("epicbox_posts_total", "result" => label).increment(1);
        out
    }

    async fn post_slate_inner(&self, ip: IpAddr, req: PostReq, allow_cancel: bool) -> PostOutcome {
        use PostOutcome::Refused;
        let lim = &self.cfg.limits;
        let body_len = req.str_.as_ref().map(|s| s.len()).unwrap_or(0);
        if let Err(s) = self.limiter.post_ip(ip, body_len) {
            return Refused(Refusal::RateLimited(s));
        }
        if let Some(s) = self.limiter.sig_blocked(ip) {
            return Refused(Refusal::RateLimited(s));
        }
        if body_len > lim.max_str_bytes {
            return Refused(Refusal::Invalid(
                "InvalidRequest",
                format!("Slate is larger than {} bytes.", lim.max_str_bytes),
            ));
        }
        let from_s = req.from.clone().unwrap_or_default();
        let to_s = req.to.clone().unwrap_or_default();

        // 3.1.0 fields: both absent (legacy) or both valid.
        let cancel_fields = allow_cancel && self.cfg.protocol.cancel;
        let (txid, txidsig) = if cancel_fields {
            match (&req.txid, &req.txidsig) {
                (None, None) => (None, None),
                (Some(Value::String(t)), Some(Value::String(s))) if is_txid(t) => {
                    (Some(t.clone()), Some(s.clone()))
                }
                _ => {
                    return Refused(Refusal::Invalid(
                        "InvalidRequest",
                        "PostSlate requires from, to, str, and signature. epicboxtxid and epicboxtxidsig \
                         must either both be absent (legacy) or both be valid (protocol 3.1.0)."
                            .into(),
                    ))
                }
            }
        } else {
            (None, None)
        };
        if cancel_fields && (req.str_.is_none() || req.signature.is_none() || req.from.is_none() || req.to.is_none()) {
            return Refused(Refusal::Invalid(
                "InvalidRequest",
                "PostSlate requires from, to, str, and signature. epicboxtxid and epicboxtxidsig \
                 must either both be absent (legacy) or both be valid (protocol 3.1.0)."
                    .into(),
            ));
        }

        let wrong = || {
            Refused(Refusal::Invalid(
                "InvalidRequest",
                format!("Wrong address format. From: {from_s}, To: {to_s}"),
            ))
        };
        let (Ok(from), Ok(to)) = (parse_address(&from_s), parse_address(&to_s)) else {
            return wrong();
        };
        if !from.public_key_valid() || !to.public_key_valid() {
            return wrong();
        }
        let (Some(body), Some(signature)) = (req.str_.clone(), req.signature.clone()) else {
            self.limiter.sig_failed(ip);
            return Refused(Refusal::Invalid("InvalidRequest", "Error postslate signature.".into()));
        };
        if sig::verify(&from.public_key, &body, &signature).is_err() {
            self.limiter.sig_failed(ip);
            return Refused(Refusal::Invalid("InvalidRequest", "Error postslate signature.".into()));
        }
        if let (Some(t), Some(ts)) = (&txid, &txidsig) {
            if sig::verify(&from.public_key, t, ts).is_err() {
                self.limiter.sig_failed(ip);
                return Refused(Refusal::Invalid("InvalidSignature", "Invalid epicboxtxid signature.".into()));
            }
        }
        if let Err(s) = self.limiter.post_addr(&from.public_key) {
            return Refused(Refusal::RateLimited(s));
        }

        // Route by the destination inside the signed slate, as the stock relay does.
        let Ok(payload) = serde_json::from_str::<Value>(&body) else {
            return Refused(Refusal::Invalid("InvalidRequest", "Invalid Slate payload.".into()));
        };
        let Some((dest_key, dest_domain, dest_port)) = destination(&payload) else {
            return Refused(Refusal::Invalid("InvalidRequest", "Invalid slate destination.".into()));
        };
        let now = now_ms();
        let expires_at = now + self.retention_ms();

        if self.cfg.is_local(&dest_domain, dest_port) {
            let remote_endpoint = endpoint_of(from.domain.as_deref(), from.port)
                .filter(|_| !self.cfg.is_local(from.domain.as_deref().unwrap_or(""), from.port.unwrap_or(443)));
            let m = NewMessage {
                queue: dest_key.clone(),
                sender: from_s.clone(),
                sender_key: from.public_key.clone(),
                recipient: to_s.clone(),
                body,
                signature,
                challenge: String::new(),
                txid: txid.clone(),
                txidsig,
                remote_endpoint,
                msgid: rand_id(32),
                created_at: now,
                expires_at,
                deliveries: 0,
                queue_cap: lim.queue_cap,
                per_sender_cap: lim.per_sender_cap,
            };
            return match self.store.put_message(m).await {
                Ok(PutOutcome::Stored { msgid }) => {
                    self.registry.wake(&dest_key);
                    self.bus.publish(Event::MailStored { queue: dest_key });
                    PostOutcome::Stored { msgid, txid }
                }
                Ok(PutOutcome::Duplicate { msgid }) => {
                    // Wake anyway: the earlier copy may be waiting for a listener that just came.
                    self.registry.wake(&dest_key);
                    PostOutcome::Stored { msgid, txid }
                }
                Ok(PutOutcome::QueueFull) => {
                    Refused(Refusal::Full("Recipient mailbox is full; try again later.".into()))
                }
                Ok(PutOutcome::SenderCapped) => Refused(Refusal::Full(
                    "Too many messages from this sender are waiting for the recipient.".into(),
                )),
                Ok(PutOutcome::Cancelled) => PostOutcome::Cancelled { txid: txid.unwrap_or_default() },
                Ok(PutOutcome::NotParticipant) => Refused(Refusal::Invalid(
                    "InvalidRequest",
                    "Posting address is not a participant of epicboxtxid.".into(),
                )),
                Err(e) => {
                    tracing::error!(error = %e, "store put_message failed");
                    self.store_ok.store(false, Ordering::Relaxed);
                    Refused(Refusal::Internal)
                }
            };
        }

        // Another relay.
        let peer = format!("{}:{}", dest_domain.to_ascii_lowercase(), dest_port);
        if let Some(r) = self.forward_refusal(&dest_domain, dest_port) {
            return Refused(r);
        }
        if let Some(t) = &txid {
            match self.store.tx_info(t).await {
                Ok(info) if info.tombstone.is_some() => return PostOutcome::Cancelled { txid: t.clone() },
                Ok(_) => {}
                Err(_) => return Refused(Refusal::Internal),
            }
        }
        let mut frame = json!({"type":"PostSlate","from":from_s,"to":to_s,"str":body,"signature":signature});
        if let (Some(t), Some(ts)) = (&txid, &txidsig) {
            frame["epicboxtxid"] = json!(t);
            frame["epicboxtxidsig"] = json!(ts);
        }
        let f = NewForward {
            peer,
            kind: ForwardKind::PostSlate,
            frame: frame.to_string(),
            txid: txid.clone(),
            tx_keys: vec![from.public_key.clone(), dest_key],
            created_at: now,
            expires_at,
            attempts: 0,
        };
        match self.store.put_forward(f).await {
            Ok(_) => {
                self.forward_notify.notify_one();
                PostOutcome::Forwarded { txid }
            }
            Err(e) => {
                tracing::error!(error = %e, "store put_forward failed");
                Refused(Refusal::Internal)
            }
        }
    }

    /// Policy check for a remote destination (allow/deny lists, federation switch). Addresses are
    /// vetted again when the forward manager resolves the name.
    pub fn forward_refusal(&self, domain: &str, port: u16) -> Option<Refusal> {
        let fed = &self.cfg.federation;
        let d = domain.to_ascii_lowercase();
        let dp = format!("{d}:{port}");
        if !fed.enabled {
            return Some(Refusal::Invalid("InvalidRequest", "This relay does not forward to other relays.".into()));
        }
        let listed = |l: &Vec<String>| l.iter().any(|x| x.eq_ignore_ascii_case(&d) || x.eq_ignore_ascii_case(&dp));
        if listed(&fed.deny) || (!fed.allow.is_empty() && !listed(&fed.allow)) {
            return Some(Refusal::Invalid("InvalidRequest", format!("Forwarding to {dp} is not allowed.")));
        }
        if d.is_empty() || d.len() > 253 || !d.contains('.') && !fed.peers.contains_key(&dp) {
            return Some(Refusal::Invalid("InvalidRequest", "Invalid slate destination.".into()));
        }
        None
    }

    // ---- 3.1.0 cancel ----------------------------------------------------------------------

    /// CancelTx. `socket_key` is the key this socket proved with Subscribe, if any.
    pub async fn cancel_tx(&self, ip: IpAddr, socket_key: Option<&str>, msg: &Value) -> CancelOutcome {
        use CancelOutcome::Refused as R;
        let requester = match socket_key {
            Some(k) => Some(k.to_string()),
            None => msg
                .get("address")
                .and_then(|a| a.as_str())
                .and_then(|a| parse_address(a).ok())
                .map(|a| a.public_key),
        };
        let Some(requester) = requester else {
            return R(Refusal::Invalid("InvalidRequest", "Missing cancellation address.".into()));
        };
        let txid = match msg.get("epicboxtxid").and_then(|t| t.as_str()) {
            Some(t) if is_txid(t) => t.to_string(),
            _ => {
                return R(Refusal::Invalid(
                    "InvalidRequest",
                    "Invalid or missing 32-character epicboxtxid.".into(),
                ))
            }
        };
        let Some(signature) = msg.get("signature").and_then(|s| s.as_str()) else {
            return R(Refusal::Invalid("InvalidRequest", "Missing signature.".into()));
        };
        if let Some(s) = self.limiter.sig_blocked(ip) {
            return R(Refusal::RateLimited(s));
        }
        // A bare signature over the txid is what PostSlate's epicboxtxidsig already is, so anyone
        // who saw the slate holds one. Accept it only from a socket that proved the key this
        // session; otherwise require the domain-separated form.
        let separated = sig::verify(&requester, &format!("{CANCEL_SIG_PREFIX}{txid}"), signature).is_ok();
        let bare_ok = !separated && socket_key.is_some() && sig::verify(&requester, &txid, signature).is_ok();
        if !separated && !bare_ok {
            self.limiter.sig_failed(ip);
            return R(Refusal::Invalid("InvalidSignature", "Invalid signature.".into()));
        }
        let info = match self.store.tx_info(&txid).await {
            Ok(i) => i,
            Err(_) => return R(Refusal::Internal),
        };
        if let Some(t) = &info.tombstone {
            return if t.participants.contains(&requester) {
                CancelOutcome::Cancelled(txid)
            } else {
                CancelOutcome::Ok
            };
        }
        if info.participants.is_empty() || !info.participants.contains(&requester) {
            return CancelOutcome::Ok;
        }
        let receiver = info.participants.iter().find(|p| **p != requester).cloned();
        let now = now_ms();
        let queues = match self.store.cancel_tx(&txid, info.participants.clone(), receiver.clone(), now).await {
            Ok(q) => q,
            Err(_) => return R(Refusal::Internal),
        };
        metrics::counter!("epicbox_cancels_total").increment(1);
        if separated || self.cfg.protocol.forward_bare_cancel {
            for peer in &info.endpoints {
                let frame = json!({"type":"CancelTx","address":requester,"epicboxtxid":txid,"signature":signature});
                let f = NewForward {
                    peer: peer.clone(),
                    kind: ForwardKind::CancelTx,
                    frame: frame.to_string(),
                    txid: None,
                    tx_keys: vec![],
                    created_at: now,
                    expires_at: now + self.retention_ms(),
                    attempts: 0,
                };
                if self.store.put_forward(f).await.is_err() {
                    return R(Refusal::Internal);
                }
            }
            if !info.endpoints.is_empty() {
                self.forward_notify.notify_one();
            }
        }
        if let Some(r) = &receiver {
            for h in self.registry.classic_sockets(r) {
                if h.cancel {
                    h.send(Cmd::Cancelled { txid: txid.clone() });
                }
            }
        }
        self.bus.publish(Event::TxCancelled { txid: txid.clone(), queues });
        CancelOutcome::Cancelled(txid)
    }
}

/// `destination{public_key, domain, port}` from a slate body. Port may be a number or a numeric
/// string; it defaults to 443.
pub fn destination(payload: &Value) -> Option<(String, String, u16)> {
    let d = payload.get("destination")?;
    let key = d.get("public_key")?.as_str()?;
    let domain = d.get("domain")?.as_str()?;
    let port = match d.get("port") {
        None | Some(Value::Null) => 443,
        Some(Value::Number(n)) => u16::try_from(n.as_u64()?).ok()?,
        Some(Value::String(s)) => s.parse().ok()?,
        _ => return None,
    };
    if domain.is_empty() || !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return None;
    }
    let addr = parse_address(key).ok()?;
    if addr.domain.is_some() || !addr.public_key_valid() {
        return None;
    }
    Some((addr.public_key, domain.to_string(), port))
}
