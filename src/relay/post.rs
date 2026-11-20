//! PostSlate, from every entry point: limits, address and signature checks, then storage for
//! this relay's mailboxes or a forward row for another relay.

use std::net::IpAddr;
use std::sync::atomic::Ordering;

use serde_json::{json, Value};

use super::{PostOutcome, PostReq, Refusal, Relay, SigScope};
use crate::address::{parse_address, EpicboxAddress};
use crate::clock::now_ms;
use crate::ids::{is_txid, rand_id};
use crate::logging::short_addr;
use crate::sig;
use crate::store::{ForwardKind, NewForward, NewMessage, PutOutcome};
use crate::traffic::Count;

/// The refusal text for a PostSlate with missing fields or half the 3.1.0 fields, worded as the
/// stock relay words it.
const MISSING_FIELDS: &str = "PostSlate requires from, to, str, and signature. epicboxtxid and epicboxtxidsig \
                              must either both be absent (legacy) or both be valid (protocol 3.1.0).";

/// A slate that passed every check in `check_post`.
struct Slate {
    from_s: String,
    to_s: String,
    from: EpicboxAddress,
    body: String,
    signature: String,
    txid: Option<String>,
    txidsig: Option<String>,
    dest_key: String,
    dest_domain: String,
    dest_port: u16,
}

impl Relay {
    /// Validate, store or queue a slate. `allow_cancel` accepts the 3.1.0 fields.
    pub async fn post_slate(&self, ip: IpAddr, req: PostReq, allow_cancel: bool) -> PostOutcome {
        self.post_slate_scoped(ip, req, allow_cancel, &mut SigScope::default()).await
    }

    /// `post_slate` for a websocket frame: `scope` says whether this is the socket's first signed
    /// frame and collects the failed signatures.
    pub async fn post_slate_scoped(
        &self,
        ip: IpAddr,
        req: PostReq,
        allow_cancel: bool,
        scope: &mut SigScope,
    ) -> PostOutcome {
        let who = (tracing::level_filters::LevelFilter::current() >= tracing::Level::DEBUG).then(|| {
            let addr = |a: &Option<String>| a.as_deref().map(short_addr).unwrap_or_default();
            (addr(&req.from), addr(&req.to), req.str_.as_ref().map_or(0, String::len))
        });
        let has_txid = allow_cancel && self.cfg.protocol.cancel && req.txid.is_some();
        let size = req.str_.as_ref().map_or(0, String::len);
        let (out, peer, policy) = self.post_slate_inner(ip, req, allow_cancel, scope).await;
        let label = match &out {
            PostOutcome::Stored { .. } => "stored",
            PostOutcome::Forwarded { .. } => "forwarded",
            PostOutcome::Cancelled { .. } => "cancelled",
            PostOutcome::Refused(Refusal::RateLimited(_)) => "rate_limited",
            PostOutcome::Refused(Refusal::Full(_)) => "full",
            PostOutcome::Refused(Refusal::DeniedHost(_)) => "denied_sender_host",
            PostOutcome::Refused(Refusal::Internal) => "internal",
            PostOutcome::Refused(Refusal::Invalid(..)) if policy => "policy",
            PostOutcome::Refused(Refusal::Invalid(..)) => "invalid",
        };
        let txid_label = if has_txid { "yes" } else { "no" };
        metrics::counter!("epicbox_posts_total", "result" => label, "txid" => txid_label).increment(1);
        if matches!(out, PostOutcome::Stored { .. } | PostOutcome::Forwarded { .. }) {
            let bucket = crate::traffic::size_bucket(size);
            metrics::counter!("epicbox_post_size_total", "size" => bucket.label(), "txid" => txid_label).increment(1);
            self.traffic.add(if has_txid { Count::PostsTxid } else { Count::PostsNoTxid }, 1);
            self.traffic.add(bucket.count(), 1);
        }
        self.traffic.add(
            match &out {
                PostOutcome::Stored { .. } => Count::PostsStored,
                PostOutcome::Forwarded { .. } => Count::PostsForwarded,
                _ => Count::PostsRefused,
            },
            1,
        );
        if let PostOutcome::Refused(Refusal::DeniedHost(_)) = out {
            metrics::counter!("epicbox_denied_sender_host_total").increment(1);
            self.traffic.add(Count::PostsDeniedHost, 1);
        }
        // A policy refusal is the operator's allow/deny list at work, not a client misbehaving.
        if let (PostOutcome::Refused(Refusal::Invalid(..)), false) = (&out, policy) {
            self.limiter.invalid_post(ip);
        }
        if let PostOutcome::Refused(Refusal::RateLimited(_)) = out {
            self.limiter.refused("posts", ip);
        }
        if let Some((from, to, size)) = who {
            match &out {
                PostOutcome::Stored { msgid, .. } => {
                    tracing::debug!(ip = %ip, from = %from, to = %to, size, id = %msgid, result = label, "post")
                }
                PostOutcome::Forwarded { .. } => tracing::debug!(
                    ip = %ip, from = %from, to = %to, size, peer = peer.as_deref().unwrap_or(""), result = label, "post"
                ),
                PostOutcome::Refused(Refusal::Invalid(kind, _)) => {
                    tracing::debug!(ip = %ip, from = %from, to = %to, size, result = "refused", reason = kind, "post")
                }
                _ => {
                    tracing::debug!(ip = %ip, from = %from, to = %to, size, result = "refused", reason = label, "post")
                }
            }
        }
        out
    }

    /// The outcome; for a forward the peer relay it is queued for; and whether the refusal is
    /// the federation allow/deny list's.
    async fn post_slate_inner(
        &self,
        ip: IpAddr,
        req: PostReq,
        allow_cancel: bool,
        scope: &mut SigScope,
    ) -> (PostOutcome, Option<String>, bool) {
        let slate = match self.check_post(ip, req, allow_cancel, scope) {
            Ok(s) => s,
            Err(r) => return (PostOutcome::Refused(r), None, false),
        };
        let local = self.cfg.is_local(&slate.dest_domain, slate.dest_port);
        if local {
            if let Some(r) = self.sender_host_refusal(&slate.from) {
                return (PostOutcome::Refused(r), None, false);
            }
        }
        if let Some(r) = self.store_full() {
            return (PostOutcome::Refused(r), None, false);
        }
        let now = now_ms();
        let expires_at = now + self.retention_ms();
        if local {
            (self.store_local(slate, now, expires_at).await, None, false)
        } else {
            let peer = format!("{}:{}", slate.dest_domain, slate.dest_port);
            if let Some((r, policy)) = self.forward_refusal_kind(&slate.dest_domain, slate.dest_port) {
                if policy {
                    static POLICY: crate::logging::KeyedGate = crate::logging::KeyedGate::new();
                    let peer = peer.to_ascii_lowercase();
                    if POLICY.admit(&peer, now_ms()).is_some() {
                        crate::sampled!(
                            warn,
                            peer = %peer,
                            "refused a post: the federation allow/deny list does not permit forwarding to this peer"
                        );
                    }
                }
                return (PostOutcome::Refused(r), Some(peer), policy);
            }
            (self.store_forward(slate, now, expires_at).await, Some(peer), false)
        }
    }

    /// Every check that needs no store: limits, sizes, addresses, signatures and the
    /// destination inside the slate.
    fn check_post(
        &self,
        ip: IpAddr,
        req: PostReq,
        allow_cancel: bool,
        scope: &mut SigScope,
    ) -> Result<Slate, Refusal> {
        let lim = &self.cfg.limits;
        let body_len = req.str_.as_ref().map(|s| s.len()).unwrap_or(0);
        self.limiter.post_ip(ip, body_len).map_err(Refusal::RateLimited)?;
        // The socket's first signed frame is not refused for failures other sockets of the prefix
        // made: that costs the sender a connection of its own.
        if !scope.first {
            if let Some(s) = self.limiter.sig_blocked(ip) {
                return Err(Refusal::RateLimited(s));
            }
        }
        if body_len > lim.max_str_bytes {
            return Err(Refusal::Invalid(
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
                (Some(Value::String(t)), Some(Value::String(s))) if is_txid(t) => (Some(t.clone()), Some(s.clone())),
                _ => return Err(Refusal::Invalid("InvalidRequest", MISSING_FIELDS.into())),
            }
        } else {
            (None, None)
        };
        if cancel_fields && (req.str_.is_none() || req.signature.is_none() || req.from.is_none() || req.to.is_none()) {
            return Err(Refusal::Invalid("InvalidRequest", MISSING_FIELDS.into()));
        }

        let wrong = || Refusal::Invalid("InvalidRequest", format!("Wrong address format. From: {from_s}, To: {to_s}"));
        let (Ok(from), Ok(to)) = (parse_address(&from_s), parse_address(&to_s)) else {
            return Err(wrong());
        };
        if !from.public_key_valid() || !to.public_key_valid() {
            return Err(wrong());
        }
        // No signature to check, so no failed one: the same answer, not counted.
        let (Some(body), Some(signature)) = (req.str_.clone(), req.signature.clone()) else {
            return Err(Refusal::Invalid("InvalidRequest", "Error postslate signature.".into()));
        };
        if sig::verify(&from.public_key, &body, &signature).is_err() {
            self.limiter.sig_failed(ip);
            scope.failed += 1;
            return Err(Refusal::Invalid("InvalidRequest", "Error postslate signature.".into()));
        }
        if let (Some(t), Some(ts)) = (&txid, &txidsig) {
            if sig::verify(&from.public_key, t, ts).is_err() {
                self.limiter.sig_failed(ip);
                scope.failed += 1;
                return Err(Refusal::Invalid("InvalidSignature", "Invalid epicboxtxid signature.".into()));
            }
        }
        self.limiter.post_addr(&from.public_key).map_err(Refusal::RateLimited)?;

        // Route by the destination inside the signed slate, as the stock relay does.
        let Ok(payload) = serde_json::from_str::<Value>(&body) else {
            return Err(Refusal::Invalid("InvalidRequest", "Invalid Slate payload.".into()));
        };
        let Some((dest_key, dest_domain, dest_port)) = destination(&payload) else {
            return Err(Refusal::Invalid("InvalidRequest", "Invalid slate destination.".into()));
        };
        Ok(Slate { from_s, to_s, from, body, signature, txid, txidsig, dest_key, dest_domain, dest_port })
    }

    /// A refusal when the host in the sender's address is in `federation.deny_sender_hosts`.
    /// Every PostSlate for a local mailbox passes here, whether the sender connected directly or
    /// another relay forwarded the slate (it keeps `from` as the wallet wrote it). The host is
    /// the sender's claim: the signature covers the slate, not the address's host part.
    fn sender_host_refusal(&self, from: &EpicboxAddress) -> Option<Refusal> {
        let host = self.cfg.denied_sender_host(from.domain.as_deref())?;
        crate::sampled!(info, host = %host, "refused a slate from a denied sender host");
        Some(Refusal::DeniedHost(format!("This relay does not accept slates from {host}.")))
    }

    /// A refusal when the store holds `store.max_bytes` of live data or more.
    fn store_full(&self) -> Option<Refusal> {
        let cap = self.cfg.store.max_bytes;
        let used = self.store.used_bytes()?;
        if cap == 0 || used < cap {
            return None;
        }
        metrics::counter!("epicbox_limit_refusals_total", "limit" => "store_bytes").increment(1);
        crate::sampled!(warn, used_bytes = used, max_bytes = cap, "store is full; refusing posts");
        Some(Refusal::Full("Relay storage is full; try again later.".into()))
    }

    /// Store a checked slate for one of this relay's mailboxes and wake its listener.
    async fn store_local(&self, slate: Slate, now: i64, expires_at: i64) -> PostOutcome {
        use PostOutcome::Refused;
        let lim = &self.cfg.limits;
        let Slate { from_s, to_s, from, body, signature, txid, txidsig, dest_key, .. } = slate;
        let remote_endpoint = endpoint_of(from.domain.as_deref(), from.port)
            .filter(|_| !self.cfg.is_local(from.domain.as_deref().unwrap_or(""), from.port.unwrap_or(443)));
        let m = NewMessage {
            queue: dest_key.clone(),
            sender: from_s,
            sender_key: from.public_key,
            recipient: to_s,
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
        match self.store.put_message(m).await {
            Ok(PutOutcome::Stored { msgid }) => {
                self.registry.wake(&dest_key);
                self.pull_waiters.wake(&dest_key);
                PostOutcome::Stored { msgid, txid }
            }
            Ok(PutOutcome::Duplicate { msgid }) => {
                // Wake anyway: the earlier copy may be waiting for a listener that just came.
                self.registry.wake(&dest_key);
                PostOutcome::Stored { msgid, txid }
            }
            Ok(PutOutcome::QueueFull) => Refused(Refusal::Full("Recipient mailbox is full; try again later.".into())),
            Ok(PutOutcome::SenderCapped) => {
                Refused(Refusal::Full("Too many messages from this sender are waiting for the recipient.".into()))
            }
            Ok(PutOutcome::Cancelled) => PostOutcome::Cancelled { txid: txid.unwrap_or_default() },
            Ok(PutOutcome::NotParticipant) => Refused(Refusal::Invalid(
                "InvalidRequest",
                "Posting address is not a participant of epicboxtxid.".into(),
            )),
            Err(e) => {
                crate::sampled!(error, error = %e, "store put_message failed");
                self.store_ok.store(false, Ordering::Relaxed);
                Refused(Refusal::Internal)
            }
        }
    }

    /// Queue a checked slate for another relay and wake the forward manager.
    async fn store_forward(&self, slate: Slate, now: i64, expires_at: i64) -> PostOutcome {
        use PostOutcome::Refused;
        let Slate { from_s, to_s, from, body, signature, txid, txidsig, dest_key, dest_domain, dest_port } = slate;
        let peer = format!("{}:{}", dest_domain.to_ascii_lowercase(), dest_port);
        if let Some(t) = &txid {
            match self.store.tx_info(t).await {
                Ok(info) if info.tombstone.is_some() => return PostOutcome::Cancelled { txid: t.clone() },
                // The same rule as for local mail: once a transaction has participants here, a
                // stranger cannot post under its txid, or the forward would link them as a
                // participant and let them cancel it.
                Ok(info) if !info.participants.is_empty() && !info.participants.contains(&from.public_key) => {
                    return Refused(Refusal::Invalid(
                        "InvalidRequest",
                        "Posting address is not a participant of epicboxtxid.".into(),
                    ));
                }
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
            tx_keys: vec![from.public_key, dest_key],
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
                crate::sampled!(error, error = %e, "store put_forward failed");
                Refused(Refusal::Internal)
            }
        }
    }

    /// Policy check for a remote destination (allow/deny lists, federation switch). Addresses are
    /// vetted again when the forward manager resolves the name.
    pub fn forward_refusal(&self, domain: &str, port: u16) -> Option<Refusal> {
        self.forward_refusal_kind(domain, port).map(|(r, _)| r)
    }

    /// `forward_refusal`, and whether the refusal comes from the allow/deny lists.
    fn forward_refusal_kind(&self, domain: &str, port: u16) -> Option<(Refusal, bool)> {
        let invalid = |d: &str| Refusal::Invalid("InvalidRequest", d.to_string());
        let fed = &self.cfg.federation;
        let d = crate::config::normalize_domain(domain).unwrap_or_default();
        let dp = format!("{d}:{port}");
        if !fed.enabled {
            return Some((invalid("This relay does not forward to other relays."), false));
        }
        let listed = |l: &Vec<String>| {
            l.iter().any(|x| {
                let x = x.strip_suffix('.').unwrap_or(x);
                x.eq_ignore_ascii_case(&d) || x.eq_ignore_ascii_case(&dp)
            })
        };
        if listed(&fed.deny) || (!fed.allow.is_empty() && !listed(&fed.allow)) {
            return Some((invalid(&format!("Forwarding to {dp} is not allowed.")), true));
        }
        if d.is_empty() || d.len() > 253 || !d.contains('.') && !fed.peers.contains_key(&dp) {
            return Some((invalid("Invalid slate destination."), false));
        }
        None
    }
}

impl Relay {
    /// True when federation policy allows forwarding to `peer` (`domain:port`). Forward rows
    /// are checked again with this before every delivery round.
    pub fn peer_allowed(&self, peer: &str) -> bool {
        match peer.rsplit_once(':').and_then(|(d, p)| Some((d, p.parse::<u16>().ok()?))) {
            Some((domain, port)) => !self.cfg.is_local(domain, port) && self.forward_refusal(domain, port).is_none(),
            None => false,
        }
    }
}

fn endpoint_of(domain: Option<&str>, port: Option<u16>) -> Option<String> {
    domain.map(|d| format!("{}:{}", d.to_ascii_lowercase(), port.unwrap_or(443)))
}

/// `destination{public_key, domain, port}` from a slate body. Port may be a number or a numeric
/// string; it defaults to 443.
fn destination(payload: &Value) -> Option<(String, String, u16)> {
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
    // `relay.example.org.` is the same host as `relay.example.org`: route both the same way, or
    // an absolute name makes this relay forward to itself and slips past `federation.deny`.
    let domain = crate::config::normalize_domain(domain)?;
    let addr = parse_address(key).ok()?;
    if addr.domain.is_some() || !addr.public_key_valid() {
        return None;
    }
    Some((addr.public_key, domain, port))
}
