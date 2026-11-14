//! mux/1: one socket holds many mailboxes, proves each with one signature over a per-socket
//! challenge, and has several messages in flight at once. The protocol is in docs/mux-1.md.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocket;
use serde_json::{json, Value};

use super::{ok, with_ref, Flow, Session};
use crate::address::parse_address;
use crate::clock::now_ms;
use crate::ids::{is_msgid, rand_b64url};
use crate::relay::{Cmd, PostOutcome, PostReq, Refusal, OFFER_LEASE_MS};
use crate::sig;
use crate::store::ClaimMode;

/// Most message ids one Ack may carry.
pub const MAX_ACK_IDS: usize = 256;
/// Longest Hold, in seconds; longer requests are clamped.
pub const HOLD_MAX_S: u64 = 3600;
/// How often every attached mailbox is checked, to catch leases that ended on other sockets.
const MUX_SWEEP: Duration = Duration::from_secs(120);
/// How often a mux/1 socket runs its timer work.
pub(super) const MUX_PUMP_TICK: Duration = Duration::from_secs(15);

/// mux/1 state of a socket.
pub(super) struct Mux {
    /// Attach signs this.
    challenge: String,
    pub(super) attached: HashSet<String>,
    /// msgid -> (row id, mailbox)
    pub(super) inflight: HashMap<String, (i64, String)>,
    /// msgid -> (mailbox, until ms)
    held: HashMap<String, (String, i64)>,
    /// Mailboxes that may have messages to send.
    pub(super) dirty: HashSet<String>,
    /// Hash of the live resume token.
    token: Option<[u8; 32]>,
    /// Attach/Resume budget window: (start, frames counted in it).
    attach_window: (Instant, u32),
    last_sweep: Instant,
}

/// A mux/1 `Error` frame. `kind` is derived from `code` so classic-style clients still read it.
pub(super) fn mux_error(code: &str, description: &str, r#ref: &Option<String>, retry_after: Option<u64>) -> Value {
    let kind = match code {
        "bad_signature" => "InvalidSignature",
        "too_many_mailboxes" => "TooManySubscriptions",
        "token_unknown" => "InvalidChallenge",
        "internal" => "UnknownError",
        _ => "InvalidRequest",
    };
    let mut v = json!({"type":"Error","kind":kind,"code":code,"description":description});
    if let Some(r) = r#ref {
        v["ref"] = json!(r);
    }
    if let Some(s) = retry_after {
        v["retry_after"] = json!(s);
    }
    v
}

/// The client's `ref`, when it is a string of at most 64 bytes.
pub(super) fn ref_of(msg: &Value) -> Option<String> {
    msg.get("ref").and_then(|r| r.as_str()).filter(|r| r.len() <= 64).map(String::from)
}

impl Session {
    /// Switch this socket to mux/1 and send the challenge and limits. False when the client's
    /// prefix is at its mux/1 socket cap; the socket then stays classic.
    pub(super) async fn upgrade_to_mux(&mut self, ws: &mut WebSocket) -> bool {
        let (_, mult) = self.relay.limiter.prefix(self.ip);
        if !self.permit.upgrade_mux(mult) {
            metrics::counter!("epicbox_limit_refusals_total", "limit" => "mux_sockets").increment(1);
            return false;
        }
        let lim = &self.relay.cfg.limits;
        let challenge = rand_b64url(16);
        let reply = json!({
            "type":"Ok","ext":["mux/1"],"challenge":challenge,
            "limits":{
                "attach_per_frame":lim.mux_attach_per_frame,
                "mailboxes_per_socket":lim.mux_mailboxes_per_socket,
                "inflight_per_socket":lim.mux_inflight,
                "hold_max_s":HOLD_MAX_S
            }
        });
        self.mux = Some(Mux {
            challenge,
            attached: HashSet::new(),
            inflight: HashMap::new(),
            held: HashMap::new(),
            dirty: HashSet::new(),
            token: None,
            attach_window: (Instant::now(), 0),
            last_sweep: Instant::now(),
        });
        metrics::counter!("epicbox_mux_sessions_total").increment(1);
        self.send(ws, reply).await;
        true
    }

    /// Dispatch one frame on a mux/1 socket.
    pub(super) async fn on_mux(&mut self, ws: &mut WebSocket, ty: &str, msg: &Value) -> Flow {
        let r#ref = ref_of(msg);
        match ty {
            "attach" => self.attach(ws, msg, &r#ref).await,
            "resume" => self.resume(ws, msg, &r#ref).await,
            "detach" => self.detach(ws, msg, &r#ref).await,
            "ack" => self.ack(ws, msg, &r#ref).await,
            "waiting" => self.waiting(ws, &r#ref).await,
            "hold" => self.hold(ws, msg, &r#ref).await,
            "postslate" => {
                let out = self.relay.post_slate(self.ip, PostReq::from_json(msg), false).await;
                let frame = match out {
                    PostOutcome::Stored { .. } | PostOutcome::Forwarded { .. } => with_ref(ok(), &r#ref),
                    PostOutcome::Cancelled { .. } => {
                        mux_error("post_refused", "Transaction was cancelled.", &r#ref, None)
                    }
                    PostOutcome::Refused(Refusal::RateLimited(s)) => {
                        mux_error("rate_limited", "Rate limit exceeded.", &r#ref, Some(s))
                    }
                    PostOutcome::Refused(Refusal::Internal) => {
                        mux_error("internal", "Internal error; try again.", &r#ref, None)
                    }
                    PostOutcome::Refused(Refusal::Invalid(_, d) | Refusal::Full(d)) => {
                        mux_error("post_refused", &d, &r#ref, None)
                    }
                };
                self.send(ws, frame).await;
            }
            "getversion" => {
                let v = json!({"type":"GetVersion","str":self.relay.cfg.protocol.getversion});
                self.send(ws, v).await;
            }
            "clientdetails" => {
                self.send(ws, with_ref(ok(), &r#ref)).await;
            }
            "subscribe" | "made" | "unsubscribe" | "challenge" => {
                self.send(ws, mux_error("classic_only", "Not allowed on a mux/1 socket.", &r#ref, None)).await;
            }
            _ => {
                self.send(ws, mux_error("unknown_type", "Unknown frame type.", &r#ref, None)).await;
            }
        }
        Flow::Continue
    }

    /// Attach/Resume budget: `mux_attach_frames_per_min` per socket, and eight times that per
    /// IP prefix, so opening more sockets does not multiply it. Err holds seconds to wait.
    fn attach_budget(&mut self) -> Result<(), u64> {
        let cap = self.relay.cfg.limits.mux_attach_frames_per_min;
        let Some(m) = self.mux.as_mut() else { return Err(60) };
        if m.attach_window.0.elapsed() >= Duration::from_secs(60) {
            m.attach_window = (Instant::now(), 0);
        }
        m.attach_window.1 += 1;
        if m.attach_window.1 > cap {
            let left = Duration::from_secs(60).saturating_sub(m.attach_window.0.elapsed());
            return Err(left.as_secs().max(1));
        }
        self.relay.limiter.attach_ip(self.ip)
    }

    /// Take a mailbox on this socket, replacing any other holder. Returns the number of
    /// messages waiting in it.
    async fn take_mailbox(&mut self, key: &str) -> Result<i64, &'static str> {
        let r = self.relay.clone();
        let cap = r.cfg.limits.mux_mailboxes_per_socket as usize;
        let m = self.mux.as_mut().expect("mux");
        if !m.attached.contains(key) {
            if m.attached.len() >= cap {
                return Err("too_many_mailboxes");
            }
            if let Some(prev) = r.registry.attach_mux(key, self.handle.clone()) {
                prev.send(Cmd::Detached { mailbox: key.to_string(), reason: "replaced" });
            }
            m.attached.insert(key.to_string());
        }
        m.dirty.insert(key.to_string());
        r.store.waiting(key, now_ms()).await.map_err(|_| "internal")
    }

    /// Attach: prove each mailbox over the socket challenge and take it.
    async fn attach(&mut self, ws: &mut WebSocket, msg: &Value, r#ref: &Option<String>) {
        let r = self.relay.clone();
        let Some(list) = msg.get("mailboxes").and_then(|m| m.as_array()) else {
            self.send(ws, mux_error("bad_frame", "Attach needs mailboxes.", r#ref, None)).await;
            return;
        };
        if list.len() > r.cfg.limits.mux_attach_per_frame as usize {
            self.send(ws, mux_error("too_many_mailboxes", "Too many mailboxes in one Attach.", r#ref, None)).await;
            return;
        }
        if let Err(wait) = self.attach_budget() {
            metrics::counter!("epicbox_limit_refusals_total", "limit" => "mux_attach").increment(1);
            self.send(ws, mux_error("rate_limited", "Too many Attach frames.", r#ref, Some(wait))).await;
            return;
        }
        if let Some(s) = r.limiter.sig_blocked(self.ip) {
            self.send(ws, mux_error("rate_limited", "Too many failed signatures.", r#ref, Some(s))).await;
            return;
        }
        let challenge = self.mux.as_ref().map(|m| m.challenge.clone()).unwrap_or_default();
        let mut out = Vec::with_capacity(list.len());
        let mut any = false;
        for e in list {
            let address = e.get("address").and_then(|a| a.as_str()).unwrap_or("");
            let signature = e.get("signature").and_then(|a| a.as_str()).unwrap_or("");
            let Some(key) = parse_address(address).ok().filter(|a| a.public_key_valid()).map(|a| a.public_key) else {
                out.push(json!({"mailbox":address,"ok":false,"code":"bad_address"}));
                continue;
            };
            if sig::verify(&key, &challenge, signature).is_err() {
                r.limiter.sig_failed(self.ip);
                out.push(json!({"mailbox":key,"ok":false,"code":"bad_signature"}));
                continue;
            }
            match self.take_mailbox(&key).await {
                Ok(waiting) => {
                    any = true;
                    out.push(json!({"mailbox":key,"ok":true,"waiting":waiting}));
                }
                Err(code) => out.push(json!({"mailbox":key,"ok":false,"code":code})),
            }
        }
        self.attached_reply(ws, out, any, r#ref).await;
    }

    /// Resume: take the mailboxes held under a token issued to an earlier socket.
    async fn resume(&mut self, ws: &mut WebSocket, msg: &Value, r#ref: &Option<String>) {
        let Some(token) = msg.get("token").and_then(|t| t.as_str()) else {
            self.send(ws, mux_error("bad_frame", "Resume needs a token.", r#ref, None)).await;
            return;
        };
        if let Err(wait) = self.attach_budget() {
            metrics::counter!("epicbox_limit_refusals_total", "limit" => "mux_attach").increment(1);
            self.send(ws, mux_error("rate_limited", "Too many Resume frames.", r#ref, Some(wait))).await;
            return;
        }
        let Some(set) = self.relay.take_token(token) else {
            self.send(ws, mux_error("token_unknown", "Token unknown, used or expired.", r#ref, None)).await;
            return;
        };
        let mut out = Vec::with_capacity(set.len());
        for key in set {
            match self.take_mailbox(&key).await {
                Ok(waiting) => {
                    out.push(json!({"mailbox":key,"ok":true,"waiting":waiting}));
                }
                Err(code) => out.push(json!({"mailbox":key,"ok":false,"code":code})),
            }
        }
        metrics::counter!("epicbox_mux_resumes_total").increment(1);
        // A resumed empty set still gets a token, so the session can go on.
        self.attached_reply(ws, out, true, r#ref).await;
    }

    /// Answer Attach or Resume, with a new token when `issue` is set, then deliver.
    async fn attached_reply(&mut self, ws: &mut WebSocket, out: Vec<Value>, issue: bool, r#ref: &Option<String>) {
        let mut reply = json!({"type":"Attached","mailboxes":out});
        if let Some(r) = r#ref {
            reply["ref"] = json!(r);
        }
        if issue {
            let m = self.mux.as_mut().expect("mux");
            let set: Vec<String> = m.attached.iter().cloned().collect();
            let (token, hash, expires) = self.relay.issue_token(m.token, set);
            m.token = Some(hash);
            reply["token"] = json!(token);
            reply["token_expires"] = json!(expires);
        }
        self.send(ws, reply).await;
        self.pump(ws).await;
    }

    /// Keep the mailbox set of the live token equal to the attached set.
    fn sync_token(&self) {
        if let Some(m) = &self.mux {
            if let Some(h) = &m.token {
                self.relay.update_token(h, m.attached.iter().cloned().collect());
            }
        }
    }

    /// Release in-flight messages of `key` on this socket.
    async fn drop_inflight(&mut self, key: &str) {
        let Some(m) = self.mux.as_mut() else { return };
        let ids: Vec<i64> = m.inflight.values().filter(|(_, k)| k == key).map(|(id, _)| *id).collect();
        m.inflight.retain(|_, (_, k)| k != key);
        m.held.retain(|_, (k, _)| k != key);
        m.dirty.remove(key);
        if !ids.is_empty() {
            let _ = self.relay.store.release(ids).await;
        }
    }

    /// Detach: give mailboxes up so other listeners can collect them.
    async fn detach(&mut self, ws: &mut WebSocket, msg: &Value, r#ref: &Option<String>) {
        let Some(list) = msg.get("mailboxes").and_then(|m| m.as_array()) else {
            self.send(ws, mux_error("bad_frame", "Detach needs mailboxes.", r#ref, None)).await;
            return;
        };
        // A socket never holds more than this, and each entry costs an address parse.
        if list.len() > self.relay.cfg.limits.mux_mailboxes_per_socket as usize {
            self.send(ws, mux_error("too_many_mailboxes", "Too many mailboxes in one Detach.", r#ref, None)).await;
            return;
        }
        let keys: Vec<String> = list
            .iter()
            .filter_map(|a| a.as_str())
            .filter_map(|a| parse_address(a).ok().map(|a| a.public_key))
            .collect();
        for k in keys {
            let had = self.mux.as_mut().map(|m| m.attached.remove(&k)).unwrap_or(false);
            if had {
                self.relay.registry.detach_mux(&k, self.id);
                self.drop_inflight(&k).await;
                self.relay.registry.wake(&k);
            }
        }
        self.sync_token();
        self.send(ws, with_ref(ok(), r#ref)).await;
    }

    /// Another socket took `key`.
    pub(super) async fn mux_lost(&mut self, ws: &mut WebSocket, key: &str, reason: &'static str) {
        let had = self.mux.as_mut().map(|m| m.attached.remove(key)).unwrap_or(false);
        if !had {
            return;
        }
        self.drop_inflight(key).await;
        self.sync_token();
        self.send(ws, json!({"type":"Detached","mailbox":key,"reason":reason})).await;
        // The new holder may have found these leased.
        self.relay.registry.wake(key);
    }

    /// Ack: delete delivered messages and free their in-flight slots.
    async fn ack(&mut self, ws: &mut WebSocket, msg: &Value, r#ref: &Option<String>) {
        let Some(ids) = msg.get("ids").and_then(|m| m.as_array()) else {
            self.send(ws, mux_error("bad_frame", "Ack needs ids.", r#ref, None)).await;
            return;
        };
        if ids.len() > MAX_ACK_IDS {
            self.send(ws, mux_error("bad_frame", "At most 256 ids per Ack.", r#ref, None)).await;
            return;
        }
        let ids: Vec<String> =
            ids.iter().filter_map(|i| i.as_str()).filter(|i| is_msgid(i)).map(String::from).collect();
        let attached: Vec<String> = self.mux.as_ref().map(|m| m.attached.iter().cloned().collect()).unwrap_or_default();
        if !ids.is_empty() && !attached.is_empty() {
            match self.relay.store.made_in(attached, ids.clone()).await {
                Ok(n) => metrics::counter!("epicbox_made_total", "mode" => "mux").increment(n),
                Err(e) => {
                    tracing::error!(error = %e, "ack failed");
                    self.send(ws, mux_error("internal", "Internal error; try again.", r#ref, None)).await;
                    return;
                }
            }
        }
        if let Some(m) = self.mux.as_mut() {
            for id in &ids {
                if let Some((_, k)) = m.inflight.remove(id) {
                    m.dirty.insert(k);
                }
            }
        }
        self.send(ws, with_ref(ok(), r#ref)).await;
        self.pump(ws).await;
    }

    /// Hold: delay an in-flight message by 1 to `HOLD_MAX_S` seconds.
    async fn hold(&mut self, ws: &mut WebSocket, msg: &Value, r#ref: &Option<String>) {
        let id = msg.get("id").and_then(|i| i.as_str());
        let secs = msg.get("seconds").and_then(|s| s.as_u64());
        let (Some(id), Some(secs)) = (id, secs) else {
            self.send(ws, mux_error("bad_frame", "Hold needs id and seconds.", r#ref, None)).await;
            return;
        };
        let secs = secs.clamp(1, HOLD_MAX_S);
        let Some((_, key)) = self.mux.as_ref().and_then(|m| m.inflight.get(id).cloned()) else {
            self.send(ws, mux_error("unknown_id", "That id is not in flight on this socket.", r#ref, None)).await;
            return;
        };
        let until = now_ms() + secs as i64 * 1000;
        match self.relay.store.hold(&key, id, until).await {
            Ok(_) => {
                if let Some(m) = self.mux.as_mut() {
                    m.inflight.remove(id);
                    m.held.insert(id.to_string(), (key.clone(), until));
                    m.dirty.insert(key);
                }
                self.send(ws, with_ref(ok(), r#ref)).await;
                self.pump(ws).await;
            }
            Err(_) => {
                self.send(ws, mux_error("internal", "Internal error; try again.", r#ref, None)).await;
            }
        }
    }

    /// Waiting: message counts per attached mailbox.
    async fn waiting(&mut self, ws: &mut WebSocket, r#ref: &Option<String>) {
        let Some(m) = self.mux.as_ref() else { return };
        let keys: Vec<String> = m.attached.iter().cloned().collect();
        let inflight = m.inflight.len();
        let now = now_ms();
        let held = m.held.values().filter(|(_, u)| *u > now).count();
        let mut w = serde_json::Map::new();
        for k in keys {
            match self.relay.store.waiting(&k, now).await {
                Ok(n) => {
                    w.insert(k, json!(n));
                }
                Err(_) => {
                    self.send(ws, mux_error("internal", "Internal error; try again.", r#ref, None)).await;
                    return;
                }
            }
        }
        let v = with_ref(json!({"type":"Ok","waiting":w,"inflight":inflight,"held":held}), r#ref);
        self.send(ws, v).await;
    }

    /// How long until the first hold on this socket ends, if any.
    pub(super) fn next_hold_end(&self) -> Option<Duration> {
        let first = self.mux.as_ref()?.held.values().map(|(_, until)| *until).min()?;
        Some(Duration::from_millis(first.saturating_sub(now_ms()).max(0) as u64))
    }

    /// Timer work: end holds that are due and, every `MUX_SWEEP`, mark every attached
    /// mailbox for a look.
    pub(super) async fn mux_timer(&mut self, ws: &mut WebSocket) {
        let now = now_ms();
        let Some(m) = self.mux.as_mut() else { return };
        // Holds that ended put their mailbox back on the list.
        let ended: Vec<String> = m.held.iter().filter(|(_, (_, u))| *u <= now).map(|(id, _)| id.clone()).collect();
        for id in ended {
            if let Some((k, _)) = m.held.remove(&id) {
                m.dirty.insert(k);
            }
        }
        // Rarely, look at every mailbox: catches leases that ended on other sockets.
        if m.last_sweep.elapsed() >= MUX_SWEEP {
            m.last_sweep = Instant::now();
            let all: Vec<String> = m.attached.iter().cloned().collect();
            m.dirty.extend(all);
        }
        self.pump(ws).await;
    }

    /// Push Mail for dirty mailboxes while in-flight slots are free.
    pub(super) async fn pump(&mut self, ws: &mut WebSocket) {
        let r = self.relay.clone();
        let cap = r.cfg.limits.mux_inflight as usize;
        loop {
            let Some(m) = self.mux.as_mut() else { return };
            let free = cap.saturating_sub(m.inflight.len());
            if free == 0 {
                return;
            }
            let Some(key) = m.dirty.iter().next().cloned() else { return };
            m.dirty.remove(&key);
            if !m.attached.contains(&key) || r.is_stalled(&key) {
                continue;
            }
            let exclude: Vec<i64> = m.inflight.values().filter(|(_, k)| *k == key).map(|(id, _)| *id).collect();
            let got =
                match r.store.claim(&key, now_ms(), free, exclude, ClaimMode::Offer { lease_ms: OFFER_LEASE_MS }).await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error = %e, "mux claim failed");
                        return;
                    }
                };
            let full = got.len() == free;
            for msg in got {
                let frame = json!({
                    "type":"Mail","mailbox":key,"id":msg.msgid,"from":msg.sender,
                    "str":msg.body,"signature":msg.signature,"created":msg.created_at / 1000
                });
                if let Some(m) = self.mux.as_mut() {
                    m.inflight.insert(msg.msgid.clone(), (msg.id, key.clone()));
                }
                metrics::counter!("epicbox_deliveries_total", "mode" => "mux").increment(1);
                if !self.send(ws, frame).await {
                    return;
                }
            }
            if full {
                if let Some(m) = self.mux.as_mut() {
                    m.dirty.insert(key);
                }
            }
        }
    }
}
