//! One task per websocket. A socket starts in Epicbox 3.0.0 mode (classic) and may switch to
//! mux/1 with `ClientDetails{ext:["mux/1"]}` before its first Subscribe.
//!
//! Classic rules follow the stock relay frame by frame (see docs/compat.md), with these fixes:
//! a Subscribe signed over the previous challenge is still accepted (the interval Challenge raced
//! it), the message in flight is leased instead of blocking the mailbox, a watchdog closes
//! sockets that stop answering Challenges while mail waits, and malformed frames cannot crash
//! anything. Classic sockets never receive a frame type the classic wallet cannot parse.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio::time::{interval_at, MissedTickBehavior};

use super::{CancelOutcome, Cmd, PostOutcome, PostReq, Refusal, Relay, SockHandle, OFFER_LEASE_MS};
use crate::address::parse_address;
use crate::config::FirstChallenge;
use crate::limits::SocketPermit;
use crate::sig;
use crate::store::{ClaimMode, StoredMessage};
use crate::util::{is_msgid, now_ms, rand_b64url, rand_id};

/// The stock relay's fixed first challenge. Wallets older than 3.5.2 sign it.
pub const STATIC_CHALLENGE: &str = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";
const MUX_SWEEP: Duration = Duration::from_secs(120);
const MUX_PUMP_TICK: Duration = Duration::from_secs(15);
const MAX_ACK_IDS: usize = 256;
const HOLD_MAX_S: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Ver {
    /// No `ver` in Subscribe: pre-2.0.0 wallets, no Made.
    Legacy,
    V2,
    V3,
    V31,
}

impl Ver {
    fn as_str(self) -> &'static str {
        match self {
            Ver::Legacy => "",
            Ver::V2 => "2.0.0",
            Ver::V3 => "3.0.0",
            Ver::V31 => "3.1.0",
        }
    }
}

struct Inflight {
    id: i64,
}

struct Mux {
    challenge: String,
    attached: HashSet<String>,
    /// msgid -> (row id, mailbox)
    inflight: HashMap<String, (i64, String)>,
    /// msgid -> (mailbox, until ms)
    held: HashMap<String, (String, i64)>,
    dirty: HashSet<String>,
    token: Option<[u8; 32]>,
    attach_window: (Instant, u32),
    last_sweep: Instant,
}

enum Flow {
    Continue,
    Close(u16, &'static str),
}

pub struct Session {
    relay: Arc<Relay>,
    id: u64,
    ip: IpAddr,
    permit: SocketPermit,
    handle: SockHandle,
    // classic
    challenge: String,
    prev_challenge: Option<String>,
    ver: Option<Ver>,
    key: Option<String>,
    details_seen: bool,
    inflight: Option<Inflight>,
    attempts: u32,
    rounds: u32,
    pending_challenge: bool,
    last_sub: Instant,
    misses: u32,
    pending_cancel_ack: Option<String>,
    // mux
    mux: Option<Mux>,
    // limits
    frames: (Instant, u32),
    last_seen: Instant,
}

pub async fn run(relay: Arc<Relay>, ws: WebSocket, ip: IpAddr, permit: SocketPermit) {
    let (tx, rx) = mpsc::channel(256);
    let id = relay.next_socket_id();
    let handle = SockHandle { id, tx, cancel: false };
    let mut s = Session {
        relay,
        id,
        ip,
        permit,
        handle,
        challenge: String::new(),
        prev_challenge: None,
        ver: None,
        key: None,
        details_seen: false,
        inflight: None,
        attempts: 0,
        rounds: 0,
        pending_challenge: false,
        last_sub: Instant::now(),
        misses: 0,
        pending_cancel_ack: None,
        mux: None,
        frames: (Instant::now(), 0),
        last_seen: Instant::now(),
    };
    metrics::gauge!("epicbox_sockets").increment(1.0);
    s.serve(ws, rx).await;
    s.cleanup().await;
    metrics::gauge!("epicbox_sockets").decrement(1.0);
}

fn text(v: &Value) -> Message {
    Message::Text(Utf8Bytes::from(v.to_string()))
}

fn ok() -> Value {
    json!({"type":"Ok"})
}

fn mux_error(code: &str, description: &str, r#ref: &Option<String>, retry_after: Option<u64>) -> Value {
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

fn with_ref(mut v: Value, r#ref: &Option<String>) -> Value {
    if let Some(r) = r#ref {
        v["ref"] = json!(r);
    }
    v
}

impl Session {
    async fn send(&self, ws: &mut WebSocket, v: Value) -> bool {
        metrics::counter!("epicbox_frames_out_total").increment(1);
        ws.send(text(&v)).await.is_ok()
    }

    async fn serve(&mut self, mut ws: WebSocket, mut rx: mpsc::Receiver<Cmd>) {
        let p = &self.relay.cfg.protocol;
        let challenge_every = Duration::from_secs(p.challenge_interval_s);
        let ping_every = Duration::from_secs(p.ping_interval_s.max(1));
        let idle = Duration::from_secs(p.idle_timeout_s.max(p.ping_interval_s + 1));
        let mut challenge_tick = interval_at(tokio::time::Instant::now() + challenge_every, challenge_every);
        challenge_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut ping_tick = interval_at(tokio::time::Instant::now() + ping_every, ping_every);
        ping_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut pump_tick = interval_at(tokio::time::Instant::now() + MUX_PUMP_TICK, MUX_PUMP_TICK);
        pump_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut shutdown = self.relay.shutdown.subscribe();

        // First Challenge, as the stock relay sends on connect.
        self.challenge = match p.first_challenge {
            FirstChallenge::Static => STATIC_CHALLENGE.to_string(),
            FirstChallenge::Random => rand_id(32),
        };
        self.pending_challenge = true;
        let first = json!({"type":"Challenge","str":self.challenge});
        if !self.send(&mut ws, first).await {
            return;
        }

        let flow = loop {
            tokio::select! {
                m = ws.recv() => {
                    let Some(Ok(m)) = m else { break Flow::Continue };
                    self.last_seen = Instant::now();
                    let f = match m {
                        Message::Text(t) => self.on_text(&mut ws, t.as_str()).await,
                        Message::Binary(b) => match std::str::from_utf8(&b) {
                            Ok(t) => { let t = t.to_string(); self.on_text(&mut ws, &t).await }
                            Err(_) => self.bad_json(&mut ws).await,
                        },
                        Message::Close(_) => break Flow::Continue,
                        _ => Flow::Continue,
                    };
                    if let Flow::Close(..) = f { break f; }
                }
                c = rx.recv() => {
                    let Some(c) = c else { break Flow::Continue };
                    let f = self.on_cmd(&mut ws, c).await;
                    if let Flow::Close(..) = f { break f; }
                }
                _ = challenge_tick.tick(), if self.mux.is_none() => {
                    let f = self.on_challenge_tick(&mut ws).await;
                    if let Flow::Close(..) = f { break f; }
                }
                _ = ping_tick.tick() => {
                    if self.last_seen.elapsed() > idle {
                        break Flow::Close(1001, "Idle timeout.");
                    }
                    if ws.send(Message::Ping(Default::default())).await.is_err() {
                        break Flow::Continue;
                    }
                }
                _ = pump_tick.tick(), if self.mux.is_some() => {
                    self.mux_timer(&mut ws).await;
                }
                _ = shutdown.changed() => {
                    if let Some(m) = &self.mux {
                        let keys: Vec<String> = m.attached.iter().cloned().collect();
                        for k in keys {
                            let _ = self.send(&mut ws, json!({"type":"Detached","mailbox":k,"reason":"shutdown"})).await;
                        }
                    }
                    break Flow::Close(1001, "Relay restarting.");
                }
            }
        };
        if let Flow::Close(code, reason) = flow {
            let _ = ws
                .send(Message::Close(Some(CloseFrame { code, reason: Utf8Bytes::from_static(reason) })))
                .await;
        }
    }

    async fn cleanup(&mut self) {
        let r = &self.relay;
        let mut release = Vec::new();
        let mut wake = Vec::new();
        if let Some(k) = &self.key {
            r.registry.unsubscribe_classic(k, self.id);
            if let Some(i) = self.inflight.take() {
                release.push(i.id);
                wake.push(k.clone());
            }
        }
        if let Some(m) = self.mux.take() {
            for k in &m.attached {
                r.registry.detach_mux(k, self.id);
                wake.push(k.clone());
            }
            release.extend(m.inflight.values().map(|(id, _)| *id));
        }
        if !release.is_empty() {
            if let Err(e) = r.store.release(release).await {
                tracing::warn!(error = %e, "release on close failed");
            }
        }
        for k in wake {
            r.registry.wake(&k);
        }
    }

    // ---- inbound ---------------------------------------------------------------------------

    fn frame_budget(&mut self) -> bool {
        let cap = self.relay.cfg.limits.frames_per_min_per_socket;
        if self.frames.0.elapsed() >= Duration::from_secs(60) {
            self.frames = (Instant::now(), 0);
        }
        self.frames.1 += 1;
        self.frames.1 <= cap
    }

    async fn bad_json(&mut self, ws: &mut WebSocket) -> Flow {
        if self.mux.is_some() {
            self.send(ws, mux_error("bad_frame", "Frame is not a JSON object.", &None, None)).await;
            Flow::Continue
        } else {
            Flow::Close(3000, "Error parsing message.")
        }
    }

    async fn on_text(&mut self, ws: &mut WebSocket, t: &str) -> Flow {
        metrics::counter!("epicbox_frames_in_total").increment(1);
        if !self.frame_budget() {
            return Flow::Close(1008, "Too many frames.");
        }
        let Ok(msg) = serde_json::from_str::<Value>(t) else {
            return self.bad_json(ws).await;
        };
        let Some(ty) = msg.get("type").and_then(|t| t.as_str()).map(|t| t.to_ascii_lowercase()) else {
            if self.mux.is_some() {
                let r = ref_of(&msg);
                self.send(ws, mux_error("bad_frame", "Frame has no type.", &r, None)).await;
            }
            return Flow::Continue;
        };
        if self.mux.is_some() {
            return self.on_mux(ws, &ty, &msg).await;
        }
        match ty.as_str() {
            // Stock behaviour: answer a JSON ping with the bare text.
            "ping" => {
                let _ = ws.send(Message::Text(Utf8Bytes::from_static("pong"))).await;
            }
            "pong" => {
                let _ = ws.send(Message::Text(Utf8Bytes::from_static("ping"))).await;
            }
            "challenge" => self.new_challenge(ws).await,
            "subscribe" => return self.subscribe(ws, &msg).await,
            "unsubscribe" => return Flow::Close(1000, "Work complete."),
            "postslate" => self.post(ws, &msg).await,
            "made" => self.made(ws, &msg).await,
            "canceltx" if self.relay.cfg.protocol.cancel => self.cancel(ws, &msg).await,
            "getversion" => {
                let v = json!({"type":"GetVersion","str":self.relay.cfg.protocol.getversion});
                self.send(ws, v).await;
            }
            "fastsend" => {
                self.send(ws, ok()).await;
            }
            "clientdetails" => self.client_details(ws, &msg).await,
            _ => {}
        }
        Flow::Continue
    }

    async fn on_cmd(&mut self, ws: &mut WebSocket, c: Cmd) -> Flow {
        match c {
            Cmd::Close { code, reason } => return Flow::Close(code, reason),
            Cmd::Wake(k) => {
                if self.mux.is_some() {
                    if let Some(m) = self.mux.as_mut() {
                        if m.attached.contains(&k) {
                            m.dirty.insert(k);
                        }
                    }
                    self.pump(ws).await;
                } else {
                    self.push(ws).await;
                }
            }
            Cmd::Detached { mailbox, reason } => self.mux_lost(ws, &mailbox, reason).await,
            Cmd::Cancelled { txid } => {
                if self.ver == Some(Ver::V31) && self.key.is_some() {
                    self.inflight = None;
                    self.attempts = 0;
                    self.send(ws, json!({"type":"TransactionCancelled","epicboxtxid":txid})).await;
                    self.pending_cancel_ack = Some(txid);
                }
            }
        }
        Flow::Continue
    }

    // ---- classic ---------------------------------------------------------------------------

    async fn new_challenge(&mut self, ws: &mut WebSocket) {
        let fresh = match self.ver {
            None | Some(Ver::V2) | Some(Ver::Legacy)
                if self.relay.cfg.protocol.first_challenge == FirstChallenge::Static =>
            {
                STATIC_CHALLENGE.to_string()
            }
            _ => rand_id(32),
        };
        let old = std::mem::replace(&mut self.challenge, fresh);
        if old != self.challenge {
            self.prev_challenge = Some(old);
        }
        self.pending_challenge = true;
        let v = json!({"type":"Challenge","str":self.challenge});
        self.send(ws, v).await;
    }

    async fn on_challenge_tick(&mut self, ws: &mut WebSocket) -> Flow {
        let Some(key) = self.key.clone() else { return Flow::Continue };
        if self.relay.is_stalled(&key) {
            return Flow::Continue;
        }
        let interval = Duration::from_secs(self.relay.cfg.protocol.challenge_interval_s);
        if self.pending_challenge {
            // The last Challenge was not answered. Count it if mail is waiting.
            let waiting = self.inflight.is_some()
                || self.relay.store.has_offerable(&key, now_ms(), vec![]).await.unwrap_or(false);
            if waiting {
                self.misses += 1;
                if self.misses >= self.relay.cfg.protocol.watchdog_misses.max(1) {
                    metrics::counter!("epicbox_watchdog_closes_total").increment(1);
                    return Flow::Close(1001, "Delivery stalled; reconnect.");
                }
            }
            if self.last_sub.elapsed() < interval {
                return Flow::Continue;
            }
        }
        self.new_challenge(ws).await;
        Flow::Continue
    }

    async fn client_details(&mut self, ws: &mut WebSocket, msg: &Value) {
        self.details_seen = true;
        let wants_mux = msg
            .get("ext")
            .and_then(|e| e.as_array())
            .map(|a| a.iter().any(|x| x.as_str() == Some("mux/1")))
            .unwrap_or(false);
        let cfg = &self.relay.cfg;
        if wants_mux && cfg.protocol.mux && self.key.is_none() {
            let (_, mult) = self.relay.limiter.prefix(self.ip);
            if self.permit.upgrade_mux(mult) {
                let challenge = rand_b64url(16);
                let reply = json!({
                    "type":"Ok","ext":["mux/1"],"challenge":challenge,
                    "limits":{
                        "attach_per_frame":cfg.limits.mux_attach_per_frame,
                        "mailboxes_per_socket":cfg.limits.mux_mailboxes_per_socket,
                        "inflight_per_socket":cfg.limits.mux_inflight,
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
                return;
            }
            // Over the mux/1 socket cap for this prefix: stay 3.0.0.
            metrics::counter!("epicbox_limit_refusals_total", "limit" => "mux_sockets").increment(1);
        }
        self.send(ws, ok()).await;
    }

    async fn subscribe(&mut self, ws: &mut WebSocket, msg: &Value) -> Flow {
        let r = self.relay.clone();
        if let Some(v) = msg.get("ver") {
            self.ver = Some(match v.as_str() {
                Some("2.0.0") => Ver::V2,
                Some("3.1.0") if r.cfg.protocol.cancel => Ver::V31,
                _ => Ver::V3,
            });
        }
        let invalid = json!({"type":"Error","kind":"InvalidSignature","description":"Invalid signature."});
        if let Some(s) = r.limiter.sig_blocked(self.ip) {
            let e = Refusal::RateLimited(s).classic_frame();
            self.send(ws, e).await;
            return Flow::Continue;
        }
        let address = msg.get("address").and_then(|a| a.as_str()).unwrap_or("");
        let signature = msg.get("signature").and_then(|a| a.as_str()).unwrap_or("");
        let key = parse_address(address).ok().filter(|a| a.public_key_valid()).map(|a| a.public_key);
        let verified = key.as_ref().is_some_and(|k| {
            sig::verify(k, &self.challenge, signature).is_ok()
                || self.prev_challenge.as_ref().is_some_and(|p| sig::verify(k, p, signature).is_ok())
        });
        let Some(key) = key.filter(|_| verified) else {
            r.limiter.sig_failed(self.ip);
            metrics::counter!("epicbox_subscribe_total", "result" => "bad_signature").increment(1);
            if let Some(k) = self.key.take() {
                r.registry.unsubscribe_classic(&k, self.id);
            }
            self.send(ws, invalid).await;
            return Flow::Continue;
        };
        metrics::counter!("epicbox_subscribe_total", "result" => "ok").increment(1);
        self.prev_challenge = None;

        // 3.1.0: a successful Subscribe acknowledges the TransactionCancelled sent before it.
        if let (Some(t), Some(k)) = (self.pending_cancel_ack.take(), self.key.as_ref()) {
            if r.store.ack_cancel(k, &t).await.is_err() {
                let e = json!({"type":"Error","kind":"InvalidRequest","description":"Unable to acknowledge cancellation."});
                self.send(ws, e).await;
                return Flow::Continue;
            }
        }

        if self.key.as_deref() != Some(key.as_str()) {
            if let Some(old) = self.key.take() {
                r.registry.unsubscribe_classic(&old, self.id);
                if let Some(i) = self.inflight.take() {
                    let _ = r.store.release(vec![i.id]).await;
                }
            }
            self.handle.cancel = self.ver == Some(Ver::V31);
            let evicted = r.registry.subscribe_classic(
                &key,
                self.handle.clone(),
                r.cfg.limits.sockets_per_address as usize,
            );
            for h in evicted {
                h.send(Cmd::Close { code: 4001, reason: "Too many connections for this address." });
            }
            self.key = Some(key.clone());
        } else if self.handle.cancel != (self.ver == Some(Ver::V31)) {
            self.handle.cancel = self.ver == Some(Ver::V31);
            r.registry.subscribe_classic(&key, self.handle.clone(), r.cfg.limits.sockets_per_address as usize);
        }
        self.last_sub = Instant::now();
        self.pending_challenge = false;
        self.misses = 0;

        // Redelivery after three Subscribes without Made, at most three rounds; then the message
        // steps aside (the store orders it after the others) instead of being deleted.
        if self.attempts >= 3 {
            self.attempts = 0;
            self.rounds += 1;
            if let Some(i) = self.inflight.take() {
                let _ = r.store.release(vec![i.id]).await;
            }
        }
        self.deliver(ws, true).await;
        Flow::Continue
    }

    /// Send the next message (or, on Subscribe, `Ok` when there is none).
    async fn deliver(&mut self, ws: &mut WebSocket, on_subscribe: bool) {
        let r = self.relay.clone();
        let Some(key) = self.key.clone() else { return };
        let ver = self.ver.unwrap_or(Ver::Legacy);
        if ver == Ver::V31 {
            match r.store.pending_cancel(&key).await {
                Ok(Some(txid)) => {
                    self.inflight = None;
                    self.attempts = 0;
                    self.send(ws, json!({"type":"TransactionCancelled","epicboxtxid":txid})).await;
                    self.pending_cancel_ack = Some(txid);
                    return;
                }
                Ok(None) => {}
                Err(_) => {
                    if on_subscribe {
                        self.send(ws, ok()).await;
                    }
                    return;
                }
            }
        }
        if self.inflight.is_some() {
            if on_subscribe {
                self.attempts += 1;
                self.send(ws, ok()).await;
            }
            return;
        }
        if r.is_stalled(&key) {
            if on_subscribe {
                self.send(ws, ok()).await;
            }
            return;
        }
        let mode = if ver == Ver::Legacy { ClaimMode::Consume } else { ClaimMode::Offer { lease_ms: OFFER_LEASE_MS } };
        let claimed = r.store.claim(&key, now_ms(), 1, vec![], mode).await;
        match claimed {
            Ok(mut v) if !v.is_empty() => {
                let m = v.remove(0);
                let frame = self.slate_frame(&m, ver);
                if ver != Ver::Legacy {
                    self.inflight = Some(Inflight { id: m.id });
                }
                metrics::counter!("epicbox_deliveries_total", "mode" => "classic").increment(1);
                self.send(ws, frame).await;
            }
            Ok(_) => {
                if on_subscribe {
                    self.send(ws, ok()).await;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "claim failed");
                if on_subscribe {
                    self.send(ws, ok()).await;
                }
            }
        }
    }

    fn slate_frame(&self, m: &StoredMessage, ver: Ver) -> Value {
        let mut f = json!({
            "type":"Slate","from":m.sender,"str":m.body,"signature":m.signature,"challenge":m.challenge
        });
        if ver != Ver::Legacy {
            f["epicboxmsgid"] = json!(m.msgid);
            f["ver"] = json!(ver.as_str());
        }
        if ver == Ver::V31 {
            if let Some(t) = &m.txid {
                f["epicboxtxid"] = json!(t);
            }
        }
        f
    }

    /// Push on Wake: only to a subscribed 2.0.0+ socket with nothing in flight.
    async fn push(&mut self, ws: &mut WebSocket) {
        if self.key.is_none() || matches!(self.ver, None | Some(Ver::Legacy)) || self.inflight.is_some() {
            return;
        }
        self.deliver(ws, false).await;
    }

    async fn made(&mut self, ws: &mut WebSocket, msg: &Value) {
        let r = self.relay.clone();
        let Some(key) = self.key.clone() else { return };
        let Some(msgid) = msg.get("epicboxmsgid").and_then(|m| m.as_str()) else { return };
        let ver = match msg.get("ver").and_then(|v| v.as_str()) {
            Some("2.0.0") => Ver::V2,
            Some("3.0.0") => Ver::V3,
            Some("3.1.0") if r.cfg.protocol.cancel => Ver::V31,
            // The stock relay ignores other Made frames without an answer.
            _ => return,
        };
        let signature = msg.get("signature").and_then(|s| s.as_str()).unwrap_or("");
        let signed = if ver == Ver::V2 { self.challenge.as_str() } else { msgid };
        let ok_sig = sig::verify(&key, signed, signature).is_ok()
            || (ver == Ver::V2 && self.prev_challenge.as_ref().is_some_and(|p| sig::verify(&key, p, signature).is_ok()));
        if !ok_sig {
            r.limiter.sig_failed(self.ip);
            self.send(ws, json!({"type":"Error","kind":"InvalidSignature","description":"Invalid signature."})).await;
            return;
        }
        if !is_msgid(msgid) {
            self.send(ws, ok()).await;
            return;
        }
        if let Err(e) = r.store.made(&key, vec![msgid.to_string()]).await {
            tracing::error!(error = %e, "made failed");
            self.send(ws, json!({"type":"Error","kind":"UnknownError","description":"Internal error; try again."})).await;
            return;
        }
        metrics::counter!("epicbox_made_total", "mode" => "classic").increment(1);
        self.send(ws, ok()).await;
        self.inflight = None;
        self.attempts = 0;
        self.rounds = 0;
        self.new_challenge(ws).await;
    }

    async fn post(&mut self, ws: &mut WebSocket, msg: &Value) {
        let req = PostReq::from_json(msg);
        let out = self.relay.post_slate(self.ip, req, true).await;
        let frame = match out {
            PostOutcome::Stored { msgid, txid } => match txid {
                Some(t) => json!({"type":"Ok","epicboxmsgid":msgid,"epicboxtxid":t}),
                None => ok(),
            },
            PostOutcome::Forwarded { txid } => match txid {
                Some(t) => json!({"type":"Ok","epicboxtxid":t}),
                None => ok(),
            },
            PostOutcome::Cancelled { txid } => json!({"type":"TransactionCancelled","epicboxtxid":txid}),
            PostOutcome::Refused(r) => r.classic_frame(),
        };
        self.send(ws, frame).await;
    }

    async fn cancel(&mut self, ws: &mut WebSocket, msg: &Value) {
        let key = self.key.clone();
        let out = self.relay.cancel_tx(self.ip, key.as_deref(), msg).await;
        let frame = match out {
            CancelOutcome::Cancelled(t) => json!({"type":"TransactionCancelled","epicboxtxid":t}),
            CancelOutcome::Ok => ok(),
            CancelOutcome::Refused(r) => r.classic_frame(),
        };
        self.send(ws, frame).await;
    }

    // ---- mux/1 -----------------------------------------------------------------------------

    async fn on_mux(&mut self, ws: &mut WebSocket, ty: &str, msg: &Value) -> Flow {
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

    /// Per-socket Attach/Resume budget.
    fn attach_budget(&mut self) -> bool {
        let cap = self.relay.cfg.limits.mux_attach_frames_per_min;
        let Some(m) = self.mux.as_mut() else { return false };
        if m.attach_window.0.elapsed() >= Duration::from_secs(60) {
            m.attach_window = (Instant::now(), 0);
        }
        m.attach_window.1 += 1;
        m.attach_window.1 <= cap
    }

    /// Take a mailbox on this socket. Returns `waiting`.
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
        if !self.attach_budget() {
            self.send(ws, mux_error("rate_limited", "Too many Attach frames.", r#ref, Some(60))).await;
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
            let Some(key) = parse_address(address).ok().filter(|a| a.public_key_valid()).map(|a| a.public_key)
            else {
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

    async fn resume(&mut self, ws: &mut WebSocket, msg: &Value, r#ref: &Option<String>) {
        let Some(token) = msg.get("token").and_then(|t| t.as_str()) else {
            self.send(ws, mux_error("bad_frame", "Resume needs a token.", r#ref, None)).await;
            return;
        };
        if !self.attach_budget() {
            self.send(ws, mux_error("rate_limited", "Too many Resume frames.", r#ref, Some(60))).await;
            return;
        }
        let Some(set) = self.relay.take_token(token) else {
            self.send(ws, mux_error("token_unknown", "Token unknown, used or expired.", r#ref, None)).await;
            return;
        };
        let mut out = Vec::with_capacity(set.len());
        let mut any = false;
        for key in set {
            match self.take_mailbox(&key).await {
                Ok(waiting) => {
                    any = true;
                    out.push(json!({"mailbox":key,"ok":true,"waiting":waiting}));
                }
                Err(code) => out.push(json!({"mailbox":key,"ok":false,"code":code})),
            }
        }
        metrics::counter!("epicbox_mux_resumes_total").increment(1);
        // A resumed empty set still gets a token, so the session can go on.
        self.attached_reply(ws, out, true, r#ref).await;
        let _ = any;
    }

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

    async fn detach(&mut self, ws: &mut WebSocket, msg: &Value, r#ref: &Option<String>) {
        let Some(list) = msg.get("mailboxes").and_then(|m| m.as_array()) else {
            self.send(ws, mux_error("bad_frame", "Detach needs mailboxes.", r#ref, None)).await;
            return;
        };
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
    async fn mux_lost(&mut self, ws: &mut WebSocket, key: &str, reason: &'static str) {
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

    async fn ack(&mut self, ws: &mut WebSocket, msg: &Value, r#ref: &Option<String>) {
        let Some(ids) = msg.get("ids").and_then(|m| m.as_array()) else {
            self.send(ws, mux_error("bad_frame", "Ack needs ids.", r#ref, None)).await;
            return;
        };
        if ids.len() > MAX_ACK_IDS {
            self.send(ws, mux_error("bad_frame", "At most 256 ids per Ack.", r#ref, None)).await;
            return;
        }
        let ids: Vec<String> = ids.iter().filter_map(|i| i.as_str()).filter(|i| is_msgid(i)).map(String::from).collect();
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

    async fn mux_timer(&mut self, ws: &mut WebSocket) {
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
    async fn pump(&mut self, ws: &mut WebSocket) {
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
            let got = match r
                .store
                .claim(&key, now_ms(), free, exclude, ClaimMode::Offer { lease_ms: OFFER_LEASE_MS })
                .await
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

fn ref_of(msg: &Value) -> Option<String> {
    msg.get("ref").and_then(|r| r.as_str()).filter(|r| r.len() <= 64).map(String::from)
}

#[allow(dead_code)]
fn _assert_send() {
    fn is_send<T: Send>(_: T) {}
    let _ = |relay: Arc<Relay>, ws: WebSocket, ip: IpAddr, p: SocketPermit| is_send(run(relay, ws, ip, p));
    let _ = Ordering::Relaxed;
}
