//! One task per websocket. A socket starts in Epicbox 3.0.0 mode (classic) and may switch to
//! mux/1 with `ClientDetails{ext:["mux/1"]}` before its first Subscribe.
//!
//! Classic sockets answer frame by frame as the stock Epicbox relay does, with four additions: a
//! Subscribe signed over the previous challenge is still accepted (the interval Challenge can
//! race it), the message in flight is leased instead of blocking the mailbox, a watchdog closes
//! sockets that stop answering Challenges while mail waits, and a malformed frame affects only
//! its own socket. Classic sockets never receive a frame type a classic wallet cannot parse.
//!
//! This file holds the event loop both modes share; `classic.rs` handles the 2.0.0, 3.0.0 and
//! 3.1.0 frames and `mux.rs` the mux/1 frames.

mod classic;
mod mux;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio::time::{interval_at, MissedTickBehavior};

use super::{Cmd, Relay, SockHandle};
use crate::ids::rand_id;
use crate::limits::SocketPermit;
use classic::{Inflight, Ver};
use mux::{mux_error, ref_of, Mux, MUX_PUMP_TICK};

pub use mux::{HOLD_MAX_S, MAX_ACK_IDS, WAITING_PER_MIN};

/// What the event loop does after a frame or command.
enum Flow {
    Continue,
    /// Send a Close frame with this code and reason, then end the session.
    Close(u16, &'static str),
}

/// State of one websocket.
pub struct Session {
    relay: Arc<Relay>,
    /// Registry id of this socket.
    id: u64,
    ip: IpAddr,
    /// Held for the life of the socket; counts it against the per-prefix caps.
    permit: SocketPermit,
    /// Cloned into the registry so other tasks can reach this socket.
    handle: SockHandle,
    /// The Challenge last sent. Subscribe and 2.0.0 Made sign it.
    challenge: String,
    /// The Challenge before it, accepted until the next successful Subscribe.
    prev_challenge: Option<String>,
    /// Version from the last Subscribe; None before the first.
    ver: Option<Ver>,
    /// The key proved by Subscribe.
    key: Option<String>,
    /// The message offered and not yet acknowledged with Made.
    inflight: Option<Inflight>,
    /// Subscribes received while `inflight` was outstanding.
    attempts: u32,
    /// A Challenge was sent and no Subscribe has answered it.
    pending_challenge: bool,
    last_sub: Instant,
    /// Interval Challenges left unanswered while mail waited.
    misses: u32,
    /// A TransactionCancelled was sent; the next Subscribe acknowledges it.
    pending_cancel_ack: Option<String>,
    /// Set once the socket has switched to mux/1.
    mux: Option<Mux>,
    /// Frame budget window: (start, frames counted in it).
    frames: (Instant, u32),
    /// When the last frame arrived, for the idle timeout.
    last_seen: Instant,
    /// Longest a single write may wait for the client to read (`protocol.idle_timeout_s`).
    send_timeout: Duration,
    /// A write failed or timed out: the socket is gone and the event loop ends.
    dead: bool,
}

/// Serve one upgraded websocket until it closes.
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
        inflight: None,
        attempts: 0,
        pending_challenge: false,
        last_sub: Instant::now(),
        misses: 0,
        pending_cancel_ack: None,
        mux: None,
        frames: (Instant::now(), 0),
        last_seen: Instant::now(),
        send_timeout: Duration::ZERO,
        dead: false,
    };
    metrics::gauge!("epicbox_sockets").increment(1.0);
    s.serve(ws, rx).await;
    s.cleanup().await;
    metrics::gauge!("epicbox_sockets").decrement(1.0);
}

/// Serialize a frame.
fn text(v: &Value) -> Message {
    Message::Text(Utf8Bytes::from(v.to_string()))
}

/// The bare `{"type":"Ok"}` frame.
fn ok() -> Value {
    json!({"type":"Ok"})
}

/// Echo the client's `ref` in a reply, if it sent one.
fn with_ref(mut v: Value, r#ref: &Option<String>) -> Value {
    if let Some(r) = r#ref {
        v["ref"] = json!(r);
    }
    v
}

impl Session {
    /// Send one frame. False when the socket is gone.
    async fn send(&mut self, ws: &mut WebSocket, v: Value) -> bool {
        metrics::counter!("epicbox_frames_out_total").increment(1);
        self.send_raw(ws, text(&v)).await
    }

    /// Write one message, waiting at most `send_timeout` for the client to take it. A client
    /// that stops reading would otherwise block this task, and with it the idle timeout, for
    /// as long as the TCP connection lives. On failure the session is marked dead.
    async fn send_raw(&mut self, ws: &mut WebSocket, m: Message) -> bool {
        if self.dead {
            return false;
        }
        match tokio::time::timeout(self.send_timeout, ws.send(m)).await {
            Ok(Ok(())) => true,
            Ok(Err(_)) => {
                self.dead = true;
                false
            }
            Err(_) => {
                metrics::counter!("epicbox_send_timeouts_total").increment(1);
                self.dead = true;
                false
            }
        }
    }

    /// The event loop: frames in, commands from other tasks, timers and shutdown.
    async fn serve(&mut self, mut ws: WebSocket, mut rx: mpsc::Receiver<Cmd>) {
        let p = &self.relay.cfg.protocol;
        let challenge_every = Duration::from_secs(p.challenge_interval_s);
        let ping_every = Duration::from_secs(p.ping_interval_s.max(1));
        let idle = Duration::from_secs(p.idle_timeout_s.max(p.ping_interval_s + 1));
        self.send_timeout = idle;
        let mut challenge_tick = interval_at(tokio::time::Instant::now() + challenge_every, challenge_every);
        challenge_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut ping_tick = interval_at(tokio::time::Instant::now() + ping_every, ping_every);
        ping_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut pump_tick = interval_at(tokio::time::Instant::now() + MUX_PUMP_TICK, MUX_PUMP_TICK);
        pump_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut shutdown = self.relay.shutdown.subscribe();

        // First Challenge, sent on connect as the stock relay does, but always random: the
        // stock relay's fixed first challenge made every first Subscribe replayable forever.
        self.challenge = rand_id(32);
        self.pending_challenge = true;
        let first = json!({"type":"Challenge","str":self.challenge});
        if !self.send(&mut ws, first).await {
            return;
        }

        let flow = loop {
            if self.dead {
                break Flow::Continue;
            }
            // A held message goes back out when its hold ends, not at the next pump tick.
            let hold_ends = self.next_hold_end();
            tokio::select! {
                () = tokio::time::sleep(hold_ends.unwrap_or(MUX_PUMP_TICK)), if hold_ends.is_some() => {
                    self.mux_timer(&mut ws).await;
                }
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
                    if !self.send_raw(&mut ws, Message::Ping(Default::default())).await {
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
            let close = Message::Close(Some(CloseFrame { code, reason: Utf8Bytes::from_static(reason) }));
            self.send_raw(&mut ws, close).await;
        }
    }

    /// Unregister the socket and hand its leased messages back to the store.
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

    /// Count a frame against the per-socket budget. False when over it.
    fn frame_budget(&mut self) -> bool {
        let cap = self.relay.cfg.limits.frames_per_min_per_socket;
        if self.frames.0.elapsed() >= Duration::from_secs(60) {
            self.frames = (Instant::now(), 0);
        }
        self.frames.1 += 1;
        self.frames.1 <= cap
    }

    /// A frame that is not JSON. A classic socket closes, as the stock relay does; a mux/1
    /// socket gets `bad_frame` and stays open.
    async fn bad_json(&mut self, ws: &mut WebSocket) -> Flow {
        if self.mux.is_some() {
            self.send(ws, mux_error("bad_frame", "Frame is not a JSON object.", &None, None)).await;
            Flow::Continue
        } else {
            Flow::Close(3000, "Error parsing message.")
        }
    }

    /// Dispatch one text frame.
    async fn on_text(&mut self, ws: &mut WebSocket, t: &str) -> Flow {
        metrics::counter!("epicbox_frames_in_total").increment(1);
        if !self.frame_budget() {
            return Flow::Close(1008, "Too many frames.");
        }
        let Ok(msg) = serde_json::from_str::<Value>(t) else {
            return self.bad_json(ws).await;
        };
        let ty = msg.get("type").and_then(|t| t.as_str()).map(|t| t.to_ascii_lowercase());
        // Every frame pays its size into the prefix's byte budget. A PostSlate pays for its
        // `str` in `post_slate` and for the rest of the frame here, so neither a large frame of
        // another kind nor a PostSlate padded outside `str` goes unmetered.
        let charge = match ty.as_deref() {
            Some("postslate") => t.len().saturating_sub(msg.get("str").and_then(|s| s.as_str()).map_or(0, str::len)),
            _ => t.len(),
        };
        if self.relay.limiter.frame_bytes(self.ip, charge).is_err() {
            metrics::counter!("epicbox_limit_refusals_total", "limit" => "bytes_per_ip").increment(1);
            return Flow::Close(1008, "Too many bytes.");
        }
        let Some(ty) = ty else {
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
                self.send_raw(ws, Message::Text(Utf8Bytes::from_static("pong"))).await;
            }
            "pong" => {
                self.send_raw(ws, Message::Text(Utf8Bytes::from_static("ping"))).await;
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

    /// Act on a command sent to this socket through the registry.
    async fn on_cmd(&mut self, ws: &mut WebSocket, c: Cmd) -> Flow {
        match c {
            Cmd::Close { code, reason } => return Flow::Close(code, reason),
            Cmd::Wake(k) => {
                if let Some(m) = self.mux.as_mut() {
                    if m.attached.contains(&k) {
                        m.dirty.insert(k);
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
}
