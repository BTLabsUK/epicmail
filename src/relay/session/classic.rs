//! Classic Epicbox frames: Challenge, Subscribe, Slate, Made, PostSlate and the 3.1.0
//! CancelTx and TransactionCancelled.

use std::time::{Duration, Instant};

use axum::extract::ws::WebSocket;
use serde_json::{json, Value};

use super::{ok, Flow, Session};
use crate::address::parse_address;
use crate::clock::now_ms;
use crate::ids::{is_msgid, rand_id};
use crate::relay::{CancelOutcome, Cmd, PostOutcome, PostReq, Refusal, OFFER_LEASE_MS};
use crate::sig;
use crate::store::{ClaimMode, StoredMessage};

/// Protocol version a classic socket announced in Subscribe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Ver {
    /// No `ver` in Subscribe: pre-2.0.0 wallets, no Made.
    Legacy,
    V2,
    V3,
    /// 3.0.0 plus transaction cancel.
    V31,
}

impl Ver {
    /// The `ver` string sent back in Slate frames.
    fn as_str(self) -> &'static str {
        match self {
            Ver::Legacy => "",
            Ver::V2 => "2.0.0",
            Ver::V3 => "3.0.0",
            Ver::V31 => "3.1.0",
        }
    }
}

/// The message a classic socket was offered and has not acknowledged.
pub(super) struct Inflight {
    /// Store row id.
    pub(super) id: i64,
}

impl Session {
    /// Send a fresh Challenge. The one it replaces stays valid until the next successful
    /// Subscribe.
    pub(super) async fn new_challenge(&mut self, ws: &mut WebSocket) {
        let old = std::mem::replace(&mut self.challenge, rand_id(32));
        self.prev_challenge = Some(old);
        self.pending_challenge = true;
        let v = json!({"type":"Challenge","str":self.challenge});
        self.send(ws, v).await;
    }

    /// The interval Challenge, and the watchdog: close a socket that leaves
    /// `watchdog_misses` Challenges unanswered while mail waits for it.
    pub(super) async fn on_challenge_tick(&mut self, ws: &mut WebSocket) -> Flow {
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

    /// ClientDetails. A request for mux/1 upgrades the socket when allowed; otherwise `Ok`.
    pub(super) async fn client_details(&mut self, ws: &mut WebSocket, msg: &Value) {
        let wants_mux = msg
            .get("ext")
            .and_then(|e| e.as_array())
            .map(|a| a.iter().any(|x| x.as_str() == Some("mux/1")))
            .unwrap_or(false);
        if wants_mux && self.relay.cfg.protocol.mux && self.key.is_none() && self.upgrade_to_mux(ws).await {
            return;
        }
        self.send(ws, ok()).await;
    }

    /// Subscribe: prove the key over the current or previous challenge, register the socket
    /// and deliver.
    pub(super) async fn subscribe(&mut self, ws: &mut WebSocket, msg: &Value) -> Flow {
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
        // Over the current challenge and, failing that, the previous one: up to two checks.
        if let Err(s) = r.limiter.sig_checks(self.ip, 1 + usize::from(self.prev_challenge.is_some())) {
            self.send(ws, Refusal::RateLimited(s).classic_frame()).await;
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
                // The message in flight was that key's: hand it back, or it blocks the next
                // key subscribed on this socket and waits out its lease for the owner.
                if let Some(i) = self.inflight.take() {
                    let _ = r.store.release(vec![i.id]).await;
                    r.registry.wake(&k);
                }
                self.attempts = 0;
            }
            self.send(ws, invalid).await;
            return Flow::Continue;
        };
        metrics::counter!("epicbox_subscribe_total", "result" => "ok").increment(1);
        self.prev_challenge = None;

        // 3.1.0: a successful Subscribe acknowledges the TransactionCancelled sent before it.
        if let (Some(t), Some(k)) = (self.pending_cancel_ack.take(), self.key.as_ref()) {
            if r.store.ack_cancel(k, &t).await.is_err() {
                let e =
                    json!({"type":"Error","kind":"InvalidRequest","description":"Unable to acknowledge cancellation."});
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
            let evicted =
                r.registry.subscribe_classic(&key, self.handle.clone(), r.cfg.limits.sockets_per_address as usize);
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

        // After three Subscribes without Made the message steps aside: its lease is released and
        // the store orders it after the others. It is never deleted for this.
        if self.attempts >= 3 {
            self.attempts = 0;
            if let Some(i) = self.inflight.take() {
                let _ = r.store.release(vec![i.id]).await;
            }
        }
        self.deliver(ws, true).await;
        Flow::Continue
    }

    /// Send the next message, a pending TransactionCancelled, or (on Subscribe) `Ok` when there
    /// is nothing.
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

    /// The Slate frame for `m` in the form `ver` expects.
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
    pub(super) async fn push(&mut self, ws: &mut WebSocket) {
        if self.key.is_none() || matches!(self.ver, None | Some(Ver::Legacy)) || self.inflight.is_some() {
            return;
        }
        self.deliver(ws, false).await;
    }

    /// Made: verify and delete the delivered message, then send a new Challenge.
    pub(super) async fn made(&mut self, ws: &mut WebSocket, msg: &Value) {
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
        let checks = 1 + usize::from(ver == Ver::V2 && self.prev_challenge.is_some());
        if let Err(s) = r.limiter.sig_checks(self.ip, checks) {
            self.send(ws, Refusal::RateLimited(s).classic_frame()).await;
            return;
        }
        let signature = msg.get("signature").and_then(|s| s.as_str()).unwrap_or("");
        let signed = if ver == Ver::V2 { self.challenge.as_str() } else { msgid };
        let ok_sig = sig::verify(&key, signed, signature).is_ok()
            || (ver == Ver::V2
                && self.prev_challenge.as_ref().is_some_and(|p| sig::verify(&key, p, signature).is_ok()));
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
            self.send(ws, json!({"type":"Error","kind":"UnknownError","description":"Internal error; try again."}))
                .await;
            return;
        }
        metrics::counter!("epicbox_made_total", "mode" => "classic").increment(1);
        self.send(ws, ok()).await;
        self.inflight = None;
        self.attempts = 0;
        self.new_challenge(ws).await;
    }

    /// PostSlate on a classic socket.
    pub(super) async fn post(&mut self, ws: &mut WebSocket, msg: &Value) {
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

    /// CancelTx (3.1.0).
    pub(super) async fn cancel(&mut self, ws: &mut WebSocket, msg: &Value) {
        let key = self.key.clone();
        let out = self.relay.cancel_tx(self.ip, key.as_deref(), msg).await;
        let frame = match out {
            CancelOutcome::Cancelled(t) => json!({"type":"TransactionCancelled","epicboxtxid":t}),
            CancelOutcome::Ok => ok(),
            CancelOutcome::Refused(r) => r.classic_frame(),
        };
        self.send(ws, frame).await;
    }
}
