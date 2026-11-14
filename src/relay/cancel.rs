//! The 3.1.0 transaction cancel: check the requester's signature, record the cancel, forward it
//! to the other relays involved and tell the receiver's 3.1.0 sockets.
//!
//! Compatible with the reference cancel relay (epicbox `app_mongo.js` 3.1.0): a CancelTx may
//! come from a wallet's own socket or from another relay on a socket that never subscribed, with
//! `address` and a signature over the bare `epicboxtxid`, and with a `cancelrequestid` that
//! relays pass on so a cancel that comes back around is confirmed instead of sent on again.

use std::net::IpAddr;

use serde_json::{json, Value};

use super::{CancelOutcome, Cmd, Refusal, Relay, CANCEL_SIG_PREFIX};
use crate::address::parse_address;
use crate::clock::now_ms;
use crate::ids::{is_txid, rand_id};
use crate::sig;
use crate::store::{ForwardKind, NewForward};

impl Relay {
    /// CancelTx. `socket_key` is the key this socket proved with Subscribe, if any.
    pub async fn cancel_tx(&self, ip: IpAddr, socket_key: Option<&str>, msg: &Value) -> CancelOutcome {
        use CancelOutcome::Refused as R;
        let requester = match socket_key {
            Some(k) => Some(k.to_string()),
            None => {
                msg.get("address").and_then(|a| a.as_str()).and_then(|a| parse_address(a).ok()).map(|a| a.public_key)
            }
        };
        let Some(requester) = requester else {
            return R(Refusal::Invalid("InvalidRequest", "Missing cancellation address.".into()));
        };
        let txid = match msg.get("epicboxtxid").and_then(|t| t.as_str()) {
            Some(t) if is_txid(t) => t.to_string(),
            _ => return R(Refusal::Invalid("InvalidRequest", "Invalid or missing 32-character epicboxtxid.".into())),
        };
        let Some(signature) = msg.get("signature").and_then(|s| s.as_str()) else {
            return R(Refusal::Invalid("InvalidRequest", "Missing signature.".into()));
        };
        if let Some(s) = self.limiter.sig_blocked(ip) {
            return R(Refusal::RateLimited(s));
        }
        // The domain-separated form, then the bare one: up to two checks.
        if let Err(s) = self.limiter.sig_checks(ip, 2) {
            return R(Refusal::RateLimited(s));
        }
        // Wallets and the reference relay sign the bare txid, and relays forward that signature
        // on sockets that never subscribed, so it is accepted from any socket. It is the same
        // signature PostSlate carries as epicboxtxidsig: anyone who saw the slate can cancel it.
        // The domain-separated form (`epicbox-cancel/1:<txid>`) proves the sender asked to
        // cancel and is accepted too.
        let separated = sig::verify(&requester, &format!("{CANCEL_SIG_PREFIX}{txid}"), signature).is_ok();
        let bare_ok = !separated && sig::verify(&requester, &txid, signature).is_ok();
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
        // Relays pass the request id on; a request seen moments ago is one coming back around a
        // relay loop, so it is confirmed and not processed or forwarded again.
        let request_id = msg
            .get("cancelrequestid")
            .and_then(|c| c.as_str())
            .filter(|c| is_txid(c))
            .map(String::from)
            .unwrap_or_else(|| rand_id(32));
        if !self.first_cancel_request(&txid, &request_id) {
            return CancelOutcome::Cancelled(txid);
        }
        let receiver = info.participants.iter().find(|p| **p != requester).cloned();
        let now = now_ms();
        let queues = match self.store.cancel_tx(&txid, info.participants.clone(), receiver.clone(), now).await {
            Ok(q) => q,
            Err(_) => return R(Refusal::Internal),
        };
        metrics::counter!("epicbox_cancels_total").increment(1);
        if separated || self.cfg.protocol.forward_bare_cancel {
            // Endpoints come from the sender's address, which the slate signature does not
            // cover, so they get the same federation policy as a posted slate.
            let peers: Vec<&String> = info.endpoints.iter().filter(|p| self.peer_allowed(p)).collect();
            for peer in &peers {
                let frame = json!({"type":"CancelTx","address":requester,"epicboxtxid":txid,
                    "signature":signature,"cancelrequestid":request_id});
                let f = NewForward {
                    peer: (*peer).clone(),
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
            if !peers.is_empty() {
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
        tracing::debug!(mailboxes = queues.len(), "transaction cancelled");
        CancelOutcome::Cancelled(txid)
    }
}

/// How long a cancel request id is remembered for the loop guard.
const CANCEL_REQUEST_TTL_MS: i64 = 10 * 60 * 1000;
/// Most request ids remembered; past it expired ones are dropped first, then all.
const CANCEL_REQUEST_MAX: usize = 100_000;

impl Relay {
    /// True the first time `txid:request_id` is seen within `CANCEL_REQUEST_TTL_MS`.
    fn first_cancel_request(&self, txid: &str, request_id: &str) -> bool {
        let now = now_ms();
        let mut seen = self.cancel_requests.lock();
        if seen.len() >= CANCEL_REQUEST_MAX {
            seen.retain(|_, until| *until > now);
            if seen.len() >= CANCEL_REQUEST_MAX {
                seen.clear();
            }
        }
        let key = format!("{txid}:{request_id}");
        match seen.get(&key) {
            Some(until) if *until > now => false,
            _ => {
                seen.insert(key, now + CANCEL_REQUEST_TTL_MS);
                true
            }
        }
    }
}
