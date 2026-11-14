//! The HTTPS mailbox API under /v1 (`epicbox-https/0.1`): info, post, pull and made.
//!
//! /v1 authenticates like Subscribe without the handshake: the client makes its own challenge,
//! `ebh-<unix seconds>-<random hex>`, and signs it. Each challenge is accepted once per key and
//! only inside the window. Acknowledgements are signed over the message id, as `Made` is.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};
use tokio::sync::broadcast::error::RecvError;

use super::{client_ip, err, reply, too_many, AppState, HTTPS_PROTOCOL};
use crate::address::parse_address;
use crate::bus::Event;
use crate::clock::now_ms;
use crate::ids::is_msgid;
use crate::relay::{PostOutcome, PostReq, Refusal};
use crate::sig;
use crate::store::ClaimMode;

const CHALLENGE_PREFIX: &str = "ebh-";
const CHALLENGE_FUTURE_S: i64 = 60;
const PULL_RECHECK: Duration = Duration::from_secs(5);

pub(super) async fn info(State(st): State<AppState>) -> Response {
    let cfg = &st.relay.cfg;
    let h = &cfg.http_api;
    reply(
        "info",
        StatusCode::OK,
        json!({
            "protocol": HTTPS_PROTOCOL,
            "epicbox_protocol": if cfg.protocol.cancel { "3.1.0" } else { "3.0.0" },
            "identity": format!("{}:{}", cfg.server.domain, cfg.server.port),
            "federation": cfg.federation.enabled,
            "challenge": format!(
                "{CHALLENGE_PREFIX}<unix seconds>-<random hex>, signed like Subscribe, accepted for {} s, \
                 single use per address",
                h.challenge_window_s
            ),
            "challenge_single_use": true,
            "max_mailboxes_per_pull": h.max_mailboxes,
            "max_messages_per_mailbox": h.max_per_mailbox,
            "max_wait_seconds": h.max_wait_s,
            "redeliver_after_seconds": h.lease_s,
        }),
    )
}

fn parse_body(body: &Bytes) -> Result<serde_json::Map<String, Value>, String> {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err("not a JSON object".into()),
        Err(e) => Err(e.to_string().chars().take(160).collect()),
    }
}

pub(super) async fn post(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    const R: &str = "post";
    let relay = &st.relay;
    let m = match parse_body(&body) {
        Ok(m) => m,
        Err(e) => return err(R, StatusCode::BAD_REQUEST, format!("body must be a PostSlate: {e}")),
    };
    for k in ["from", "to", "str", "signature"] {
        if !m.get(k).map(|v| v.is_string()).unwrap_or(false) {
            return err(R, StatusCode::BAD_REQUEST, format!("body must be a PostSlate: {k} must be a string"));
        }
    }
    let ip = client_ip(peer, &headers, &relay.cfg.server.trusted_proxies);
    let req = PostReq::from_json(&Value::Object(m));
    match relay.post_slate(ip, req, true).await {
        PostOutcome::Stored { msgid, txid } => {
            let mut v = json!({"ok": true, "id": msgid});
            if let Some(t) = txid {
                v["epicboxtxid"] = json!(t);
            }
            reply(R, StatusCode::OK, v)
        }
        PostOutcome::Forwarded { .. } => reply(R, StatusCode::OK, json!({"ok": true, "forwarded": true})),
        PostOutcome::Cancelled { txid } => reply(
            R,
            StatusCode::CONFLICT,
            json!({"error": "The transaction was cancelled.", "epicboxtxid": txid}),
        ),
        PostOutcome::Refused(Refusal::RateLimited(s)) => {
            too_many(R, format!("Rate limit exceeded; retry in {s} s."), s)
        }
        PostOutcome::Refused(Refusal::Full(d)) => err(R, StatusCode::TOO_MANY_REQUESTS, d),
        PostOutcome::Refused(Refusal::Invalid(_, d)) => err(R, StatusCode::BAD_REQUEST, d),
        PostOutcome::Refused(Refusal::Internal) => {
            err(R, StatusCode::SERVICE_UNAVAILABLE, "Internal error; try again.")
        }
    }
}

/// `ebh-<digits>-<lowercase hex>`, at most 64 characters, issued no later than a minute from now
/// and inside the window. Returns the issue time in seconds.
fn challenge_issued(challenge: &str, now_s: i64, window_s: i64) -> Option<i64> {
    if challenge.len() > 64 {
        return None;
    }
    let rest = challenge.strip_prefix(CHALLENGE_PREFIX)?;
    let (secs, hex) = rest.split_once('-')?;
    if secs.is_empty() || !secs.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let issued: i64 = secs.parse().ok()?;
    (issued <= now_s + CHALLENGE_FUTURE_S && now_s - issued <= window_s).then_some(issued)
}

struct Proven {
    address: String,
    key: Result<String, &'static str>,
}

async fn prove(st: &AppState, ip: IpAddr, mb: &Value) -> Result<Proven, String> {
    let s = |k: &str| mb.get(k).and_then(|v| v.as_str());
    let (Some(address), Some(challenge), Some(signature)) = (s("address"), s("challenge"), s("signature")) else {
        return Err("each mailbox needs address, challenge and signature strings".into());
    };
    let relay = &st.relay;
    let address = address.to_string();
    let key = match parse_address(&address) {
        Ok(a) if a.public_key_valid() => a.public_key,
        _ => return Ok(Proven { address, key: Err("malformed address") }),
    };
    let window = relay.cfg.http_api.challenge_window_s as i64;
    let now_s = now_ms() / 1000;
    let Some(issued) = challenge_issued(challenge, now_s, window) else {
        return Ok(Proven { address, key: Err("challenge is stale or malformed") });
    };
    if sig::verify(&key, challenge, signature).is_err() {
        relay.limiter.sig_failed(ip);
        return Ok(Proven { address, key: Err("signature does not verify") });
    }
    let expires = (issued + window + CHALLENGE_FUTURE_S) * 1000;
    match relay.store.use_challenge(&format!("{key}:{challenge}"), expires).await {
        Ok(true) => Ok(Proven { address, key: Ok(key) }),
        Ok(false) => Ok(Proven { address, key: Err("challenge was already used") }),
        Err(e) => {
            tracing::error!(error = %e, "store use_challenge failed");
            Err("internal".into())
        }
    }
}

pub(super) async fn pull(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    const R: &str = "pull";
    let relay = st.relay.clone();
    let h = &relay.cfg.http_api;
    let shape = "body must be {mailboxes: [{address, challenge, signature}]}";
    let m = match parse_body(&body) {
        Ok(m) => m,
        Err(e) => return err(R, StatusCode::BAD_REQUEST, format!("{shape}: {e}")),
    };
    let Some(list) = m.get("mailboxes").and_then(|v| v.as_array()) else {
        return err(R, StatusCode::BAD_REQUEST, format!("{shape}: mailboxes is missing"));
    };
    if list.is_empty() || list.len() > h.max_mailboxes {
        return err(R, StatusCode::BAD_REQUEST, format!("{shape}: 1 to {} mailboxes", h.max_mailboxes));
    }
    let int = |k: &str, default: i64| -> Result<i64, String> {
        match m.get(k) {
            None | Some(Value::Null) => Ok(default),
            Some(v) => v.as_i64().ok_or_else(|| format!("{k} must be an integer")),
        }
    };
    let limit = match int("limit", 20) {
        Ok(n) if (1..=h.max_per_mailbox as i64).contains(&n) => n as usize,
        Ok(_) => return err(R, StatusCode::BAD_REQUEST, format!("{shape}: limit is 1 to {}", h.max_per_mailbox)),
        Err(e) => return err(R, StatusCode::BAD_REQUEST, format!("{shape}: {e}")),
    };
    let wait = match int("wait", 0) {
        Ok(n) if (0..=h.max_wait_s as i64).contains(&n) => n as u64,
        Ok(_) => return err(R, StatusCode::BAD_REQUEST, format!("{shape}: wait is 0 to {}", h.max_wait_s)),
        Err(e) => return err(R, StatusCode::BAD_REQUEST, format!("{shape}: {e}")),
    };
    let ip = client_ip(peer, &headers, &relay.cfg.server.trusted_proxies);
    if let Some(s) = relay.limiter.sig_blocked(ip) {
        metrics::counter!("epicbox_limit_refusals_total", "limit" => "failed_sigs").increment(1);
        return too_many(R, format!("Too many failed signatures; retry in {s} s."), s);
    }

    let mut proven = Vec::with_capacity(list.len());
    for mb in list {
        match prove(&st, ip, mb).await {
            Ok(p) => proven.push(p),
            Err(e) if e == "internal" => return err(R, StatusCode::SERVICE_UNAVAILABLE, "Internal error; try again."),
            Err(e) => return err(R, StatusCode::BAD_REQUEST, format!("{shape}: {e}")),
        }
    }
    let keys: HashSet<String> = proven.iter().filter_map(|p| p.key.clone().ok()).collect();
    let lease_ms = (h.lease_s.max(1) * 1000) as i64;

    // Subscribe before the first claim so a message stored in between still wakes us.
    let mut events = relay.bus.subscribe();
    let mut shutdown = relay.shutdown.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    loop {
        let mut results = Vec::with_capacity(proven.len());
        let mut found = 0usize;
        for p in &proven {
            let key = match &p.key {
                Ok(k) => k,
                Err(e) => {
                    results.push(json!({"address": p.address, "error": e}));
                    continue;
                }
            };
            let msgs = if relay.is_stalled(key) {
                vec![]
            } else {
                match relay.store.claim(key, now_ms(), limit, vec![], ClaimMode::Offer { lease_ms }).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error = %e, "store claim failed");
                        return err(R, StatusCode::SERVICE_UNAVAILABLE, "Internal error; try again.");
                    }
                }
            };
            found += msgs.len();
            if !msgs.is_empty() {
                metrics::counter!("epicbox_deliveries_total", "mode" => "https").increment(msgs.len() as u64);
            }
            let msgs: Vec<Value> = msgs
                .into_iter()
                .map(|s| {
                    let mut v = json!({
                        "id": s.msgid, "from": s.sender, "str": s.body,
                        "signature": s.signature, "attempt": s.deliveries,
                    });
                    if let Some(t) = s.txid {
                        v["epicboxtxid"] = json!(t);
                    }
                    v
                })
                .collect();
            results.push(json!({"address": p.address, "messages": msgs}));
        }
        let now = tokio::time::Instant::now();
        if found > 0 || now >= deadline || keys.is_empty() || *shutdown.borrow() {
            return reply(R, StatusCode::OK, json!({ "mailboxes": results }));
        }
        let nap = (deadline - now).min(PULL_RECHECK);
        let woken = async {
            loop {
                match events.recv().await {
                    Ok(Event::MailStored { queue }) if keys.contains(&queue) => return,
                    Ok(_) => continue,
                    Err(RecvError::Lagged(_)) => return,
                    Err(RecvError::Closed) => std::future::pending::<()>().await,
                }
            }
        };
        tokio::select! {
            _ = woken => {}
            _ = tokio::time::sleep(nap) => {}
            _ = shutdown.changed() => {}
        }
    }
}

pub(super) async fn made(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    const R: &str = "made";
    let relay = &st.relay;
    let shape = "body must be {address, acks: [{id, signature}]}";
    let m = match parse_body(&body) {
        Ok(m) => m,
        Err(e) => return err(R, StatusCode::BAD_REQUEST, format!("{shape}: {e}")),
    };
    let key = match m.get("address").and_then(|a| a.as_str()).map(parse_address) {
        Some(Ok(a)) if a.public_key_valid() => a.public_key,
        _ => return err(R, StatusCode::BAD_REQUEST, format!("{shape}: malformed address")),
    };
    let max = relay.cfg.http_api.max_per_mailbox;
    let acks = match m.get("acks").and_then(|a| a.as_array()) {
        Some(a) if !a.is_empty() && a.len() <= max => a,
        _ => return err(R, StatusCode::BAD_REQUEST, format!("{shape}: 1 to {max} acks")),
    };
    let ip = client_ip(peer, &headers, &relay.cfg.server.trusted_proxies);
    if let Some(s) = relay.limiter.sig_blocked(ip) {
        return err(R, StatusCode::TOO_MANY_REQUESTS, format!("Too many failed signatures; retry in {s} s."));
    }
    let mut ids = Vec::with_capacity(acks.len());
    let mut refused = 0u64;
    for a in acks {
        let id = a.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let signature = a.get("signature").and_then(|v| v.as_str()).unwrap_or("");
        if is_msgid(id) && sig::verify(&key, id, signature).is_ok() {
            ids.push(id.to_string());
        } else {
            relay.limiter.sig_failed(ip);
            refused += 1;
        }
    }
    let removed = if ids.is_empty() {
        0
    } else {
        match relay.store.made(&key, ids).await {
            Ok(v) => v.into_iter().filter(|x| *x).count() as u64,
            Err(e) => {
                tracing::error!(error = %e, "store made failed");
                return err(R, StatusCode::SERVICE_UNAVAILABLE, "Internal error; try again.");
            }
        }
    };
    if removed > 0 {
        metrics::counter!("epicbox_made_total", "mode" => "https").increment(removed);
        relay.registry.wake(&key);
    }
    reply(R, StatusCode::OK, json!({"removed": removed, "refused": refused}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges() {
        let now = 1_800_000_000;
        assert_eq!(challenge_issued(&format!("ebh-{now}-00ff"), now, 1200), Some(now));
        assert!(challenge_issued(&format!("ebh-{}-00ff", now - 1201), now, 1200).is_none());
        assert!(challenge_issued(&format!("ebh-{}-00ff", now + 61), now, 1200).is_none());
        assert!(challenge_issued(&format!("ebh-{now}-00FF"), now, 1200).is_none());
        assert!(challenge_issued(&format!("ebh-{now}-"), now, 1200).is_none());
        assert!(challenge_issued(&format!("ebh-{now}-{}", "a".repeat(60)), now, 1200).is_none());
        assert!(challenge_issued("ebh--00ff", now, 1200).is_none());
    }
}
