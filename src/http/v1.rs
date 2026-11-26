//! The HTTPS mailbox API under /v1 (`epicbox-https/0.1`): info, post, pull and made.
//!
//! /v1 authenticates like Subscribe without the handshake: the client makes its own challenge,
//! `ebh-<unix seconds>-<random hex>`, and signs `<challenge>@<identity>` (identity is
//! `domain:port`, as `/v1/info` shows it), so a proof made for one relay is refused by another.
//! Each challenge is accepted once per key and only inside the window. Acknowledgements are signed over the message id, as `Made` is.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};

use super::{client_ip, err, reply, too_many, AppState, HTTPS_PROTOCOL};
use crate::address::parse_address;
use crate::clock::now_ms;
use crate::ids::is_msgid;
use crate::logging::short;
use crate::relay::waiters::WaitRefusal;
use crate::relay::{PostOutcome, PostReq, Refusal, Relay};
use crate::sig;
use crate::store::{ClaimMode, StoredMessage};

const CHALLENGE_PREFIX: &str = "ebh-";
const CHALLENGE_FUTURE_S: i64 = 60;
const PULL_RECHECK: Duration = Duration::from_secs(5);
/// Most slate bytes one `/v1/pull` response carries. Mailboxes past it are left for the next
/// pull and the reply says `"more": true`. Without it one pull of 64 mailboxes x 50 messages of
/// 128 KiB is 400 MiB, held in memory twice while it is serialised.
const PULL_MAX_BYTES: usize = 4 << 20;

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
                "{CHALLENGE_PREFIX}<unix seconds>-<random hex>; sign <challenge>@<identity> like Subscribe \
                 (identity as in this reply); accepted for {} s, single use per address",
                h.challenge_window_s
            ),
            "challenge_single_use": true,
            "max_mailboxes_per_pull": h.max_mailboxes,
            "max_messages_per_mailbox": h.max_per_mailbox,
            "max_wait_seconds": h.max_wait_s,
            "redeliver_after_seconds": h.lease_s,
            "max_waiting_pulls_per_ip": h.max_waiting_per_ip,
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
    // `str` pays in post_slate; the rest of the body pays here, as a websocket frame does.
    let outside = body.len().saturating_sub(m.get("str").and_then(|s| s.as_str()).map_or(0, str::len));
    if let Err(s) = relay.limiter.frame_bytes(ip, outside) {
        relay.limiter.refused("bytes_per_ip", ip);
        return too_many(R, format!("Rate limit exceeded; retry in {s} s."), s);
    }
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
        PostOutcome::Cancelled { txid } => {
            reply(R, StatusCode::CONFLICT, json!({"error": "The transaction was cancelled.", "epicboxtxid": txid}))
        }
        PostOutcome::Refused(Refusal::RateLimited(s)) => {
            too_many(R, format!("Rate limit exceeded; retry in {s} s."), s)
        }
        PostOutcome::Refused(Refusal::Full(d)) => err(R, StatusCode::TOO_MANY_REQUESTS, d),
        PostOutcome::Refused(Refusal::DeniedHost(d)) => err(R, StatusCode::FORBIDDEN, d),
        PostOutcome::Refused(Refusal::Invalid(_, d)) => err(R, StatusCode::BAD_REQUEST, d),
        PostOutcome::Refused(Refusal::Internal) => {
            err(R, StatusCode::SERVICE_UNAVAILABLE, "Internal error; try again.")
        }
    }
}

/// The names other than `server.domain:server.port` a `/v1/pull` signature may be bound to: each
/// `server.aliases` entry, with its own port or else `server.port`. Lower case, no trailing dot,
/// the primary name left out.
fn alias_names(cfg: &crate::config::Config) -> Vec<(String, u16)> {
    let primary = (crate::config::normalize_domain(&cfg.server.domain).unwrap_or_default(), cfg.server.port);
    let mut out: Vec<(String, u16)> = Vec::new();
    for a in &cfg.server.aliases {
        let (host, port) = match a.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => (h, p),
                Err(_) => (a.as_str(), cfg.server.port),
            },
            None => (a.as_str(), cfg.server.port),
        };
        let Some(host) = crate::config::normalize_domain(host) else { continue };
        let name = (host, port);
        if name != primary && !out.contains(&name) {
            out.push(name);
        }
    }
    out
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

/// One mailbox of a pull: its address as sent, and its key or why it was not proven.
struct Proven {
    address: String,
    key: Result<String, &'static str>,
}

/// Why a whole pull is refused while proving its mailboxes.
enum ProveError {
    /// A mailbox entry lacks a string field: 400.
    Shape,
    /// The challenge could not be recorded: 503.
    Store,
}

/// Check one mailbox entry: address, challenge window, signature, then record the challenge as
/// used. A mailbox that fails is reported in the answer; only a malformed entry or a store
/// error fails the whole pull.
async fn prove(st: &AppState, ip: IpAddr, mb: &Value) -> Result<Proven, ProveError> {
    let s = |k: &str| mb.get(k).and_then(|v| v.as_str());
    let (Some(address), Some(challenge), Some(signature)) = (s("address"), s("challenge"), s("signature")) else {
        return Err(ProveError::Shape);
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
    let signed = epicmail_core::text::v1_proof_text(challenge, &relay.cfg.server.domain, relay.cfg.server.port);
    if sig::verify(&key, &signed, signature).is_err() {
        // A client that dialled one of the relay's aliases signs for that name. Every extra
        // check is charged to the same budget as a mailbox, and only a mailbox that matches
        // none of the names counts as a failed signature.
        let mut verified = false;
        for (host, port) in alias_names(&relay.cfg) {
            if relay.limiter.http_ip(ip, 1).is_err() {
                relay.limiter.refused("http", ip);
                return Ok(Proven { address, key: Err("rate limit exceeded; try again later") });
            }
            if sig::verify(&key, &epicmail_core::text::v1_proof_text(challenge, &host, port), signature).is_ok() {
                verified = true;
                break;
            }
        }
        if !verified {
            relay.limiter.sig_failed(ip);
            return Ok(Proven { address, key: Err("signature does not verify") });
        }
    }
    let expires = (issued + window + CHALLENGE_FUTURE_S) * 1000;
    match relay.store.use_challenge(&format!("{key}:{challenge}"), expires).await {
        Ok(true) => Ok(Proven { address, key: Ok(key) }),
        Ok(false) => Ok(Proven { address, key: Err("challenge was already used") }),
        Err(e) => {
            crate::sampled!(error, error = %e, "store use_challenge failed");
            Err(ProveError::Store)
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
    // Every proven mailbox writes a used-challenge row, kept for the challenge window. Posts
    // stop at store.max_bytes; pulls stop a quarter above it, so draining goes on while posts
    // are refused but rows from pulls alone cannot grow the store without bound.
    let cap = relay.cfg.store.max_bytes;
    if cap > 0 && relay.store.used_bytes().is_some_and(|u| u >= cap.saturating_add(cap / 4)) {
        metrics::counter!("epicbox_limit_refusals_total", "limit" => "store_bytes").increment(1);
        return err(R, StatusCode::SERVICE_UNAVAILABLE, "Relay storage is full; try again later.");
    }
    if let Some(s) = relay.limiter.sig_blocked(ip) {
        relay.limiter.refused("failed_sigs", ip);
        return too_many(R, format!("Too many failed signatures; retry in {s} s."), s);
    }
    // Every mailbox costs a signature check and a challenge write.
    if let Err(s) = relay.limiter.http_ip(ip, list.len()) {
        relay.limiter.refused("http", ip);
        return too_many(R, format!("Rate limit exceeded; retry in {s} s."), s);
    }

    let mut proven = Vec::with_capacity(list.len());
    for mb in list {
        match prove(&st, ip, mb).await {
            Ok(p) => proven.push(p),
            Err(ProveError::Store) => return err(R, StatusCode::SERVICE_UNAVAILABLE, "Internal error; try again."),
            Err(ProveError::Shape) => {
                let e = "each mailbox needs address, challenge and signature strings";
                return err(R, StatusCode::BAD_REQUEST, format!("{shape}: {e}"));
            }
        }
    }
    let keys: HashSet<String> = proven.iter().filter_map(|p| p.key.clone().ok()).collect();
    relay.traffic.add(crate::traffic::Count::LoginsOk, keys.len() as u64);
    for p in &proven {
        match &p.key {
            Ok(k) => tracing::trace!(ip = %ip, mailbox = %short(k), transport = "https", "pull proven"),
            Err(reason) => tracing::trace!(ip = %ip, reason, transport = "https", "pull refused"),
        }
    }
    let lease_ms = (h.lease_s.max(1) * 1000) as i64;

    // A long poll registers before the first claim, so a message stored in between still
    // wakes it. Waiting pulls are capped per prefix and in total.
    let guard = if wait > 0 && !keys.is_empty() {
        let (prefix, mult) = relay.limiter.prefix(ip);
        let per_ip = (f64::from(h.max_waiting_per_ip) * mult) as u32;
        match relay.pull_waiters.register(keys.iter().cloned(), prefix, per_ip, h.max_waiting) {
            Ok(g) => Some(g),
            Err(why) => {
                let (limit, text) = match why {
                    WaitRefusal::PerIp => ("http_waiting_per_ip", "Too many waiting pulls from this network"),
                    WaitRefusal::Total => ("http_waiting", "Too many waiting pulls"),
                };
                relay.limiter.refused(limit, ip);
                return too_many(R, format!("{text}; retry in {} s.", PULL_RECHECK.as_secs()), PULL_RECHECK.as_secs());
            }
        }
    } else {
        None
    };
    let mut shutdown = relay.shutdown.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    loop {
        let Some((results, found, more)) = claim_round(&relay, &proven, limit, lease_ms).await else {
            return err(R, StatusCode::SERVICE_UNAVAILABLE, "Internal error; try again.");
        };
        let now = tokio::time::Instant::now();
        let Some(g) = guard.as_ref().filter(|_| found == 0 && now < deadline && !*shutdown.borrow()) else {
            let mut body = json!({ "mailboxes": results });
            if more {
                body["more"] = json!(true);
            }
            return reply(R, StatusCode::OK, body);
        };
        // Leases that end on other sockets wake nobody, so look again every few seconds.
        let nap = (deadline - now).min(PULL_RECHECK);
        tokio::select! {
            _ = g.notified() => {}
            _ = tokio::time::sleep(nap) => {}
            _ = shutdown.changed() => {}
        }
    }
}

/// One pass over the proven mailboxes: offer up to `limit` messages from each, within
/// `PULL_MAX_BYTES` in all. Returns the per-mailbox results, the number of messages offered, and
/// whether the byte budget left mailboxes out; None on a store error.
async fn claim_round(
    relay: &Relay,
    proven: &[Proven],
    limit: usize,
    lease_ms: i64,
) -> Option<(Vec<Value>, usize, bool)> {
    let mut results = Vec::with_capacity(proven.len());
    let mut found = 0usize;
    let mut bytes = 0usize;
    let mut more = false;
    // A claimed message is leased, so claim only what fits: each message counts as the largest
    // allowed until its real size is known.
    let max_msg = relay.cfg.limits.max_str_bytes.max(1) + 1024;
    for p in proven {
        let key = match &p.key {
            Ok(k) => k,
            Err(e) => {
                results.push(json!({"address": p.address, "error": e}));
                continue;
            }
        };
        let room = PULL_MAX_BYTES.saturating_sub(bytes) / max_msg;
        let take = limit.min(room);
        let msgs = if relay.is_stalled(key) {
            vec![]
        } else if take == 0 {
            more = true;
            vec![]
        } else {
            // A read first: a long poll looks every few seconds, and an empty mailbox should
            // not cost a write each time.
            match relay.store.has_offerable(key, now_ms(), vec![]).await {
                Ok(false) => vec![],
                Ok(true) => match relay.store.claim(key, now_ms(), take, vec![], ClaimMode::Offer { lease_ms }).await {
                    Ok(v) => v,
                    Err(e) => {
                        crate::sampled!(error, error = %e, "store claim failed");
                        return None;
                    }
                },
                Err(e) => {
                    crate::sampled!(error, error = %e, "store read failed");
                    return None;
                }
            }
        };
        if take < limit && msgs.len() == take {
            more = true;
        }
        bytes += msgs.iter().map(|m| m.body.len() + m.signature.len() + m.sender.len()).sum::<usize>();
        found += msgs.len();
        if !msgs.is_empty() {
            metrics::counter!("epicbox_deliveries_total", "mode" => "https").increment(msgs.len() as u64);
            relay.traffic.add(crate::traffic::Count::Delivered, msgs.len() as u64);
            for m in &msgs {
                tracing::debug!(mailbox = %short(key), id = %m.msgid, transport = "https", "delivered");
            }
        }
        let msgs: Vec<Value> = msgs.into_iter().map(message_json).collect();
        results.push(json!({"address": p.address, "messages": msgs}));
    }
    Some((results, found, more))
}

/// A message as `/v1/pull` returns it.
fn message_json(s: StoredMessage) -> Value {
    let mut v = json!({
        "id": s.msgid, "from": s.sender, "str": s.body,
        "signature": s.signature, "attempt": s.deliveries,
    });
    if let Some(t) = s.txid {
        v["epicboxtxid"] = json!(t);
    }
    v
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
        relay.limiter.refused("failed_sigs", ip);
        return too_many(R, format!("Too many failed signatures; retry in {s} s."), s);
    }
    if let Err(s) = relay.limiter.http_ip(ip, acks.len()) {
        relay.limiter.refused("http", ip);
        return too_many(R, format!("Rate limit exceeded; retry in {s} s."), s);
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
    let acked_ids = (tracing::level_filters::LevelFilter::current() >= tracing::Level::DEBUG).then(|| ids.join(","));
    let removed = if ids.is_empty() {
        0
    } else {
        match relay.store.made(&key, ids).await {
            Ok(v) => v.into_iter().filter(|x| *x).count() as u64,
            Err(e) => {
                crate::sampled!(error, error = %e, "store made failed");
                return err(R, StatusCode::SERVICE_UNAVAILABLE, "Internal error; try again.");
            }
        }
    };
    if removed > 0 {
        metrics::counter!("epicbox_made_total", "mode" => "https").increment(removed);
        relay.traffic.add(crate::traffic::Count::Acked, removed);
        relay.registry.wake(&key);
    }
    if let Some(ids) = acked_ids {
        tracing::debug!(ip = %ip, mailbox = %short(&key), ids = %ids, removed, refused, transport = "https", "acked");
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

    #[test]
    fn alias_names_take_their_own_port_or_the_servers() {
        let mut c = crate::config::Config::default();
        c.server.domain = "Relay.Example.".into();
        c.server.port = 443;
        c.server.aliases = vec!["Alias.Example.".into(), "other.example:8443".into(), "relay.example".into()];
        assert_eq!(
            alias_names(&c),
            vec![("alias.example".to_string(), 443), ("other.example".to_string(), 8443)],
            "the primary name is left out"
        );
    }
}
