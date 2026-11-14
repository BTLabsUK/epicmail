//! HTTP: the websocket upgrade (any path, as the stock relay), health and readiness, metrics,
//! a status document, the info document, the HTTPS mailbox API (/v1, epicbox-https/0.1) and the
//! test stall knob.
//!
//! /v1 authenticates like Subscribe without the handshake: the client makes its own challenge,
//! `ebh-<unix seconds>-<random hex>`, and signs it. Each challenge is accepted once per key and
//! only inside the window. Acknowledgements are signed over the message id, as `Made` is.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::JsonRejection;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipnet::IpNet;
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::{json, Value};
use tokio::sync::broadcast::error::RecvError;

use crate::address::parse_address;
use crate::bus::Event;
use crate::limits::SocketRefusal;
use crate::relay::{session, PostOutcome, PostReq, Refusal, Relay};
use crate::sig;
use crate::store::ClaimMode;
use crate::util::{is_msgid, now_ms};

pub const HTTPS_PROTOCOL: &str = "epicbox-https/0.1";
const CHALLENGE_PREFIX: &str = "ebh-";
const CHALLENGE_FUTURE_S: i64 = 60;
const PULL_RECHECK: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct AppState {
    pub relay: Arc<Relay>,
    pub metrics: Option<PrometheusHandle>,
    /// Serve /metrics on the main listener (loopback callers only).
    pub metrics_on_main: bool,
}

/// The main listener's routes.
pub fn router(state: AppState) -> Router {
    let cfg = &state.relay.cfg;
    let body_limit = cfg.limits.max_frame_bytes.max(64 * 1024);
    let mut r = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics_main))
        .route("/status.json", get(status))
        .route("/.well-known/epicbox.json", get(well_known));
    if cfg.http_api.enabled {
        r = r
            .route("/v1/info", get(v1_info))
            .route("/v1/post", post(v1_post))
            .route("/v1/pull", post(v1_pull))
            .route("/v1/made", post(v1_made));
    }
    if cfg.test.stall_endpoint {
        r = r.route("/test/stall", post(test_stall));
    }
    r.fallback(fallback).layer(DefaultBodyLimit::max(body_limit)).with_state(state)
}

/// The separate metrics listener (`server.metrics_listen`).
pub fn metrics_router(handle: PrometheusHandle) -> Router {
    Router::new().route("/metrics", get(move || async move { handle.render() }))
}

fn canon(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// The client address. X-Forwarded-For is read only when the connection comes from a trusted
/// proxy, and then from the right: the first address that is not a trusted proxy is the client.
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let mut ip = canon(peer.ip());
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(&ip) {
        return ip;
    }
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .collect();
    for hop in hops.iter().rev() {
        let Ok(h) = hop.trim().parse::<IpAddr>() else { break };
        ip = canon(h);
        if !is_trusted(&ip) {
            break;
        }
    }
    ip
}

fn count(route: &'static str, status: StatusCode) {
    metrics::counter!("epicbox_http_requests_total", "route" => route, "status" => status.as_str().to_string())
        .increment(1);
}

fn reply(route: &'static str, status: StatusCode, body: Value) -> Response {
    count(route, status);
    (status, Json(body)).into_response()
}

fn err(route: &'static str, status: StatusCode, message: impl Into<String>) -> Response {
    reply(route, status, json!({ "error": message.into() }))
}

// ---- websocket and plain pages -----------------------------------------------------------

async fn fallback(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let relay = st.relay.clone();
    let ws = match ws {
        Ok(ws) => ws,
        Err(_) if method == Method::GET => {
            return (StatusCode::OK, "Epicbox relay. Connect with a websocket.\n").into_response();
        }
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    if relay.draining.load(Ordering::Relaxed) {
        return (StatusCode::SERVICE_UNAVAILABLE, "Relay restarting.\n").into_response();
    }
    let ip = client_ip(peer, &headers, &relay.cfg.server.trusted_proxies);
    let permit = match relay.limiter.open_socket(ip) {
        Ok(p) => p,
        Err(SocketRefusal::Total) => {
            metrics::counter!("epicbox_limit_refusals_total", "limit" => "sockets_total").increment(1);
            return (StatusCode::SERVICE_UNAVAILABLE, "Relay is full.\n").into_response();
        }
        Err(SocketRefusal::PerIp) => {
            metrics::counter!("epicbox_limit_refusals_total", "limit" => "sockets_per_ip").increment(1);
            return (StatusCode::TOO_MANY_REQUESTS, "Too many connections from this network.\n").into_response();
        }
    };
    let max = relay.cfg.limits.max_frame_bytes;
    // Small socket buffers: the 128 KiB defaults cost about 136 KiB of RSS per idle socket.
    // Reads grow past 8 KiB as a large frame arrives; writes go out at each flush.
    ws.read_buffer_size(WS_READ_BUFFER)
        .write_buffer_size(0)
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| session::run(relay, socket, ip, permit))
}

const WS_READ_BUFFER: usize = 8 * 1024;

async fn health() -> &'static str {
    "ok\n"
}

async fn ready(State(st): State<AppState>) -> Response {
    let r = &st.relay;
    if r.draining.load(Ordering::Relaxed) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ready":false,"reason":"draining"}))).into_response();
    }
    match r.store.check_writable().await {
        Ok(()) => {
            r.store_ok.store(true, Ordering::Relaxed);
            Json(json!({"ready":true})).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "store write check failed");
            r.store_ok.store(false, Ordering::Relaxed);
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ready":false,"reason":"store"}))).into_response()
        }
    }
}

async fn metrics_main(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    // Behind a proxy on the same host every request comes from loopback: a forwarded request is
    // a public one.
    let local = canon(peer.ip()).is_loopback() && !headers.contains_key("x-forwarded-for");
    match (&st.metrics, st.metrics_on_main && local) {
        (Some(h), true) => h.render().into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Aggregate counts only: no addresses, keys or IPs.
async fn status(State(st): State<AppState>) -> Response {
    let r = &st.relay;
    let (mailboxes, mux, classic) = r.registry.counts();
    let stats = r.store.stats(now_ms()).await.ok();
    Json(json!({
        "name": r.cfg.server.name,
        "identity": format!("{}:{}", r.cfg.server.domain, r.cfg.server.port),
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_s": r.started.elapsed().as_secs(),
        "draining": r.draining.load(Ordering::Relaxed),
        "store_ok": r.store_ok.load(Ordering::Relaxed),
        "sockets": r.limiter.sockets_open(),
        "listening_mailboxes": mailboxes,
        "mux_holders": mux,
        "classic_subscriptions": classic,
        "mux_tokens": r.tokens_live(),
        "store": stats,
    }))
    .into_response()
}

async fn well_known(State(st): State<AppState>) -> Response {
    let cfg = &st.relay.cfg;
    let mut versions = vec!["2.0.0", "3.0.0"];
    if cfg.protocol.cancel {
        versions.push("3.1.0");
    }
    let mut features = serde_json::Map::new();
    if cfg.protocol.mux {
        let l = &cfg.limits;
        features.insert(
            "mux/1".into(),
            json!({
                "limits": {
                    "attach_per_frame": l.mux_attach_per_frame,
                    "mailboxes_per_socket": l.mux_mailboxes_per_socket,
                    "inflight_per_socket": l.mux_inflight,
                    "ids_per_ack": 256,
                    "hold_max_s": 3600,
                    "attach_frames_per_min": l.mux_attach_frames_per_min,
                    "failed_sigs_per_min_per_ip": l.failed_sigs_per_min_per_ip,
                    "mux_sockets_per_ip": l.mux_sockets_per_ip,
                }
            }),
        );
    }
    if cfg.http_api.enabled {
        features.insert("https".into(), json!({"protocol": HTTPS_PROTOCOL, "base": "/v1"}));
    }
    Json(json!({
        "software": "epicbox-relay",
        "version": env!("CARGO_PKG_VERSION"),
        "name": cfg.server.name,
        "identity": format!("{}:{}", cfg.server.domain, cfg.server.port),
        "protocol_versions": versions,
        "federation": cfg.federation.enabled,
        "features": features,
    }))
    .into_response()
}

// ---- /v1 ---------------------------------------------------------------------------------

async fn v1_info(State(st): State<AppState>) -> Response {
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

async fn v1_post(
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
            let mut resp = err(R, StatusCode::TOO_MANY_REQUESTS, format!("Rate limit exceeded; retry in {s} s."));
            if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
            resp
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
pub fn challenge_issued(challenge: &str, now_s: i64, window_s: i64) -> Option<i64> {
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

async fn v1_pull(
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
        let mut resp = err(R, StatusCode::TOO_MANY_REQUESTS, format!("Too many failed signatures; retry in {s} s."));
        if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return resp;
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

async fn v1_made(
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

// ---- test knob ---------------------------------------------------------------------------

/// `POST /test/stall {address, seconds}`: the relay delivers nothing to that mailbox for the
/// given seconds (0 ends it). Only with `test.stall_endpoint`, only from loopback.
async fn test_stall(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    if !canon(peer.ip()).is_loopback() || headers.contains_key("x-forwarded-for") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(Json(v)) = body else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error":"body must be {address, seconds}"}))).into_response();
    };
    let key = match v.get("address").and_then(|a| a.as_str()).map(parse_address) {
        Some(Ok(a)) => a.public_key,
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error":"malformed address"}))).into_response(),
    };
    let Some(seconds) = v.get("seconds").and_then(|s| s.as_u64()) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error":"seconds must be a number"}))).into_response();
    };
    st.relay.stall(&key, seconds);
    if seconds == 0 {
        st.relay.registry.wake(&key);
    }
    tracing::info!(seconds, "test stall set");
    Json(json!({"ok": true, "seconds": seconds})).into_response()
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
    fn forwarded_for_only_through_trusted_proxies() {
        let trusted: Vec<IpNet> = vec!["127.0.0.1/32".parse().unwrap(), "10.0.0.0/8".parse().unwrap()];
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 1.2.3.4, 10.0.0.5".parse().unwrap());
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let public: SocketAddr = "9.9.9.9:5000".parse().unwrap();
        assert_eq!(client_ip(local, &h, &trusted), "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(public, &h, &trusted), "9.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(local, &HeaderMap::new(), &trusted), "127.0.0.1".parse::<IpAddr>().unwrap());
    }
}
