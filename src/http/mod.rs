//! HTTP: the websocket upgrade (any path, as the stock relay), health and readiness, metrics,
//! a status document, the info document, the page a browser gets at `/` (`landing.rs`), the
//! HTTPS mailbox API (`v1.rs`) and the test stall knob.

mod landing;
mod v1;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipnet::IpNet;
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::{json, Value};

use crate::address::parse_address;
use crate::limits::SocketRefusal;
use crate::relay::{session, Relay};

/// The /v1 protocol name, as reported by `/v1/info` and the info document.
pub const HTTPS_PROTOCOL: &str = "epicbox-https/0.1";
/// Initial websocket read buffer; it grows as a large frame arrives.
const WS_READ_BUFFER: usize = 8 * 1024;

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
            .route("/v1/info", get(v1::info))
            .route("/v1/post", post(v1::post))
            .route("/v1/pull", post(v1::pull))
            .route("/v1/made", post(v1::made));
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

/// Set once the untrusted X-Forwarded-For warning has been logged.
static XFF_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The client address. X-Forwarded-For is read only when the connection comes from a trusted
/// proxy, and then from the right: the first address that is not a trusted proxy is the client.
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let mut ip = canon(peer.ip());
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(&ip) {
        if headers.contains_key("x-forwarded-for") && !XFF_WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                peer_net = %crate::limits::ip_prefix(ip, 24, 48),
                "X-Forwarded-For ignored from an untrusted peer; add the proxy to server.trusted_proxies if it is yours (logged once)"
            );
        }
        return ip;
    }
    let hops: Vec<&str> =
        headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).collect();
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

/// 429 with the wait in both the error text and `Retry-After`.
fn too_many(route: &'static str, message: String, retry_s: u64) -> Response {
    let mut resp = err(route, StatusCode::TOO_MANY_REQUESTS, message);
    if let Ok(v) = HeaderValue::from_str(&retry_s.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

async fn fallback(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let relay = st.relay.clone();
    let ws = match ws {
        Ok(ws) => ws,
        Err(_) if method == Method::GET => {
            if relay.cfg.server.landing_page && uri.path() == "/" && landing::wanted(&headers) {
                count("landing", StatusCode::OK);
                return landing::page();
            }
            return (StatusCode::OK, "Epicbox relay. Connect with a websocket.\n").into_response();
        }
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    if relay.draining.load(Ordering::Relaxed) {
        return (StatusCode::SERVICE_UNAVAILABLE, "Relay restarting.\n").into_response();
    }
    if headers.get(crate::relay::INSTANCE_HEADER).is_some_and(|v| v.as_bytes() == relay.instance_id.as_bytes()) {
        metrics::counter!("epicbox_forward_loops_total").increment(1);
        return (StatusCode::LOOP_DETECTED, "This relay forwarded to itself.\n").into_response();
    }
    let ip = client_ip(peer, &headers, &relay.cfg.server.trusted_proxies);
    let permit = match relay.limiter.open_socket(ip) {
        Ok(p) => p,
        Err(SocketRefusal::Total) => {
            relay.limiter.refused("sockets_total", ip);
            return (StatusCode::SERVICE_UNAVAILABLE, "Relay is full.\n").into_response();
        }
        Err(SocketRefusal::PerIp) => {
            relay.limiter.refused("sockets_per_ip", ip);
            return (StatusCode::TOO_MANY_REQUESTS, "Too many connections from this network.\n").into_response();
        }
    };
    let max = relay.cfg.limits.max_frame_bytes;
    // Small socket buffers: the 128 KiB defaults make every idle socket hold that much memory.
    // Reads grow past 8 KiB as a large frame arrives; writes go out at each flush.
    ws.read_buffer_size(WS_READ_BUFFER)
        .write_buffer_size(0)
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| session::run(relay, socket, ip, permit))
}

async fn health() -> &'static str {
    "ok\n"
}

/// `/ready` writes to the store at most this often; probes in between get the last result.
const READY_PROBE_EVERY: Duration = Duration::from_secs(5);

async fn ready(State(st): State<AppState>) -> Response {
    let r = &st.relay;
    if r.draining.load(Ordering::Relaxed) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ready":false,"reason":"draining"}))).into_response();
    }
    // /ready is reachable through the proxy, so a flood of probes must not become a flood of
    // commits.
    let probe = {
        let mut last = r.last_ready_probe.lock();
        let due = last.is_none_or(|t| t.elapsed() >= READY_PROBE_EVERY);
        if due {
            *last = Some(Instant::now());
        }
        due
    };
    if !probe {
        return if r.store_ok.load(Ordering::Relaxed) {
            Json(json!({"ready":true})).into_response()
        } else {
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ready":false,"reason":"store"}))).into_response()
        };
    }
    match r.store.check_writable().await {
        Ok(()) => {
            r.store_ok.store(true, Ordering::Relaxed);
            Json(json!({"ready":true})).into_response()
        }
        Err(e) => {
            crate::sampled!(error, error = %e, "store write check failed");
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

/// Aggregate counts only: no addresses, keys or IPs. Store totals come from the last
/// housekeeping round (every 15 s), so a public request never scans the tables.
async fn status(State(st): State<AppState>) -> Response {
    let r = &st.relay;
    let (mailboxes, mux, classic) = r.registry.counts();
    let stats = r.last_stats.lock().clone();
    Json(json!({
        "name": r.cfg.server.name,
        "identity": format!("{}:{}", r.cfg.server.domain, r.cfg.server.port),
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

/// Publishes what a client needs: no exact version, no per-IP abuse thresholds.
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
                    "ids_per_ack": session::MAX_ACK_IDS,
                    "hold_max_s": session::HOLD_MAX_S,
                    "waiting_frames_per_min": session::WAITING_PER_MIN,
                    "attach_frames_per_min": l.mux_attach_frames_per_min,
                }
            }),
        );
    }
    if cfg.protocol.mux && cfg.protocol.cancel {
        features.insert("txcancel/1".into(), json!({}));
    }
    if cfg.protocol.cancel {
        features.insert(
            crate::relay::CANCEL_SEPARATED_EXT.into(),
            json!({
                "signed_text": format!("{}<txid>", crate::relay::CANCEL_SIG_PREFIX),
                "bare_accepted": cfg.protocol.accept_bare_cancel,
            }),
        );
    }
    if cfg.protocol.mux {
        features.insert(
            crate::relay::ATTACH_HOST_EXT.into(),
            json!({
                "signed_text": format!("{}<host>:<challenge>", crate::relay::ATTACH_SIG_PREFIX),
                "bare_accepted": cfg.protocol.accept_bare_attach,
            }),
        );
    }
    if cfg.http_api.enabled {
        features.insert("https".into(), json!({"protocol": HTTPS_PROTOCOL, "base": "/v1"}));
    }
    Json(json!({
        "software": "epicmail",
        "name": cfg.server.name,
        "identity": format!("{}:{}", cfg.server.domain, cfg.server.port),
        "protocol_versions": versions,
        "federation": cfg.federation.enabled,
        "features": features,
    }))
    .into_response()
}

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
