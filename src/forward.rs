//! Forwards to other relays. One lane per peer (`domain:port`), at most `federation.max_lanes`
//! at once. Every forward uses its own connection: wait for the peer's Challenge, send the stored
//! frame, read until `Ok`, `TransactionCancelled` or `Error`. No state is shared between forwards.
//!
//! The peer name is resolved here and every address is vetted: private, loopback, link-local and
//! other special ranges are refused unless `federation.allow_private` is set. The TCP connection
//! goes to the vetted address and TLS checks the certificate against the peer's domain, so a DNS
//! answer cannot point the relay at an internal service. `federation.peers` overrides the URL for
//! a peer (operator-configured, not vetted).

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;

use crate::clock::now_ms;
use crate::relay::Relay;
use crate::store::ForwardRow;

const TICK: Duration = Duration::from_secs(5);
const BATCH: usize = 50;
/// A peer that answers `Error` this many times for one frame has refused it for good.
const MAX_REFUSALS: i64 = 3;
const BACKOFF_BASE_MS: i64 = 5_000;
const BACKOFF_MAX_MS: i64 = 3_600_000;
/// Longest wait for a TCP connection. A peer that drops SYNs must not hold a lane for the whole
/// `federation.timeout_s`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Peers that failed to answer at all, with when to try them next (unix ms) and how many times
/// in a row they failed. One unreachable peer then costs one attempt per backoff period, not
/// one per queued row, so it cannot keep every lane busy.
#[derive(Default)]
pub struct PeerBackoff {
    map: Mutex<std::collections::HashMap<String, (i64, i64)>>,
}

impl PeerBackoff {
    /// True when `peer` may be tried at `now`.
    pub fn ready(&self, peer: &str, now: i64) -> bool {
        self.map.lock().get(peer).is_none_or(|(until, _)| *until <= now)
    }
    /// Record a failure; returns the time of the next try.
    pub fn failed(&self, peer: &str, now: i64) -> i64 {
        let mut m = self.map.lock();
        let e = m.entry(peer.to_string()).or_insert((0, 0));
        e.1 += 1;
        e.0 = now + backoff_ms(e.1);
        e.0
    }
    pub fn ok(&self, peer: &str) {
        self.map.lock().remove(peer);
    }
    /// Forget peers whose backoff ended long ago.
    pub fn prune(&self, now: i64) {
        self.map.lock().retain(|_, (until, _)| *until + BACKOFF_MAX_MS > now);
    }
}

/// Delay before the next try after `attempts` failures: 5 s, doubling, at most an hour.
pub fn backoff_ms(attempts: i64) -> i64 {
    let n = attempts.clamp(0, 20) as u32;
    BACKOFF_BASE_MS.saturating_mul(1i64 << n).min(BACKOFF_MAX_MS)
}

/// Addresses a relay may connect to without `allow_private`.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
                || v.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
                || o[0] >= 240)
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return is_public(IpAddr::V4(m));
            }
            let s = v.segments();
            let o = v.octets();
            // Transition ranges that carry an IPv4 address: judge that address. Through a NAT64
            // gateway (64:ff9b::/96) or a 6to4 relay (2002::/16) a public-looking IPv6 address
            // can reach a private IPv4 one.
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                return is_public(IpAddr::V4(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15])));
            }
            if s[0] == 0x2002 {
                return is_public(IpAddr::V4(std::net::Ipv4Addr::new(o[2], o[3], o[4], o[5])));
            }
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x2001 && s[1] == 0x0000) // 2001::/32 Teredo: the real address is hidden
                || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site local (deprecated)
                || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 1) // 64:ff9b:1::/48 local NAT64
                || s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0)
            // ::/96 compat
        }
    }
}

/// Runs until shutdown.
pub async fn run(relay: Arc<Relay>) {
    let lanes: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let backoff = Arc::new(PeerBackoff::default());
    let tls = Arc::new(tls_config());
    let mut shutdown = relay.shutdown.subscribe();
    loop {
        if relay.cfg.federation.enabled {
            let now = now_ms();
            backoff.prune(now);
            match relay.store.forward_peers_due(now).await {
                Ok(peers) => {
                    for peer in peers {
                        if !backoff.ready(&peer, now) {
                            continue;
                        }
                        let mut l = lanes.lock();
                        if l.contains(&peer) || l.len() >= relay.cfg.federation.max_lanes.max(1) {
                            continue;
                        }
                        l.insert(peer.clone());
                        drop(l);
                        let (relay, lanes, tls, backoff) = (relay.clone(), lanes.clone(), tls.clone(), backoff.clone());
                        tokio::spawn(async move {
                            lane(&relay, &peer, tls, &backoff).await;
                            lanes.lock().remove(&peer);
                        });
                    }
                }
                Err(e) => crate::sampled!(error, error = %e, "forward queue read failed"),
            }
        }
        metrics::gauge!("epicbox_forward_lanes").set(lanes.lock().len() as f64);
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = relay.forward_notify.notified() => {}
            _ = shutdown.changed() => return,
        }
    }
}

fn tls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
}

async fn lane(relay: &Arc<Relay>, peer: &str, tls: Arc<rustls::ClientConfig>, backoff: &PeerBackoff) {
    loop {
        let rows = match relay.store.forwards_due(peer, now_ms(), BATCH).await {
            Ok(r) if !r.is_empty() => r,
            Ok(_) => return,
            Err(e) => {
                crate::sampled!(error, error = %e, "forward queue read failed");
                return;
            }
        };
        // Rows queued under an older config (or imported) may name a peer the policy now
        // refuses: drop them instead of connecting.
        if !relay.peer_allowed(peer) {
            metrics::counter!("epicbox_forwards_total", "result" => "policy").increment(rows.len() as u64);
            crate::sampled!(warn, peer, rows = rows.len(), "dropping forwards the federation policy refuses");
            for row in rows {
                if let Err(e) = relay.store.forward_failed(row.id, now_ms(), "refused by federation policy", true).await
                {
                    crate::sampled!(error, error = %e, "forward bookkeeping failed");
                    return;
                }
            }
            continue;
        }
        for row in rows {
            let timeout = Duration::from_secs(relay.cfg.federation.timeout_s.max(1));
            let res = tokio::time::timeout(timeout, deliver(relay, peer, &row, tls.clone())).await;
            let res = res.unwrap_or_else(|_| Err(Failure::Transport("timed out".into())));
            let attempts = row.attempts + 1;
            let r = match res {
                Ok(()) => {
                    backoff.ok(peer);
                    metrics::counter!("epicbox_forwards_total", "result" => "ok").increment(1);
                    tracing::debug!(peer, kind = ?row.kind, "forwarded");
                    relay.store.forward_done(row.id).await
                }
                Err(Failure::Refused(e)) => {
                    let drop = attempts >= MAX_REFUSALS;
                    metrics::counter!("epicbox_forwards_total", "result" => "refused").increment(1);
                    // The text is the peer's: logged escaped, so it cannot add lines to our log.
                    crate::sampled!(warn, peer, error = ?e, attempts, dropped = drop, "peer refused forward");
                    relay.store.forward_failed(row.id, now_ms() + backoff_ms(attempts), &e, drop).await
                }
                Err(Failure::Loop) => {
                    metrics::counter!("epicbox_forwards_total", "result" => "loop").increment(1);
                    crate::sampled!(warn, peer, "forward dropped: the peer is this relay under another name");
                    relay.store.forward_failed(row.id, now_ms(), "forward loop", true).await
                }
                Err(Failure::Transport(e)) => {
                    metrics::counter!("epicbox_forwards_total", "result" => "failed").increment(1);
                    // The whole peer waits, not only this row.
                    let next = backoff.failed(peer, now_ms());
                    crate::sampled!(warn, peer, error = ?e, attempts, retry_in_s = (next - now_ms()) / 1000, "forward failed");
                    let r =
                        relay.store.forward_failed(row.id, next.max(now_ms() + backoff_ms(attempts)), &e, false).await;
                    // The peer is unreachable: leave the rest of the batch for the next round.
                    if let Err(e) = r {
                        crate::sampled!(error, error = %e, "forward bookkeeping failed");
                    }
                    return;
                }
            };
            if let Err(e) = r {
                crate::sampled!(error, error = %e, "forward bookkeeping failed");
                return;
            }
        }
    }
}

enum Failure {
    /// The peer answered Error.
    Refused(String),
    /// No answer: DNS, TCP, TLS, timeout, closed.
    Transport(String),
    /// The peer is this relay under another name: never worth retrying.
    Loop,
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Failure::Transport(format!("{e:#}"))
    }
}

/// The URL and the vetted socket address for a peer.
async fn target(relay: &Relay, peer: &str) -> Result<(String, Option<SocketAddr>)> {
    let fed = &relay.cfg.federation;
    if let Some(url) = fed.peers.get(peer) {
        return Ok((url.clone(), None));
    }
    let (domain, port) = peer.rsplit_once(':').ok_or_else(|| anyhow!("bad peer name"))?;
    let port: u16 = port.parse().context("bad peer port")?;
    if relay.cfg.is_local(domain, port) {
        bail!("peer is this relay");
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((domain, port)).await.context("resolve")?.collect();
    let ok = addrs.iter().find(|a| fed.allow_private || is_public(a.ip())).copied();
    let Some(addr) = ok else {
        if addrs.is_empty() {
            bail!("no addresses");
        }
        bail!("peer resolves only to non-public addresses");
    };
    Ok((format!("wss://{domain}:{port}"), Some(addr)))
}

async fn deliver(relay: &Relay, peer: &str, row: &ForwardRow, tls: Arc<rustls::ClientConfig>) -> Result<(), Failure> {
    let (url, addr) = target(relay, peer).await?;
    let parsed = url::Url::parse(&url).map_err(|e| Failure::Transport(format!("url: {e}")))?;
    let addr = match addr {
        Some(a) => a,
        None => {
            let host = parsed.host_str().ok_or_else(|| Failure::Transport("url has no host".into()))?;
            let port = parsed.port_or_known_default().unwrap_or(443);
            tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| Failure::Transport(format!("resolve: {e}")))?
                .next()
                .ok_or_else(|| Failure::Transport("no addresses".into()))?
        }
    };
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| Failure::Transport("connect timed out".into()))?
        .map_err(|e| Failure::Transport(format!("connect: {e}")))?;
    let _ = tcp.set_nodelay(true);
    let mut cfg = WebSocketConfig::default();
    cfg.max_message_size = Some(relay.cfg.limits.max_frame_bytes);
    cfg.max_frame_size = Some(relay.cfg.limits.max_frame_bytes);
    let mut req = url.as_str().into_client_request().map_err(|e| Failure::Transport(format!("url: {e}")))?;
    if let Ok(v) = HeaderValue::from_str(&relay.instance_id) {
        req.headers_mut().insert(crate::relay::INSTANCE_HEADER, v);
    }
    let (mut ws, _) =
        tokio_tungstenite::client_async_tls_with_config(req, tcp, Some(cfg), Some(Connector::Rustls(tls)))
            .await
            .map_err(|e| match e {
                tokio_tungstenite::tungstenite::Error::Http(r) if r.status().as_u16() == 508 => Failure::Loop,
                e => Failure::Transport(format!("handshake: {e}")),
            })?;

    // The peer greets with a Challenge; the frame goes after it, as the stock relay does.
    let mut sent = false;
    while let Some(m) = ws.next().await {
        let m = m.map_err(|e| Failure::Transport(format!("read: {e}")))?;
        let t = match m {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break,
            _ => continue,
        };
        let v: Value = match serde_json::from_str(&t) {
            Ok(v) => v,
            Err(_) => continue, // "pong" and the like
        };
        let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("").to_ascii_lowercase();
        match ty.as_str() {
            "challenge" if !sent => {
                ws.send(Message::Text(row.frame.clone().into()))
                    .await
                    .map_err(|e| Failure::Transport(format!("send: {e}")))?;
                sent = true;
            }
            "ok" | "transactioncancelled" if sent => {
                let _ = ws.close(None).await;
                return Ok(());
            }
            "error" if sent => {
                let _ = ws.close(None).await;
                let d = v.get("description").and_then(|d| d.as_str()).unwrap_or("error");
                return Err(Failure::Refused(crate::logging::clean(d)));
            }
            _ => {}
        }
    }
    Err(Failure::Transport(if sent { "closed before an answer".into() } else { "closed before a challenge".into() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_transition_ranges_are_judged_by_their_ipv4() {
        let p = |a: &str| is_public(a.parse().unwrap());
        assert!(!p("64:ff9b::10.0.0.1"), "NAT64 to a private address");
        assert!(!p("64:ff9b::7f00:1"), "NAT64 to loopback");
        assert!(p("64:ff9b::8.8.8.8"), "NAT64 to a public address");
        assert!(!p("2002:0a00:0001::1"), "6to4 of 10.0.0.1");
        assert!(!p("2002:c0a8:0101::1"), "6to4 of 192.168.1.1");
        assert!(p("2002:0808:0808::1"), "6to4 of 8.8.8.8");
        assert!(!p("2001:0:4136:e378::1"), "Teredo");
        assert!(!p("fec0::1"), "site local");
        assert!(p("2606:4700::1111"), "ordinary public address");
    }

    #[test]
    fn an_unreachable_peer_waits_as_a_whole() {
        let b = PeerBackoff::default();
        assert!(b.ready("p:443", 0));
        let next = b.failed("p:443", 0);
        assert_eq!(next, backoff_ms(1));
        assert!(!b.ready("p:443", next - 1) && b.ready("p:443", next));
        assert!(b.ready("other:443", 1), "other peers are not held back");
        assert_eq!(b.failed("p:443", next), next + backoff_ms(2), "doubles while it keeps failing");
        b.ok("p:443");
        assert!(b.ready("p:443", next));
    }

    #[test]
    fn vetting() {
        for ip in [
            "10.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.1.2.3",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8", "100.128.0.1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_ms(0), 5_000);
        assert_eq!(backoff_ms(1), 10_000);
        assert_eq!(backoff_ms(30), BACKOFF_MAX_MS);
    }
}
