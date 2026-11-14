//! Load generator for a local relay: many subscribed classic 3.0.0 listeners, senders posting at
//! a fixed rate, and the latency from post to delivery.
//!
//! Each listener answers Slate with Made and every Challenge with Subscribe, like the classic
//! wallet. Clients bind to source addresses in 127.0.0.0/8 so the relay's per-prefix limits see
//! many /24 prefixes (senders 127.1.x.y, listeners 127.2.x.y), as real traffic would.
//!
//!   cargo run --release --example loadgen -- --url ws://127.0.0.1:3430/ --domain loadtest.local \
//!       --listeners 20000 --rate 500 --duration 120 --pid <relay pid>

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use rand::RngExt;
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use tokio::net::TcpSocket;
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use epicmail::sig;

#[derive(Parser, Clone)]
struct Args {
    /// Relay websocket URL.
    #[arg(long, default_value = "ws://127.0.0.1:3430/")]
    url: String,
    /// The relay's domain; addresses are `key@domain` (port 443).
    #[arg(long, default_value = "loadtest.local")]
    domain: String,
    /// Subscribed listener sockets, one key each.
    #[arg(long, default_value_t = 1000)]
    listeners: usize,
    /// Sender sockets; default rate / 10.
    #[arg(long)]
    senders: Option<usize>,
    /// PostSlate frames per second, all senders together. 0 holds the listeners idle.
    #[arg(long, default_value_t = 100)]
    rate: u64,
    /// Seconds of posting (or idle holding when rate is 0).
    #[arg(long, default_value_t = 60)]
    duration: u64,
    /// Size of the encrypted_message field in bytes.
    #[arg(long, default_value_t = 2048)]
    payload: usize,
    /// Source /24 prefixes to spread clients over.
    #[arg(long, default_value_t = 250)]
    prefixes: usize,
    /// Parallel connection attempts while connecting listeners.
    #[arg(long, default_value_t = 256)]
    connect_parallel: usize,
    /// Relay process id, for RSS and CPU samples.
    #[arg(long)]
    pid: Option<u32>,
    /// Seconds to wait after posting stops for outstanding deliveries.
    #[arg(long, default_value_t = 30)]
    drain: u64,
}

#[derive(Default)]
struct Stats {
    subscribed: AtomicU64,
    connect_failed: AtomicU64,
    listener_closed: AtomicU64,
    posted: AtomicU64,
    post_ok: AtomicU64,
    post_err: AtomicU64,
    post_timeout: AtomicU64,
    delivered: AtomicU64,
    duplicates: AtomicU64,
    ok_frames: AtomicU64,
    errors_seen: Mutex<Vec<String>>,
    post_lat_us: Mutex<Vec<u32>>,
    deliver_lat_us: Mutex<Vec<u32>>,
}

struct Key {
    secret: SecretKey,
    pk: String,
}

impl Key {
    fn new() -> Self {
        let secret = SecretKey::from_secret_bytes(rand::random()).unwrap();
        let pk = sig::encode_public_key(&PublicKey::from_secret_key(&secret), sig::VERSION_MAINNET);
        Key { secret, pk }
    }
}

fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

type Ws = WebSocketStream<tokio::net::TcpStream>;

async fn connect(url: &str, target: SocketAddr, src: Ipv4Addr) -> anyhow::Result<Ws> {
    let sock = TcpSocket::new_v4()?;
    sock.bind(SocketAddr::new(src.into(), 0))?;
    let stream = tokio::time::timeout(Duration::from_secs(10), sock.connect(target)).await??;
    stream.set_nodelay(true)?;
    let (ws, _) = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::client_async(url, stream)).await??;
    Ok(ws)
}

fn src_ip(second: u8, i: usize, prefixes: usize) -> Ipv4Addr {
    let p = (i % prefixes) as u8;
    let host = 1 + ((i / prefixes) % 250) as u8;
    Ipv4Addr::new(127, second, p, host)
}

fn text(v: Value) -> Message {
    Message::Text(v.to_string().into())
}

fn record_err(st: &Stats, v: &Value) {
    let mut e = st.errors_seen.lock();
    if e.len() < 20 {
        e.push(v.to_string().chars().take(200).collect());
    }
}

async fn listener(args: Arc<Args>, target: SocketAddr, i: usize, key: Arc<Key>, st: Arc<Stats>, sem: Arc<Semaphore>) {
    let permit = sem.acquire_owned().await.unwrap();
    let mut ws = match connect(&args.url, target, src_ip(2, i, args.prefixes)).await {
        Ok(w) => w,
        Err(_) => {
            st.connect_failed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut first_ok = true;
    let mut permit = Some(permit);
    while let Some(m) = ws.next().await {
        let Ok(Message::Text(t)) = m else {
            if matches!(m, Ok(Message::Close(_)) | Err(_)) {
                break;
            }
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&t) else { continue };
        match v["type"].as_str().unwrap_or("") {
            "Challenge" => {
                let ch = v["str"].as_str().unwrap_or("");
                let f =
                    json!({"type":"Subscribe","address":key.pk,"ver":"3.0.0","signature":sig::sign(&key.secret, ch)});
                if ws.send(text(f)).await.is_err() {
                    break;
                }
            }
            "Ok" => {
                if first_ok {
                    first_ok = false;
                    st.subscribed.fetch_add(1, Ordering::Relaxed);
                    permit.take();
                } else {
                    st.ok_frames.fetch_add(1, Ordering::Relaxed);
                }
            }
            "Slate" => {
                let msgid = v["epicboxmsgid"].as_str().unwrap_or("").to_string();
                if !seen.insert(msgid.clone()) {
                    st.duplicates.fetch_add(1, Ordering::Relaxed);
                } else {
                    st.delivered.fetch_add(1, Ordering::Relaxed);
                    let sent = v["str"]
                        .as_str()
                        .and_then(|s| serde_json::from_str::<Value>(s).ok())
                        .and_then(|b| b["encrypted_message"].as_str().map(|e| e[..16].to_string()))
                        .and_then(|h| u64::from_str_radix(&h, 16).ok());
                    if let Some(sent) = sent {
                        st.deliver_lat_us.lock().push(now_us().saturating_sub(sent).min(u32::MAX as u64) as u32);
                    }
                }
                let f = json!({"type":"Made","address":key.pk,"signature":sig::sign(&key.secret, &msgid),"epicboxmsgid":msgid,"ver":"3.0.0"});
                if ws.send(text(f)).await.is_err() {
                    break;
                }
            }
            _ => record_err(&st, &v),
        }
    }
    if first_ok {
        st.connect_failed.fetch_add(1, Ordering::Relaxed);
    } else {
        st.listener_closed.fetch_add(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
async fn sender(
    args: Arc<Args>,
    target: SocketAddr,
    i: usize,
    per_sender: f64,
    keys: Arc<Vec<Arc<Key>>>,
    st: Arc<Stats>,
    stop: Instant,
) {
    let me = Key::new();
    let Ok(mut ws) = connect(&args.url, target, src_ip(1, i, args.prefixes)).await else {
        st.connect_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // The first frame is the Challenge.
    let _ = tokio::time::timeout(Duration::from_secs(10), ws.next()).await;
    let pad = "0".repeat(args.payload.saturating_sub(24));
    let gap = Duration::from_secs_f64(1.0 / per_sender);
    // Spread the senders' start times over one gap.
    let jitter: f64 = rand::rng().random_range(0.0..1.0);
    tokio::time::sleep(gap.mul_f64(jitter)).await;
    let mut tick = tokio::time::interval(gap);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut seq: u32 = 0;
    while Instant::now() < stop {
        tick.tick().await;
        let pick: usize = rand::rng().random_range(0..keys.len());
        let to = &keys[pick];
        seq = seq.wrapping_add(1);
        let t0 = now_us();
        let body = json!({
            "destination": {"public_key": to.pk, "domain": args.domain, "port": 443},
            "encrypted_message": format!("{t0:016x}{seq:08x}{pad}"), "salt": "00", "nonce": "00"
        })
        .to_string();
        let f = json!({"type":"PostSlate","from":format!("{}@{}", me.pk, args.domain),
            "to":format!("{}@{}", to.pk, args.domain),"str":body,"signature":sig::sign(&me.secret, &body)});
        st.posted.fetch_add(1, Ordering::Relaxed);
        if ws.send(text(f)).await.is_err() {
            break;
        }
        // Wait for this post's answer, skipping interval Challenges.
        let answer = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(Ok(m)) = ws.next().await {
                if let Message::Text(t) = m {
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        if v["type"] != "Challenge" {
                            return Some(v);
                        }
                    }
                }
            }
            None
        })
        .await;
        match answer {
            Ok(Some(v)) if v["type"] == "Ok" => {
                st.post_ok.fetch_add(1, Ordering::Relaxed);
                st.post_lat_us.lock().push((now_us() - t0).min(u32::MAX as u64) as u32);
            }
            Ok(Some(v)) => {
                st.post_err.fetch_add(1, Ordering::Relaxed);
                record_err(&st, &v);
            }
            Ok(None) => break,
            Err(_) => {
                st.post_timeout.fetch_add(1, Ordering::Relaxed);
            }
        };
    }
    let _ = ws.close(None).await;
}

fn pct(v: &mut [u32], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_unstable();
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i] as f64 / 1000.0
}

fn proc_sample(pid: Option<u32>) -> Option<(u64, f64, u64)> {
    let pid = pid?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_kb: u64 = status.lines().find(|l| l.starts_with("VmRSS:"))?.split_whitespace().nth(1)?.parse().ok()?;
    let threads: u64 = status.lines().find(|l| l.starts_with("Threads:"))?.split_whitespace().nth(1)?.parse().ok()?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    let f: Vec<&str> = after.split_whitespace().collect();
    let ticks: u64 = f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?;
    Some((rss_kb, ticks as f64 / 100.0, threads))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arc::new(Args::parse());
    let u = url::Url::parse(&args.url)?;
    let target: SocketAddr = format!("{}:{}", u.host_str().unwrap_or("127.0.0.1"), u.port().unwrap_or(80)).parse()?;
    let st = Arc::new(Stats::default());
    let t_start = Instant::now();
    let base = proc_sample(args.pid);

    // Phase 1: listeners.
    let keys: Arc<Vec<Arc<Key>>> = Arc::new((0..args.listeners).map(|_| Arc::new(Key::new())).collect());
    let sem = Arc::new(Semaphore::new(args.connect_parallel));
    for (i, k) in keys.iter().enumerate() {
        tokio::spawn(listener(args.clone(), target, i, k.clone(), st.clone(), sem.clone()));
    }
    loop {
        let done = st.subscribed.load(Ordering::Relaxed) + st.connect_failed.load(Ordering::Relaxed);
        if done as usize >= args.listeners || t_start.elapsed() > Duration::from_secs(600) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let connect_s = t_start.elapsed().as_secs_f64();
    let after_connect = proc_sample(args.pid);
    println!(
        "listeners: {} subscribed, {} failed, in {:.1} s; relay {}",
        st.subscribed.load(Ordering::Relaxed),
        st.connect_failed.load(Ordering::Relaxed),
        connect_s,
        after_connect.map(|(r, c, t)| format!("rss {} MiB, cpu {c:.1} s, threads {t}", r / 1024)).unwrap_or_default()
    );

    // Phase 2: posting.
    let t_post = Instant::now();
    let stop = t_post + Duration::from_secs(args.duration);
    let senders = if args.rate == 0 { 0 } else { args.senders.unwrap_or(((args.rate as usize) / 10).max(1)) };
    let per_sender = args.rate as f64 / senders.max(1) as f64;
    let mut handles = Vec::new();
    for i in 0..senders {
        handles.push(tokio::spawn(sender(args.clone(), target, i, per_sender, keys.clone(), st.clone(), stop)));
    }
    let mut last = (0u64, 0u64, Instant::now(), proc_sample(args.pid));
    let mut peak_rss = after_connect.map(|s| s.0).unwrap_or(0);
    while Instant::now() < stop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let (p, d) = (st.post_ok.load(Ordering::Relaxed), st.delivered.load(Ordering::Relaxed));
        let now = Instant::now();
        let s = proc_sample(args.pid);
        let dt = now.duration_since(last.2).as_secs_f64();
        let cpu = match (s, last.3) {
            (Some(a), Some(b)) => format!(", relay rss {} MiB, cpu {:.0}%", a.0 / 1024, (a.1 - b.1) / dt * 100.0),
            _ => String::new(),
        };
        if let Some(a) = s {
            peak_rss = peak_rss.max(a.0);
        }
        println!(
            "t+{:>4.0}s posts ok {:>7.1}/s, delivered {:>7.1}/s, errors {}, timeouts {}, listeners closed {}{cpu}",
            t_post.elapsed().as_secs_f64(),
            (p - last.0) as f64 / dt,
            (d - last.1) as f64 / dt,
            st.post_err.load(Ordering::Relaxed),
            st.post_timeout.load(Ordering::Relaxed),
            st.listener_closed.load(Ordering::Relaxed),
        );
        last = (p, d, now, s);
    }
    for h in handles {
        let _ = h.await;
    }
    let post_s = t_post.elapsed().as_secs_f64();

    // Phase 3: drain.
    let drain_until = Instant::now() + Duration::from_secs(args.drain);
    while st.delivered.load(Ordering::Relaxed) < st.post_ok.load(Ordering::Relaxed) && Instant::now() < drain_until {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let end = proc_sample(args.pid);
    if let Some(a) = end {
        peak_rss = peak_rss.max(a.0);
    }

    let mut pl = std::mem::take(&mut *st.post_lat_us.lock());
    let mut dl = std::mem::take(&mut *st.deliver_lat_us.lock());
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let summary = json!({
        "listeners": args.listeners, "subscribed": g(&st.subscribed), "connect_failed": g(&st.connect_failed),
        "connect_seconds": (connect_s * 10.0).round() / 10.0,
        "senders": senders, "rate_target": args.rate, "duration_s": args.duration, "payload_bytes": args.payload,
        "posted": g(&st.posted), "post_ok": g(&st.post_ok), "post_err": g(&st.post_err), "post_timeout": g(&st.post_timeout),
        "post_ok_per_s": (g(&st.post_ok) as f64 / post_s * 10.0).round() / 10.0,
        "delivered": g(&st.delivered), "duplicates": g(&st.duplicates), "ok_frames": g(&st.ok_frames),
        "undelivered": g(&st.post_ok).saturating_sub(g(&st.delivered)),
        "listeners_closed": g(&st.listener_closed),
        "post_ms": {"p50": pct(&mut pl, 0.5), "p99": pct(&mut pl, 0.99), "max": pct(&mut pl, 1.0)},
        "deliver_ms": {"p50": pct(&mut dl, 0.5), "p99": pct(&mut dl, 0.99), "max": pct(&mut dl, 1.0)},
        "relay": {
            "rss_mib_start": base.map(|s| s.0 / 1024), "rss_mib_after_connect": after_connect.map(|s| s.0 / 1024),
            "rss_mib_peak_sampled": peak_rss / 1024, "rss_mib_end": end.map(|s| s.0 / 1024),
            "cpu_s_posting": match (last.3, after_connect) { (Some(a), Some(b)) => Some(((a.1 - b.1) * 10.0).round() / 10.0), _ => None },
        },
        "errors_sample": *st.errors_seen.lock(),
    });
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
