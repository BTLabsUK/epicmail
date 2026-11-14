//! Ordinary wallet traffic against one relay, for comparing relays under the same load: a
//! population of listening wallets that reconnect now and then, short sessions that connect,
//! check for mail and leave, and transactions where a sender posts a slate to a listener, the
//! listener answers with a slate back, and the sender collects it.
//!
//! Every wallet sends ClientDetails (wallet_mode "listener") before Subscribe, as wallets do; the
//! classic relay pushes mail live only to sockets that did. Clients bind to source addresses in
//! 127.0.0.0/8 so per-prefix limits see many /24s, so this runs on the relay host against its
//! loopback port.
//!
//!   daysim --url ws://127.0.0.1:3423/ --domain relay.example.org --listeners 2000 \
//!       --conn-rate 7 --tx-per-hour 1000 --duration 1800 --keys keys.txt --out minutes.jsonl
//!
//! Prints a line a minute, appends the same as JSON to --out, then a summary. Writes every
//! wallet's secret key to --keys and its public key to --keys.addrs, for cleaning up.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use serde_json::{json, Value};
use tokio::net::TcpSocket;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use epicmail::sig;

#[derive(Parser, Clone)]
struct Args {
    /// Relay websocket URL on its loopback port, e.g. ws://127.0.0.1:3423/.
    #[arg(long)]
    url: String,
    /// The relay's own domain; addresses are `key@domain` (port 443).
    #[arg(long)]
    domain: String,
    /// Wallets listening at any time.
    #[arg(long, default_value_t = 2000)]
    listeners: usize,
    /// Other wallets: short sessions and transaction senders.
    #[arg(long, default_value_t = 4000)]
    occasional: usize,
    /// Mean seconds a listener stays connected before it reconnects.
    #[arg(long, default_value_t = 1800.0)]
    listener_life: f64,
    /// New connections per second in total: listener reconnects, short sessions and senders.
    #[arg(long, default_value_t = 7.0)]
    conn_rate: f64,
    /// Transactions per hour (two slates each).
    #[arg(long, default_value_t = 1000.0)]
    tx_per_hour: f64,
    /// Seconds of traffic after the ramp.
    #[arg(long, default_value_t = 1800)]
    duration: u64,
    /// Seconds over which the listeners first connect.
    #[arg(long, default_value_t = 120)]
    ramp: u64,
    /// Size of each slate's encrypted_message in bytes.
    #[arg(long, default_value_t = 3000)]
    payload: usize,
    /// Source /24 prefixes to spread clients over.
    #[arg(long, default_value_t = 250)]
    prefixes: usize,
    /// Second octet of listener source addresses (127.N.x.y); other wallets use N+1.
    #[arg(long, default_value_t = 30)]
    second_octet: u8,
    /// File for every wallet's secret key (hex, one a line).
    #[arg(long)]
    keys: String,
    /// File the minute lines are appended to, as JSON.
    #[arg(long)]
    out: String,
}

struct Key {
    secret: SecretKey,
    pk: String,
}

impl Key {
    fn new() -> Self {
        let secret = SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let pk = sig::encode_public_key(&PublicKey::from_secret_key(SECP256K1, &secret), sig::VERSION_MAINNET);
        Key { secret, pk }
    }
    fn sign(&self, m: &str) -> String {
        sig::sign(&self.secret, m)
    }
}

#[derive(Default, Clone)]
struct Win {
    conn_ok: u64,
    conn_fail: u64,
    conn_ms: Vec<f32>,
    dropped: u64,
    short_done: u64,
    tx_started: u64,
    tx_done: u64,
    tx_timeout: u64,
    tx_ms: Vec<f32>,
    post_ok: u64,
    post_err: u64,
    post_ms: Vec<f32>,
    leg1_ms: Vec<f32>,
    leg2_ms: Vec<f32>,
    errors: BTreeMap<String, u64>,
}

impl Win {
    fn err(&mut self, e: impl Into<String>) {
        let e: String = e.into();
        *self.errors.entry(e.chars().take(80).collect()).or_insert(0) += 1;
    }
}

struct Shared {
    args: Args,
    target: SocketAddr,
    lkeys: Vec<Arc<Key>>,
    okeys: Vec<Arc<Key>>,
    online: Vec<AtomicBool>,
    online_n: AtomicI64,
    busy: Vec<AtomicBool>,
    active_tx: AtomicI64,
    stop: AtomicBool,
    stats: Mutex<(Win, Win)>,
    pad: String,
}

impl Shared {
    fn rec(&self, f: impl Fn(&mut Win)) {
        let mut s = self.stats.lock();
        f(&mut s.0);
        f(&mut s.1);
    }
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
    fn take_occ(&self) -> Option<usize> {
        for _ in 0..64 {
            let i = rand::random::<usize>() % self.okeys.len();
            if self.busy[i].compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return Some(i);
            }
        }
        None
    }
    fn release(&self, i: usize) {
        self.busy[i].store(false, Ordering::Release);
    }
    fn online_listener(&self) -> Option<usize> {
        for _ in 0..64 {
            let i = rand::random::<usize>() % self.lkeys.len();
            if self.online[i].load(Ordering::Relaxed) {
                return Some(i);
            }
        }
        None
    }
}

type Ws = WebSocketStream<tokio::net::TcpStream>;

fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

fn exp_sample(mean: f64) -> f64 {
    -mean * (1.0 - rand::random::<f64>()).ln()
}

fn src_ip(second: u8, i: usize, prefixes: usize) -> Ipv4Addr {
    let p = (i % prefixes) as u8;
    let host = 1 + ((i / prefixes) % 250) as u8;
    Ipv4Addr::new(127, second, p, host)
}

async fn connect(url: &str, target: SocketAddr, src: Ipv4Addr) -> Result<Ws, String> {
    let sock = TcpSocket::new_v4().map_err(|e| format!("socket {e}"))?;
    sock.bind(SocketAddr::new(src.into(), 0)).map_err(|e| format!("bind {e}"))?;
    let stream = tokio::time::timeout(Duration::from_secs(10), sock.connect(target))
        .await
        .map_err(|_| "tcp timeout".to_string())?
        .map_err(|e| format!("tcp {:?}", e.kind()))?;
    let _ = stream.set_nodelay(true);
    let (ws, _) = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::client_async(url, stream))
        .await
        .map_err(|_| "handshake timeout".to_string())?
        .map_err(|e| format!("handshake {e}"))?;
    Ok(ws)
}

fn text(v: &Value) -> Message {
    Message::Text(v.to_string().into())
}

/// Next JSON frame, or why there is none.
async fn next_json(ws: &mut Ws, t: Duration) -> Result<Value, String> {
    let deadline = Instant::now() + t;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, ws.next()).await {
            Err(_) => return Err("timeout".into()),
            Ok(None) => return Err("closed".into()),
            Ok(Some(Err(e))) => return Err(format!("ws {e}")),
            Ok(Some(Ok(Message::Text(s)))) => {
                return Ok(serde_json::from_str(&s).unwrap_or(Value::String(s.to_string())));
            }
            Ok(Some(Ok(Message::Close(c)))) => {
                return Err(format!("closed {}", c.map(|c| u16::from(c.code).to_string()).unwrap_or_default()))
            }
            Ok(Some(Ok(_))) => continue,
        }
    }
}

fn subscribe_frame(key: &Key, challenge: &str) -> Value {
    json!({"type":"Subscribe","address":key.pk,"ver":"3.0.0","signature":key.sign(challenge)})
}

/// Connect, send ClientDetails, Subscribe. Returns the socket and a Slate the relay sent instead of
/// Ok, if any.
async fn open(sh: &Shared, key: &Key, src: Ipv4Addr) -> Result<(Ws, Option<Value>), String> {
    let t0 = Instant::now();
    let mut ws = connect(&sh.args.url, sh.target, src).await?;
    let ch = next_json(&mut ws, Duration::from_secs(10)).await?;
    if ch["type"] != "Challenge" {
        return Err(format!("first frame {}", ch["type"]));
    }
    let details =
        json!({"type":"ClientDetails","wallet_version":"3.6.0","wallet_mode":"listener","protocol_version":"3.0.0"});
    ws.send(text(&details)).await.map_err(|e| format!("send {e}"))?;
    let ok = next_json(&mut ws, Duration::from_secs(10)).await?;
    if ok["type"] != "Ok" {
        return Err(format!("ClientDetails answer {}", ok["type"]));
    }
    let mut challenge = ch["str"].as_str().unwrap_or("").to_string();
    ws.send(text(&subscribe_frame(key, &challenge))).await.map_err(|e| format!("send {e}"))?;
    loop {
        let r = next_json(&mut ws, Duration::from_secs(10)).await?;
        match r["type"].as_str().unwrap_or("") {
            "Ok" => {
                let ms = t0.elapsed().as_secs_f32() * 1000.0;
                sh.rec(|w| {
                    w.conn_ok += 1;
                    w.conn_ms.push(ms);
                });
                return Ok((ws, None));
            }
            "Slate" => {
                let ms = t0.elapsed().as_secs_f32() * 1000.0;
                sh.rec(|w| {
                    w.conn_ok += 1;
                    w.conn_ms.push(ms);
                });
                return Ok((ws, Some(r)));
            }
            "Challenge" => {
                challenge = r["str"].as_str().unwrap_or("").to_string();
                ws.send(text(&subscribe_frame(key, &challenge))).await.map_err(|e| format!("send {e}"))?;
            }
            _ => return Err(format!("Subscribe answer {}", short(&r))),
        }
    }
}

fn short(v: &Value) -> String {
    let t = v["type"].as_str().unwrap_or("?");
    let d = v["description"].as_str().or(v["code"].as_str()).unwrap_or("");
    format!("{t} {d}").chars().take(80).collect()
}

/// (kind, sent microseconds, txid) from a slate this tool posted.
fn header(slate: &Value) -> Option<(char, u64, String)> {
    let body: Value = serde_json::from_str(slate["str"].as_str()?).ok()?;
    let em = body["encrypted_message"].as_str()?;
    if em.len() < 33 {
        return None;
    }
    let kind = em.chars().next()?;
    let t = u64::from_str_radix(&em[1..17], 16).ok()?;
    Some((kind, t, em[17..33].to_string()))
}

fn post_frame(sh: &Shared, from: &Key, to_pk: &str, kind: char, txid: &str) -> Value {
    let d = &sh.args.domain;
    let em = format!("{kind}{:016x}{txid}{}", now_us(), sh.pad);
    let body = json!({
        "destination": {"public_key": to_pk, "domain": d, "port": 443},
        "encrypted_message": em, "salt": "00", "nonce": "00"
    })
    .to_string();
    json!({"type":"PostSlate","from":format!("{}@{d}", from.pk),"to":format!("{to_pk}@{d}"),"str":body,"signature":from.sign(&body)})
}

fn made_frame(key: &Key, slate: &Value) -> Value {
    let id = slate["epicboxmsgid"].as_str().unwrap_or("");
    json!({"type":"Made","address":key.pk,"signature":key.sign(id),"epicboxmsgid":id,"ver":"3.0.0"})
}

/// A listener's answer to a Slate: Made, and for a first leg the second leg back to the sender.
async fn listener_slate(sh: &Shared, key: &Key, ws: &mut Ws, v: &Value) -> bool {
    if ws.send(text(&made_frame(key, v))).await.is_err() {
        return false;
    }
    if let Some(('1', t, txid)) = header(v) {
        let ms = now_us().saturating_sub(t) as f32 / 1000.0;
        sh.rec(|w| w.leg1_ms.push(ms));
        let sender = v["from"].as_str().unwrap_or("").split('@').next().unwrap_or("").to_string();
        if ws.send(text(&post_frame(sh, key, &sender, '2', &txid))).await.is_err() {
            return false;
        }
    }
    true
}

async fn listener(sh: Arc<Shared>, i: usize) {
    let key = sh.lkeys[i].clone();
    tokio::time::sleep(Duration::from_secs_f64(rand::random::<f64>() * sh.args.ramp as f64)).await;
    let mut first = true;
    while !sh.stopped() {
        let life =
            if first { rand::random::<f64>() * 2.0 * sh.args.listener_life } else { exp_sample(sh.args.listener_life) };
        first = false;
        let (mut ws, pending) = match open(&sh, &key, src_ip(sh.args.second_octet, i, sh.args.prefixes)).await {
            Ok(x) => x,
            Err(e) => {
                sh.rec(|w| {
                    w.conn_fail += 1;
                    w.err(format!("listener connect: {e}"));
                });
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        sh.online[i].store(true, Ordering::Relaxed);
        sh.online_n.fetch_add(1, Ordering::Relaxed);
        let mut ok = match &pending {
            Some(v) => listener_slate(&sh, &key, &mut ws, v).await,
            None => true,
        };
        let deadline = Instant::now() + Duration::from_secs_f64(life);
        let mut by_relay = None;
        while ok && !sh.stopped() && Instant::now() < deadline {
            match next_json(&mut ws, Duration::from_secs(1)).await {
                Err(e) if e == "timeout" => continue,
                Err(e) => {
                    by_relay = Some(e);
                    break;
                }
                Ok(v) => match v["type"].as_str().unwrap_or("") {
                    "Challenge" => {
                        let c = v["str"].as_str().unwrap_or("").to_string();
                        ok = ws.send(text(&subscribe_frame(&key, &c))).await.is_ok();
                    }
                    "Slate" => ok = listener_slate(&sh, &key, &mut ws, &v).await,
                    "Error" => sh.rec(|w| w.err(format!("listener got {}", short(&v)))),
                    _ => {}
                },
            }
        }
        sh.online[i].store(false, Ordering::Relaxed);
        sh.online_n.fetch_sub(1, Ordering::Relaxed);
        match by_relay {
            Some(e) => {
                sh.rec(|w| {
                    w.dropped += 1;
                    w.err(format!("listener ended: {e}"));
                });
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            None => {
                let _ = ws.close(None).await;
            }
        }
    }
}

async fn short_session(sh: Arc<Shared>) {
    let Some(a) = sh.take_occ() else {
        sh.rec(|w| w.err("no free wallet for a short session"));
        return;
    };
    let key = sh.okeys[a].clone();
    match open(&sh, &key, src_ip(sh.args.second_octet + 1, a, sh.args.prefixes)).await {
        Err(e) => sh.rec(|w| {
            w.conn_fail += 1;
            w.err(format!("short connect: {e}"));
        }),
        Ok((mut ws, pending)) => {
            if let Some(v) = pending {
                let _ = ws.send(text(&made_frame(&key, &v))).await;
            }
            let until = Instant::now() + Duration::from_secs_f64(5.0 + rand::random::<f64>() * 25.0);
            while Instant::now() < until {
                match next_json(&mut ws, Duration::from_secs(1)).await {
                    Err(e) if e == "timeout" => continue,
                    Err(_) => break,
                    Ok(v) => match v["type"].as_str().unwrap_or("") {
                        "Challenge" => {
                            let c = v["str"].as_str().unwrap_or("").to_string();
                            let _ = ws.send(text(&subscribe_frame(&key, &c))).await;
                        }
                        "Slate" => {
                            let _ = ws.send(text(&made_frame(&key, &v))).await;
                        }
                        _ => {}
                    },
                }
            }
            let _ = ws.close(None).await;
            sh.rec(|w| w.short_done += 1);
        }
    }
    sh.release(a);
}

async fn transaction(sh: Arc<Shared>) {
    let Some(b) = sh.online_listener() else {
        sh.rec(|w| w.err("no listener online for a transaction"));
        return;
    };
    let Some(a) = sh.take_occ() else {
        sh.rec(|w| w.err("no free sender for a transaction"));
        return;
    };
    sh.active_tx.fetch_add(1, Ordering::Relaxed);
    sh.rec(|w| w.tx_started += 1);
    let key = sh.okeys[a].clone();
    let to = sh.lkeys[b].pk.clone();
    match open(&sh, &key, src_ip(sh.args.second_octet + 1, a, sh.args.prefixes)).await {
        Err(e) => sh.rec(|w| {
            w.conn_fail += 1;
            w.err(format!("sender connect: {e}"));
        }),
        Ok((mut ws, pending)) => {
            if let Some(v) = pending {
                let _ = ws.send(text(&made_frame(&key, &v))).await;
            }
            let txid = format!("{:016x}", rand::random::<u64>());
            let t0 = Instant::now();
            let sent = ws.send(text(&post_frame(&sh, &key, &to, '1', &txid))).await.is_ok();
            if !sent {
                sh.rec(|w| w.err("sender could not send its post"));
            }
            let deadline = t0 + Duration::from_secs(120);
            let mut posted = false;
            if sent {
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        sh.rec(|w| w.tx_timeout += 1);
                        break;
                    }
                    match next_json(&mut ws, left.min(Duration::from_secs(5))).await {
                        Err(e) if e == "timeout" => continue,
                        Err(e) => {
                            sh.rec(|w| w.err(format!("sender socket: {e}")));
                            break;
                        }
                        Ok(v) => match v["type"].as_str().unwrap_or("") {
                            "Ok" if !posted => {
                                posted = true;
                                let ms = t0.elapsed().as_secs_f32() * 1000.0;
                                sh.rec(|w| {
                                    w.post_ok += 1;
                                    w.post_ms.push(ms);
                                });
                            }
                            "Error" if !posted => {
                                sh.rec(|w| {
                                    w.post_err += 1;
                                    w.err(format!("post refused: {}", short(&v)));
                                });
                                break;
                            }
                            "Challenge" => {
                                let c = v["str"].as_str().unwrap_or("").to_string();
                                let _ = ws.send(text(&subscribe_frame(&key, &c))).await;
                            }
                            "Slate" => {
                                let _ = ws.send(text(&made_frame(&key, &v))).await;
                                if let Some(('2', t, id)) = header(&v) {
                                    if id == txid {
                                        let leg2 = now_us().saturating_sub(t) as f32 / 1000.0;
                                        let tx = t0.elapsed().as_secs_f32() * 1000.0;
                                        sh.rec(|w| {
                                            w.leg2_ms.push(leg2);
                                            w.tx_done += 1;
                                            w.tx_ms.push(tx);
                                        });
                                        // Let the Made reach the relay before closing.
                                        let _ = next_json(&mut ws, Duration::from_millis(500)).await;
                                        break;
                                    }
                                }
                            }
                            _ => {}
                        },
                    }
                }
            }
            let _ = ws.close(None).await;
        }
    }
    sh.release(a);
    sh.active_tx.fetch_sub(1, Ordering::Relaxed);
}

/// Start `f` at random (Poisson) times, `rate` a second, until the run stops.
async fn poisson<F, Fut>(sh: Arc<Shared>, rate: f64, f: F)
where
    F: Fn(Arc<Shared>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    if rate <= 0.0 {
        return;
    }
    while !sh.stopped() {
        tokio::time::sleep(Duration::from_secs_f64(exp_sample(1.0 / rate))).await;
        if sh.stopped() {
            break;
        }
        tokio::spawn(f(sh.clone()));
    }
}

fn pct(v: &mut [f32], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    (v[i] as f64 * 10.0).round() / 10.0
}

fn summary(w: &mut Win) -> Value {
    json!({
        "conn_ok": w.conn_ok, "conn_fail": w.conn_fail,
        "conn_ms": {"p50": pct(&mut w.conn_ms, 0.5), "p99": pct(&mut w.conn_ms, 0.99), "max": pct(&mut w.conn_ms, 1.0)},
        "listener_drops": w.dropped, "short_sessions": w.short_done,
        "tx_started": w.tx_started, "tx_done": w.tx_done, "tx_timeout": w.tx_timeout,
        "tx_ms": {"p50": pct(&mut w.tx_ms, 0.5), "p99": pct(&mut w.tx_ms, 0.99), "max": pct(&mut w.tx_ms, 1.0)},
        "post_ok": w.post_ok, "post_err": w.post_err,
        "post_ms": {"p50": pct(&mut w.post_ms, 0.5), "p99": pct(&mut w.post_ms, 0.99)},
        "leg1_ms": {"p50": pct(&mut w.leg1_ms, 0.5), "p99": pct(&mut w.leg1_ms, 0.99)},
        "leg2_ms": {"p50": pct(&mut w.leg2_ms, 0.5), "p99": pct(&mut w.leg2_ms, 0.99)},
        "errors": w.errors,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let u = url::Url::parse(&args.url)?;
    let target: SocketAddr = format!("{}:{}", u.host_str().unwrap_or("127.0.0.1"), u.port().unwrap_or(80)).parse()?;
    let lkeys: Vec<Arc<Key>> = (0..args.listeners).map(|_| Arc::new(Key::new())).collect();
    let okeys: Vec<Arc<Key>> = (0..args.occasional).map(|_| Arc::new(Key::new())).collect();
    {
        let mut k = std::fs::File::create(&args.keys)?;
        let mut a = std::fs::File::create(format!("{}.addrs", args.keys))?;
        for key in lkeys.iter().chain(okeys.iter()) {
            writeln!(k, "{}", hex::encode(key.secret.secret_bytes()))?;
            writeln!(a, "{}", key.pk)?;
        }
    }
    let tx_rate = args.tx_per_hour / 3600.0;
    let reconnect_rate = args.listeners as f64 / args.listener_life;
    let short_rate = (args.conn_rate - reconnect_rate - tx_rate).max(0.0);
    println!(
        "listeners {}, reconnects {reconnect_rate:.2}/s, short sessions {short_rate:.2}/s, transactions {tx_rate:.3}/s",
        args.listeners
    );
    let sh = Arc::new(Shared {
        online: (0..args.listeners).map(|_| AtomicBool::new(false)).collect(),
        busy: (0..args.occasional).map(|_| AtomicBool::new(false)).collect(),
        online_n: AtomicI64::new(0),
        active_tx: AtomicI64::new(0),
        stop: AtomicBool::new(false),
        stats: Mutex::new((Win::default(), Win::default())),
        pad: "0".repeat(args.payload.saturating_sub(33)),
        target,
        lkeys,
        okeys,
        args: args.clone(),
    });
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(&args.out)?;

    for i in 0..args.listeners {
        tokio::spawn(listener(sh.clone(), i));
    }
    let t_start = Instant::now();
    // Ramp: listeners connect; report but start no sessions yet.
    let ramp_end = t_start + Duration::from_secs(args.ramp);
    let end = ramp_end + Duration::from_secs(args.duration);
    let mut started = false;
    let mut minute = 0u64;
    loop {
        let next = t_start + Duration::from_secs(60 * (minute + 1));
        let wake = if !started { next.min(ramp_end) } else { next.min(end) };
        tokio::time::sleep_until(wake.into()).await;
        if !started && Instant::now() >= ramp_end {
            started = true;
            tokio::spawn(poisson(sh.clone(), short_rate, short_session));
            tokio::spawn(poisson(sh.clone(), tx_rate, transaction));
            println!("ramp done: {} listeners online", sh.online_n.load(Ordering::Relaxed));
            if Instant::now() < next {
                continue;
            }
        }
        if Instant::now() >= next {
            minute += 1;
            let mut w = std::mem::take(&mut sh.stats.lock().0);
            let mut s = summary(&mut w);
            s["minute"] = json!(minute);
            s["phase"] = json!(if started { "run" } else { "ramp" });
            s["listeners_online"] = json!(sh.online_n.load(Ordering::Relaxed));
            s["unix"] = json!(now_us() / 1_000_000);
            writeln!(out, "{s}")?;
            println!(
                "min {minute:>3} {:<4} online {:>5} conn {:>5} fail {:>3} conn_p50 {:>6}ms tx {:>3}/{:<3} timeout {} tx_p50 {:>7}ms tx_p99 {:>7}ms leg1_p50 {:>6}ms post_err {} drops {}",
                s["phase"].as_str().unwrap(),
                s["listeners_online"], s["conn_ok"], s["conn_fail"], s["conn_ms"]["p50"],
                s["tx_done"], s["tx_started"], s["tx_timeout"], s["tx_ms"]["p50"], s["tx_ms"]["p99"],
                s["leg1_ms"]["p50"], s["post_err"], s["listener_drops"]
            );
        }
        if started && Instant::now() >= end {
            break;
        }
    }
    sh.stop.store(true, Ordering::Relaxed);
    // Let transactions in flight finish (they time out at 120 s).
    let drain_until = Instant::now() + Duration::from_secs(125);
    while sh.active_tx.load(Ordering::Relaxed) > 0 && Instant::now() < drain_until {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut total = std::mem::take(&mut sh.stats.lock().1);
    let mut s = summary(&mut total);
    s["final"] = json!(true);
    s["run_seconds"] = json!(args.duration);
    writeln!(out, "{s}")?;
    println!("{}", serde_json::to_string_pretty(&s)?);
    Ok(())
}
