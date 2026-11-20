//! Checks and abuse runs against a running relay at its public address (wss and https through
//! the reverse proxy), for testing a deployment.
//!
//!   livetest --url https://relay.example.org --domain relay.example.org probe
//!   livetest ... sockets --n 400 --hold 60       many idle sockets from this host
//!   livetest ... junk --kind badsig --sockets 8 --seconds 60
//!   livetest ... spam --rate 20 --seconds 60 --keys spam-keys.txt
//!   livetest ... drain --keys spam-keys.txt      collect and ack what `spam` left
//!   livetest ... http --path /status.json --concurrency 64 --seconds 30 [--new-conn]
//!   livetest ... pulls --concurrency 16 --seconds 30
//!   livetest ... longpolls --n 100
//!
//! `probe` exits non-zero if a check fails. The other modes print counts of each outcome every
//! 10 s and a summary at the end. Everything comes from this host's address, so the relay's
//! per-prefix limits apply to the whole run.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use epicmail::sig;

/// The original relay's fixed first challenge, which wallets older than 3.5.2 sign.
const STATIC: &str = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";

#[derive(Parser)]
struct Args {
    /// Relay base URL: https://host[:port] (websocket at wss://host/) or http:// for a bare relay.
    #[arg(long)]
    url: String,
    /// The relay's domain, as written in addresses.
    #[arg(long)]
    domain: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Functional checks: classic, mux/1, /v1, refusals. Exits 1 on a failed check.
    Probe,
    /// Open many websocket sockets and hold them.
    Sockets {
        #[arg(long, default_value_t = 300)]
        n: usize,
        #[arg(long, default_value_t = 64)]
        parallel: usize,
        #[arg(long, default_value_t = 60)]
        hold: u64,
    },
    /// Send bad frames as fast as the relay takes them: badjson, typeless, badsig, big, subscribe.
    Junk {
        #[arg(long)]
        kind: String,
        #[arg(long, default_value_t = 4)]
        sockets: usize,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
    /// Post signed slates to mailboxes nobody collects; their keys go to --keys for `drain`.
    Spam {
        #[arg(long, default_value_t = 4)]
        senders: usize,
        #[arg(long, default_value_t = 10.0)]
        rate: f64,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        #[arg(long, default_value_t = 32)]
        mailboxes: usize,
        #[arg(long, default_value_t = 2048)]
        payload: usize,
        #[arg(long)]
        keys: String,
    },
    /// Attach the mailboxes in --keys over mux/1 and ack everything waiting.
    Drain {
        #[arg(long)]
        keys: String,
    },
    /// GET one path as fast as possible.
    Http {
        #[arg(long, default_value = "/status.json")]
        path: String,
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
        #[arg(long, default_value_t = 30)]
        seconds: u64,
        /// A new TCP and TLS connection for every request.
        #[arg(long)]
        new_conn: bool,
    },
    /// Signed /v1/pull requests for fresh empty mailboxes, wait 0.
    Pulls {
        #[arg(long, default_value_t = 16)]
        concurrency: usize,
        #[arg(long, default_value_t = 30)]
        seconds: u64,
    },
    /// Post one slate from a fresh key here to a fresh key on another relay, so this relay
    /// forwards it. Nobody holds the recipient key: no wallet ever reads it. Check the relay's
    /// log or metrics for the forward result.
    Forward {
        /// The other relay's domain, e.g. epicbox.epiccash.com
        #[arg(long)]
        to: String,
    },
    /// Hold many /v1 long polls (wait 25) at once.
    Longpolls {
        #[arg(long, default_value_t = 100)]
        n: usize,
    },
}

// ---------------------------------------------------------------------------------------------
// Keys and frames

struct Key {
    secret: SecretKey,
    pk: String,
}

impl Key {
    fn new() -> Self {
        Self::from_secret(SecretKey::from_secret_bytes(rand::random()).unwrap())
    }
    fn from_secret(secret: SecretKey) -> Self {
        let pk = sig::encode_public_key(&PublicKey::from_secret_key(&secret), sig::VERSION_MAINNET);
        Key { secret, pk }
    }
    fn sign(&self, m: &str) -> String {
        sig::sign(&self.secret, m)
    }
    fn at(&self, d: &str) -> String {
        format!("{}@{d}", self.pk)
    }
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn post_frame(from: &Key, from_d: &str, to: &Key, to_d: &str, msg: &str) -> Value {
    let body = json!({
        "destination": {"public_key": to.pk, "domain": to_d, "port": 443},
        "encrypted_message": msg, "salt": "00", "nonce": "00"
    })
    .to_string();
    json!({"type":"PostSlate","from":from.at(from_d),"to":to.at(to_d),"str":body,"signature":from.sign(&body)})
}

/// A /v1 mailbox proof: a fresh challenge signed as `<challenge>@<domain>:443`, bound to the relay.
fn ebh(k: &Key, d: &str) -> Value {
    let ch = format!("ebh-{}-{:016x}", now_s(), rand::random::<u64>());
    let signed = format!("{ch}@{}:443", d.to_ascii_lowercase());
    json!({"address":k.pk,"challenge":ch,"signature":k.sign(&signed)})
}

// ---------------------------------------------------------------------------------------------
// Websocket

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn ws_connect(url: &str) -> Result<Ws, String> {
    match tokio::time::timeout(Duration::from_secs(15), tokio_tungstenite::connect_async(url)).await {
        Err(_) => Err("connect timeout".into()),
        Ok(Err(tungstenite::Error::Http(r))) => Err(format!("http {}", r.status().as_u16())),
        Ok(Err(tungstenite::Error::Io(e))) => Err(format!("io {:?}", e.kind())),
        Ok(Err(e)) => Err(short(&e.to_string())),
        Ok(Ok((ws, _))) => Ok(ws),
    }
}

fn short(s: &str) -> String {
    s.chars().take(80).collect()
}

enum Frame {
    Json(Value),
    Closed(Option<u16>),
    Timeout,
    Err(String),
}

impl Frame {
    fn label(&self) -> String {
        match self {
            Frame::Json(v) => {
                let t = v["type"].as_str().unwrap_or("?");
                match (v["kind"].as_str(), v["code"].as_str()) {
                    (_, Some(c)) => format!("{t} {c}"),
                    (Some(k), None) => format!("{t} {k}"),
                    _ => t.to_string(),
                }
            }
            Frame::Closed(c) => format!("closed {}", c.map(|c| c.to_string()).unwrap_or("-".into())),
            Frame::Timeout => "timeout".into(),
            Frame::Err(e) => format!("error {e}"),
        }
    }
    fn json(&self) -> Value {
        match self {
            Frame::Json(v) => v.clone(),
            _ => json!({"frame": self.label()}),
        }
    }
}

async fn next_frame(ws: &mut Ws, t: Duration) -> Frame {
    let deadline = Instant::now() + t;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, ws.next()).await {
            Err(_) => return Frame::Timeout,
            Ok(None) => return Frame::Closed(None),
            Ok(Some(Err(tungstenite::Error::ConnectionClosed))) => return Frame::Closed(None),
            Ok(Some(Err(e))) => return Frame::Err(short(&e.to_string())),
            Ok(Some(Ok(Message::Text(s)))) => {
                return Frame::Json(serde_json::from_str(&s).unwrap_or(Value::String(s.to_string())))
            }
            Ok(Some(Ok(Message::Close(c)))) => return Frame::Closed(c.map(|c| u16::from(c.code))),
            Ok(Some(Ok(_))) => continue,
        }
    }
}

/// Next frame that is not an interval Challenge.
async fn answer(ws: &mut Ws, t: Duration) -> Frame {
    loop {
        let f = next_frame(ws, t).await;
        if let Frame::Json(v) = &f {
            if v["type"] == "Challenge" {
                continue;
            }
        }
        return f;
    }
}

async fn send(ws: &mut Ws, v: &Value) -> Result<(), String> {
    ws.send(Message::Text(v.to_string().into())).await.map_err(|e| short(&e.to_string()))
}

async fn challenge(ws: &mut Ws) -> anyhow::Result<String> {
    match next_frame(ws, Duration::from_secs(10)).await {
        Frame::Json(v) if v["type"] == "Challenge" => Ok(v["str"].as_str().unwrap_or("").to_string()),
        f => bail!("expected Challenge, got {}", f.label()),
    }
}

// ---------------------------------------------------------------------------------------------
// HTTP/1.1 over TLS (or plain), one request at a time per connection

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Http {
    host: String,
    port: u16,
    tls: Option<tokio_rustls::TlsConnector>,
}

struct Conn {
    io: Box<dyn Io>,
    buf: Vec<u8>,
}

struct Resp {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::String(String::from_utf8_lossy(&self.body).into()))
    }
}

impl Http {
    fn new(base: &url::Url) -> anyhow::Result<Self> {
        let host = base.host_str().context("url has no host")?.to_string();
        let tls = base.scheme() == "https";
        let port = base.port().unwrap_or(if tls { 443 } else { 80 });
        let tls = if tls {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
            Some(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
        } else {
            None
        };
        Ok(Http { host, port, tls })
    }

    async fn open(&self) -> anyhow::Result<Conn> {
        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((self.host.as_str(), self.port)))
            .await
            .map_err(|_| anyhow!("connect timeout"))??;
        tcp.set_nodelay(true)?;
        let io: Box<dyn Io> = match &self.tls {
            Some(c) => {
                let name = rustls::pki_types::ServerName::try_from(self.host.clone())?;
                Box::new(
                    tokio::time::timeout(Duration::from_secs(10), c.connect(name, tcp))
                        .await
                        .map_err(|_| anyhow!("tls timeout"))??,
                )
            }
            None => Box::new(tcp),
        };
        Ok(Conn { io, buf: Vec::new() })
    }

    async fn request(
        &self,
        c: &mut Conn,
        method: &str,
        path: &str,
        body: Option<&Value>,
        t: Duration,
    ) -> anyhow::Result<Resp> {
        let b = body.map(|b| b.to_string()).unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
            self.host,
            b.len()
        );
        tokio::time::timeout(t, async {
            c.io.write_all(req.as_bytes()).await?;
            c.io.flush().await?;
            read_response(c).await
        })
        .await
        .map_err(|_| anyhow!("response timeout"))?
    }

    /// One request on a new connection.
    async fn once(&self, method: &str, path: &str, body: Option<&Value>) -> anyhow::Result<Resp> {
        let mut c = self.open().await?;
        self.request(&mut c, method, path, body, Duration::from_secs(40)).await
    }
}

async fn fill(c: &mut Conn) -> anyhow::Result<()> {
    let mut tmp = [0u8; 16384];
    let n = c.io.read(&mut tmp).await?;
    if n == 0 {
        bail!("connection closed");
    }
    c.buf.extend_from_slice(&tmp[..n]);
    Ok(())
}

async fn read_response(c: &mut Conn) -> anyhow::Result<Resp> {
    let head_end = loop {
        if let Some(i) = c.buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        fill(c).await?;
    };
    let head = String::from_utf8_lossy(&c.buf[..head_end]).to_string();
    c.buf.drain(..head_end + 4);
    let status: u16 = head.split(' ').nth(1).context("bad status line")?.parse()?;
    let lower = head.to_ascii_lowercase();
    let header = |name: &str| {
        lower.lines().find_map(|l| l.strip_prefix(name).map(|v| v.trim_start_matches(':').trim().to_string()))
    };
    let body = if let Some(len) = header("content-length") {
        let len: usize = len.parse()?;
        while c.buf.len() < len {
            fill(c).await?;
        }
        c.buf.drain(..len).collect()
    } else if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        let mut out = Vec::new();
        loop {
            let line_end = loop {
                if let Some(i) = c.buf.windows(2).position(|w| w == b"\r\n") {
                    break i;
                }
                fill(c).await?;
            };
            let size_s = String::from_utf8_lossy(&c.buf[..line_end]).to_string();
            let size = usize::from_str_radix(size_s.split(';').next().unwrap_or("0").trim(), 16)?;
            c.buf.drain(..line_end + 2);
            while c.buf.len() < size + 2 {
                fill(c).await?;
            }
            out.extend(c.buf.drain(..size));
            c.buf.drain(..2);
            if size == 0 {
                break;
            }
        }
        out
    } else {
        // No length: the body runs to the end of the connection.
        while fill(c).await.is_ok() {}
        std::mem::take(&mut c.buf)
    };
    Ok(Resp { status, head, body })
}

// ---------------------------------------------------------------------------------------------
// Tallies

#[derive(Default)]
struct Tally {
    counts: Mutex<BTreeMap<String, u64>>,
    lat_ms: Mutex<Vec<f64>>,
}

impl Tally {
    fn add(&self, k: impl Into<String>) {
        *self.counts.lock().entry(k.into()).or_insert(0) += 1;
    }
    fn lat(&self, t0: Instant) {
        self.lat_ms.lock().push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    fn snapshot(&self) -> BTreeMap<String, u64> {
        self.counts.lock().clone()
    }
    fn total(&self) -> u64 {
        self.counts.lock().values().sum()
    }
    fn summary(&self, elapsed: f64) -> Value {
        let mut l = self.lat_ms.lock().clone();
        l.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p = |q: f64| {
            if l.is_empty() {
                0.0
            } else {
                (l[((l.len() - 1) as f64 * q).round() as usize] * 10.0).round() / 10.0
            }
        };
        json!({
            "seconds": (elapsed * 10.0).round() / 10.0,
            "outcomes": self.snapshot(),
            "per_s": ((self.total() as f64 / elapsed.max(0.001)) * 10.0).round() / 10.0,
            "ms": {"p50": p(0.5), "p90": p(0.9), "p99": p(0.99), "max": p(1.0), "n": l.len()},
        })
    }
}

/// Print the tally every 10 s until `stop`.
fn reporter(t: Arc<Tally>, stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let t0 = Instant::now();
        let mut last = 0u64;
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let total = t.total();
            println!(
                "t+{:>4.0}s {:>7.1}/s {:?}",
                t0.elapsed().as_secs_f64(),
                (total - last) as f64 / 10.0,
                t.snapshot()
            );
            last = total;
        }
    })
}

// ---------------------------------------------------------------------------------------------
// probe

#[derive(Default)]
struct Checks {
    failed: u32,
    passed: u32,
}

impl Checks {
    fn check(&mut self, name: &str, ok: bool, detail: impl std::fmt::Display) {
        if ok {
            self.passed += 1;
            println!("PASS  {name}  ({detail})");
        } else {
            self.failed += 1;
            println!("FAIL  {name}  ({detail})");
        }
    }
}

fn ms(t0: Instant) -> String {
    format!("{:.0} ms", t0.elapsed().as_secs_f64() * 1000.0)
}

async fn probe(ws_url: &str, http: &Http, d: &str) -> anyhow::Result<bool> {
    let mut c = Checks::default();
    let long = Duration::from_secs(10);

    for path in ["/health", "/ready", "/status.json", "/.well-known/epicbox.json", "/v1/info"] {
        let t0 = Instant::now();
        match http.once("GET", path, None).await {
            Ok(r) => c.check(&format!("GET {path}"), r.status == 200, format!("{} in {}", r.status, ms(t0))),
            Err(e) => c.check(&format!("GET {path}"), false, e),
        }
    }
    let r = http.once("GET", "/metrics", None).await?;
    c.check("/metrics is not public", r.status == 404, r.status);
    let wk = http.once("GET", "/.well-known/epicbox.json", None).await?.json();
    c.check("info offers mux/1", wk["features"]["mux/1"].is_object(), short(&wk["features"].to_string()));
    c.check(
        "info publishes the Waiting budget",
        wk.to_string().contains("waiting_frames_per_min"),
        short(&wk["features"]["mux/1"].to_string()),
    );

    // Classic 3.0.0.
    let mut s = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
    let first = challenge(&mut s).await?;
    c.check("first challenge is random", first.len() == 32 && first != STATIC, &first);
    send(&mut s, &json!({"type":"GetVersion"})).await.map_err(|e| anyhow!(e))?;
    let v = answer(&mut s, long).await.json();
    c.check("GetVersion answers 3.1.0", v["str"] == "3.1.0", &v);

    let eve = Key::new();
    send(&mut s, &json!({"type":"Subscribe","address":eve.pk,"ver":"3.0.0","signature":eve.sign(STATIC)}))
        .await
        .map_err(|e| anyhow!(e))?;
    let r = answer(&mut s, long).await;
    c.check(
        "Subscribe over the fixed challenge is refused",
        !matches!(&r, Frame::Json(v) if v["type"] == "Ok"),
        r.label(),
    );
    let mut s2 = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
    challenge(&mut s2).await?;
    send(&mut s2, &json!({"type":"Subscribe","address":eve.pk,"signature":eve.sign(STATIC)}))
        .await
        .map_err(|e| anyhow!(e))?;
    let r = answer(&mut s2, long).await;
    c.check(
        "legacy Subscribe (no ver) over the fixed challenge is refused",
        !matches!(&r, Frame::Json(v) if v["type"] == "Ok"),
        r.label(),
    );

    let (alice, bob) = (Key::new(), Key::new());
    let mut b = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
    let ch = challenge(&mut b).await?;
    send(&mut b, &json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":bob.sign(&ch)}))
        .await
        .map_err(|e| anyhow!(e))?;
    let r = answer(&mut b, long).await;
    c.check("classic Subscribe", matches!(&r, Frame::Json(v) if v["type"] == "Ok"), r.label());

    let mut a = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
    challenge(&mut a).await?;
    let t0 = Instant::now();
    send(&mut a, &post_frame(&alice, d, &bob, d, "probe-1")).await.map_err(|e| anyhow!(e))?;
    let r = answer(&mut a, long).await;
    c.check(
        "PostSlate to a local mailbox",
        matches!(&r, Frame::Json(v) if v["type"] == "Ok"),
        format!("{} in {}", r.label(), ms(t0)),
    );
    let slate = answer(&mut b, long).await.json();
    c.check(
        "Slate pushed to the subscriber",
        slate["type"] == "Slate" && slate["from"] == alice.at(d),
        format!("{} after {}", slate["type"], ms(t0)),
    );
    let msgid = slate["epicboxmsgid"].as_str().unwrap_or("").to_string();
    send(
        &mut b,
        &json!({"type":"Made","address":bob.pk,"signature":alice.sign(&msgid),"epicboxmsgid":msgid,"ver":"3.0.0"}),
    )
    .await
    .map_err(|e| anyhow!(e))?;
    let r = answer(&mut b, long).await;
    c.check("Made with a wrong signature is refused", r.label().contains("InvalidSignature"), r.label());
    send(
        &mut b,
        &json!({"type":"Made","address":bob.pk,"signature":bob.sign(&msgid),"epicboxmsgid":msgid,"ver":"3.0.0"}),
    )
    .await
    .map_err(|e| anyhow!(e))?;
    let r = answer(&mut b, long).await;
    c.check("Made", matches!(&r, Frame::Json(v) if v["type"] == "Ok"), r.label());

    // Mail for an offline mailbox waits and arrives on Subscribe.
    let carol = Key::new();
    send(&mut a, &post_frame(&alice, d, &carol, d, "probe-2")).await.map_err(|e| anyhow!(e))?;
    let r = answer(&mut a, long).await;
    c.check("PostSlate to an offline mailbox", matches!(&r, Frame::Json(v) if v["type"] == "Ok"), r.label());
    let mut cs = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
    let ch = challenge(&mut cs).await?;
    send(&mut cs, &json!({"type":"Subscribe","address":carol.pk,"ver":"3.0.0","signature":carol.sign(&ch)}))
        .await
        .map_err(|e| anyhow!(e))?;
    let mut got = None;
    for _ in 0..3 {
        let f = answer(&mut cs, long).await.json();
        if f["type"] == "Slate" {
            got = Some(f);
            break;
        }
    }
    c.check(
        "waiting mail delivered on Subscribe",
        got.is_some(),
        got.as_ref().map(|v| v["type"].to_string()).unwrap_or("none".into()),
    );
    if let Some(sl) = got {
        let id = sl["epicboxmsgid"].as_str().unwrap_or("").to_string();
        send(
            &mut cs,
            &json!({"type":"Made","address":carol.pk,"signature":carol.sign(&id),"epicboxmsgid":id,"ver":"3.0.0"}),
        )
        .await
        .map_err(|e| anyhow!(e))?;
        let r = answer(&mut cs, long).await;
        c.check("Made for waiting mail", matches!(&r, Frame::Json(v) if v["type"] == "Ok"), r.label());
    }


    // Bad JSON closes the socket.
    let mut j = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
    challenge(&mut j).await?;
    j.send(Message::Text("{oops".into())).await.ok();
    let r = next_frame(&mut j, long).await;
    c.check("bad JSON closes with 3000", matches!(r, Frame::Closed(Some(3000))), r.label());

    // mux/1.
    let mut m = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
    challenge(&mut m).await?;
    let details = json!({"type":"ClientDetails","wallet_version":"livetest","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]});
    send(&mut m, &details).await.map_err(|e| anyhow!(e))?;
    let ok = answer(&mut m, long).await.json();
    c.check("mux/1 offered on ClientDetails", ok["ext"] == json!(["mux/1"]), short(&ok.to_string()));
    let mch = ok["challenge"].as_str().unwrap_or("").to_string();
    let erin = Key::new();
    send(&mut m, &json!({"type":"Attach","ref":"a1","mailboxes":[{"address":erin.pk,"signature":erin.sign(&mch)},{"address":alice.pk,"signature":erin.sign(&mch)}]}))
        .await
        .map_err(|e| anyhow!(e))?;
    let at = answer(&mut m, long).await.json();
    c.check(
        "Attach: own mailbox ok, a wrong signature refused",
        at["type"] == "Attached" && at["mailboxes"][0]["ok"] == true && at["mailboxes"][1]["ok"] == false,
        short(&at.to_string()),
    );
    let token = at["token"].as_str().unwrap_or("").to_string();
    let t0 = Instant::now();
    send(&mut a, &post_frame(&alice, d, &erin, d, "probe-4")).await.map_err(|e| anyhow!(e))?;
    answer(&mut a, long).await;
    let mail = answer(&mut m, long).await.json();
    c.check(
        "Mail pushed on mux/1",
        mail["type"] == "Mail" && mail["mailbox"] == erin.pk.as_str(),
        format!("{} after {}", mail["type"], ms(t0)),
    );
    send(&mut m, &json!({"type":"Waiting","ref":"w1"})).await.map_err(|e| anyhow!(e))?;
    let w = answer(&mut m, long).await.json();
    // The pushed message is in flight, so it is not counted as waiting.
    c.check(
        "Waiting: mailbox listed, pushed mail counted in flight",
        w["ref"] == "w1" && w["waiting"][&erin.pk] == 0 && w["inflight"] == 1,
        format!("waiting {} inflight {}", w["waiting"][&erin.pk], w["inflight"]),
    );
    send(&mut m, &json!({"type":"Ack","ref":"k1","ids":[mail["id"]]})).await.map_err(|e| anyhow!(e))?;
    let r = answer(&mut m, long).await.json();
    c.check("Ack", r == json!({"type":"Ok","ref":"k1"}), &r);
    drop(m);
    let mut m2 = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
    challenge(&mut m2).await?;
    send(&mut m2, &details).await.map_err(|e| anyhow!(e))?;
    answer(&mut m2, long).await;
    send(&mut m2, &json!({"type":"Resume","ref":"r1","token":token})).await.map_err(|e| anyhow!(e))?;
    let r = answer(&mut m2, long).await.json();
    c.check("Resume with the token", r["type"] == "Attached", short(&r.to_string()));

    // mux/1 with epicbox-attach/1: an entry with `host` is signed over the host-bound text; an
    // entry without it, over the bare challenge, on the same socket.
    let mut h = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
    challenge(&mut h).await?;
    let hdetails = json!({"type":"ClientDetails","wallet_version":"livetest","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1","epicbox-attach/1"]});
    send(&mut h, &hdetails).await.map_err(|e| anyhow!(e))?;
    let ok = answer(&mut h, long).await.json();
    c.check(
        "epicbox-attach/1 echoed on ClientDetails",
        ok["ext"].as_array().is_some_and(|e| e.iter().any(|x| x == "epicbox-attach/1")),
        short(&ok.to_string()),
    );
    let hch = ok["challenge"].as_str().unwrap_or("").to_string();
    let (gina, hank, ivan) = (Key::new(), Key::new(), Key::new());
    let bound = format!("epicbox-attach/1:{d}:{hch}");
    let other = format!("epicbox-attach/1:other.example:{hch}");
    send(
        &mut h,
        &json!({"type":"Attach","ref":"h1","mailboxes":[
            {"address":gina.pk,"host":d,"signature":gina.sign(&bound)},
            {"address":hank.pk,"signature":hank.sign(&hch)},
            {"address":ivan.pk,"host":"other.example","signature":ivan.sign(&other)}]}),
    )
    .await
    .map_err(|e| anyhow!(e))?;
    let at = answer(&mut h, long).await.json();
    c.check(
        "Attach: host-bound form ok, bare form ok, another host refused",
        at["type"] == "Attached"
            && at["mailboxes"][0]["ok"] == true
            && at["mailboxes"][1]["ok"] == true
            && at["mailboxes"][2]["ok"] == false,
        short(&at.to_string()),
    );

    // /v1.
    let frank = Key::new();
    let mut f = post_frame(&alice, d, &frank, d, "probe-5");
    f.as_object_mut().unwrap().remove("type");
    let r = http.once("POST", "/v1/post", Some(&f)).await?;
    let id = r.json()["id"].as_str().unwrap_or("").to_string();
    c.check("/v1/post", r.status == 200 && !id.is_empty(), format!("{} {}", r.status, short(&r.json().to_string())));
    let pull = json!({"mailboxes":[ebh(&frank, d)],"wait":0});
    let r = http.once("POST", "/v1/pull", Some(&pull)).await?;
    let v = r.json();
    c.check(
        "/v1/pull returns the message",
        r.status == 200 && v["mailboxes"][0]["messages"][0]["id"] == id.as_str(),
        short(&v.to_string()),
    );
    let r = http.once("POST", "/v1/pull", Some(&pull)).await?;
    c.check(
        "/v1 challenge cannot be used twice",
        r.json()["mailboxes"][0]["error"] == "challenge was already used",
        short(&r.json().to_string()),
    );
    let made = json!({"address":frank.pk,"acks":[{"id":id,"signature":frank.sign(&id)}]});
    let r = http.once("POST", "/v1/made", Some(&made)).await?;
    c.check("/v1/made removes it", r.status == 200 && r.json()["removed"] == 1, short(&r.json().to_string()));

    let pull = json!({"mailboxes":[ebh(&frank, d)],"wait":20});
    let http2 = Http { host: http.host.clone(), port: http.port, tls: http.tls.clone() };
    let t0 = Instant::now();
    let poll = tokio::spawn(async move { http2.once("POST", "/v1/pull", Some(&pull)).await });
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let mut f = post_frame(&alice, d, &frank, d, "probe-6");
    f.as_object_mut().unwrap().remove("type");
    http.once("POST", "/v1/post", Some(&f)).await?;
    let r = poll.await??;
    let v = r.json();
    let msgs = v["mailboxes"][0]["messages"].as_array().cloned().unwrap_or_default();
    c.check(
        "/v1 long poll wakes on new mail",
        r.status == 200 && msgs.len() == 1 && t0.elapsed() < Duration::from_secs(8),
        format!("{} after {}", msgs.len(), ms(t0)),
    );
    if let Some(id) = msgs.first().and_then(|m| m["id"].as_str()) {
        let made = json!({"address":frank.pk,"acks":[{"id":id,"signature":frank.sign(id)}]});
        http.once("POST", "/v1/made", Some(&made)).await?;
    }

    println!("\n{} passed, {} failed", c.passed, c.failed);
    Ok(c.failed == 0)
}

// ---------------------------------------------------------------------------------------------
// sockets

async fn sockets(ws_url: &str, n: usize, parallel: usize, hold: u64) {
    let t = Arc::new(Tally::default());
    let open_now = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let sem = Arc::new(Semaphore::new(parallel));
    let t0 = Instant::now();
    let until = t0 + Duration::from_secs(hold);
    let mut hs = Vec::new();
    for _ in 0..n {
        let (t, open_now, sem, url) = (t.clone(), open_now.clone(), sem.clone(), ws_url.to_string());
        hs.push(tokio::spawn(async move {
            let permit = sem.acquire_owned().await.unwrap();
            let t1 = Instant::now();
            let mut ws = match ws_connect(&url).await {
                Ok(w) => w,
                Err(e) => {
                    t.add(format!("connect {e}"));
                    return;
                }
            };
            match next_frame(&mut ws, Duration::from_secs(15)).await {
                Frame::Json(v) if v["type"] == "Challenge" => {
                    t.add("open");
                    t.lat(t1);
                }
                f => {
                    t.add(format!("first frame {}", f.label()));
                    return;
                }
            }
            drop(permit);
            open_now.fetch_add(1, Ordering::Relaxed);
            loop {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                match next_frame(&mut ws, left).await {
                    Frame::Timeout => break,
                    Frame::Json(_) => continue,
                    f => {
                        t.add(format!("later {}", f.label()));
                        break;
                    }
                }
            }
            open_now.fetch_sub(1, Ordering::Relaxed);
            let _ = ws.close(None).await;
        }));
    }
    let ticker = {
        let open_now = open_now.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                println!("t+{:>4.0}s open {}", t0.elapsed().as_secs_f64(), open_now.load(Ordering::Relaxed));
            }
        })
    };
    for h in hs {
        let _ = h.await;
    }
    ticker.abort();
    println!("{}", serde_json::to_string_pretty(&t.summary(t0.elapsed().as_secs_f64())).unwrap());
}

// ---------------------------------------------------------------------------------------------
// junk

async fn junk(ws_url: &str, d: &str, kind: &str, n: usize, seconds: u64) -> anyhow::Result<()> {
    if !["badjson", "typeless", "badsig", "big", "subscribe"].contains(&kind) {
        bail!("unknown kind {kind}");
    }
    let t = Arc::new(Tally::default());
    let stop = Arc::new(AtomicBool::new(false));
    let rep = reporter(t.clone(), stop.clone());
    let t0 = Instant::now();
    let until = t0 + Duration::from_secs(seconds);
    let mut hs = Vec::new();
    for _ in 0..n {
        let (t, url, kind, d) = (t.clone(), ws_url.to_string(), kind.to_string(), d.to_string());
        hs.push(tokio::spawn(async move {
            let (alice, bob, eve) = (Key::new(), Key::new(), Key::new());
            let big = format!("{{\"type\":\"Junk\",\"pad\":\"{}\"}}", "a".repeat(1_000_000));
            while Instant::now() < until {
                let mut ws = match ws_connect(&url).await {
                    Ok(w) => w,
                    Err(e) => {
                        t.add(format!("connect {e}"));
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let Ok(mut ch) = challenge(&mut ws).await else {
                    t.add("no challenge");
                    continue;
                };
                let mut sent_here = 0u64;
                let end = loop {
                    if Instant::now() >= until {
                        break None;
                    }
                    let t1 = Instant::now();
                    let r = match kind.as_str() {
                        "badjson" => {
                            let _ = ws.send(Message::Text("{oops".into())).await;
                            next_frame(&mut ws, Duration::from_secs(10)).await
                        }
                        "typeless" => {
                            // No answer is sent for these; send in bursts and look for a close.
                            let mut r = Frame::Timeout;
                            for _ in 0..50 {
                                if let Err(e) = send(&mut ws, &json!({"x":1})).await {
                                    r = Frame::Err(e);
                                    break;
                                }
                                sent_here += 1;
                            }
                            if matches!(r, Frame::Timeout) {
                                r = next_frame(&mut ws, Duration::from_millis(20)).await;
                            }
                            r
                        }
                        "badsig" => {
                            let mut f = post_frame(&alice, &d, &bob, &d, "junk");
                            f["signature"] = json!(eve.sign(f["str"].as_str().unwrap()));
                            if let Err(e) = send(&mut ws, &f).await {
                                Frame::Err(e)
                            } else {
                                answer(&mut ws, Duration::from_secs(10)).await
                            }
                        }
                        "big" => {
                            if let Err(e) = ws.send(Message::Text(big.clone().into())).await {
                                Frame::Err(short(&e.to_string()))
                            } else {
                                sent_here += 1;
                                next_frame(&mut ws, Duration::from_millis(200)).await
                            }
                        }
                        _ => {
                            // subscribe: a fresh key over the current challenge, again and again.
                            let k = Key::new();
                            if let Err(e) = send(
                                &mut ws,
                                &json!({"type":"Subscribe","address":k.pk,"ver":"3.0.0","signature":k.sign(&ch)}),
                            )
                            .await
                            {
                                Frame::Err(e)
                            } else {
                                let f = next_frame(&mut ws, Duration::from_secs(10)).await;
                                if let Frame::Json(v) = &f {
                                    if v["type"] == "Challenge" {
                                        ch = v["str"].as_str().unwrap_or("").to_string();
                                    }
                                }
                                f
                            }
                        }
                    };
                    match r {
                        Frame::Timeout if kind == "typeless" || kind == "big" => continue,
                        Frame::Json(v) => {
                            t.lat(t1);
                            t.add(Frame::Json(v).label());
                        }
                        f => break Some(f),
                    }
                };
                if sent_here > 0 {
                    t.add(format!("frames sent ({kind})"));
                    *t.counts.lock().entry(format!("frames sent ({kind})")).or_insert(0) += sent_here - 1;
                }
                if let Some(f) = end {
                    t.add(f.label());
                }
            }
        }));
    }
    for h in hs {
        let _ = h.await;
    }
    stop.store(true, Ordering::Relaxed);
    rep.abort();
    println!("{}", serde_json::to_string_pretty(&t.summary(t0.elapsed().as_secs_f64()))?);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// spam and drain

#[allow(clippy::too_many_arguments)]
async fn spam(
    ws_url: &str,
    d: &str,
    senders: usize,
    rate: f64,
    seconds: u64,
    mailboxes: usize,
    payload: usize,
    keys: &str,
) -> anyhow::Result<()> {
    let dests: Arc<Vec<Key>> = Arc::new((0..mailboxes).map(|_| Key::new()).collect());
    let lines: Vec<String> = dests.iter().map(|k| hex::encode(k.secret.to_secret_bytes())).collect();
    std::fs::write(keys, lines.join("\n") + "\n")?;
    println!("{} destination keys written to {keys}", dests.len());
    let t = Arc::new(Tally::default());
    let stop = Arc::new(AtomicBool::new(false));
    let rep = reporter(t.clone(), stop.clone());
    let t0 = Instant::now();
    let until = t0 + Duration::from_secs(seconds);
    let gap = Duration::from_secs_f64(senders as f64 / rate);
    let pad = "0".repeat(payload);
    let mut hs = Vec::new();
    for i in 0..senders {
        let (t, url, d, dests, pad) = (t.clone(), ws_url.to_string(), d.to_string(), dests.clone(), pad.clone());
        hs.push(tokio::spawn(async move {
            tokio::time::sleep(gap.mul_f64(i as f64 / senders as f64)).await;
            let me = Key::new();
            let mut tick = tokio::time::interval(gap);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut seq = 0u64;
            'outer: while Instant::now() < until {
                let mut ws = match ws_connect(&url).await {
                    Ok(w) => w,
                    Err(e) => {
                        t.add(format!("connect {e}"));
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                if challenge(&mut ws).await.is_err() {
                    t.add("no challenge");
                    continue;
                }
                while Instant::now() < until {
                    tick.tick().await;
                    seq += 1;
                    let to = &dests[rand::random_range(0..dests.len())];
                    let f = post_frame(&me, &d, to, &d, &format!("{seq:016x}{pad}"));
                    let t1 = Instant::now();
                    if send(&mut ws, &f).await.is_err() {
                        t.add("send failed");
                        continue 'outer;
                    }
                    let r = answer(&mut ws, Duration::from_secs(15)).await;
                    match &r {
                        Frame::Json(_) => {
                            t.lat(t1);
                            t.add(r.label());
                        }
                        _ => {
                            t.add(r.label());
                            continue 'outer;
                        }
                    }
                }
            }
        }));
    }
    for h in hs {
        let _ = h.await;
    }
    stop.store(true, Ordering::Relaxed);
    rep.abort();
    println!("{}", serde_json::to_string_pretty(&t.summary(t0.elapsed().as_secs_f64()))?);
    Ok(())
}

async fn drain(ws_url: &str, keys: &str) -> anyhow::Result<()> {
    let ks: Vec<Key> = std::fs::read_to_string(keys)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            Ok(Key::from_secret(SecretKey::from_secret_bytes(
                hex::decode(l.trim())?.try_into().map_err(|_| anyhow!("a key line must be 32 bytes of hex"))?,
            )?))
        })
        .collect::<anyhow::Result<_>>()?;
    let t0 = Instant::now();
    let mut total_acked = 0u64;
    let mut total_waiting = 0u64;
    for chunk in ks.chunks(256) {
        let mut ws = ws_connect(ws_url).await.map_err(|e| anyhow!(e))?;
        challenge(&mut ws).await?;
        let details = json!({"type":"ClientDetails","wallet_version":"livetest","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]});
        send(&mut ws, &details).await.map_err(|e| anyhow!(e))?;
        let ok = answer(&mut ws, Duration::from_secs(10)).await.json();
        let mch = ok["challenge"].as_str().context("no mux/1 challenge")?.to_string();
        let mut waiting = 0u64;
        let mut pending: Vec<Value> = Vec::new();
        let mut acked = 0u64;
        for (i, part) in chunk.chunks(64).enumerate() {
            let mbs: Vec<Value> = part.iter().map(|k| json!({"address":k.pk,"signature":k.sign(&mch)})).collect();
            send(&mut ws, &json!({"type":"Attach","ref":format!("a{i}"),"mailboxes":mbs}))
                .await
                .map_err(|e| anyhow!(e))?;
            loop {
                match answer(&mut ws, Duration::from_secs(10)).await {
                    Frame::Json(v) if v["type"] == "Attached" => {
                        waiting += v["mailboxes"]
                            .as_array()
                            .map(|a| a.iter().map(|m| m["waiting"].as_u64().unwrap_or(0)).sum())
                            .unwrap_or(0);
                        break;
                    }
                    Frame::Json(v) if v["type"] == "Mail" => pending.push(v["id"].clone()),
                    f => bail!("attach: {}", f.label()),
                }
            }
        }
        let mut n = 0u32;
        while acked < waiting {
            match answer(&mut ws, Duration::from_secs(3)).await {
                Frame::Json(v) if v["type"] == "Mail" => pending.push(v["id"].clone()),
                Frame::Json(v) if v["type"] == "Ok" => {}
                Frame::Json(v) => println!("drain: {}", short(&v.to_string())),
                Frame::Timeout if pending.is_empty() => {
                    println!("drain: idle with {acked}/{waiting} acked");
                    break;
                }
                Frame::Timeout => {}
                f => bail!("drain: {}", f.label()),
            }
            if pending.len() >= 32 || (!pending.is_empty() && acked + pending.len() as u64 >= waiting) {
                n += 1;
                acked += pending.len() as u64;
                let ids = std::mem::take(&mut pending);
                send(&mut ws, &json!({"type":"Ack","ref":format!("k{n}"),"ids":ids})).await.map_err(|e| anyhow!(e))?;
            }
        }
        // Collect the last Oks.
        let _ = answer(&mut ws, Duration::from_millis(500)).await;
        let _ = ws.close(None).await;
        total_acked += acked;
        total_waiting += waiting;
        println!("chunk of {}: {waiting} waiting, {acked} acked", chunk.len());
    }
    println!("drained {total_acked} of {total_waiting} in {:.1} s", t0.elapsed().as_secs_f64());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// HTTP floods

async fn http_flood(http: Arc<Http>, path: &str, conc: usize, seconds: u64, new_conn: bool) -> anyhow::Result<()> {
    let t = Arc::new(Tally::default());
    let stop = Arc::new(AtomicBool::new(false));
    let rep = reporter(t.clone(), stop.clone());
    let t0 = Instant::now();
    let until = t0 + Duration::from_secs(seconds);
    let mut hs = Vec::new();
    for _ in 0..conc {
        let (t, http, path) = (t.clone(), http.clone(), path.to_string());
        hs.push(tokio::spawn(async move {
            let mut conn: Option<Conn> = None;
            while Instant::now() < until {
                let t1 = Instant::now();
                if conn.is_none() || new_conn {
                    match http.open().await {
                        Ok(c) => conn = Some(c),
                        Err(e) => {
                            t.add(format!("connect {}", short(&e.to_string())));
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                }
                match http.request(conn.as_mut().unwrap(), "GET", &path, None, Duration::from_secs(15)).await {
                    Ok(r) => {
                        t.lat(t1);
                        t.add(format!("{}", r.status));
                        if r.head.to_ascii_lowercase().contains("connection: close") {
                            conn = None;
                        }
                    }
                    Err(e) => {
                        t.add(format!("error {}", short(&e.to_string())));
                        conn = None;
                    }
                }
            }
        }));
    }
    for h in hs {
        let _ = h.await;
    }
    stop.store(true, Ordering::Relaxed);
    rep.abort();
    println!("{}", serde_json::to_string_pretty(&t.summary(t0.elapsed().as_secs_f64()))?);
    Ok(())
}

async fn pulls(http: Arc<Http>, conc: usize, seconds: u64) -> anyhow::Result<()> {
    let t = Arc::new(Tally::default());
    let stop = Arc::new(AtomicBool::new(false));
    let rep = reporter(t.clone(), stop.clone());
    let t0 = Instant::now();
    let until = t0 + Duration::from_secs(seconds);
    let mut hs = Vec::new();
    for _ in 0..conc {
        let (t, http) = (t.clone(), http.clone());
        hs.push(tokio::spawn(async move {
            let mut conn: Option<Conn> = None;
            while Instant::now() < until {
                if conn.is_none() {
                    match http.open().await {
                        Ok(c) => conn = Some(c),
                        Err(e) => {
                            t.add(format!("connect {}", short(&e.to_string())));
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                }
                let k = Key::new();
                let body = json!({"mailboxes":[ebh(&k, &http.host)],"wait":0});
                let t1 = Instant::now();
                match http
                    .request(conn.as_mut().unwrap(), "POST", "/v1/pull", Some(&body), Duration::from_secs(15))
                    .await
                {
                    Ok(r) => {
                        t.lat(t1);
                        let v = r.json();
                        let e = v["mailboxes"][0]["error"].as_str().map(|e| format!(" {e}")).unwrap_or_default();
                        t.add(format!("{}{e}", r.status));
                        if r.status == 429 {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                    Err(e) => {
                        t.add(format!("error {}", short(&e.to_string())));
                        conn = None;
                    }
                }
            }
        }));
    }
    for h in hs {
        let _ = h.await;
    }
    stop.store(true, Ordering::Relaxed);
    rep.abort();
    println!("{}", serde_json::to_string_pretty(&t.summary(t0.elapsed().as_secs_f64()))?);
    Ok(())
}

async fn longpolls(http: Arc<Http>, n: usize) -> anyhow::Result<()> {
    let t = Arc::new(Tally::default());
    let t0 = Instant::now();
    let mut hs = Vec::new();
    for _ in 0..n {
        let (t, http) = (t.clone(), http.clone());
        hs.push(tokio::spawn(async move {
            let k = Key::new();
            let body = json!({"mailboxes":[ebh(&k, &http.host)],"wait":25});
            let t1 = Instant::now();
            match http.once("POST", "/v1/pull", Some(&body)).await {
                Ok(r) => {
                    t.lat(t1);
                    let held = if t1.elapsed() > Duration::from_secs(20) { "held" } else { "fast" };
                    t.add(format!("{} {held}", r.status));
                }
                Err(e) => t.add(format!("error {}", short(&e.to_string()))),
            }
        }));
    }
    for h in hs {
        let _ = h.await;
    }
    println!("{}", serde_json::to_string_pretty(&t.summary(t0.elapsed().as_secs_f64()))?);
    Ok(())
}

// ---------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let base = url::Url::parse(&args.url)?;
    let ws_url = format!(
        "{}://{}{}/",
        if base.scheme() == "https" { "wss" } else { "ws" },
        base.host_str().unwrap_or(""),
        base.port().map(|p| format!(":{p}")).unwrap_or_default()
    );
    let http = Arc::new(Http::new(&base)?);
    let d = args.domain.as_str();
    match args.cmd {
        Cmd::Probe => {
            if !probe(&ws_url, &http, d).await? {
                std::process::exit(1);
            }
        }
        Cmd::Sockets { n, parallel, hold } => sockets(&ws_url, n, parallel, hold).await,
        Cmd::Junk { kind, sockets, seconds } => junk(&ws_url, d, &kind, sockets, seconds).await?,
        Cmd::Spam { senders, rate, seconds, mailboxes, payload, keys } => {
            spam(&ws_url, d, senders, rate, seconds, mailboxes, payload, &keys).await?
        }
        Cmd::Drain { keys } => drain(&ws_url, &keys).await?,
        Cmd::Http { path, concurrency, seconds, new_conn } => {
            http_flood(http, &path, concurrency, seconds, new_conn).await?
        }
        Cmd::Pulls { concurrency, seconds } => pulls(http, concurrency, seconds).await?,
        Cmd::Longpolls { n } => longpolls(http, n).await?,
        Cmd::Forward { to } => {
            let (from, rcpt) = (Key::new(), Key::new());
            let mut s = ws_connect(&ws_url).await.map_err(|e| anyhow!(e))?;
            challenge(&mut s).await?;
            send(&mut s, &post_frame(&from, d, &rcpt, &to, "livetest-forward")).await.map_err(|e| anyhow!(e))?;
            let r = answer(&mut s, Duration::from_secs(15)).await;
            println!("to {} -> {}", rcpt.at(&to), r.label());
            if !matches!(&r, Frame::Json(v) if v["type"] == "Ok") {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
