//! Client code shared by the livetest and conformance examples: keys, frames, a websocket
//! client and a small HTTP/1.1 client. Included with `#[path]`, so it is compiled into each.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context};
use futures_util::{SinkExt, StreamExt};
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use epicmail::sig;

/// The original relay's fixed first challenge, which wallets older than 3.5.2 sign.
pub const STATIC: &str = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";

#[derive(Clone)]
pub struct Key {
    pub secret: SecretKey,
    pub pk: String,
}

impl Key {
    pub fn new() -> Self {
        Self::from_secret(SecretKey::from_secret_bytes(rand::random()).unwrap())
    }
    pub fn from_secret(secret: SecretKey) -> Self {
        let pk = sig::encode_public_key(&PublicKey::from_secret_key(&secret), sig::VERSION_MAINNET);
        Key { secret, pk }
    }
    pub fn sign(&self, m: &str) -> String {
        sig::sign(&self.secret, m)
    }
    pub fn at(&self, d: &str) -> String {
        format!("{}@{d}", self.pk)
    }
}

pub fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn post_frame(from: &Key, from_d: &str, to: &Key, to_d: &str, msg: &str) -> Value {
    let body = json!({
        "destination": {"public_key": to.pk, "domain": to_d, "port": 443},
        "encrypted_message": msg, "salt": "00", "nonce": "00"
    })
    .to_string();
    json!({"type":"PostSlate","from":from.at(from_d),"to":to.at(to_d),"str":body,"signature":from.sign(&body)})
}

/// A /v1 mailbox proof: a fresh challenge signed as `<challenge>@<domain>:443`, bound to the relay.
pub fn ebh(k: &Key, d: &str) -> Value {
    let ch = format!("ebh-{}-{:016x}", now_s(), rand::random::<u64>());
    let signed = format!("{ch}@{}:443", d.to_ascii_lowercase());
    json!({"address":k.pk,"challenge":ch,"signature":k.sign(&signed)})
}

// ---------------------------------------------------------------------------------------------
// Websocket

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn ws_connect(url: &str) -> Result<Ws, String> {
    match tokio::time::timeout(Duration::from_secs(15), tokio_tungstenite::connect_async(url)).await {
        Err(_) => Err("connect timeout".into()),
        Ok(Err(tungstenite::Error::Http(r))) => Err(format!("http {}", r.status().as_u16())),
        Ok(Err(tungstenite::Error::Io(e))) => Err(format!("io {:?}", e.kind())),
        Ok(Err(e)) => Err(short(&e.to_string())),
        Ok(Ok((ws, _))) => Ok(ws),
    }
}

pub fn short(s: &str) -> String {
    s.chars().take(80).collect()
}

pub enum Frame {
    Json(Value),
    Closed(Option<u16>),
    Timeout,
    Err(String),
}

impl Frame {
    pub fn label(&self) -> String {
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
    pub fn json(&self) -> Value {
        match self {
            Frame::Json(v) => v.clone(),
            _ => json!({"frame": self.label()}),
        }
    }
}

pub async fn next_frame(ws: &mut Ws, t: Duration) -> Frame {
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
pub async fn answer(ws: &mut Ws, t: Duration) -> Frame {
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

pub async fn send(ws: &mut Ws, v: &Value) -> Result<(), String> {
    ws.send(Message::Text(v.to_string().into())).await.map_err(|e| short(&e.to_string()))
}

pub async fn challenge(ws: &mut Ws) -> anyhow::Result<String> {
    match next_frame(ws, Duration::from_secs(10)).await {
        Frame::Json(v) if v["type"] == "Challenge" => Ok(v["str"].as_str().unwrap_or("").to_string()),
        f => bail!("expected Challenge, got {}", f.label()),
    }
}

// ---------------------------------------------------------------------------------------------
// HTTP/1.1 over TLS (or plain), one request at a time per connection

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub struct Http {
    pub host: String,
    pub port: u16,
    pub tls: Option<tokio_rustls::TlsConnector>,
}

pub struct Conn {
    pub io: Box<dyn Io>,
    pub buf: Vec<u8>,
}

pub struct Resp {
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::String(String::from_utf8_lossy(&self.body).into()))
    }
}

impl Http {
    pub fn new(base: &url::Url) -> anyhow::Result<Self> {
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

    pub async fn open(&self) -> anyhow::Result<Conn> {
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

    pub async fn request(
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
    pub async fn once(&self, method: &str, path: &str, body: Option<&Value>) -> anyhow::Result<Resp> {
        let mut c = self.open().await?;
        self.request(&mut c, method, path, body, Duration::from_secs(40)).await
    }
}

pub async fn fill(c: &mut Conn) -> anyhow::Result<()> {
    let mut tmp = [0u8; 16384];
    let n = c.io.read(&mut tmp).await?;
    if n == 0 {
        bail!("connection closed");
    }
    c.buf.extend_from_slice(&tmp[..n]);
    Ok(())
}

pub async fn read_response(c: &mut Conn) -> anyhow::Result<Resp> {
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

pub fn ms(t0: Instant) -> String {
    format!("{:.0} ms", t0.elapsed().as_secs_f64() * 1000.0)
}
