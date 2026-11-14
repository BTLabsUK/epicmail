//! Route check between Epicbox relays: a mailbox on relay A sends one slate to a mailbox on relay
//! B, and B answers with one back, the way two wallets exchange a transaction. Each side speaks the
//! wallet's protocol: ClientDetails (listener), Subscribe 3.0.0 over each Challenge, Made after
//! each Slate, so the relays push mail live and delete it after.
//!
//!   routes --home wss://relay.example.org/@relay.example.org \
//!          --peer wss://epicbox.example.com/@epicbox.example.com --peer ...
//!
//! Tests home -> home and, for each peer, home -> peer -> home. Prints one JSON line per route.
//! The slates carry no transaction: the envelope is well formed and signed, the encrypted part is
//! random bytes, so a relay routes it like any other and a wallet would reject it.

use std::time::{Duration, Instant};

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use epicmail::sig;

#[derive(Parser)]
struct Args {
    /// The relay under test, as `<websocket url>@<domain>[:port]`.
    #[arg(long)]
    home: String,
    /// Other relays, same form. Repeat.
    #[arg(long)]
    peer: Vec<String>,
    /// Seconds to wait for each delivery.
    #[arg(long, default_value_t = 90)]
    wait: u64,
    /// Use floonet (testnet) address versions instead of mainnet.
    #[arg(long)]
    floonet: bool,
    /// Instead of routes: behave like an epicbox 2.0.0 wallet (epic-wallet 3.4.0 to 3.5.1) on
    /// each relay given, as receiver and as sender, next to a 3.0.0 wallet.
    #[arg(long)]
    legacy: bool,
}

/// The original relay's fixed first challenge; 2.0.0 wallets sign it whatever the relay sends.
const STATIC: &str = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";

/// A 2.0.0 wallet on `relay`: how its Subscribe is answered, and whether its post reaches a
/// 3.0.0 wallet on the same relay.
async fn legacy(relay: &Relay, floonet: bool, wait: Duration) -> Value {
    let mut out = json!({"relay": relay.domain});
    let (old, new) = (Key::new(floonet), Key::new(floonet));
    // As a receiver: GetVersion and Challenge on the first Challenge, then Subscribe 2.0.0 over
    // the fixed constant.
    let r = async {
        let (mut ws, _) = tokio_tungstenite::connect_async(&relay.url).await.map_err(|e| format!("connect: {e}"))?;
        let first = next(&mut ws, Duration::from_secs(15)).await?;
        let first_static = first["str"] == STATIC;
        send(&mut ws, &json!({"type":"GetVersion"})).await?;
        send(&mut ws, &json!({"type":"Challenge"})).await?;
        send(&mut ws, &json!({"type":"Subscribe","address":old.pk,"ver":"2.0.0","signature":old.sign(STATIC)})).await?;
        let mut answers = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match next(&mut ws, Duration::from_millis(1500)).await {
                Ok(v) => {
                    let t = v["type"].as_str().unwrap_or("?").to_string();
                    let k = v["kind"].as_str().map(|k| format!(" {k}")).unwrap_or_default();
                    answers.push(format!("{t}{k}"));
                }
                Err(_) => break,
            }
        }
        Ok::<_, String>(json!({"first_challenge_is_static": first_static, "answers": answers,
            "subscribed": answers.iter().any(|a| a == "Ok" ) && !answers.iter().any(|a| a.contains("InvalidSignature"))}))
    }
    .await;
    out["as_receiver"] = r.unwrap_or_else(|e| json!({"error": e}));
    // As a sender to a 3.0.0 wallet: GetVersion, Challenge, FastSend, then PostSlate.
    let s = async {
        let mut mb = Mailbox::open(relay, &new).await?;
        let (mut ws, _) = tokio_tungstenite::connect_async(&relay.url).await.map_err(|e| format!("connect: {e}"))?;
        next(&mut ws, Duration::from_secs(15)).await?;
        for f in [json!({"type":"GetVersion"}), json!({"type":"Challenge"}), json!({"type":"FastSend"})] {
            send(&mut ws, &f).await?;
        }
        let marker = format!("cc{:08x}", rand::random::<u32>());
        let body = json!({
            "destination": {"public_key": new.pk, "domain": relay.domain, "port": relay.port},
            "encrypted_message": format!("{marker}{}", hex::encode(rand::random::<[u8; 32]>())),
            "salt": "00", "nonce": "00"
        })
        .to_string();
        send(&mut ws, &json!({"type":"PostSlate","from":relay.addr(&old),"to":relay.addr(&new),"str":body,"signature":old.sign(&body)})).await?;
        let mut post = "no answer".to_string();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match next(&mut ws, Duration::from_secs(2)).await {
                Ok(v) if v["type"] == "Ok" || v["type"] == "Error" => {
                    post = format!("{}{}", v["type"].as_str().unwrap_or(""), v["kind"].as_str().map(|k| format!(" {k}")).unwrap_or_default());
                    if v["type"] == "Error" { break; }
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let delivered = mb.receive(&marker, wait).await.is_ok();
        Ok::<_, String>(json!({"answers_ok_or_error": post, "delivered_to_3_0_0": delivered}))
    }
    .await;
    out["as_sender"] = s.unwrap_or_else(|e| json!({"error": e}));
    out
}

struct Relay {
    url: String,
    domain: String,
    port: u16,
}

impl Relay {
    fn parse(s: &str) -> anyhow::Result<Self> {
        let (url, ident) = s.rsplit_once('@').ok_or_else(|| anyhow::anyhow!("expected url@domain: {s}"))?;
        let (domain, port) = match ident.rsplit_once(':') {
            Some((d, p)) => (d.to_string(), p.parse()?),
            None => (ident.to_string(), 443),
        };
        Ok(Relay { url: url.to_string(), domain, port })
    }
    fn addr(&self, k: &Key) -> String {
        if self.port == 443 {
            format!("{}@{}", k.pk, self.domain)
        } else {
            format!("{}@{}:{}", k.pk, self.domain, self.port)
        }
    }
}

struct Key {
    secret: SecretKey,
    pk: String,
}

impl Key {
    fn new(floonet: bool) -> Self {
        let secret = SecretKey::from_secret_bytes(rand::random()).unwrap();
        let v = if floonet { sig::VERSION_FLOONET } else { sig::VERSION_MAINNET };
        let pk = sig::encode_public_key(&PublicKey::from_secret_key(&secret), v);
        Key { secret, pk }
    }
    fn sign(&self, m: &str) -> String {
        sig::sign(&self.secret, m)
    }
}

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// A subscribed socket for `key` on `relay`.
struct Mailbox<'a> {
    ws: Ws,
    key: &'a Key,
    challenge: String,
}

impl<'a> Mailbox<'a> {
    async fn open(relay: &Relay, key: &'a Key) -> Result<Mailbox<'a>, String> {
        let (mut ws, _) = tokio::time::timeout(Duration::from_secs(15), tokio_tungstenite::connect_async(&relay.url))
            .await
            .map_err(|_| "connect timeout".to_string())?
            .map_err(|e| format!("connect: {e}"))?;
        let first = next(&mut ws, Duration::from_secs(15)).await?;
        if first["type"] != "Challenge" {
            return Err(format!("first frame {first}"));
        }
        let challenge = first["str"].as_str().unwrap_or("").to_string();
        let details = json!({"type":"ClientDetails","wallet_version":"3.6.0","wallet_mode":"listener","protocol_version":"3.0.0"});
        send(&mut ws, &details).await?;
        let mut m = Mailbox { ws, key, challenge };
        m.subscribe().await?;
        // Answers: Ok for ClientDetails (relays that answer it) and Ok for Subscribe.
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut oks = 0;
        while oks < 1 || Instant::now() < deadline.min(Instant::now() + Duration::from_millis(300)) {
            match next(&mut m.ws, Duration::from_millis(1500)).await {
                Ok(v) if v["type"] == "Ok" => oks += 1,
                Ok(v) if v["type"] == "Challenge" => {
                    m.challenge = v["str"].as_str().unwrap_or("").to_string();
                    m.subscribe().await?;
                }
                Ok(v) if v["type"] == "Error" => return Err(format!("subscribe refused: {v}")),
                Ok(_) => {}
                Err(e) if e == "timeout" && oks > 0 => break,
                Err(e) => return Err(format!("subscribe: {e}")),
            }
            if Instant::now() > deadline {
                break;
            }
        }
        if oks == 0 {
            return Err("no Ok after Subscribe".into());
        }
        Ok(m)
    }

    async fn subscribe(&mut self) -> Result<(), String> {
        let f =
            json!({"type":"Subscribe","address":self.key.pk,"ver":"3.0.0","signature":self.key.sign(&self.challenge)});
        send(&mut self.ws, &f).await
    }

    /// Post a slate to `to` (full address) for `dest` (public key, domain, port); wait for the
    /// relay's answer.
    async fn post(&mut self, from: &str, to: &str, dest: (&str, &str, u16), marker: &str) -> Result<(), String> {
        let em = format!("{marker}{}", hex::encode([rand::random::<[u8; 32]>(), rand::random::<[u8; 32]>()].concat()));
        let body = json!({
            "destination": {"public_key": dest.0, "domain": dest.1, "port": dest.2},
            "encrypted_message": em, "salt": hex::encode(rand::random::<[u8; 8]>()),
            "nonce": hex::encode(rand::random::<[u8; 12]>())
        })
        .to_string();
        let f = json!({"type":"PostSlate","from":from,"to":to,"str":body,"signature":self.key.sign(&body)});
        send(&mut self.ws, &f).await?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match next(&mut self.ws, left).await? {
                v if v["type"] == "Ok" => return Ok(()),
                v if v["type"] == "Error" => return Err(format!("post refused: {}", v["description"])),
                v if v["type"] == "Challenge" => {
                    self.challenge = v["str"].as_str().unwrap_or("").to_string();
                    self.subscribe().await?;
                }
                _ => {}
            }
        }
    }

    /// Wait for the Slate carrying `marker`; Made it. Other slates are Made too.
    async fn receive(&mut self, marker: &str, wait: Duration) -> Result<Duration, String> {
        let t0 = Instant::now();
        let deadline = t0 + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("not delivered in time".into());
            }
            let v = match next(&mut self.ws, left).await {
                Ok(v) => v,
                Err(e) if e == "timeout" => return Err("not delivered in time".into()),
                Err(e) => return Err(e),
            };
            match v["type"].as_str().unwrap_or("") {
                "Challenge" => {
                    self.challenge = v["str"].as_str().unwrap_or("").to_string();
                    self.subscribe().await?;
                }
                "Slate" => {
                    let id = v["epicboxmsgid"].as_str().unwrap_or("").to_string();
                    let made = json!({"type":"Made","address":self.key.pk,"signature":self.key.sign(&id),"epicboxmsgid":id,"ver":"3.0.0"});
                    send(&mut self.ws, &made).await?;
                    let ours = v["str"]
                        .as_str()
                        .and_then(|s| serde_json::from_str::<Value>(s).ok())
                        .and_then(|b| b["encrypted_message"].as_str().map(|e| e.starts_with(marker)))
                        .unwrap_or(false);
                    if ours {
                        // Let the Made land before the socket closes.
                        let _ = next(&mut self.ws, Duration::from_millis(800)).await;
                        return Ok(t0.elapsed());
                    }
                }
                _ => {}
            }
        }
    }
}

async fn send(ws: &mut Ws, v: &Value) -> Result<(), String> {
    ws.send(Message::Text(v.to_string().into())).await.map_err(|e| format!("send: {e}"))
}

async fn next(ws: &mut Ws, t: Duration) -> Result<Value, String> {
    let deadline = Instant::now() + t;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, ws.next()).await {
            Err(_) => return Err("timeout".into()),
            Ok(None) => return Err("closed".into()),
            Ok(Some(Err(e))) => return Err(format!("ws: {e}")),
            Ok(Some(Ok(Message::Text(s)))) => {
                return Ok(serde_json::from_str(&s).unwrap_or(Value::String(s.to_string())))
            }
            Ok(Some(Ok(Message::Close(c)))) => return Err(format!("closed by relay: {c:?}")),
            Ok(Some(Ok(_))) => continue,
        }
    }
}

/// One exchange: `a` on relay `ra` sends to `b` on relay `rb`, `b` answers.
async fn exchange(ra: &Relay, rb: &Relay, floonet: bool, wait: Duration) -> Value {
    let (ka, kb) = (Key::new(floonet), Key::new(floonet));
    let route = format!("{} -> {} -> {}", ra.domain, rb.domain, ra.domain);
    let mut out = json!({"route": route});
    let mut ma = match Mailbox::open(ra, &ka).await {
        Ok(m) => m,
        Err(e) => {
            out["error"] = json!(format!("{}: {e}", ra.domain));
            return out;
        }
    };
    let mut mb = match Mailbox::open(rb, &kb).await {
        Ok(m) => m,
        Err(e) => {
            out["error"] = json!(format!("{}: {e}", rb.domain));
            return out;
        }
    };
    let m1 = format!("aa{:08x}", rand::random::<u32>());
    let t = Instant::now();
    match ma.post(&ra.addr(&ka), &rb.addr(&kb), (&kb.pk, &rb.domain, rb.port), &m1).await {
        Err(e) => {
            out["leg1"] = json!({"ok": false, "error": e});
            return out;
        }
        Ok(()) => out["leg1_post_ms"] = json!(t.elapsed().as_millis()),
    }
    match mb.receive(&m1, wait).await {
        Err(e) => {
            out["leg1"] = json!({"ok": false, "error": e});
            return out;
        }
        Ok(_) => out["leg1"] = json!({"ok": true, "ms": t.elapsed().as_millis()}),
    }
    let m2 = format!("bb{:08x}", rand::random::<u32>());
    let t = Instant::now();
    if let Err(e) = mb.post(&rb.addr(&kb), &ra.addr(&ka), (&ka.pk, &ra.domain, ra.port), &m2).await {
        out["leg2"] = json!({"ok": false, "error": e});
        return out;
    }
    match ma.receive(&m2, wait).await {
        Err(e) => out["leg2"] = json!({"ok": false, "error": e}),
        Ok(_) => out["leg2"] = json!({"ok": true, "ms": t.elapsed().as_millis()}),
    }
    let _ = ma.ws.close(None).await;
    let _ = mb.ws.close(None).await;
    out
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let home = Relay::parse(&args.home)?;
    let peers: Vec<Relay> = args.peer.iter().map(|p| Relay::parse(p)).collect::<anyhow::Result<_>>()?;
    let wait = Duration::from_secs(args.wait);
    if args.legacy {
        println!("{}", legacy(&home, args.floonet, wait).await);
        for p in &peers {
            println!("{}", legacy(p, args.floonet, wait).await);
        }
        return Ok(());
    }
    println!("{}", exchange(&home, &home, args.floonet, wait).await);
    for p in &peers {
        println!("{}", exchange(&home, p, args.floonet, wait).await);
    }
    Ok(())
}
