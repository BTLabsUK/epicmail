//! End-to-end tests over real sockets on 127.0.0.1: classic 3.0.0, mux/1, /v1 and federation
//! between two relays in one process.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use epicmail::clock::now_ms;
use epicmail::config::Config;
use epicmail::http::{self, AppState};
use epicmail::relay::Relay;
use epicmail::sig;
use epicmail::store::sqlite::SqliteStore;
use epicmail::store::Store;

/// The original relay's fixed first challenge, which wallets older than 3.5.2 always sign.
const STATIC: &str = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Node {
    addr: SocketAddr,
    relay: Arc<Relay>,
}

async fn start(dir: &Path, domain: &str, tweak: impl FnOnce(&mut Config)) -> Node {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = Config::default();
    cfg.server.domain = domain.into();
    cfg.store.path = dir.join(format!("{domain}.db"));
    cfg.test.stall_endpoint = true;
    tweak(&mut cfg);
    cfg.validate().unwrap();
    let cfg = Arc::new(cfg);
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&cfg.store.path, 2, 64).unwrap());
    let relay = Relay::new(cfg.clone(), store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = http::router(AppState { relay: relay.clone(), metrics: None, metrics_on_main: false })
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::spawn(epicmail::forward::run(relay.clone()));
    Node { addr, relay }
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
    fn at(&self, domain: &str) -> String {
        format!("{}@{domain}", self.pk)
    }
}

fn post_frame(from: &Key, from_domain: &str, to: &Key, to_domain: &str, n: u32) -> Value {
    let body = json!({
        "destination": {"public_key": to.pk, "domain": to_domain, "port": 443},
        "encrypted_message": format!("{n:08x}"), "salt": "00", "nonce": "00"
    })
    .to_string();
    json!({"type":"PostSlate","from":from.at(from_domain),"to":to.at(to_domain),"str":body,"signature":from.sign(&body)})
}

async fn connect(n: &Node) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{}/", n.addr)).await.unwrap();
    ws
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

/// Next JSON frame, skipping websocket control frames.
async fn recv(ws: &mut Ws) -> Value {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("timed out waiting for a frame")
            .expect("socket ended")
            .expect("socket error");
        if let Message::Text(t) = m {
            return serde_json::from_str(&t).unwrap_or(Value::String(t.to_string()));
        }
        if let Message::Close(c) = m {
            return json!({"closed": c.map(|c| u16::from(c.code))});
        }
    }
}

/// Next frame of the given type, skipping interval Challenges.
async fn recv_type(ws: &mut Ws, ty: &str) -> Value {
    loop {
        let v = recv(ws).await;
        if v["type"] == "Challenge" && ty != "Challenge" {
            continue;
        }
        assert_eq!(v["type"], ty, "unexpected frame {v}");
        return v;
    }
}

async fn http(n: &Node, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let (status, _, v) = http_with_head(n, method, path, body).await;
    (status, v)
}

/// Like `http`, and also returns the response head (status line and headers).
async fn http_with_head(n: &Node, method: &str, path: &str, body: Option<Value>) -> (u16, String, Value) {
    let mut s = TcpStream::connect(n.addr).await.unwrap();
    let b = body.map(|b| b.to_string()).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
        b.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(40), s.read_to_end(&mut out)).await.unwrap().unwrap();
    let text = String::from_utf8_lossy(&out);
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head.to_string(), serde_json::from_str(body).unwrap_or(Value::String(body.to_string())))
}

async fn waiting(n: &Node) -> u64 {
    n.relay.store.stats(now_ms()).await.unwrap().messages_waiting as u64
}

/// Queued forwards on `n`, read until they equal `want` or 5 s pass. Returns the last count.
async fn forwards_waiting_settles(n: &Node, want: i64) -> i64 {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let got = n.relay.store.stats(now_ms()).await.unwrap().forwards_waiting;
        if got == want || std::time::Instant::now() >= deadline {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Subscribe a classic 3.0.0 socket; returns the challenge it signed.
async fn subscribe(ws: &mut Ws, k: &Key, ver: &str) {
    let c = recv_type(ws, "Challenge").await;
    let ch = c["str"].as_str().unwrap().to_string();
    send(ws, json!({"type":"Subscribe","address":k.pk,"ver":ver,"signature":k.sign(&ch)})).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classic_post_push_made() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());

    let mut b = connect(&n).await;
    let first = recv(&mut b).await;
    assert_eq!(first["type"], "Challenge");
    let first = first["str"].as_str().unwrap().to_string();
    assert!(first.len() == 32 && first != STATIC, "{first}");
    send(&mut b, json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":bob.sign(&first)})).await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));

    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");

    let slate = recv_type(&mut b, "Slate").await;
    assert_eq!(slate["from"], alice.at("relay.test"));
    assert_eq!(slate["ver"], "3.0.0");
    let msgid = slate["epicboxmsgid"].as_str().unwrap().to_string();
    assert_eq!(waiting(&n).await, 1);

    // A bad Made signature is refused and the message stays.
    send(
        &mut b,
        json!({"type":"Made","address":bob.pk,"signature":alice.sign(&msgid),"epicboxmsgid":msgid,"ver":"3.0.0"}),
    )
    .await;
    assert_eq!(recv(&mut b).await["kind"], "InvalidSignature");
    assert_eq!(waiting(&n).await, 1);

    send(
        &mut b,
        json!({"type":"Made","address":bob.pk,"signature":bob.sign(&msgid),"epicboxmsgid":msgid,"ver":"3.0.0"}),
    )
    .await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    let c = recv_type(&mut b, "Challenge").await;
    assert_ne!(c["str"], first.as_str());
    assert_eq!(waiting(&n).await, 0);

    // Subscribing again finds nothing.
    send(
        &mut b,
        json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":bob.sign(c["str"].as_str().unwrap())}),
    )
    .await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_waits_and_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, bob) = (Key::new(), Key::new());
    {
        let n = start(dir.path(), "relay.test", |_| {}).await;
        let mut a = connect(&n).await;
        recv_type(&mut a, "Challenge").await;
        let f = post_frame(&alice, "relay.test", &bob, "relay.test", 7);
        send(&mut a, f.clone()).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
        // The same frame again is a duplicate, not a second message.
        send(&mut a, f).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
        assert_eq!(waiting(&n).await, 1);
    }
    let n = start(dir.path(), "relay.test", |_| {}).await;
    assert_eq!(waiting(&n).await, 1);
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.0.0").await;
    let slate = recv_type(&mut b, "Slate").await;
    assert_eq!(slate["from"], alice.at("relay.test"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_frames_do_not_stop_the_relay() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    for junk in
        ["not json", "{\"type\":5}", "{\"type\":\"Subscribe\",\"address\":\"x@:\"}", "{\"type\":\"PostSlate\"}", "[]"]
    {
        let mut s = connect(&n).await;
        recv_type(&mut s, "Challenge").await;
        s.send(Message::Text(junk.into())).await.unwrap();
        // Typeless frames are ignored on a classic socket; the others get an error or a close.
        let _ = tokio::time::timeout(Duration::from_millis(500), s.next()).await;
    }
    let (st, v) = http(&n, "GET", "/health", None).await;
    assert_eq!(st, 200, "{v}");
    let bob = Key::new();
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.0.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_json_closes_with_3000() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let mut s = connect(&n).await;
    recv_type(&mut s, "Challenge").await;
    s.send(Message::Text("{oops".into())).await.unwrap();
    assert_eq!(recv(&mut s).await, json!({"closed": 3000}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_attach_mail_ack_resume() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");

    let mut m = connect(&n).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]})).await;
    let ok = recv(&mut m).await;
    assert_eq!(ok["ext"], json!(["mux/1"]), "{ok}");
    let ch = ok["challenge"].as_str().unwrap().to_string();
    assert_eq!(ch.len(), 22);
    send(
        &mut m,
        json!({"type":"Attach","ref":"a1","mailboxes":[
        {"address":bob.pk,"signature":bob.sign(&ch)},
        {"address":alice.pk,"signature":bob.sign(&ch)}]}),
    )
    .await;
    let at = recv(&mut m).await;
    assert_eq!(at["type"], "Attached", "{at}");
    assert_eq!(at["mailboxes"][0]["ok"], true);
    assert_eq!(at["mailboxes"][0]["waiting"], 1);
    assert_eq!(at["mailboxes"][1]["ok"], false);
    let token = at["token"].as_str().unwrap().to_string();
    let mail = recv(&mut m).await;
    assert_eq!(mail["type"], "Mail", "{mail}");
    assert_eq!(mail["mailbox"], bob.pk);
    send(&mut m, json!({"type":"Ack","ref":"k1","ids":[mail["id"]]})).await;
    assert_eq!(recv(&mut m).await, json!({"type":"Ok","ref":"k1"}));
    assert_eq!(waiting(&n).await, 0);

    // Push after attach.
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 2)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let mail = recv(&mut m).await;
    assert_eq!(mail["type"], "Mail", "{mail}");
    drop(m);

    // Resume on a new socket: the unacked message comes again.
    let mut m2 = connect(&n).await;
    recv_type(&mut m2, "Challenge").await;
    send(&mut m2, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]})).await;
    recv(&mut m2).await;
    send(&mut m2, json!({"type":"Resume","ref":"r1","token":token})).await;
    let at = recv(&mut m2).await;
    assert_eq!(at["type"], "Attached", "{at}");
    let again = recv(&mut m2).await;
    assert_eq!(again["id"], mail["id"]);
    // The token is single use.
    let mut m3 = connect(&n).await;
    recv_type(&mut m3, "Challenge").await;
    send(&mut m3, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]})).await;
    recv(&mut m3).await;
    send(&mut m3, json!({"type":"Resume","ref":"r2","token":token})).await;
    let e = recv(&mut m3).await;
    assert_eq!(e["code"], "token_unknown", "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_hold_comes_back_when_it_ends() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");

    let mut m = connect(&n).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]})).await;
    let ch = recv(&mut m).await["challenge"].as_str().unwrap().to_string();
    send(&mut m, json!({"type":"Attach","ref":"a1","mailboxes":[{"address":bob.pk,"signature":bob.sign(&ch)}]})).await;
    assert_eq!(recv(&mut m).await["type"], "Attached");
    let mail = recv(&mut m).await;
    assert_eq!(mail["type"], "Mail", "{mail}");

    // Held for 2 s: it comes back after the hold, well before the 15 s pump tick.
    let held = std::time::Instant::now();
    send(&mut m, json!({"type":"Hold","ref":"h1","id":mail["id"],"seconds":2})).await;
    assert_eq!(recv(&mut m).await, json!({"type":"Ok","ref":"h1"}));
    let again = recv(&mut m).await;
    assert_eq!(again["id"], mail["id"], "{again}");
    let after = held.elapsed();
    assert!(after >= Duration::from_millis(1900) && after < Duration::from_secs(5), "back after {after:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_post_pull_made() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", 1);
    f.as_object_mut().unwrap().remove("type");
    let (st, v) = http(&n, "POST", "/v1/post", Some(f)).await;
    assert_eq!(st, 200, "{v}");
    let id = v["id"].as_str().unwrap().to_string();

    let ch = format!("ebh-{}-{:016x}", now_ms() / 1000, rand::random::<u64>());
    let pull = json!({"mailboxes":[{"address":bob.pk,"challenge":ch,"signature":bob.sign(&ch)}],"wait":0});
    let (st, v) = http(&n, "POST", "/v1/pull", Some(pull.clone())).await;
    assert_eq!(st, 200, "{v}");
    let msgs = &v["mailboxes"][0]["messages"];
    assert_eq!(msgs[0]["id"], id, "{v}");
    assert_eq!(msgs[0]["from"], alice.at("relay.test"));

    // The challenge cannot be used twice.
    let (_, v) = http(&n, "POST", "/v1/pull", Some(pull)).await;
    assert_eq!(v["mailboxes"][0]["error"], "challenge was already used", "{v}");

    let made = json!({"address":bob.pk,"acks":[{"id":id,"signature":bob.sign(&id)}]});
    let (st, v) = http(&n, "POST", "/v1/made", Some(made)).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["removed"], 1, "{v}");
    assert_eq!(waiting(&n).await, 0);

    // Long poll wakes when mail arrives.
    let ch = format!("ebh-{}-{:016x}", now_ms() / 1000, rand::random::<u64>());
    let pull = json!({"mailboxes":[{"address":bob.pk,"challenge":ch,"signature":bob.sign(&ch)}],"wait":20});
    let n2 = Node { addr: n.addr, relay: n.relay.clone() };
    let t0 = std::time::Instant::now();
    let poll = tokio::spawn(async move { http(&n2, "POST", "/v1/pull", Some(pull)).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", 2);
    f.as_object_mut().unwrap().remove("type");
    assert_eq!(http(&n, "POST", "/v1/post", Some(f)).await.0, 200);
    let (st, v) = poll.await.unwrap();
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["mailboxes"][0]["messages"].as_array().unwrap().len(), 1, "{v}");
    assert!(t0.elapsed() < Duration::from_secs(5), "long poll did not wake: {:?}", t0.elapsed());

    let (st, wk) = http(&n, "GET", "/.well-known/epicbox.json", None).await;
    assert_eq!(st, 200);
    assert!(wk["features"]["mux/1"].is_object(), "{wk}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_made_says_when_to_retry_after_failed_signatures() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.limits.failed_sigs_per_min_per_ip = 2).await;
    let (bob, eve) = (Key::new(), Key::new());
    let id = "0123456789abcdef0123456789abcdef";
    let bad = json!({"address":bob.pk,"acks":[{"id":id,"signature":eve.sign(id)},{"id":id,"signature":eve.sign(id)}]});
    let (st, v) = http(&n, "POST", "/v1/made", Some(bad.clone())).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["refused"], 2, "{v}");

    let (st, head, v) = http_with_head(&n, "POST", "/v1/made", Some(bad)).await;
    assert_eq!(st, 429, "{v}");
    let retry = head
        .lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("retry-after")))
        .map(|(_, v)| v.trim().parse::<u64>().unwrap());
    assert!(matches!(retry, Some(s) if s >= 1), "no Retry-After in {head}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_between_two_relays() {
    let dir = tempfile::tempdir().unwrap();
    let b = start(dir.path(), "relayb.test", |_| {}).await;
    let b_url = format!("ws://{}", b.addr);
    let a = start(dir.path(), "relaya.test", |c| {
        c.federation.peers.insert("relayb.test:443".into(), b_url.clone());
    })
    .await;
    let (alice, bob) = (Key::new(), Key::new());

    let mut bs = connect(&b).await;
    subscribe(&mut bs, &bob, "3.0.0").await;
    assert_eq!(recv(&mut bs).await, json!({"type":"Ok"}));

    let mut asock = connect(&a).await;
    recv_type(&mut asock, "Challenge").await;
    send(&mut asock, post_frame(&alice, "relaya.test", &bob, "relayb.test", 1)).await;
    assert_eq!(recv(&mut asock).await["type"], "Ok");

    let slate = recv_type(&mut bs, "Slate").await;
    assert_eq!(slate["from"], alice.at("relaya.test"));
    // Relay B pushes the slate to bob before relay A has read B's Ok and deleted its forward
    // row, so wait for A to catch up instead of reading its queue at once.
    assert_eq!(forwards_waiting_settles(&a, 0).await, 0);

    // A destination that is neither local nor reachable stays queued; a private one is refused
    // by vetting rather than connected to.
    send(&mut asock, post_frame(&alice, "relaya.test", &bob, "localhost", 2)).await;
    let r = recv(&mut asock).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stats = a.relay.store.stats(now_ms()).await.unwrap();
    assert!(r["type"] == "Ok" && stats.forwards_waiting == 1 || r["type"] == "Error", "{r}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stall_knob_and_watchdog() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let (st, v) = http(&n, "POST", "/test/stall", Some(json!({"address":bob.pk,"seconds":60}))).await;
    assert_eq!(st, 200, "{v}");
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.0.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    // Stalled: nothing is pushed.
    assert!(tokio::time::timeout(Duration::from_millis(800), b.next()).await.is_err());
    // Unstall: the message is pushed.
    http(&n, "POST", "/test/stall", Some(json!({"address":bob.pk,"seconds":0}))).await;
    let slate = recv_type(&mut b, "Slate").await;
    assert_eq!(slate["from"], alice.at("relay.test"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn older_sockets_beyond_cap_are_closed() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.limits.sockets_per_address = 2).await;
    let bob = Key::new();
    let mut socks = vec![];
    for _ in 0..3 {
        let mut s = connect(&n).await;
        subscribe(&mut s, &bob, "3.0.0").await;
        assert_eq!(recv(&mut s).await, json!({"type":"Ok"}));
        socks.push(s);
    }
    assert_eq!(recv(&mut socks[0]).await, json!({"closed": 4001}));
}

/// 3.1.0 cancel: a bare txid signature (which every receiver of the slate holds) cannot cancel from
/// an unauthenticated socket, a non-participant cannot cancel, and the sender's domain-separated
/// signature cancels, removes the slate and tells the receiver.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_forged_refused_real_cancel_works() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob, mallory) = (Key::new(), Key::new(), Key::new());
    let txid = "0123456789abcdef0123456789abcdef";

    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    let mut post = post_frame(&alice, "relay.test", &bob, "relay.test", 1);
    post["ver"] = json!("3.1.0");
    post["epicboxtxid"] = json!(txid);
    post["epicboxtxidsig"] = json!(alice.sign(txid));
    send(&mut a, post.clone()).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    assert_eq!(waiting(&n).await, 1);

    // Replaying the sender's bare txid signature from a socket that proved no key.
    let mut m = connect(&n).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":alice.sign(txid)})).await;
    assert_eq!(recv(&mut m).await["kind"], "InvalidSignature");
    assert_eq!(waiting(&n).await, 1);

    // A valid signature from someone who is not a participant changes nothing.
    let msig = mallory.sign(&format!("{}{txid}", epicmail::relay::CANCEL_SIG_PREFIX));
    send(&mut m, json!({"type":"CancelTx","address":mallory.pk,"epicboxtxid":txid,"signature":msig})).await;
    assert_eq!(recv(&mut m).await, json!({"type":"Ok"}));
    assert_eq!(waiting(&n).await, 1);

    // The sender cancels with the domain-separated signature.
    let asig = alice.sign(&format!("{}{txid}", epicmail::relay::CANCEL_SIG_PREFIX));
    send(&mut a, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":asig})).await;
    assert_eq!(recv(&mut a).await, json!({"type":"TransactionCancelled","epicboxtxid":txid}));
    assert_eq!(waiting(&n).await, 0);

    // The receiver on 3.1.0 hears about it instead of getting the slate.
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.1.0").await;
    assert_eq!(recv_type(&mut b, "TransactionCancelled").await["epicboxtxid"], txid);

    // Posting the same transaction again is refused.
    send(&mut a, post).await;
    assert_eq!(recv(&mut a).await["type"], "TransactionCancelled");
}

/// Open a socket and switch it to mux/1; returns the socket and its challenge.
async fn mux_socket(n: &Node) -> (Ws, String) {
    let mut m = connect(n).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]})).await;
    let ok = recv(&mut m).await;
    let ch = ok["challenge"].as_str().expect("mux/1 challenge").to_string();
    (m, ch)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_attach_budget_is_shared_by_a_prefix() {
    let dir = tempfile::tempdir().unwrap();
    // One Attach per socket per minute, so eight per prefix.
    let n = start(dir.path(), "relay.test", |c| c.limits.mux_attach_frames_per_min = 1).await;
    let mut socks = Vec::new();
    for i in 0..9 {
        let k = Key::new();
        let (mut m, ch) = mux_socket(&n).await;
        send(&mut m, json!({"type":"Attach","ref":"a","mailboxes":[{"address":k.pk,"signature":k.sign(&ch)}]})).await;
        let r = recv(&mut m).await;
        if i < 8 {
            assert_eq!(r["type"], "Attached", "socket {i}: {r}");
            // The second Attach on one socket is over the per-socket budget.
            send(&mut m, json!({"type":"Attach","ref":"b","mailboxes":[]})).await;
            let e = recv(&mut m).await;
            assert_eq!(e["code"], "rate_limited", "socket {i}: {e}");
        } else {
            assert_eq!(r["code"], "rate_limited", "socket {i}: {r}");
            assert!(r["retry_after"].as_u64().unwrap() >= 1, "{r}");
        }
        socks.push(m);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_is_not_forwarded_against_federation_policy() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.federation.enabled = false).await;
    let (alice, bob) = (Key::new(), Key::new());
    // The sender names another relay in its own address; the slate signature does not cover it.
    let txid = "abcdefghijklmnopqrstuvwxyz012345";
    let mut f = post_frame(&alice, "elsewhere.example", &bob, "relay.test", 1);
    f["epicboxtxid"] = json!(txid);
    f["epicboxtxidsig"] = json!(alice.sign(txid));
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, f).await;
    let ok = recv(&mut a).await;
    assert_eq!(ok["type"], "Ok", "{ok}");

    let cancel = json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,
        "signature":alice.sign(&format!("epicbox-cancel/1:{txid}"))});
    send(&mut a, cancel).await;
    let r = recv(&mut a).await;
    assert_eq!(r, json!({"type":"TransactionCancelled","epicboxtxid":txid}));
    assert_eq!(waiting(&n).await, 0);
    // Federation is off: nothing may be queued for elsewhere.example.
    assert_eq!(n.relay.store.stats(now_ms()).await.unwrap().forwards_waiting, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_pull_has_a_budget_per_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| {
        c.http_api.max_mailboxes = 2;
        c.http_api.max_per_mailbox = 2;
        c.limits.http_per_min_per_ip = 3;
    })
    .await;
    let (bob, carol) = (Key::new(), Key::new());
    let pull = || {
        let entry = |k: &Key| {
            let ch = format!("ebh-{}-{:016x}", now_ms() / 1000, rand::random::<u64>());
            json!({"address":k.pk,"challenge":ch,"signature":k.sign(&ch)})
        };
        json!({"mailboxes":[entry(&bob), entry(&carol)],"wait":0,"limit":1})
    };
    let (st, v) = http(&n, "POST", "/v1/pull", Some(pull())).await;
    assert_eq!(st, 200, "{v}");
    // Two mailboxes cost two of the three units; the next pull of two is refused.
    let (st, head, v) = http_with_head(&n, "POST", "/v1/pull", Some(pull())).await;
    assert_eq!(st, 429, "{v}");
    assert!(head.to_ascii_lowercase().contains("retry-after:"), "{head}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_and_status_answer_without_store_work_per_request() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    for _ in 0..3 {
        let (st, v) = http(&n, "GET", "/ready", None).await;
        assert_eq!((st, v), (200, json!({"ready":true})));
    }
    // Only the first probe in a 5 s window wrote to the store.
    assert!(n.relay.last_ready_probe.lock().is_some());
    let (st, v) = http(&n, "GET", "/status.json", None).await;
    assert_eq!(st, 200, "{v}");
    // No housekeeping runs in this rig, so no store totals have been gathered yet.
    assert!(v["store"].is_null(), "{v}");
    assert_eq!(v["identity"], "relay.test:443");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_stops_reading_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| {
        c.protocol.ping_interval_s = 1;
        c.protocol.idle_timeout_s = 2;
        c.limits.mux_inflight = 256;
        c.limits.bytes_per_min_per_ip = 1 << 30;
    })
    .await;
    let (alice, bob) = (Key::new(), Key::new());
    // About 12 MB of mail: more than the kernel buffers on both ends of a loopback socket.
    let pad = "0".repeat(100_000);
    for i in 0..120u32 {
        let body = json!({
            "destination": {"public_key": bob.pk, "domain": "relay.test", "port": 443},
            "encrypted_message": format!("{i:08x}{pad}"), "salt": "00", "nonce": "00"
        })
        .to_string();
        let post =
            json!({"from":alice.at("relay.test"),"to":bob.at("relay.test"),"str":body,"signature":alice.sign(&body)});
        let (st, v) = http(&n, "POST", "/v1/post", Some(post)).await;
        assert_eq!(st, 200, "{v}");
    }

    // A mux/1 listener with a tiny receive buffer that attaches and then never reads again.
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.set_recv_buffer_size(4096).unwrap();
    let tcp = sock.connect(n.addr).await.unwrap();
    let (mut m, _) =
        tokio_tungstenite::client_async(format!("ws://{}/", n.addr), MaybeTlsStream::Plain(tcp)).await.unwrap();
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]})).await;
    let ch = recv(&mut m).await["challenge"].as_str().unwrap().to_string();
    send(&mut m, json!({"type":"Attach","ref":"a","mailboxes":[{"address":bob.pk,"signature":bob.sign(&ch)}]})).await;
    assert_eq!(n.relay.limiter.sockets_open(), 1);

    // The relay's writes stall; within a few idle timeouts it gives up and frees the socket.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while n.relay.limiter.sockets_open() > 0 {
        assert!(std::time::Instant::now() < deadline, "the socket of a client that stopped reading stayed open");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(m);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_detach_list_is_capped() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.limits.mux_mailboxes_per_socket = 2).await;
    let (mut m, _) = mux_socket(&n).await;
    let keys: Vec<String> = (0..3).map(|_| Key::new().pk).collect();
    send(&mut m, json!({"type":"Detach","ref":"d1","mailboxes":keys[..2]})).await;
    assert_eq!(recv(&mut m).await, json!({"type":"Ok","ref":"d1"}));
    send(&mut m, json!({"type":"Detach","ref":"d2","mailboxes":keys})).await;
    let e = recv(&mut m).await;
    assert_eq!((e["code"].as_str(), e["ref"].as_str()), (Some("too_many_mailboxes"), Some("d2")), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscribe_over_the_fixed_challenge_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");

    // A signature over the fixed constant is what an old wallet sends, and what anyone who has
    // seen one can replay. Neither with nor without `ver` may it open the mailbox.
    for frame in [
        json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":bob.sign(STATIC)}),
        json!({"type":"Subscribe","address":bob.pk,"signature":bob.sign(STATIC)}),
    ] {
        let mut s = connect(&n).await;
        recv_type(&mut s, "Challenge").await;
        send(&mut s, frame).await;
        assert_eq!(recv(&mut s).await["kind"], "InvalidSignature");
    }
    assert_eq!(waiting(&n).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_waiting_counts_every_mailbox_and_has_a_budget() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.limits.mux_inflight = 1).await;
    let (alice, bob, carol) = (Key::new(), Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    for i in 0..3 {
        send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", i)).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
    }
    let (mut m, ch) = mux_socket(&n).await;
    send(
        &mut m,
        json!({"type":"Attach","ref":"a","mailboxes":[
            {"address":bob.pk,"signature":bob.sign(&ch)},{"address":carol.pk,"signature":carol.sign(&ch)}]}),
    )
    .await;
    assert_eq!(recv(&mut m).await["type"], "Attached");
    assert_eq!(recv(&mut m).await["type"], "Mail");
    // One of bob's three is in flight; carol has none.
    send(&mut m, json!({"type":"Waiting","ref":"w"})).await;
    let w = recv(&mut m).await;
    assert_eq!(w["waiting"], json!({bob.pk.clone(): 2, carol.pk.clone(): 0}), "{w}");
    assert_eq!((w["inflight"].as_u64(), w["ref"].as_str()), (Some(1), Some("w")));
    for _ in 1..60 {
        send(&mut m, json!({"type":"Waiting"})).await;
        assert_eq!(recv(&mut m).await["type"], "Ok");
    }
    send(&mut m, json!({"type":"Waiting","ref":"x"})).await;
    let e = recv(&mut m).await;
    assert_eq!(e["code"], "rate_limited", "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_long_polls_are_capped_per_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.http_api.max_waiting_per_ip = 1).await;
    let (alice, bob) = (Key::new(), Key::new());
    let pull = |k: &Key, wait: u64| {
        let ch = format!("ebh-{}-{:016x}", now_ms() / 1000, rand::random::<u64>());
        json!({"mailboxes":[{"address":k.pk,"challenge":ch,"signature":k.sign(&ch)}],"wait":wait})
    };
    let n2 = Node { addr: n.addr, relay: n.relay.clone() };
    let first = pull(&bob, 20);
    let t0 = std::time::Instant::now();
    let poll = tokio::spawn(async move { http(&n2, "POST", "/v1/pull", Some(first)).await });
    while n.relay.pull_waiters.waiting() == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // A second long poll from the same prefix is refused; a plain pull is not.
    let (st, head, v) = http_with_head(&n, "POST", "/v1/pull", Some(pull(&bob, 20))).await;
    assert_eq!(st, 429, "{v}");
    assert!(head.to_ascii_lowercase().contains("retry-after:"), "{head}");
    assert_eq!(http(&n, "POST", "/v1/pull", Some(pull(&bob, 0))).await.0, 200);
    // Mail for another mailbox does not end the poll; mail for bob does.
    let mut f = post_frame(&alice, "relay.test", &alice, "relay.test", 1);
    f.as_object_mut().unwrap().remove("type");
    assert_eq!(http(&n, "POST", "/v1/post", Some(f)).await.0, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!poll.is_finished(), "woken by mail for another mailbox");
    let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", 2);
    f.as_object_mut().unwrap().remove("type");
    assert_eq!(http(&n, "POST", "/v1/post", Some(f)).await.0, 200);
    let (st, v) = poll.await.unwrap();
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["mailboxes"][0]["messages"].as_array().unwrap().len(), 1, "{v}");
    assert!(t0.elapsed() < Duration::from_secs(5));
    assert_eq!(n.relay.pull_waiters.waiting(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn posts_are_refused_when_the_store_is_full() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.store.max_bytes = 1).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    let r = recv(&mut a).await;
    assert_eq!(r["type"], "Error", "{r}");
    assert!(r["description"].as_str().unwrap().contains("storage is full"), "{r}");
    let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", 2);
    f.as_object_mut().unwrap().remove("type");
    let (st, v) = http(&n, "POST", "/v1/post", Some(f)).await;
    assert_eq!(st, 429, "{v}");
    assert_eq!(waiting(&n).await, 0);
    // Only posts are refused: a full relay still lets wallets subscribe and collect.
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.0.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn frames_other_than_posts_pay_the_byte_budget() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.limits.bytes_per_min_per_ip = 100_000).await;
    let pad = "a".repeat(60_000);
    let mut s = connect(&n).await;
    recv_type(&mut s, "Challenge").await;
    // Typeless frames are ignored on a classic socket, but their bytes count.
    s.send(Message::Text(json!({ "pad": pad }).to_string().into())).await.unwrap();
    s.send(Message::Text(json!({ "pad": pad }).to_string().into())).await.unwrap();
    assert_eq!(recv(&mut s).await, json!({"closed": 1008}));

    // A post over the budget gets the usual rate-limit error, and its socket stays open.
    let (alice, bob) = (Key::new(), Key::new());
    let body = json!({
        "destination": {"public_key": bob.pk, "domain": "relay.test", "port": 443},
        "encrypted_message": pad, "salt": "00", "nonce": "00"
    })
    .to_string();
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(
        &mut a,
        json!({"type":"PostSlate","from":alice.at("relay.test"),"to":bob.at("relay.test"),"str":body,"signature":alice.sign(&body)}),
    )
    .await;
    let r = recv(&mut a).await;
    assert_eq!(r["type"], "Error", "{r}");
    assert!(r["description"].as_str().unwrap().contains("Rate limit"), "{r}");
    send(&mut a, json!({"type":"GetVersion"})).await;
    assert_eq!(recv(&mut a).await["type"], "GetVersion");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signature_checks_have_a_budget_per_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.limits.sig_checks_per_min_per_ip = 3).await;
    // Valid Subscribes with fresh keys: each costs a check, and passing does not make it free.
    let mut s = connect(&n).await;
    let ch = recv_type(&mut s, "Challenge").await["str"].as_str().unwrap().to_string();
    for _ in 0..3 {
        let k = Key::new();
        send(&mut s, json!({"type":"Subscribe","address":k.pk,"ver":"3.0.0","signature":k.sign(&ch)})).await;
        assert_eq!(recv(&mut s).await, json!({"type":"Ok"}));
    }
    let k = Key::new();
    send(&mut s, json!({"type":"Subscribe","address":k.pk,"ver":"3.0.0","signature":k.sign(&ch)})).await;
    let r = recv(&mut s).await;
    assert_eq!(r["type"], "Error", "{r}");
    assert!(r["description"].as_str().unwrap().contains("Rate limit"), "{r}");

    // The same prefix's mux/1 Attach is refused before any check runs.
    let mut m = connect(&n).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]})).await;
    let ok = recv(&mut m).await;
    let mch = ok["challenge"].as_str().unwrap().to_string();
    send(&mut m, json!({"type":"Attach","ref":"a1","mailboxes":[{"address":k.pk,"signature":k.sign(&mch)}]})).await;
    let r = recv(&mut m).await;
    assert_eq!(r["code"], "rate_limited", "{r}");
}

/// Open a mux/1 socket; returns it with its Attach challenge.
async fn mux_open(n: &Node) -> (Ws, String) {
    let mut m = connect(n).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]})).await;
    let ok = recv(&mut m).await;
    let ch = ok["challenge"].as_str().unwrap().to_string();
    (m, ch)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stolen_resume_token_is_revoked_by_the_owners_next_attach() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let bob = Key::new();
    // The owner attaches and gets a token; a thief takes it.
    let (mut a, ch) = mux_open(&n).await;
    send(&mut a, json!({"type":"Attach","ref":"a","mailboxes":[{"address":bob.pk,"signature":bob.sign(&ch)}]})).await;
    let at = recv(&mut a).await;
    let stolen = at["token"].as_str().unwrap().to_string();
    let first_expiry = at["token_expires"].as_i64().unwrap();
    // The thief resumes: it holds the mailbox, and its new token keeps the old expiry.
    let (mut t, _) = mux_open(&n).await;
    send(&mut t, json!({"type":"Resume","ref":"r","token":stolen})).await;
    let at = recv(&mut t).await;
    assert_eq!(at["mailboxes"][0]["ok"], true, "{at}");
    assert_eq!(at["token_expires"].as_i64().unwrap(), first_expiry, "Resume extended the token: {at}");
    let thief_token = at["token"].as_str().unwrap().to_string();
    drop(t);
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The owner proves the key again on a new socket.
    let (mut c, ch) = mux_open(&n).await;
    send(&mut c, json!({"type":"Attach","ref":"a","mailboxes":[{"address":bob.pk,"signature":bob.sign(&ch)}]})).await;
    assert_eq!(recv(&mut c).await["mailboxes"][0]["ok"], true);
    // The thief's token no longer resumes that mailbox.
    let (mut t2, _) = mux_open(&n).await;
    send(&mut t2, json!({"type":"Resume","ref":"r","token":thief_token})).await;
    let at = recv(&mut t2).await;
    assert_eq!(at["type"], "Attached", "{at}");
    assert_eq!(at["mailboxes"].as_array().unwrap().len(), 0, "stolen token still resumes the mailbox: {at}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_absolute_domain_is_this_relay_not_a_peer() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.federation.allow_private = true).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    // The destination inside the slate names this relay with a trailing dot.
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test.", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    assert_eq!(waiting(&n).await, 1, "stored here");
    assert_eq!(forwards_waiting_settles(&n, 0).await, 0, "not queued for a forward to itself");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socket_with_our_own_instance_id_is_a_forward_loop() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let mut req = format!("ws://{}/", n.addr).into_client_request().unwrap();
    req.headers_mut().insert("x-epicmail-instance", n.relay.instance_id.parse().unwrap());
    match tokio_tungstenite::connect_async(req).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => assert_eq!(r.status().as_u16(), 508),
        other => panic!("expected 508, got {:?}", other.map(|_| ())),
    }
    // Another relay's id is a normal peer.
    let mut req = format!("ws://{}/", n.addr).into_client_request().unwrap();
    req.headers_mut().insert("x-epicmail-instance", "someone-else".parse().unwrap());
    assert!(tokio_tungstenite::connect_async(req).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_peer_costs_one_attempt_per_backoff_not_one_per_row() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| {
        c.federation.allow_private = true;
        // Nothing listens on the discard port: every connect fails at once.
        c.federation.peers.insert("dead.test:443".into(), "ws://127.0.0.1:9/".into());
    })
    .await;
    let alice = Key::new();
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    for i in 0..3 {
        send(&mut a, post_frame(&alice, "relay.test", &Key::new(), "dead.test", i)).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
    }
    // Two manager ticks (5 s each) pass; the peer failed once and is held back as a whole.
    tokio::time::sleep(Duration::from_secs(11)).await;
    let rows = n.relay.store.forwards_due("dead.test:443", now_ms() + 7_200_000, 50).await.unwrap();
    assert_eq!(rows.len(), 3);
    let attempts: i64 = rows.iter().map(|r| r.attempts).sum();
    assert_eq!(attempts, 1, "each tick tried another row of the dead peer");
}
