//! End-to-end tests over real sockets on 127.0.0.1: classic 3.0.0, mux/1, /v1 and federation
//! between two relays in one process.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use secp256k1::{PublicKey, SecretKey};
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

/// What a client signs for `/v1/pull` at `domain` (port 443 in the test config).
fn proof(ch: &str, domain: &str) -> String {
    format!("{ch}@{domain}:443")
}

/// The original relay's fixed first challenge, which wallets older than 3.5.2 always sign.
const STATIC: &str = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Node {
    addr: SocketAddr,
    relay: Arc<Relay>,
}

async fn start(dir: &Path, domain: &str, tweak: impl FnOnce(&mut Config)) -> Node {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    start_on(dir, domain, listener, tweak).await
}

/// `start` on a listener the caller bound, so its address is known before the config is.
async fn start_on(
    dir: &Path,
    domain: &str,
    listener: tokio::net::TcpListener,
    tweak: impl FnOnce(&mut Config),
) -> Node {
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
        let secret = SecretKey::from_secret_bytes(rand::random()).unwrap();
        let pk = sig::encode_public_key(&PublicKey::from_secret_key(&secret), sig::VERSION_MAINNET);
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
    let pull = json!({"mailboxes":[{"address":bob.pk,"challenge":ch,"signature":bob.sign(&proof(&ch, "relay.test"))}],"wait":0});
    let (st, v) = http(&n, "POST", "/v1/pull", Some(pull.clone())).await;
    assert_eq!(st, 200, "{v}");
    let msgs = &v["mailboxes"][0]["messages"];
    assert_eq!(msgs[0]["id"], id, "{v}");
    assert_eq!(msgs[0]["from"], alice.at("relay.test"));

    // The challenge cannot be used twice.
    let (_, v) = http(&n, "POST", "/v1/pull", Some(pull)).await;
    assert_eq!(v["mailboxes"][0]["error"], "challenge was already used", "{v}");

    // A proof made for another relay is refused, and is not burnt: the right one still works.
    let ch2 = format!("ebh-{}-{:016x}", now_ms() / 1000, rand::random::<u64>());
    let entry = |sig: String| json!({"mailboxes":[{"address":bob.pk,"challenge":ch2,"signature":sig}],"wait":0});
    let (_, v) = http(&n, "POST", "/v1/pull", Some(entry(bob.sign(&proof(&ch2, "other.test"))))).await;
    assert_eq!(v["mailboxes"][0]["error"], "signature does not verify", "{v}");
    let (_, v) = http(&n, "POST", "/v1/pull", Some(entry(bob.sign(&ch2)))).await;
    assert_eq!(v["mailboxes"][0]["error"], "signature does not verify", "unbound proof: {v}");
    let (st, v) = http(&n, "POST", "/v1/pull", Some(entry(bob.sign(&proof(&ch2, "relay.test"))))).await;
    assert_eq!(st, 200, "{v}");
    assert!(v["mailboxes"][0].get("error").is_none(), "{v}");
    let (_, v) = http(&n, "POST", "/v1/pull", Some(entry(bob.sign(&proof(&ch2, "relay.test"))))).await;
    assert_eq!(v["mailboxes"][0]["error"], "challenge was already used", "{v}");

    let made = json!({"address":bob.pk,"acks":[{"id":id,"signature":bob.sign(&id)}]});
    let (st, v) = http(&n, "POST", "/v1/made", Some(made)).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["removed"], 1, "{v}");
    assert_eq!(waiting(&n).await, 0);

    // Long poll wakes when mail arrives.
    let ch = format!("ebh-{}-{:016x}", now_ms() / 1000, rand::random::<u64>());
    let pull = json!({"mailboxes":[{"address":bob.pk,"challenge":ch,"signature":bob.sign(&proof(&ch, "relay.test"))}],"wait":20});
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
    assert!(wk["features"]["txcancel/1"].is_object(), "{wk}");
    assert!(wk["protocol_versions"].as_array().unwrap().iter().any(|v| v == "3.1.0"), "{wk}");
    assert_discovery_shape(&wk);

    let (st, info) = http(&n, "GET", "/v1/info", None).await;
    assert_eq!(st, 200);
    assert_info_shape(&info);

    let (st, status) = http(&n, "GET", "/status.json", None).await;
    assert_eq!(st, 200);
    assert!(status.get("version").is_none(), "{status}");
}

/// `/v1/info` lists what clients need and omits the per-IP abuse thresholds.
fn assert_info_shape(info: &Value) {
    let mut keys: Vec<&str> = info.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "challenge",
            "challenge_single_use",
            "epicbox_protocol",
            "federation",
            "identity",
            "max_mailboxes_per_pull",
            "max_messages_per_mailbox",
            "max_wait_seconds",
            "max_waiting_pulls_per_ip",
            "protocol",
            "redeliver_after_seconds"
        ],
        "{info}"
    );
}

/// The discovery document keeps what clients read and omits the exact version and the per-IP
/// abuse thresholds.
fn assert_discovery_shape(wk: &Value) {
    let mut keys: Vec<&str> = wk.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["features", "federation", "identity", "name", "protocol_versions", "software"], "{wk}");
    assert_eq!(wk["software"], "epicmail");
    let mut limits: Vec<&str> =
        wk["features"]["mux/1"]["limits"].as_object().unwrap().keys().map(String::as_str).collect();
    limits.sort();
    assert_eq!(
        limits,
        [
            "attach_frames_per_min",
            "attach_per_frame",
            "hold_max_s",
            "ids_per_ack",
            "inflight_per_socket",
            "mailboxes_per_socket",
            "waiting_frames_per_min"
        ],
        "{wk}"
    );
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
    // Stalled: nothing is pushed (control frames such as the early ping do not count).
    let quiet = tokio::time::timeout(Duration::from_millis(800), async {
        loop {
            match b.next().await {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                other => return other,
            }
        }
    })
    .await;
    assert!(quiet.is_err(), "pushed while stalled: {quiet:?}");
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
/// The cancel follows the reference 3.1.0 relay: strangers get Ok, a forged signature is refused,
/// and the bare txid signature cancels from any socket (it is the PostSlate's epicboxtxidsig).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_follows_the_reference_relay() {
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

    // A socket that never subscribed, as a forwarding relay's is.
    let mut m = connect(&n).await;
    recv_type(&mut m, "Challenge").await;
    // A signature that is not Alice's is refused.
    send(&mut m, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":mallory.sign(txid)})).await;
    assert_eq!(recv(&mut m).await["kind"], "InvalidSignature");
    // Someone who is not a participant gets the same Ok as an unknown transaction, both forms.
    send(&mut m, json!({"type":"CancelTx","address":mallory.pk,"epicboxtxid":txid,"signature":mallory.sign(txid)}))
        .await;
    assert_eq!(recv(&mut m).await, json!({"type":"Ok"}));
    let msig = mallory.sign(&format!("{}{txid}", epicmail::relay::CANCEL_SIG_PREFIX));
    send(&mut m, json!({"type":"CancelTx","address":mallory.pk,"epicboxtxid":txid,"signature":msig})).await;
    assert_eq!(recv(&mut m).await, json!({"type":"Ok"}));
    let other = "ffffffffffffffffffffffffffffffff";
    send(&mut m, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":other,"signature":alice.sign(other)})).await;
    assert_eq!(recv(&mut m).await, json!({"type":"Ok"}));
    assert_eq!(waiting(&n).await, 1);

    // Alice's bare signature over the txid, from that unsubscribed socket, cancels.
    send(&mut m, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":alice.sign(txid)})).await;
    assert_eq!(recv(&mut m).await, json!({"type":"TransactionCancelled","epicboxtxid":txid}));
    assert_eq!(waiting(&n).await, 0);
    // Asking again is answered from the tombstone; a stranger still gets Ok.
    send(&mut a, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":alice.sign(txid)})).await;
    assert_eq!(recv(&mut a).await, json!({"type":"TransactionCancelled","epicboxtxid":txid}));
    send(&mut m, json!({"type":"CancelTx","address":mallory.pk,"epicboxtxid":txid,"signature":mallory.sign(txid)}))
        .await;
    assert_eq!(recv(&mut m).await, json!({"type":"Ok"}));

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
            json!({"address":k.pk,"challenge":ch,"signature":k.sign(&proof(&ch, "relay.test"))})
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
        json!({"mailboxes":[{"address":k.pk,"challenge":ch,"signature":k.sign(&proof(&ch, "relay.test"))}],"wait":wait})
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

    // The same prefix's mux/1 socket: its first signed frame is counted and not refused, and
    // its next Attach for a mailbox it does not hold is refused before any check runs.
    let (mut m, mch) = mux_open(&n).await;
    send(&mut m, json!({"type":"Attach","ref":"a1","mailboxes":[{"address":k.pk,"signature":k.sign(&mch)}]})).await;
    assert_eq!(recv(&mut m).await["type"], "Attached");
    let k2 = Key::new();
    send(&mut m, json!({"type":"Attach","ref":"a2","mailboxes":[{"address":k2.pk,"signature":k2.sign(&mch)}]})).await;
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
    // A manager tick (every 5 s) passes inside the peer's first 10 s backoff: per-row backoff
    // would have tried the second row by now, per-peer backoff waits.
    tokio::time::sleep(Duration::from_secs(7)).await;
    let rows = n.relay.store.forwards_due("dead.test:443", now_ms() + 7_200_000, 50).await.unwrap();
    assert_eq!(rows.len(), 3);
    let attempts: i64 = rows.iter().map(|r| r.attempts).sum();
    assert_eq!(attempts, 1, "each tick tried another row of the dead peer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pull_reply_has_a_byte_budget_and_says_when_there_is_more() {
    let dir = tempfile::tempdir().unwrap();
    // With 1 MiB slates allowed, a 4 MiB reply has room for 3 messages counted at full size.
    let n = start(dir.path(), "relay.test", |c| {
        c.limits.max_frame_bytes = 2 << 20;
        c.limits.max_str_bytes = 1 << 20;
    })
    .await;
    let (alice, bob) = (Key::new(), Key::new());
    for i in 0..5 {
        let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", i);
        f.as_object_mut().unwrap().remove("type");
        assert_eq!(http(&n, "POST", "/v1/post", Some(f)).await.0, 200);
    }
    let pull = |n: &Node| {
        let ch = format!("ebh-{}-{:016x}", now_ms() / 1000, rand::random::<u64>());
        let body =
            json!({"mailboxes":[{"address":bob.pk,"challenge":ch,"signature":bob.sign(&proof(&ch, "relay.test"))}],"limit":20,"wait":0});
        let addr = n.addr;
        let relay = n.relay.clone();
        async move { http(&Node { addr, relay }, "POST", "/v1/pull", Some(body)).await }
    };
    let (st, v) = pull(&n).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["mailboxes"][0]["messages"].as_array().unwrap().len(), 3, "{v}");
    assert_eq!(v["more"], true, "{v}");
    let (_, v) = pull(&n).await;
    assert_eq!(v["mailboxes"][0]["messages"].as_array().unwrap().len(), 2, "{v}");
    assert!(v.get("more").is_none(), "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_cannot_join_a_transaction_through_a_forward() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| {
        c.federation.peers.insert("remote.test:443".into(), "ws://127.0.0.1:9/".into());
    })
    .await;
    let (alice, bob, mallory) = (Key::new(), Key::new(), Key::new());
    let txid = "0123456789abcdef0123456789abcdef";
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    let mut post = post_frame(&alice, "relay.test", &bob, "relay.test", 1);
    post["epicboxtxid"] = json!(txid);
    post["epicboxtxidsig"] = json!(alice.sign(txid));
    send(&mut a, post).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    // Mallory knows the txid and posts under it to another relay, signing it herself.
    let mut m = connect(&n).await;
    recv_type(&mut m, "Challenge").await;
    let mut f = post_frame(&mallory, "relay.test", &Key::new(), "remote.test", 2);
    f["epicboxtxid"] = json!(txid);
    f["epicboxtxidsig"] = json!(mallory.sign(txid));
    send(&mut m, f).await;
    let r = recv(&mut m).await;
    assert!(r["description"].as_str().unwrap_or("").contains("not a participant"), "{r}");
    // So her cancel is not a participant's and changes nothing.
    let msig = mallory.sign(&format!("{}{txid}", epicmail::relay::CANCEL_SIG_PREFIX));
    send(&mut m, json!({"type":"CancelTx","address":mallory.pk,"epicboxtxid":txid,"signature":msig})).await;
    assert_eq!(recv(&mut m).await, json!({"type":"Ok"}));
    assert_eq!(waiting(&n).await, 1, "Alice's slate is still there");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_subscribe_hands_back_the_message_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob, carol) = (Key::new(), Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    for to in [&bob, &carol] {
        send(&mut a, post_frame(&alice, "relay.test", to, "relay.test", 1)).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
    }
    // Bob's slate goes out on this socket and is not Made yet.
    let mut s = connect(&n).await;
    let ch = recv_type(&mut s, "Challenge").await["str"].as_str().unwrap().to_string();
    send(&mut s, json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":bob.sign(&ch)})).await;
    assert_eq!(recv_type(&mut s, "Slate").await["from"], alice.at("relay.test"));
    // A Subscribe with a bad signature drops Bob from the socket...
    send(&mut s, json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":carol.sign(&ch)})).await;
    assert_eq!(recv(&mut s).await["kind"], "InvalidSignature");
    // ...and Carol, subscribed next on the same socket, gets her mail at once.
    send(&mut s, json!({"type":"Subscribe","address":carol.pk,"ver":"3.0.0","signature":carol.sign(&ch)})).await;
    let v = recv_type(&mut s, "Slate").await;
    assert_eq!(v["from"], alice.at("relay.test"), "{v}");
    // Bob's slate is offerable again for Bob's next socket.
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.0.0").await;
    assert_eq!(recv_type(&mut b, "Slate").await["from"], alice.at("relay.test"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_post_padded_outside_str_pays_for_the_padding() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.limits.bytes_per_min_per_ip = 100_000).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    // A small slate with 60 KB of junk beside it: the junk counts.
    let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", 1);
    f["junk"] = json!("a".repeat(60_000));
    send(&mut a, f).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", 2);
    f["junk"] = json!("a".repeat(60_000));
    send(&mut a, f).await;
    assert_eq!(recv(&mut a).await, json!({"closed": 1008}));
    // The same through /v1/post.
    let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", 3);
    f.as_object_mut().unwrap().remove("type");
    f["junk"] = json!("a".repeat(60_000));
    assert_eq!(http(&n, "POST", "/v1/post", Some(f)).await.0, 429);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slate_reposted_with_another_from_is_still_one_message() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    let f = post_frame(&alice, "relay.test", &bob, "relay.test", 1);
    for from in [alice.at("relay.test"), alice.pk.clone(), alice.at("other.test"), alice.at("relay.test:443")] {
        let mut g = f.clone();
        g["from"] = json!(from);
        send(&mut a, g).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
    }
    assert_eq!(waiting(&n).await, 1, "the same signed slate was stored more than once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pulls_stop_a_quarter_above_the_store_cap() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.store.max_bytes = 1).await;
    let bob = Key::new();
    let ch = format!("ebh-{}-{:016x}", now_ms() / 1000, rand::random::<u64>());
    let body = json!({"mailboxes":[{"address":bob.pk,"challenge":ch,"signature":bob.sign(&proof(&ch, "relay.test"))}],"wait":0});
    let (st, v) = http(&n, "POST", "/v1/pull", Some(body)).await;
    assert_eq!(st, 503, "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socket_that_missed_its_detached_can_no_longer_ack() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let (mut m, ch) = mux_open(&n).await;
    send(&mut m, json!({"type":"Attach","ref":"a","mailboxes":[{"address":bob.pk,"signature":bob.sign(&ch)}]})).await;
    assert_eq!(recv(&mut m).await["type"], "Attached");
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let mail = recv(&mut m).await;
    assert_eq!(mail["type"], "Mail", "{mail}");
    // Another socket takes the mailbox and the Detached for this one is lost on the way.
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    n.relay.registry.attach_mux(&bob.pk, epicmail::relay::SockHandle { id: u64::MAX, tx, cancel: false });
    send(&mut m, json!({"type":"Ack","ref":"k","ids":[mail["id"]]})).await;
    let d = recv(&mut m).await;
    assert_eq!(d, json!({"type":"Detached","mailbox":bob.pk,"reason":"replaced"}), "{d}");
    assert_eq!(recv(&mut m).await, json!({"type":"Ok","ref":"k"}));
    assert_eq!(waiting(&n).await, 1, "the ack of a mailbox this socket no longer holds deleted mail");
    // Its in-flight lease went back with the mailbox: the next holder gets the mail at once.
    let (mut m2, ch2) = mux_open(&n).await;
    send(&mut m2, json!({"type":"Attach","ref":"b","mailboxes":[{"address":bob.pk,"signature":bob.sign(&ch2)}]})).await;
    assert_eq!(recv(&mut m2).await["type"], "Attached");
    let again = recv(&mut m2).await;
    assert_eq!(again["type"], "Mail", "{again}");
    assert_eq!(again["id"], mail["id"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_subscribe_gets_a_ping_soon_after() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let bob = Key::new();
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.0.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    // epic-wallet's send path waits for any frame from the relay; a ping frees it.
    let t0 = std::time::Instant::now();
    let m = tokio::time::timeout(Duration::from_secs(3), b.next()).await.expect("no frame").unwrap().unwrap();
    assert!(matches!(m, Message::Ping(_)), "{m:?}");
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
}

/// A 3.1.0 slate from `from` on `from_domain` to `to` on `to_domain`, under `txid`.
fn post_tx_frame(from: &Key, from_domain: &str, to: &Key, to_domain: &str, txid: &str) -> Value {
    let mut f = post_frame(from, from_domain, to, to_domain, 1);
    f["epicboxtxid"] = json!(txid);
    f["epicboxtxidsig"] = json!(from.sign(txid));
    f
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forwarded_cancel_carries_the_request_id_and_is_sent_once() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| {
        // Nothing listens there, so forward rows stay queued and can be read.
        c.federation.peers.insert("remote.test:443".into(), "ws://127.0.0.1:9/".into());
    })
    .await;
    let (alice, bob) = (Key::new(), Key::new());
    let rows_of = |kind: &'static str| {
        let relay = n.relay.clone();
        async move {
            let rows = relay.store.forwards_due("remote.test:443", now_ms() + 7_200_000, 50).await.unwrap();
            rows.into_iter()
                .map(|r| serde_json::from_str::<Value>(&r.frame).unwrap())
                .filter(|f| f["type"] == kind)
                .collect::<Vec<Value>>()
        }
    };
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;

    // With a request id: it is passed on unchanged.
    let tx1 = "0123456789abcdef0123456789abcdef";
    send(&mut a, post_tx_frame(&alice, "relay.test", &bob, "remote.test", tx1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let crid = "requestidrequestidrequestid12345";
    let mut c = connect(&n).await;
    recv_type(&mut c, "Challenge").await;
    let cancel = json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx1,"signature":alice.sign(tx1),"cancelrequestid":crid});
    send(&mut c, cancel.clone()).await;
    assert_eq!(recv(&mut c).await, json!({"type":"TransactionCancelled","epicboxtxid":tx1}));
    let cancels = rows_of("CancelTx").await;
    assert_eq!(cancels.len(), 1, "{cancels:?}");
    assert_eq!(cancels[0]["cancelrequestid"], crid);
    assert_eq!(cancels[0]["signature"], alice.sign(tx1), "the bare signature is forwarded by default");
    // The same request again (a loop) and a new one (a retry) are confirmed and not sent on.
    send(&mut c, cancel).await;
    assert_eq!(recv(&mut c).await["type"], "TransactionCancelled");
    send(&mut c, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx1,"signature":alice.sign(tx1)})).await;
    assert_eq!(recv(&mut c).await["type"], "TransactionCancelled");
    assert_eq!(rows_of("CancelTx").await.len(), 1);

    // Without a request id: one is made, 32 characters like the reference relay's.
    let tx2 = "fedcba9876543210fedcba9876543210";
    send(&mut a, post_tx_frame(&alice, "relay.test", &bob, "remote.test", tx2)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    send(&mut c, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx2,"signature":alice.sign(tx2)})).await;
    assert_eq!(recv(&mut c).await["type"], "TransactionCancelled");
    let made: Vec<Value> = rows_of("CancelTx").await.into_iter().filter(|f| f["epicboxtxid"] == tx2).collect();
    assert_eq!(made.len(), 1);
    let id = made[0]["cancelrequestid"].as_str().unwrap();
    assert!(id.len() == 32 && id.chars().all(|ch| ch.is_ascii_alphanumeric()), "{id}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_crosses_two_relays_and_the_loop_back_ends() {
    let dir = tempfile::tempdir().unwrap();
    // Both relays know each other's address before either starts.
    let la = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a_url, b_url) = (format!("ws://{}", la.local_addr().unwrap()), format!("ws://{}", lb.local_addr().unwrap()));
    let b = start_on(dir.path(), "relayb.test", lb, |c| {
        c.federation.peers.insert("relaya.test:443".into(), a_url.clone());
    })
    .await;
    let a = start_on(dir.path(), "relaya.test", la, |c| {
        c.federation.peers.insert("relayb.test:443".into(), b_url.clone());
    })
    .await;
    let (alice, bob) = (Key::new(), Key::new());
    let txid = "0123456789abcdef0123456789abcdef";

    // Alice on A sends to Bob on B; Bob is offline, so the slate waits on B.
    let mut asock = connect(&a).await;
    recv_type(&mut asock, "Challenge").await;
    send(&mut asock, post_tx_frame(&alice, "relaya.test", &bob, "relayb.test", txid)).await;
    assert_eq!(recv(&mut asock).await["type"], "Ok");
    assert_eq!(forwards_waiting_settles(&a, 0).await, 0);
    assert_eq!(waiting(&b).await, 1);

    // Alice cancels on A, signing the bare txid as wallets do. A forwards it to B; B, which
    // got the slate from A, forwards it back to A, which ends it.
    send(&mut asock, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":alice.sign(txid)}))
        .await;
    assert_eq!(recv(&mut asock).await, json!({"type":"TransactionCancelled","epicboxtxid":txid}));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while waiting(&b).await != 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(waiting(&b).await, 0, "the cancel did not reach the relay holding the slate");
    assert!(b.relay.store.tx_info(txid).await.unwrap().tombstone.is_some());
    assert_eq!(forwards_waiting_settles(&a, 0).await, 0);
    assert_eq!(forwards_waiting_settles(&b, 0).await, 0);
    // Nothing keeps bouncing.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(a.relay.store.stats(now_ms()).await.unwrap().forwards_waiting, 0);
    assert_eq!(b.relay.store.stats(now_ms()).await.unwrap().forwards_waiting, 0);

    // Bob, coming online on B with 3.1.0, is told; posting under the txid on B is refused.
    let mut bs = connect(&b).await;
    subscribe(&mut bs, &bob, "3.1.0").await;
    assert_eq!(recv_type(&mut bs, "TransactionCancelled").await["epicboxtxid"], txid);
    send(&mut bs, post_tx_frame(&bob, "relayb.test", &alice, "relaya.test", txid)).await;
    assert_eq!(recv(&mut bs).await["type"], "TransactionCancelled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_subscribe_does_not_change_the_socket_version() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob, mallory) = (Key::new(), Key::new(), Key::new());

    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.0.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    // A Subscribe with a wrong signature and another version is refused.
    send(&mut b, json!({"type":"Subscribe","address":bob.pk,"ver":"2.0.0","signature":mallory.sign("x")})).await;
    assert_eq!(recv(&mut b).await["kind"], "InvalidSignature");
    // A good Subscribe without ver keeps the version the socket proved, 3.0.0.
    send(&mut b, json!({"type":"Challenge"})).await;
    let c = recv(&mut b).await;
    send(&mut b, json!({"type":"Subscribe","address":bob.pk,"signature":bob.sign(c["str"].as_str().unwrap())})).await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));

    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    assert_eq!(recv_type(&mut b, "Slate").await["ver"], "3.0.0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_hands_the_message_in_flight_back_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let txid = "0123456789abcdef0123456789abcdef";

    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.1.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));

    // A plain slate goes out to bob and stays in flight (no Made).
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let first = recv_type(&mut b, "Slate").await;

    // A 3.1.0 transaction between them is posted and cancelled by alice.
    let mut post = post_frame(&alice, "relay.test", &bob, "relay.test", 2);
    post["epicboxtxid"] = json!(txid);
    post["epicboxtxidsig"] = json!(alice.sign(txid));
    send(&mut a, post).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let asig = alice.sign(&format!("{}{txid}", epicmail::relay::CANCEL_SIG_PREFIX));
    send(&mut a, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":asig})).await;
    assert_eq!(recv(&mut a).await["type"], "TransactionCancelled");
    assert_eq!(recv_type(&mut b, "TransactionCancelled").await["epicboxtxid"], txid);

    // The Subscribe that acknowledges the cancel gets the first slate again, not a 60 s wait.
    send(&mut b, json!({"type":"Challenge"})).await;
    let c = recv(&mut b).await;
    send(
        &mut b,
        json!({"type":"Subscribe","address":bob.pk,"ver":"3.1.0","signature":bob.sign(c["str"].as_str().unwrap())}),
    )
    .await;
    let again = recv_type(&mut b, "Slate").await;
    assert_eq!(again["epicboxmsgid"], first["epicboxmsgid"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_failure_mid_cancel_leaves_nothing_half_done() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| {
        // Nothing listens there, so forward rows stay queued and can be read.
        c.federation.peers.insert("ok.test:443".into(), "ws://127.0.0.1:9/".into());
        c.federation.peers.insert("fail.test:443".into(), "ws://127.0.0.1:9/".into());
    })
    .await;
    let (alice, bob) = (Key::new(), Key::new());
    let txid = "0123456789abcdef0123456789abcdef";
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    // One transaction with a waiting slate here and states sent to two other relays.
    for to_domain in ["relay.test", "ok.test", "fail.test"] {
        send(&mut a, post_tx_frame(&alice, "relay.test", &bob, to_domain, txid)).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
    }
    assert_eq!(waiting(&n).await, 1);
    let cancel_rows = |peer: &'static str| {
        let relay = n.relay.clone();
        async move {
            relay
                .store
                .forwards_due(peer, now_ms() + 7_200_000, 50)
                .await
                .unwrap()
                .into_iter()
                .filter(|r| serde_json::from_str::<Value>(&r.frame).unwrap()["type"] == "CancelTx")
                .count()
        }
    };

    // The store fails while it queues the CancelTx for the second relay.
    let db = rusqlite::Connection::open(dir.path().join("relay.test.db")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER fail_cancel BEFORE INSERT ON forwards \
         WHEN NEW.peer = 'fail.test:443' AND NEW.frame LIKE '%\"CancelTx\"%' \
         BEGIN SELECT RAISE(ABORT, 'injected'); END;",
    )
    .unwrap();
    let crid = "requestidrequestidrequestid12345";
    let cancel = json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":alice.sign(txid),"cancelrequestid":crid});
    send(&mut a, cancel.clone()).await;
    let r = recv(&mut a).await;
    assert_eq!(r["type"], "Error", "{r}");
    assert_eq!(r["kind"], "UnknownError", "{r}");
    // Nothing of the cancel was kept: no tombstone, the slate still waits, no forward queued.
    assert!(n.relay.store.tx_info(txid).await.unwrap().tombstone.is_none());
    assert_eq!(waiting(&n).await, 1);
    assert_eq!((cancel_rows("ok.test:443").await, cancel_rows("fail.test:443").await), (0, 0));

    // The store recovers; the same request, as a relay would retry it, now goes through.
    db.execute_batch("DROP TRIGGER fail_cancel;").unwrap();
    send(&mut a, cancel).await;
    assert_eq!(recv(&mut a).await, json!({"type":"TransactionCancelled","epicboxtxid":txid}));
    assert!(n.relay.store.tx_info(txid).await.unwrap().tombstone.is_some());
    assert_eq!(waiting(&n).await, 0);
    assert_eq!((cancel_rows("ok.test:443").await, cancel_rows("fail.test:443").await), (1, 1));
    // Retrying again, with a new request id, queues nobody twice.
    send(&mut a, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":alice.sign(txid)})).await;
    assert_eq!(recv(&mut a).await, json!({"type":"TransactionCancelled","epicboxtxid":txid}));
    assert_eq!((cancel_rows("ok.test:443").await, cancel_rows("fail.test:443").await), (1, 1));
}

// ---- txcancel/1 ----

const TXID: &str = "0123456789abcdef0123456789abcdef";

/// Open a socket, negotiate mux/1 (and txcancel/1 when asked), attach `keys`.
async fn txmux(n: &Node, txcancel: bool, keys: &[&Key]) -> Ws {
    let mut m = connect(n).await;
    recv_type(&mut m, "Challenge").await;
    let ext = if txcancel { json!(["mux/1", "txcancel/1"]) } else { json!(["mux/1"]) };
    send(&mut m, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.1.0","ext":ext})).await;
    let ok = recv(&mut m).await;
    assert_eq!(ok["ext"], ext, "{ok}");
    let ch = ok["challenge"].as_str().unwrap().to_string();
    if !keys.is_empty() {
        let list: Vec<Value> = keys.iter().map(|k| json!({"address":k.pk,"signature":k.sign(&ch)})).collect();
        send(&mut m, json!({"type":"Attach","ref":"at","mailboxes":list})).await;
        let at = recv(&mut m).await;
        assert_eq!(at["type"], "Attached", "{at}");
    }
    m
}

fn cancel_frame(r: &str, k: &Key, txid: &str) -> Value {
    json!({"type":"CancelTx","ref":r,"address":k.pk,"epicboxtxid":txid,"signature":k.sign(txid)})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn txcancel_is_negotiated_only_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    // mux/1 alone: txid fields are ignored, CancelTx is an unknown type, Mail has no txid.
    let mut a = txmux(&n, false, &[&alice]).await;
    let mut b = txmux(&n, false, &[&bob]).await;
    let mut p = post_tx_frame(&alice, "relay.test", &bob, "relay.test", TXID);
    p["ref"] = json!("p1");
    send(&mut a, p).await;
    assert_eq!(recv(&mut a).await, json!({"type":"Ok","ref":"p1"}));
    let mail = recv(&mut b).await;
    assert_eq!(mail["type"], "Mail");
    assert!(mail.get("epicboxtxid").is_none(), "{mail}");
    send(&mut a, cancel_frame("c1", &alice, TXID)).await;
    let e = recv(&mut a).await;
    assert_eq!(e["code"], "unknown_type", "{e}");
    send(&mut a, json!({"type":"CancelAck","ref":"x","mailbox":alice.pk,"epicboxtxid":TXID})).await;
    assert_eq!(recv(&mut a).await["code"], "unknown_type");
    // The ignored fields did not register a transaction.
    let mut c = connect(&n).await;
    recv_type(&mut c, "Challenge").await;
    send(&mut c, cancel_frame("c", &alice, TXID)).await;
    assert_eq!(recv(&mut c).await, json!({"type":"Ok"}));

    // With cancel off the relay does not offer it.
    let dir2 = tempfile::tempdir().unwrap();
    let n2 = start(dir2.path(), "relay.test", |c| c.protocol.cancel = false).await;
    let mut m = connect(&n2).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","ext":["mux/1","txcancel/1"]})).await;
    assert_eq!(recv(&mut m).await["ext"], json!(["mux/1"]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn txcancel_post_echoes_txid_and_mail_carries_it() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = txmux(&n, true, &[&alice]).await;
    let mut b = txmux(&n, true, &[&bob]).await;
    let mut p = post_tx_frame(&alice, "relay.test", &bob, "relay.test", TXID);
    p["ref"] = json!("p1");
    send(&mut a, p).await;
    assert_eq!(recv(&mut a).await, json!({"type":"Ok","ref":"p1","epicboxtxid":TXID}));
    let mail = recv(&mut b).await;
    assert_eq!(mail["type"], "Mail", "{mail}");
    assert_eq!(mail["epicboxtxid"], TXID);
    // A post without the fields still works and carries no txid.
    let mut p = post_frame(&alice, "relay.test", &bob, "relay.test", 2);
    p["ref"] = json!("p2");
    send(&mut a, p).await;
    assert_eq!(recv(&mut a).await, json!({"type":"Ok","ref":"p2"}));
    assert!(recv(&mut b).await.get("epicboxtxid").is_none());
    // Half the fields, or a signature by someone else, is refused.
    let mut p = post_frame(&alice, "relay.test", &bob, "relay.test", 3);
    p["epicboxtxid"] = json!("ffffffffffffffffffffffffffffffff");
    send(&mut a, p.clone()).await;
    assert_eq!(recv(&mut a).await["code"], "post_refused");
    p["epicboxtxidsig"] = json!(bob.sign("ffffffffffffffffffffffffffffffff"));
    send(&mut a, p).await;
    assert_eq!(recv(&mut a).await["code"], "post_refused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn txcancel_cancel_confirmed_ambiguous_and_bad_signature() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob, mallory) = (Key::new(), Key::new(), Key::new());
    let mut a = txmux(&n, true, &[&alice]).await;
    send(&mut a, post_tx_frame(&alice, "relay.test", &bob, "relay.test", TXID)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    assert_eq!(waiting(&n).await, 1);

    // Someone else's signature over the txid.
    let mut bad = cancel_frame("c2", &alice, TXID);
    bad["signature"] = json!(mallory.sign(TXID));
    send(&mut a, bad).await;
    let e = recv(&mut a).await;
    assert_eq!(
        (e["code"].as_str(), e["kind"].as_str(), e["ref"].as_str()),
        (Some("bad_signature"), Some("InvalidSignature"), Some("c2"))
    );
    // Missing txid.
    send(&mut a, json!({"type":"CancelTx","ref":"c3","address":alice.pk,"signature":"00"})).await;
    assert_eq!(recv(&mut a).await["code"], "bad_request");
    // A stranger, and an unknown transaction, get a plain Ok.
    send(&mut a, cancel_frame("c4", &mallory, TXID)).await;
    assert_eq!(recv(&mut a).await, json!({"type":"Ok","ref":"c4"}));
    let other = "ffffffffffffffffffffffffffffffff";
    send(&mut a, cancel_frame("c5", &alice, other)).await;
    assert_eq!(recv(&mut a).await, json!({"type":"Ok","ref":"c5"}));
    assert_eq!(waiting(&n).await, 1);

    // A participant cancels; asking again is answered from the tombstone.
    send(&mut a, cancel_frame("c6", &alice, TXID)).await;
    assert_eq!(recv(&mut a).await, json!({"type":"TransactionCancelled","ref":"c6","epicboxtxid":TXID}));
    assert_eq!(waiting(&n).await, 0);
    send(&mut a, cancel_frame("c7", &alice, TXID)).await;
    assert_eq!(recv(&mut a).await["type"], "TransactionCancelled");
    // Posting the cancelled transaction again is refused.
    send(&mut a, post_tx_frame(&alice, "relay.test", &bob, "relay.test", TXID)).await;
    assert_eq!(recv(&mut a).await["code"], "post_refused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn txcancel_cancelled_push_live_and_on_attach_then_ack_stops_it() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = txmux(&n, true, &[&alice]).await;
    let mut b = txmux(&n, true, &[&bob]).await;
    send(&mut a, post_tx_frame(&alice, "relay.test", &bob, "relay.test", TXID)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    assert_eq!(recv(&mut b).await["type"], "Mail");

    // Live: Bob is attached when Alice cancels.
    send(&mut a, cancel_frame("c1", &alice, TXID)).await;
    assert_eq!(recv(&mut a).await["type"], "TransactionCancelled");
    let c = recv(&mut b).await;
    assert_eq!(c, json!({"type":"Cancelled","mailbox":bob.pk,"epicboxtxid":TXID}));
    // A mux session without txcancel/1 gets nothing and the tombstone stays pending.
    // Reattaching on a new txcancel/1 socket (Attach) delivers it again, before any Mail.
    let (alice2, other) = (Key::new(), "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    send(&mut a, post_tx_frame(&alice2, "relay.test", &bob, "relay.test", other)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let mut b2 = connect(&n).await;
    recv_type(&mut b2, "Challenge").await;
    send(&mut b2, json!({"type":"ClientDetails","ext":["mux/1","txcancel/1"]})).await;
    let ok = recv(&mut b2).await;
    let ch = ok["challenge"].as_str().unwrap().to_string();
    send(&mut b2, json!({"type":"Attach","ref":"a","mailboxes":[{"address":bob.pk,"signature":bob.sign(&ch)}]})).await;
    assert_eq!(recv(&mut b2).await["type"], "Attached");
    assert_eq!(recv(&mut b2).await, json!({"type":"Cancelled","mailbox":bob.pk,"epicboxtxid":TXID}));
    let mail = recv(&mut b2).await;
    assert_eq!(mail["type"], "Mail");
    assert_eq!(mail["epicboxtxid"], other);

    // Ack: Ok, idempotent, stops redelivery on the next Attach and Resume.
    let ack = json!({"type":"CancelAck","ref":"k","mailbox":bob.pk,"epicboxtxid":TXID});
    send(&mut b2, ack.clone()).await;
    assert_eq!(recv(&mut b2).await, json!({"type":"Ok","ref":"k"}));
    send(&mut b2, ack).await;
    assert_eq!(recv(&mut b2).await, json!({"type":"Ok","ref":"k"}));
    assert!(n.relay.store.pending_cancels(&bob.pk).await.unwrap().is_empty());
    send(&mut b2, json!({"type":"Ack","ids":[mail["id"]]})).await;
    assert_eq!(recv(&mut b2).await["type"], "Ok");
    drop(b2);
    let mut b3 = txmux(&n, true, &[&bob]).await;
    send(&mut b3, json!({"type":"Waiting","ref":"w"})).await;
    assert_eq!(recv(&mut b3).await["ref"], "w", "no Cancelled after the ack");
    // Bad ack frames and unattached mailboxes.
    send(&mut b3, json!({"type":"CancelAck","ref":"k2","mailbox":bob.pk,"epicboxtxid":"short"})).await;
    assert_eq!(recv(&mut b3).await["code"], "bad_frame");
    send(&mut b3, json!({"type":"CancelAck","ref":"k3","mailbox":alice.pk,"epicboxtxid":TXID})).await;
    assert_eq!(recv(&mut b3).await, json!({"type":"Ok","ref":"k3"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn txcancel_resume_delivers_pending_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = txmux(&n, true, &[&alice]).await;
    send(&mut a, post_tx_frame(&alice, "relay.test", &bob, "relay.test", TXID)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let mut b = connect(&n).await;
    recv_type(&mut b, "Challenge").await;
    send(&mut b, json!({"type":"ClientDetails","ext":["mux/1","txcancel/1"]})).await;
    let ch = recv(&mut b).await["challenge"].as_str().unwrap().to_string();
    send(&mut b, json!({"type":"Attach","mailboxes":[{"address":bob.pk,"signature":bob.sign(&ch)}]})).await;
    let token = recv(&mut b).await["token"].as_str().unwrap().to_string();
    assert_eq!(recv(&mut b).await["type"], "Mail");
    drop(b);
    // Cancelled while Bob is offline.
    send(&mut a, cancel_frame("c", &alice, TXID)).await;
    assert_eq!(recv(&mut a).await["type"], "TransactionCancelled");
    let mut b2 = connect(&n).await;
    recv_type(&mut b2, "Challenge").await;
    send(&mut b2, json!({"type":"ClientDetails","ext":["mux/1","txcancel/1"]})).await;
    recv(&mut b2).await;
    send(&mut b2, json!({"type":"Resume","token":token})).await;
    assert_eq!(recv(&mut b2).await["type"], "Attached");
    assert_eq!(recv(&mut b2).await, json!({"type":"Cancelled","mailbox":bob.pk,"epicboxtxid":TXID}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn txcancel_interoperates_with_classic_3_1_0_sockets() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());

    // Posted on a classic socket, cancelled over mux; the classic receiver is told.
    let mut c = connect(&n).await;
    recv_type(&mut c, "Challenge").await;
    send(&mut c, post_tx_frame(&alice, "relay.test", &bob, "relay.test", TXID)).await;
    assert_eq!(recv(&mut c).await["epicboxtxid"], TXID);
    let mut cb = connect(&n).await;
    subscribe(&mut cb, &bob, "3.1.0").await;
    assert_eq!(recv_type(&mut cb, "Slate").await["epicboxtxid"], TXID);
    let mut a = txmux(&n, true, &[&alice]).await;
    send(&mut a, cancel_frame("c1", &alice, TXID)).await;
    assert_eq!(recv(&mut a).await["type"], "TransactionCancelled");
    assert_eq!(recv_type(&mut cb, "TransactionCancelled").await["epicboxtxid"], TXID);

    // Posted over mux, cancelled on a classic socket; the mux receiver gets Cancelled.
    let txid2 = "11111111111111111111111111111111";
    let mut b = txmux(&n, true, &[&bob]).await;
    send(&mut a, post_tx_frame(&alice, "relay.test", &bob, "relay.test", txid2)).await;
    assert_eq!(recv(&mut a).await["epicboxtxid"], txid2);
    let mail = recv(&mut b).await;
    assert_eq!(mail["type"], "Cancelled", "the first tombstone is still pending: {mail}");
    assert_eq!(mail["epicboxtxid"], TXID);
    assert_eq!(recv(&mut b).await["type"], "Mail");
    send(&mut c, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid2,"signature":alice.sign(txid2)})).await;
    assert_eq!(recv(&mut c).await["type"], "TransactionCancelled");
    assert_eq!(recv(&mut b).await, json!({"type":"Cancelled","mailbox":bob.pk,"epicboxtxid":txid2}));

    // A mux CancelAck is what a classic re-Subscribe does: the classic socket stops hearing it.
    send(&mut b, json!({"type":"CancelAck","mailbox":bob.pk,"epicboxtxid":TXID})).await;
    assert_eq!(recv(&mut b).await["type"], "Ok");
    send(&mut b, json!({"type":"CancelAck","mailbox":bob.pk,"epicboxtxid":txid2})).await;
    assert_eq!(recv(&mut b).await["type"], "Ok");
    let mut cb2 = connect(&n).await;
    subscribe(&mut cb2, &bob, "3.1.0").await;
    assert_eq!(recv(&mut cb2).await["type"], "Ok");
}

/// A raw GET with an Accept header; returns the head and the body.
async fn get_as(n: &Node, path: &str, accept: &str) -> (String, String) {
    let mut s = TcpStream::connect(n.addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: test\r\nAccept: {accept}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await.unwrap().unwrap();
    let text = String::from_utf8_lossy(&out);
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (head.to_ascii_lowercase(), body.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_browser_gets_the_landing_page_and_nothing_else_changes() {
    const PLAIN: &str = "Epicbox relay. Connect with a websocket.\n";
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (head, body) = get_as(&n, "/", "text/html,application/xhtml+xml,*/*;q=0.8").await;
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("content-type: text/html; charset=utf-8"), "{head}");
    assert!(head.contains("content-security-policy: default-src 'none'; script-src 'sha256-"), "{head}");
    assert!(body.contains("<title>Epicbox relay</title>") && body.contains("/.well-known/epicbox.json"));
    // Anything that is not a browser asking for `/` gets the one line it always got.
    for (path, accept) in [("/", "*/*"), ("/other", "text/html"), ("/favicon.ico", "text/html")] {
        let (head, body) = get_as(&n, path, accept).await;
        assert!(head.starts_with("http/1.1 200") && head.contains("content-type: text/plain"), "{path}: {head}");
        assert_eq!(body, PLAIN, "{path}");
    }
    // A websocket on `/` still opens with the first Challenge, which is what the page checks.
    let mut ws = connect(&n).await;
    assert_eq!(recv(&mut ws).await["type"], "Challenge");

    let off = start(dir.path(), "off.test", |c| c.server.landing_page = false).await;
    let (head, body) = get_as(&off, "/", "text/html").await;
    assert!(head.contains("content-type: text/plain"), "{head}");
    assert_eq!(body, PLAIN);
}

// ---- epicbox-cancel/1: the domain-separated cancel signature ----

const SEPARATED: &str = "epicbox-cancel/1";

fn separated_text(txid: &str) -> String {
    format!("{}{txid}", epicmail::relay::CANCEL_SIG_PREFIX)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_separated_cancel_form_is_advertised_and_echoed_only_when_offered() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (st, wk) = http(&n, "GET", "/.well-known/epicbox.json", None).await;
    assert_eq!(st, 200);
    assert_eq!(wk["features"][SEPARATED]["signed_text"], "epicbox-cancel/1:<txid>", "{wk}");

    // A classic socket that offers it gets it echoed; one that does not gets the plain Ok.
    let mut c = connect(&n).await;
    recv_type(&mut c, "Challenge").await;
    send(&mut c, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.1.0","ext":[SEPARATED]})).await;
    assert_eq!(recv(&mut c).await, json!({"type":"Ok","ext":[SEPARATED]}));
    let mut c = connect(&n).await;
    recv_type(&mut c, "Challenge").await;
    send(&mut c, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.1.0"})).await;
    assert_eq!(recv(&mut c).await, json!({"type":"Ok"}));

    // On a mux/1 socket it joins the other tokens, but only when asked.
    let mut m = connect(&n).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","ext":["mux/1","txcancel/1",SEPARATED]})).await;
    assert_eq!(recv(&mut m).await["ext"], json!(["mux/1", "txcancel/1", SEPARATED]));
    let mut m = connect(&n).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","ext":["mux/1","txcancel/1"]})).await;
    assert_eq!(recv(&mut m).await["ext"], json!(["mux/1", "txcancel/1"]));

    // With cancel off the relay neither advertises nor echoes it.
    let dir2 = tempfile::tempdir().unwrap();
    let n2 = start(dir2.path(), "relay.test", |c| c.protocol.cancel = false).await;
    let (_, wk) = http(&n2, "GET", "/.well-known/epicbox.json", None).await;
    assert!(wk["features"].get(SEPARATED).is_none(), "{wk}");
    let mut c = connect(&n2).await;
    recv_type(&mut c, "Challenge").await;
    send(&mut c, json!({"type":"ClientDetails","ext":[SEPARATED]})).await;
    assert_eq!(recv(&mut c).await, json!({"type":"Ok"}));
}

/// A new-form cancel is accepted on a classic socket and on a txcancel/1 socket, and a stock
/// wallet's bare cancel still works. The signature a PostSlate carries as `epicboxtxidsig` is
/// not a signature over the separated text, so a replay of it is not a new-form cancel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_separated_cancel_is_accepted_and_a_replayed_slate_signature_is_not_one() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob, mallory) = (Key::new(), Key::new(), Key::new());
    let tx_classic = "0123456789abcdef0123456789abcdef";
    let tx_mux = "fedcba9876543210fedcba9876543210";
    let tx_bare = "abcdefghijklmnopqrstuvwxyz012345";

    // What anyone who saw the PostSlate holds.
    let seen = alice.sign(tx_classic);
    assert!(epicmail::sig::verify(&alice.pk, &separated_text(tx_classic), &seen).is_err());
    assert!(epicmail::sig::verify(&alice.pk, tx_classic, &seen).is_ok());

    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    for (i, tx) in [tx_classic, tx_mux, tx_bare].into_iter().enumerate() {
        let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", i as u32 + 1);
        f["epicboxtxid"] = json!(tx);
        f["epicboxtxidsig"] = json!(alice.sign(tx));
        send(&mut a, f).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
    }
    assert_eq!(waiting(&n).await, 3);

    // The separated form from a socket that never subscribed, signed by a stranger: refused.
    let mut c = connect(&n).await;
    recv_type(&mut c, "Challenge").await;
    send(&mut c, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx_classic,"signature":mallory.sign(&separated_text(tx_classic))})).await;
    assert_eq!(recv(&mut c).await["kind"], "InvalidSignature");
    assert_eq!(waiting(&n).await, 3);

    // Alice's separated signature cancels on a classic socket.
    send(&mut c, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx_classic,"signature":alice.sign(&separated_text(tx_classic))})).await;
    assert_eq!(recv(&mut c).await, json!({"type":"TransactionCancelled","epicboxtxid":tx_classic}));
    assert_eq!(waiting(&n).await, 2);

    // And on a txcancel/1 socket.
    let mut m = txmux(&n, true, &[&alice]).await;
    send(&mut m, json!({"type":"CancelTx","ref":"s1","address":alice.pk,"epicboxtxid":tx_mux,"signature":alice.sign(&separated_text(tx_mux))})).await;
    assert_eq!(recv(&mut m).await, json!({"type":"TransactionCancelled","ref":"s1","epicboxtxid":tx_mux}));
    assert_eq!(waiting(&n).await, 1);

    // A stock wallet signs the bare txid: still accepted.
    send(&mut c, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx_bare,"signature":alice.sign(tx_bare)})).await;
    assert_eq!(recv(&mut c).await, json!({"type":"TransactionCancelled","epicboxtxid":tx_bare}));
    assert_eq!(waiting(&n).await, 0);
}

/// With `forward_bare_cancel` off, only a cancel that proves the sender asked for it travels
/// to peer relays: the replayed slate signature is not sent on, the separated one is, and the
/// forwarded frame carries the signature unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_separated_cancel_is_forwarded_when_bare_forwarding_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| {
        c.protocol.forward_bare_cancel = false;
        // Nothing listens there, so forward rows stay queued and can be read.
        c.federation.peers.insert("remote.test:443".into(), "ws://127.0.0.1:9/".into());
    })
    .await;
    let (alice, bob) = (Key::new(), Key::new());
    let (tx_bare, tx_sep) = ("0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210");
    let cancels = || {
        let relay = n.relay.clone();
        async move {
            let rows = relay.store.forwards_due("remote.test:443", now_ms() + 7_200_000, 50).await.unwrap();
            rows.into_iter()
                .map(|r| serde_json::from_str::<Value>(&r.frame).unwrap())
                .filter(|f| f["type"] == "CancelTx")
                .collect::<Vec<Value>>()
        }
    };
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    for tx in [tx_bare, tx_sep] {
        send(&mut a, post_tx_frame(&alice, "relay.test", &bob, "remote.test", tx)).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
    }
    let mut c = connect(&n).await;
    recv_type(&mut c, "Challenge").await;

    send(&mut c, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx_bare,"signature":alice.sign(tx_bare)})).await;
    assert_eq!(recv(&mut c).await["type"], "TransactionCancelled");
    assert!(cancels().await.is_empty(), "a bare cancel was forwarded");

    let sig = alice.sign(&separated_text(tx_sep));
    send(&mut c, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx_sep,"signature":sig})).await;
    assert_eq!(recv(&mut c).await["type"], "TransactionCancelled");
    let rows = cancels().await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["epicboxtxid"], tx_sep);
    assert_eq!(rows[0]["signature"], sig, "the separated signature goes to the peer unchanged");
}

/// A PostSlate whose `from` is written exactly as given (host, case and port included).
fn post_frame_from(from: &Key, from_addr: &str, to: &Key, to_domain: &str, n: u32) -> Value {
    let mut f = post_frame(from, "x", to, to_domain, n);
    f["from"] = json!(from_addr);
    f
}

fn denied_count(n: &Node) -> u64 {
    n.relay.traffic.counts().get(epicmail::traffic::Count::PostsDeniedHost)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_sender_hosts_refuses_listed_hosts_on_every_entry_path() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.federation.deny_sender_hosts = vec!["epicbox.epicmine.test".into()])
        .await;
    let (alice, bob) = (Key::new(), Key::new());

    // Classic socket: the wallet gets an Error frame, nothing is stored.
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    for (i, from) in [
        alice.at("epicbox.epicmine.test"),
        alice.at("EpicBox.EpicMine.TEST"),
        alice.at("epicbox.epicmine.test:443"),
        alice.at("epicbox.epicmine.test:8443"),
        format!("epicbox://{}", alice.at("epicbox.epicmine.test:3425")),
    ]
    .iter()
    .enumerate()
    {
        send(&mut a, post_frame_from(&alice, from, &bob, "relay.test", i as u32)).await;
        let r = recv(&mut a).await;
        assert_eq!(r["type"], "Error", "{from}: {r}");
        assert_eq!(r["kind"], "InvalidRequest");
        assert!(r["description"].as_str().unwrap().contains("epicbox.epicmine.test"), "{r}");
        assert!(!r["description"].as_str().unwrap().contains(&alice.pk), "no address in the reply: {r}");
    }
    assert_eq!(waiting(&n).await, 0);
    assert_eq!(denied_count(&n), 5);

    // Other hosts, a parent or child name, a lookalike and no host at all pass.
    for (i, from) in [
        alice.at("epicmine.test"),
        alice.at("x.epicbox.epicmine.test"),
        alice.at("epicbox.epicmine.test.evil.test"),
        alice.at("relay.test"),
        alice.pk.clone(),
    ]
    .iter()
    .enumerate()
    {
        send(&mut a, post_frame_from(&alice, from, &bob, "relay.test", 100 + i as u32)).await;
        assert_eq!(recv(&mut a).await["type"], "Ok", "{from}");
    }
    assert_eq!(waiting(&n).await, 5);
    assert_eq!(denied_count(&n), 5);

    // mux/1: an error frame with the reason.
    let mut m = txmux(&n, false, &[]).await;
    let mut f = post_frame_from(&alice, &alice.at("epicbox.epicmine.test"), &bob, "relay.test", 200);
    f["type"] = json!("PostSlate");
    f["ref"] = json!("p1");
    send(&mut m, f).await;
    let r = recv(&mut m).await;
    assert_eq!(r["type"], "Error", "{r}");
    assert_eq!(r["code"], "post_refused", "{r}");
    assert_eq!(r["ref"], "p1");

    // HTTPS: 403 with the reason.
    let mut f = post_frame_from(&alice, &alice.at("epicbox.epicmine.test:443"), &bob, "relay.test", 201);
    f.as_object_mut().unwrap().remove("type");
    let (st, v) = http(&n, "POST", "/v1/post", Some(f)).await;
    assert_eq!(st, 403, "{v}");
    assert!(v["error"].as_str().unwrap().contains("epicbox.epicmine.test"), "{v}");
    assert_eq!(waiting(&n).await, 5);
    assert_eq!(denied_count(&n), 7);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_deny_list_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame_from(&alice, &alice.at("epicbox.epicmine.test"), &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    assert_eq!(denied_count(&n), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_sender_hosts_applies_to_slates_forwarded_by_another_relay() {
    let dir = tempfile::tempdir().unwrap();
    let b = start(dir.path(), "relayb.test", |c| c.federation.deny_sender_hosts = vec!["epicbox.epicmine.test".into()])
        .await;
    let b_url = format!("ws://{}", b.addr);
    // Relay A has no deny list: the sender's own relay accepts and queues the slate.
    let a = start(dir.path(), "relaya.test", |c| {
        c.federation.peers.insert("relayb.test:443".into(), b_url.clone());
    })
    .await;
    let (alice, bob, carol) = (Key::new(), Key::new(), Key::new());
    let mut bs = connect(&b).await;
    subscribe(&mut bs, &bob, "3.0.0").await;
    assert_eq!(recv(&mut bs).await, json!({"type":"Ok"}));

    let mut asock = connect(&a).await;
    recv_type(&mut asock, "Challenge").await;
    // A slate from the denied host is accepted by A (the sender sees Ok), forwarded, and
    // refused by B; B does not store it. A keeps the row for its few retries of a refused
    // forward, so B may count the same refusal more than once.
    send(&mut asock, post_frame_from(&alice, &alice.at("epicbox.epicmine.test"), &bob, "relayb.test", 1)).await;
    assert_eq!(recv(&mut asock).await["type"], "Ok");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while denied_count(&b) == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(denied_count(&b) >= 1, "B never refused the forwarded slate");
    assert_eq!(waiting(&b).await, 0);
    let denied = denied_count(&b);

    // A slate from another host still crosses.
    send(&mut asock, post_frame_from(&carol, &carol.at("relaya.test"), &bob, "relayb.test", 2)).await;
    assert_eq!(recv(&mut asock).await["type"], "Ok");
    let slate = recv_type(&mut bs, "Slate").await;
    assert_eq!(slate["from"], carol.at("relaya.test"));
    assert_eq!(waiting(&b).await, 1);
    assert!(denied_count(&b) >= denied);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deny_sender_hosts_does_not_stop_forwarding_through_this_relay() {
    // The list guards this relay's own mailboxes: a slate for another relay is queued as before.
    let dir = tempfile::tempdir().unwrap();
    let a = start(dir.path(), "relaya.test", |c| {
        c.federation.deny_sender_hosts = vec!["epicbox.epicmine.test".into()];
        c.federation.peers.insert("relayb.test:443".into(), "ws://127.0.0.1:9".into());
    })
    .await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut asock = connect(&a).await;
    recv_type(&mut asock, "Challenge").await;
    send(&mut asock, post_frame_from(&alice, &alice.at("epicbox.epicmine.test"), &bob, "relayb.test", 1)).await;
    assert_eq!(recv(&mut asock).await["type"], "Ok");
    assert_eq!(denied_count(&a), 0);
}

// ---- epicbox-attach/1 ----

const ATTACH: &str = "epicbox-attach/1";

/// What a wallet signs to attach `challenge` at `host` in the host-bound form.
fn attach_text(host: &str, challenge: &str) -> String {
    format!("{}{host}:{challenge}", epicmail::relay::ATTACH_SIG_PREFIX)
}

/// Open a mux/1 socket asking for `ext`; returns the socket, the echoed ext and the challenge.
async fn mux_with(n: &Node, ext: Value) -> (Ws, Value, String) {
    let mut m = connect(n).await;
    recv_type(&mut m, "Challenge").await;
    send(&mut m, json!({"type":"ClientDetails","wallet_version":"t","wallet_mode":"listener","protocol_version":"3.1.0","ext":ext})).await;
    let ok = recv(&mut m).await;
    let ch = ok["challenge"].as_str().expect("mux/1 challenge").to_string();
    (m, ok["ext"].clone(), ch)
}

async fn attach_one(m: &mut Ws, entry: Value) -> Value {
    send(m, json!({"type":"Attach","ref":"a","mailboxes":[entry]})).await;
    let at = recv_type(m, "Attached").await;
    at["mailboxes"][0].clone()
}

/// The relay advertises the host-bound attach form and echoes it only to a client that asks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_bound_attach_is_advertised_and_echoed_only_when_offered() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (st, wk) = http(&n, "GET", "/.well-known/epicbox.json", None).await;
    assert_eq!(st, 200);
    assert_eq!(wk["features"][ATTACH]["signed_text"], "epicbox-attach/1:<host>:<challenge>", "{wk}");
    assert_eq!(wk["features"][ATTACH]["bare_accepted"], true, "{wk}");
    assert_discovery_shape(&wk);

    let (_, ext, _) = mux_with(&n, json!(["mux/1", ATTACH])).await;
    assert_eq!(ext, json!(["mux/1", ATTACH]));
    let (_, ext, _) = mux_with(&n, json!(["mux/1"])).await;
    assert_eq!(ext, json!(["mux/1"]));

    let n2 = start(dir.path(), "relay2.test", |c| c.protocol.accept_bare_attach = false).await;
    let (_, wk) = http(&n2, "GET", "/.well-known/epicbox.json", None).await;
    assert_eq!(wk["features"][ATTACH]["bare_accepted"], false, "{wk}");
}

/// A released client (no extension, bare challenge) attaches on a relay that has the new form.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_released_client_attaches_with_the_bare_challenge() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let bob = Key::new();
    let (mut m, ext, ch) = mux_with(&n, json!(["mux/1", "txcancel/1"])).await;
    assert_eq!(ext, json!(["mux/1", "txcancel/1"]));
    let e = attach_one(&mut m, json!({"address":bob.pk,"signature":bob.sign(&ch)})).await;
    assert_eq!(e["ok"], true, "{e}");
}

/// A new client binds its signature to the name it dialled: the relay's domain or an alias, in
/// any case. The host must be the one signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_bound_attach_names_this_relay() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| {
        c.server.aliases = vec!["old.relay.test.".into(), "other.relay.test:8443".into()];
        c.protocol.accept_bare_attach = false;
    })
    .await;
    for host in ["relay.test", "old.relay.test", "other.relay.test", "Relay.Test"] {
        let bob = Key::new();
        let (mut m, ext, ch) = mux_with(&n, json!(["mux/1", ATTACH])).await;
        assert_eq!(ext, json!(["mux/1", ATTACH]));
        let e = attach_one(&mut m, json!({"address":bob.pk,"host":host,"signature":bob.sign(&attach_text(host, &ch))}))
            .await;
        assert_eq!(e["ok"], true, "{host}: {e}");
    }

    // The host sent is the host signed: a signature for another name does not verify.
    let bob = Key::new();
    let (mut m, _, ch) = mux_with(&n, json!(["mux/1", ATTACH])).await;
    let e = attach_one(
        &mut m,
        json!({"address":bob.pk,"host":"relay.test","signature":bob.sign(&attach_text("old.relay.test", &ch))}),
    )
    .await;
    assert_eq!(e["code"], "bad_signature", "{e}");

    // With the bare form off, a bare signature is refused.
    let (mut m, _, ch) = mux_with(&n, json!(["mux/1", ATTACH])).await;
    let e = attach_one(&mut m, json!({"address":bob.pk,"signature":bob.sign(&ch)})).await;
    assert_eq!(e["code"], "bad_signature", "{e}");
}

/// A signature bound to relay X is refused by relay Y, even over Y's own challenge: a relay that
/// passes on another relay's challenge cannot attach the wallet's mailbox there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signature_for_another_relay_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let y = start(dir.path(), "relayy.test", |_| {}).await;
    let bob = Key::new();
    let (mut m, _, ch) = mux_with(&y, json!(["mux/1", ATTACH])).await;
    let e = attach_one(
        &mut m,
        json!({"address":bob.pk,"host":"relayx.test","signature":bob.sign(&attach_text("relayx.test", &ch))}),
    )
    .await;
    assert_eq!(e["ok"], false, "{e}");
    assert_eq!(e["code"], "wrong_host", "{e}");
    // Naming Y with X's signature is a bad signature.
    let e = attach_one(
        &mut m,
        json!({"address":bob.pk,"host":"relayy.test","signature":bob.sign(&attach_text("relayx.test", &ch))}),
    )
    .await;
    assert_eq!(e["code"], "bad_signature", "{e}");
}

/// A relay from before the extension reads only `address` and `signature`: a new client that
/// was not echoed the extension sends the bare form, and the new relay treats an entry without
/// `host` the same way. A host-bound signature is not a bare one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_client_without_the_echo_signs_the_bare_challenge() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let bob = Key::new();
    let (mut m, _, ch) = mux_with(&n, json!(["mux/1"])).await;
    let e = attach_one(&mut m, json!({"address":bob.pk,"signature":bob.sign(&attach_text("relay.test", &ch))})).await;
    assert_eq!(e["code"], "bad_signature", "{e}");
    let e = attach_one(&mut m, json!({"address":bob.pk,"signature":bob.sign(&ch)})).await;
    assert_eq!(e["ok"], true, "{e}");
}

/// A relay updated without its aliases set: wallets dial a name it does not list. A new client
/// with many mailboxes gets `wrong_host` for each, then attaches them all with the bare form on
/// the same socket. `wrong_host` is not a failed signature, so the retry is not rate-limited:
/// 128 refusals are past the 120 a minute that would block the prefix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_missing_an_alias_lets_a_new_client_fall_back_to_the_bare_form() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "epicmail.relay.test", |_| {}).await;
    let keys: Vec<Key> = (0..128).map(|_| Key::new()).collect();
    let (mut m, ext, ch) = mux_with(&n, json!(["mux/1", ATTACH])).await;
    assert_eq!(ext, json!(["mux/1", ATTACH]));
    let dialled = "epicbox.relay.test";
    for chunk in keys.chunks(64) {
        let entries: Vec<Value> = chunk
            .iter()
            .map(|k| json!({"address":k.pk,"host":dialled,"signature":k.sign(&attach_text(dialled, &ch))}))
            .collect();
        send(&mut m, json!({"type":"Attach","ref":"h","mailboxes":entries})).await;
        let at = recv(&mut m).await;
        assert_eq!(at["type"], "Attached", "{at}");
        for e in at["mailboxes"].as_array().unwrap() {
            assert_eq!(e["code"], "wrong_host", "{e}");
        }
    }
    for chunk in keys.chunks(64) {
        let entries: Vec<Value> = chunk.iter().map(|k| json!({"address":k.pk,"signature":k.sign(&ch)})).collect();
        send(&mut m, json!({"type":"Attach","ref":"b","mailboxes":entries})).await;
        let at = recv(&mut m).await;
        assert_eq!(at["type"], "Attached", "{at}");
        let list = at["mailboxes"].as_array().unwrap();
        assert_eq!(list.len(), 64);
        for e in list {
            assert_eq!(e["ok"], true, "{e}");
        }
    }
}

// ---- accept_bare_cancel ----

/// With `accept_bare_cancel` off only the separated form cancels; a bare txid signature, which
/// anyone who saw the PostSlate holds, is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bare_cancel_is_refused_when_switched_off() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.protocol.accept_bare_cancel = false).await;
    let (alice, bob) = (Key::new(), Key::new());
    let tx = "0123456789abcdef0123456789abcdef";
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    let mut f = post_frame(&alice, "relay.test", &bob, "relay.test", 1);
    f["epicboxtxid"] = json!(tx);
    f["epicboxtxidsig"] = json!(alice.sign(tx));
    send(&mut a, f).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");

    let (_, wk) = http(&n, "GET", "/.well-known/epicbox.json", None).await;
    assert_eq!(wk["features"][SEPARATED]["bare_accepted"], false, "{wk}");

    let mut c = connect(&n).await;
    recv_type(&mut c, "Challenge").await;
    send(&mut c, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx,"signature":alice.sign(tx)})).await;
    assert_eq!(recv(&mut c).await["kind"], "InvalidSignature");
    assert_eq!(waiting(&n).await, 1);

    send(
        &mut c,
        json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":tx,"signature":alice.sign(&separated_text(tx))}),
    )
    .await;
    assert_eq!(recv(&mut c).await, json!({"type":"TransactionCancelled","epicboxtxid":tx}));
    assert_eq!(waiting(&n).await, 0);
}

/// The exact handshake of the client in app 26.11.5 (LEPIC 663f729b) on a relay set up as
/// production is (domain plus the old name as an alias): it offers mux/1, txcancel/1 and
/// epicbox-cancel/1, signs the bare challenge, and sends no `host`. The relay's answers carry
/// the same fields as before epicbox-attach/1: no new ext token, no new key in the Ok, and the
/// mailbox attaches and gets its mail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_26_11_5_client_handshake_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "epicmail.relay.test", |c| c.server.aliases = vec!["epicbox.relay.test".into()]).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "epicbox.relay.test", &bob, "epicbox.relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");

    let mut m = connect(&n).await;
    recv_type(&mut m, "Challenge").await;
    send(
        &mut m,
        json!({"type":"ClientDetails","wallet_version":"4.1.0","wallet_mode":"listener","protocol_version":"3.0.0",
               "ext":["mux/1","txcancel/1","epicbox-cancel/1"]}),
    )
    .await;
    let ok = recv(&mut m).await;
    assert_eq!(ok["type"], "Ok", "{ok}");
    assert_eq!(ok["ext"], json!(["mux/1", "txcancel/1", "epicbox-cancel/1"]), "{ok}");
    let mut keys: Vec<&str> = ok.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["challenge", "ext", "limits", "type"], "{ok}");
    let ch = ok["challenge"].as_str().unwrap().to_string();

    send(&mut m, json!({"type":"Attach","ref":"1","mailboxes":[{"address":bob.pk,"signature":bob.sign(&ch)}]})).await;
    let at = recv(&mut m).await;
    assert_eq!(at["type"], "Attached", "{at}");
    assert_eq!(at["ref"], "1", "{at}");
    assert_eq!(at["mailboxes"][0]["ok"], true, "{at}");
    assert_eq!(at["mailboxes"][0]["waiting"], 1, "{at}");
    let mail = recv(&mut m).await;
    assert_eq!(mail["type"], "Mail", "{mail}");
    assert_eq!(mail["mailbox"], bob.pk);

    // A wrong signature is still `bad_signature`, as before.
    let carol = Key::new();
    send(&mut m, json!({"type":"Attach","ref":"2","mailboxes":[{"address":carol.pk,"signature":bob.sign(&ch)}]})).await;
    let at = recv_type(&mut m, "Attached").await;
    assert_eq!(at["mailboxes"][0]["code"], "bad_signature", "{at}");
}

/// A peer that answers the first `busy` frames with an Error of the given kind and description
/// and the next with Ok. Returns its address and how many frames it has seen.
async fn erroring_peer(
    busy: usize,
    kind: &'static str,
    description: &'static str,
) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let count = count.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                let _ = ws.send(Message::Text(json!({"type":"Challenge","str":"c"}).to_string().into())).await;
                while let Some(Ok(m)) = ws.next().await {
                    if matches!(m, Message::Text(_)) {
                        let n = count.fetch_add(1, Ordering::SeqCst);
                        let a = if n < busy {
                            json!({"type":"Error","kind":kind,"description":description})
                        } else {
                            json!({"type":"Ok"})
                        };
                        let _ = ws.send(Message::Text(a.to_string().into())).await;
                        break;
                    }
                }
            });
        }
    });
    (addr, seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_peer_is_retried_and_the_row_is_delivered() {
    let dir = tempfile::tempdir().unwrap();
    // Three Busy answers are the refusal limit: they must not drop the row.
    let (peer, seen) = erroring_peer(3, "Busy", "busy").await;
    let url = format!("ws://{peer}");
    let a = start(dir.path(), "relaya.test", |c| {
        c.federation.peers.insert("busy.test:443".into(), url.clone());
        c.test.forward_backoff_ms = 10;
    })
    .await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut ws = connect(&a).await;
    recv_type(&mut ws, "Challenge").await;
    send(&mut ws, post_frame(&alice, "relaya.test", &bob, "busy.test", 1)).await;
    assert_eq!(recv(&mut ws).await["type"], "Ok");

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        a.relay.forward_notify.notify_one();
        if a.relay.store.stats(now_ms()).await.unwrap().forwards_waiting == 0 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "row not delivered; peer saw {:?}", seen);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 4, "three Busy answers, then Ok");
}

// ---- per-socket signature failures ----

/// The newest Challenge on `ws`: asks for one and reads up to a GetVersion sent behind it, so
/// interval Challenges queued earlier are skipped.
async fn latest_challenge(ws: &mut Ws) -> String {
    send(ws, json!({"type":"Challenge"})).await;
    send(ws, json!({"type":"GetVersion"})).await;
    let mut last = None;
    loop {
        let v = recv(ws).await;
        match v["type"].as_str() {
            Some("Challenge") => last = v["str"].as_str().map(String::from),
            Some("GetVersion") => return last.expect("no Challenge before GetVersion"),
            _ => panic!("unexpected frame {v}"),
        }
    }
}

/// A Subscribe for `addr` signed by `signer` over a fresh challenge; returns the reply.
async fn resubscribe(ws: &mut Ws, addr: &Key, signer: &Key, ver: &str) -> Value {
    let ch = latest_challenge(ws).await;
    send(ws, json!({"type":"Subscribe","address":addr.pk,"ver":ver,"signature":signer.sign(&ch)})).await;
    recv(ws).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_clients_bad_signatures_cannot_lock_out_a_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.protocol.challenge_interval_s = 5).await;
    let (k, alice) = (Key::new(), Key::new());
    let mut b = connect(&n).await;
    subscribe(&mut b, &k, "3.0.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));

    // Another client on the same prefix signs wrongly: its socket is closed after 8 failures.
    let mut failures = 0;
    let mut first = true;
    while failures < 130 {
        let mut a = connect(&n).await;
        let ch = recv_type(&mut a, "Challenge").await["str"].as_str().unwrap().to_string();
        for _ in 0..8 {
            let (x, wrong) = (Key::new(), Key::new());
            send(&mut a, json!({"type":"Subscribe","address":x.pk,"ver":"3.0.0","signature":wrong.sign(&ch)})).await;
            let r = recv(&mut a).await;
            if r["kind"] == "InvalidSignature" {
                failures += 1;
            } else {
                // Once the prefix is blocked only a socket's first signed frame is checked.
                assert!(!first, "{r}");
                assert!(r["description"].as_str().unwrap().contains("Rate limit"), "{r}");
                break;
            }
        }
        if first {
            assert_eq!(failures, 8);
            assert_eq!(recv(&mut a).await, json!({"closed": 4003}));
            first = false;
        }
    }
    assert!(n.relay.limiter.sig_blocked("127.0.0.1".parse().unwrap()).is_some(), "the prefix is blocked");

    // The wallet that proved its key still passes its challenge round, ...
    let ch = latest_challenge(&mut b).await;
    send(&mut b, json!({"type":"Subscribe","address":k.pk,"ver":"3.0.0","signature":k.sign(&ch)})).await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    // ... a slate posted to it arrives, and its Made is accepted.
    let mut p = connect(&n).await;
    recv_type(&mut p, "Challenge").await;
    send(&mut p, post_frame(&alice, "relay.test", &k, "relay.test", 1)).await;
    assert_eq!(recv(&mut p).await["type"], "Ok");
    let slate = recv_type(&mut b, "Slate").await;
    let msgid = slate["epicboxmsgid"].as_str().unwrap().to_string();
    send(&mut b, json!({"type":"Made","address":k.pk,"signature":k.sign(&msgid),"epicboxmsgid":msgid,"ver":"3.0.0"})).await;
    assert_eq!(recv_type(&mut b, "Ok").await, json!({"type":"Ok"}));
    assert_eq!(waiting(&n).await, 0);
    // A new socket's first Subscribe is not refused either.
    let mut c = connect(&n).await;
    subscribe(&mut c, &Key::new(), "3.0.0").await;
    assert_eq!(recv(&mut c).await, json!({"type":"Ok"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mux_socket_with_eight_bad_attach_entries_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (mut m, ch) = mux_open(&n).await;
    for r in ["a", "b"] {
        let list: Vec<Value> = (0..4)
            .map(|_| {
                let (x, wrong) = (Key::new(), Key::new());
                json!({"address":x.pk,"signature":wrong.sign(&ch)})
            })
            .collect();
        send(&mut m, json!({"type":"Attach","ref":r,"mailboxes":list})).await;
    }
    loop {
        let v = recv(&mut m).await;
        if v.get("closed").is_some() {
            assert_eq!(v, json!({"closed": 4003}));
            break;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_made_for_another_message_keeps_the_one_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.0.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    for i in 1..=2 {
        send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", i)).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
        if i == 1 {
            let first = recv_type(&mut b, "Slate").await;
            // A Made for a different message id is acknowledged and changes nothing here.
            let other = "not-the-one";
            send(&mut b, json!({"type":"Made","address":bob.pk,"signature":bob.sign(other),"epicboxmsgid":other,"ver":"3.0.0"})).await;
            assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
            let c = recv_type(&mut b, "Challenge").await;
            // The first message is still in flight: a Subscribe gets no second slate.
            send(&mut b, json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":bob.sign(c["str"].as_str().unwrap())})).await;
            assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
            let id = first["epicboxmsgid"].as_str().unwrap().to_string();
            send(&mut b, json!({"type":"Made","address":bob.pk,"signature":bob.sign(&id),"epicboxmsgid":id,"ver":"3.0.0"})).await;
            assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
        }
    }
    // Its own Made freed the slot: the next Subscribe is offered the second slate.
    let c = recv_type(&mut b, "Challenge").await;
    send(&mut b, json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":bob.sign(c["str"].as_str().unwrap())})).await;
    assert_eq!(recv_type(&mut b, "Slate").await["type"], "Slate");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_cancel_ack_waits_for_its_own_key() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |_| {}).await;
    let (alice, bob, carol) = (Key::new(), Key::new(), Key::new());
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.1.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_tx_frame(&alice, "relay.test", &bob, "relay.test", TXID)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    recv_type(&mut b, "Slate").await;
    send(&mut a, json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":TXID,"signature":alice.sign(TXID)})).await;
    assert_eq!(recv(&mut a).await["type"], "TransactionCancelled");
    assert_eq!(recv_type(&mut b, "TransactionCancelled").await["epicboxtxid"], TXID);

    // A failed Subscribe drops bob's key, and another key subscribes on the socket.
    let r = resubscribe(&mut b, &bob, &alice, "3.1.0").await;
    assert_eq!(r["kind"], "InvalidSignature", "{r}");
    assert_eq!(resubscribe(&mut b, &carol, &carol, "3.1.0").await, json!({"type":"Ok"}));
    // Bob proving his key again acknowledges the cancel, so it is not sent again.
    assert_eq!(resubscribe(&mut b, &bob, &bob, "3.1.0").await, json!({"type":"Ok"}));
    let mut b2 = connect(&n).await;
    subscribe(&mut b2, &bob, "3.1.0").await;
    assert_eq!(recv(&mut b2).await, json!({"type":"Ok"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_cancel_off_a_3_1_0_wallet_is_served_as_3_0_0() {
    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), "relay.test", |c| c.protocol.cancel = false).await;
    let (alice, bob) = (Key::new(), Key::new());
    let mut b = connect(&n).await;
    subscribe(&mut b, &bob, "3.1.0").await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    send(&mut b, json!({"type":"GetVersion"})).await;
    assert_eq!(recv(&mut b).await, json!({"type":"GetVersion","str":"3.0.0"}));

    let mut a = connect(&n).await;
    recv_type(&mut a, "Challenge").await;
    send(&mut a, post_frame(&alice, "relay.test", &bob, "relay.test", 1)).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let slate = recv_type(&mut b, "Slate").await;
    let id = slate["epicboxmsgid"].as_str().unwrap().to_string();
    send(&mut b, json!({"type":"Made","address":bob.pk,"signature":bob.sign(&id),"epicboxmsgid":id,"ver":"3.1.0"})).await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    recv_type(&mut b, "Challenge").await;
    assert_eq!(waiting(&n).await, 0);

    // Nothing is delivered again on the next connection.
    let mut b2 = connect(&n).await;
    subscribe(&mut b2, &bob, "3.1.0").await;
    assert_eq!(recv(&mut b2).await, json!({"type":"Ok"}));
}

/// The process-wide Prometheus recorder, installed on first use.
fn metrics_handle() -> &'static metrics_exporter_prometheus::PrometheusHandle {
    static H: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> = std::sync::OnceLock::new();
    H.get_or_init(|| epicmail::metrics::install().unwrap())
}

/// Sum of the series of `name` that carry every `key="value"` pair in `labels`.
fn metric(name: &str, labels: &[(&str, &str)]) -> f64 {
    metrics_handle()
        .render()
        .lines()
        .filter(|l| l.starts_with(&format!("{name}{{")) || l.starts_with(&format!("{name} ")))
        .filter(|l| labels.iter().all(|(k, v)| l.contains(&format!("{k}=\"{v}\""))))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
        .sum()
}

/// The queued forward rows of a relay, whenever due.
async fn queued_forwards(n: &Node, peer: &str) -> Vec<epicmail::store::ForwardRow> {
    n.relay.store.forwards_due(peer, i64::MAX, 100).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peers_temporary_errors_keep_the_row_queued_without_counting_attempts() {
    metrics_handle();
    let dir = tempfile::tempdir().unwrap();
    // Epicmail's own answer for a full mailbox, sent as InvalidRequest, more often than the
    // refusal limit.
    let (peer, seen) = erroring_peer(usize::MAX, "InvalidRequest", "Recipient mailbox is full; try again later.").await;
    let url = format!("ws://{peer}");
    let a = start(dir.path(), "relaya.test", |c| {
        c.federation.peers.insert("full.test:443".into(), url.clone());
        c.test.forward_backoff_ms = 10;
    })
    .await;
    let before = metric("epicbox_forwards_total", &[("result", "busy")]);
    let (alice, bob) = (Key::new(), Key::new());
    let mut ws = connect(&a).await;
    recv_type(&mut ws, "Challenge").await;
    send(&mut ws, post_frame(&alice, "relaya.test", &bob, "full.test", 1)).await;
    assert_eq!(recv(&mut ws).await["type"], "Ok");

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while seen.load(std::sync::atomic::Ordering::SeqCst) < 5 {
        a.relay.forward_notify.notify_one();
        assert!(std::time::Instant::now() < deadline, "peer saw {:?} frames", seen);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let rows = queued_forwards(&a, "full.test:443").await;
    assert_eq!(rows.len(), 1, "the row is still queued after five temporary answers");
    assert_eq!(rows[0].attempts, 0, "no attempt was counted");
    assert!(metric("epicbox_forwards_total", &[("result", "busy")]) >= before + 5.0);
}

/// A stock-like peer: greets with a Challenge, answers a PostSlate with Ok and stays silent to
/// anything else (it has no `CancelTx` case). Returns its address and the PostSlate count.
async fn silent_to_cancels_peer() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let posts = Arc::new(AtomicUsize::new(0));
    let count = posts.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let count = count.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                let _ = ws.send(Message::Text(json!({"type":"Challenge","str":"c"}).to_string().into())).await;
                while let Some(Ok(m)) = ws.next().await {
                    if let Message::Text(t) = m {
                        let v: Value = serde_json::from_str(&t).unwrap_or_default();
                        if v["type"] == "PostSlate" {
                            count.fetch_add(1, Ordering::SeqCst);
                            let _ = ws.send(Message::Text(json!({"type":"Ok"}).to_string().into())).await;
                            break;
                        }
                    }
                }
            });
        }
    });
    (addr, posts)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unanswered_cancel_is_dropped_and_does_not_hold_the_peer_back() {
    use epicmail::store::{ForwardKind, NewForward};
    metrics_handle();
    let dir = tempfile::tempdir().unwrap();
    let (peer, posts) = silent_to_cancels_peer().await;
    let url = format!("ws://{peer}");
    let a = start(dir.path(), "relaya.test", |c| {
        c.federation.peers.insert("stock.test:443".into(), url.clone());
        c.federation.timeout_s = 1;
    })
    .await;
    let before = metric("epicbox_forwards_total", &[("result", "unanswered")]);
    let now = now_ms();
    let cancel = json!({"type":"CancelTx","address":"x","epicboxtxid":"t","signature":"s"});
    a.relay
        .store
        .put_forward(NewForward {
            peer: "stock.test:443".into(),
            kind: ForwardKind::CancelTx,
            frame: cancel.to_string(),
            txid: None,
            tx_keys: vec![],
            created_at: now,
            expires_at: now + 3_600_000,
            attempts: 0,
        })
        .await
        .unwrap();
    a.relay.forward_notify.notify_one();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !queued_forwards(&a, "stock.test:443").await.is_empty() {
        assert!(std::time::Instant::now() < deadline, "the unanswered cancel is still queued");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(metric("epicbox_forwards_total", &[("result", "unanswered")]) >= before + 1.0);

    // A slate for the same peer goes out at once, not after a back-off (the first is 10 s).
    let (alice, bob) = (Key::new(), Key::new());
    let mut ws = connect(&a).await;
    recv_type(&mut ws, "Challenge").await;
    send(&mut ws, post_frame(&alice, "relaya.test", &bob, "stock.test", 1)).await;
    assert_eq!(recv(&mut ws).await["type"], "Ok");
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while posts.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        assert!(std::time::Instant::now() < deadline, "the slate waited behind a back-off");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
