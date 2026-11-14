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

use epicmail::config::Config;
use epicmail::http::{self, AppState};
use epicmail::relay::Relay;
use epicmail::sig;
use epicmail::store::sqlite::SqliteStore;
use epicmail::store::Store;
use epicmail::util::now_ms;

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
    (status, serde_json::from_str(body).unwrap_or(Value::String(body.to_string())))
}

async fn waiting(n: &Node) -> u64 {
    n.relay.store.stats(now_ms()).await.unwrap().messages_waiting as u64
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
    assert_eq!(first, json!({"type":"Challenge","str":STATIC}));
    send(&mut b, json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":bob.sign(STATIC)})).await;
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
    send(&mut b, json!({"type":"Made","address":bob.pk,"signature":alice.sign(&msgid),"epicboxmsgid":msgid,"ver":"3.0.0"})).await;
    assert_eq!(recv(&mut b).await["kind"], "InvalidSignature");
    assert_eq!(waiting(&n).await, 1);

    send(&mut b, json!({"type":"Made","address":bob.pk,"signature":bob.sign(&msgid),"epicboxmsgid":msgid,"ver":"3.0.0"})).await;
    assert_eq!(recv(&mut b).await, json!({"type":"Ok"}));
    let c = recv_type(&mut b, "Challenge").await;
    assert_ne!(c["str"], STATIC);
    assert_eq!(waiting(&n).await, 0);

    // Subscribing again finds nothing.
    send(&mut b, json!({"type":"Subscribe","address":bob.pk,"ver":"3.0.0","signature":bob.sign(c["str"].as_str().unwrap())})).await;
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
    for junk in ["not json", "{\"type\":5}", "{\"type\":\"Subscribe\",\"address\":\"x@:\"}", "{\"type\":\"PostSlate\"}", "[]"] {
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
    send(&mut m, json!({"type":"Attach","ref":"a1","mailboxes":[
        {"address":bob.pk,"signature":bob.sign(&ch)},
        {"address":alice.pk,"signature":bob.sign(&ch)}]})).await;
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
    let stats = a.relay.store.stats(now_ms()).await.unwrap();
    assert_eq!(stats.forwards_waiting, 0);

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
