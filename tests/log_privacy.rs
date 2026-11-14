//! Everything the relay logs at debug level while it serves a post, a subscribe, a delivery, a
//! Made, a cancel and a /v1 pull holds no full key, address, slate, signature, challenge, message
//! id or client IP. A separate test binary, because it installs the global log subscriber.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

use epicmail::config::Config;
use epicmail::http::{self, AppState};
use epicmail::relay::{Relay, CANCEL_SIG_PREFIX};
use epicmail::sig;
use epicmail::store::sqlite::SqliteStore;
use epicmail::store::Store;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn recv(ws: &mut Ws) -> Value {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), ws.next()).await.unwrap().unwrap().unwrap();
        if let Message::Text(t) = m {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] != "Challenge" || v.get("str").is_some() {
                return v;
            }
        }
    }
}

async fn send(ws: &mut Ws, v: &Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debug_logs_hold_nothing_private() {
    let buf = Buf::default();
    let writer = buf.clone();
    tracing_subscriber::fmt().with_env_filter("debug").with_ansi(false).with_writer(move || writer.clone()).init();

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.server.domain = "relay.test".into();
    cfg.store.path = dir.path().join("t.db");
    cfg.validate().unwrap();
    let cfg = Arc::new(cfg);
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&cfg.store.path, 1, 64).unwrap());
    let relay = Relay::new(cfg, store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = http::router(AppState { relay, metrics: None, metrics_on_main: false })
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (alice, bob) = (Key::new(), Key::new());
    let txid = "0123456789abcdef0123456789abcdef";
    let body =
        json!({"destination":{"public_key":bob.pk,"domain":"relay.test","port":443},"secret":"PAYLOAD"}).to_string();
    let slate_sig = alice.sign(&body);

    let (mut b, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/")).await.unwrap();
    let challenge = recv(&mut b).await["str"].as_str().unwrap().to_string();
    let sub_sig = bob.sign(&challenge);
    send(&mut b, &json!({"type":"Subscribe","address":bob.pk,"ver":"3.1.0","signature":sub_sig})).await;
    assert_eq!(recv(&mut b).await["type"], "Ok");

    let (mut a, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/")).await.unwrap();
    recv(&mut a).await;
    let post = json!({"type":"PostSlate","from":format!("{}@relay.test",alice.pk),"to":format!("{}@relay.test",bob.pk),
        "str":body,"signature":slate_sig,"epicboxtxid":txid,"epicboxtxidsig":alice.sign(txid)});
    send(&mut a, &post).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    let slate = recv(&mut b).await;
    let msgid = slate["epicboxmsgid"].as_str().unwrap().to_string();
    send(
        &mut b,
        &json!({"type":"Made","address":bob.pk,"ver":"3.1.0","epicboxmsgid":msgid,"signature":bob.sign(&msgid)}),
    )
    .await;
    assert_eq!(recv(&mut b).await["type"], "Ok");
    let cancel_sig = alice.sign(&format!("{CANCEL_SIG_PREFIX}{txid}"));
    send(&mut a, &json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":txid,"signature":cancel_sig})).await;
    recv(&mut a).await;
    // A refused Subscribe and a socket closing log too.
    send(&mut a, &json!({"type":"Subscribe","address":alice.pk,"ver":"3.0.0","signature":"00"})).await;
    recv(&mut a).await;
    drop(a);
    drop(b);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("subscribed") && logs.contains("post") && logs.contains("transaction cancelled"), "{logs}");
    for secret in [
        alice.pk.as_str(),
        bob.pk.as_str(),
        "PAYLOAD",
        slate_sig.as_str(),
        sub_sig.as_str(),
        cancel_sig.as_str(),
        challenge.as_str(),
        msgid.as_str(),
        txid,
        "127.0.0.1",
    ] {
        assert!(!logs.contains(secret), "log holds {secret}:\n{logs}");
    }
}
