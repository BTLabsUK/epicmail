//! Everything the relay logs at debug level while it serves a post, a subscribe, a delivery, a
//! Made, a cancel, a forward to another relay and bad requests, and in its traffic summary and
//! bad-request warning, holds no full key, address, slate, signature, challenge, message id or
//! client IP. A separate test binary, because it installs the global log subscriber.

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

    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    // A second relay, so a slate is forwarded and the forward is logged.
    let other = serve(dir.path(), "other.test", |_| {}).await;
    let addr = serve(dir.path(), "relay.test", |c| {
        c.federation.allow_private = true;
        c.federation.peers.insert("other.test:443".into(), format!("ws://{other}/"));
        c.log.summary_interval_s = 1;
        c.log.warn_bad_requests = 1;
    })
    .await;

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
    // A slate for a mailbox on the other relay is forwarded there.
    let carol = Key::new();
    let far_body =
        json!({"destination":{"public_key":carol.pk,"domain":"other.test","port":443},"secret":"FARPAYLOAD"})
            .to_string();
    let far_sig = alice.sign(&far_body);
    let far = json!({"type":"PostSlate","from":format!("{}@relay.test",alice.pk),"to":format!("{}@other.test",carol.pk),
        "str":far_body,"signature":far_sig});
    send(&mut a, &far).await;
    assert_eq!(recv(&mut a).await["type"], "Ok");
    // Refused Subscribes, an invalid post and a socket closing log too; three bad signatures
    // from one network are over the warning threshold of 1.
    for _ in 0..3 {
        send(&mut a, &json!({"type":"Subscribe","address":alice.pk,"ver":"3.0.0","signature":"00"})).await;
        recv(&mut a).await;
    }
    for _ in 0..2 {
        send(&mut a, &json!({"type":"PostSlate","from":alice.pk,"to":bob.pk,"str":"x","signature":"00"})).await;
        recv(&mut a).await;
    }
    drop(a);
    drop(b);

    // The summary (every second here), the warning and the forward line.
    let mut logs = String::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        if logs.contains(" traffic ")
            && logs.contains("many bad requests")
            && logs.contains("epicmail::forward: forwarded")
        {
            break;
        }
    }
    assert!(logs.contains("subscribed") && logs.contains("post") && logs.contains("transaction cancelled"), "{logs}");
    let line =
        |needle: &str| logs.lines().find(|l| l.contains(needle)).unwrap_or_else(|| panic!("no {needle}:\n{logs}"));
    let summary = line(" traffic ");
    assert!(
        summary.contains(" INFO ") && summary.contains("posts_stored=") && summary.contains("bad_signatures="),
        "{summary}"
    );
    let warning = line("many bad requests");
    assert!(warning.contains(" WARN ") && warning.contains("net=127.0.0.0/24"), "{warning}");
    let forwarded = line("epicmail::forward: forwarded");
    assert!(forwarded.contains(" INFO ") && forwarded.contains("peer=\"other.test:443\""), "{forwarded}");
    for secret in [
        alice.pk.as_str(),
        bob.pk.as_str(),
        carol.pk.as_str(),
        "PAYLOAD",
        slate_sig.as_str(),
        far_sig.as_str(),
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

/// A relay for `domain` on a loopback port, with its forward manager and log summary running.
async fn serve(dir: &std::path::Path, domain: &str, tweak: impl FnOnce(&mut Config)) -> SocketAddr {
    let mut cfg = Config::default();
    cfg.server.domain = domain.into();
    cfg.store.path = dir.join(format!("{domain}.db"));
    tweak(&mut cfg);
    cfg.validate().unwrap();
    let cfg = Arc::new(cfg);
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&cfg.store.path, 1, 64).unwrap());
    let relay = Relay::new(cfg, store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = http::router(AppState { relay: relay.clone(), metrics: None, metrics_on_main: false })
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::spawn(epicmail::forward::run(relay.clone()));
    tokio::spawn(epicmail::traffic::run(relay));
    addr
}
