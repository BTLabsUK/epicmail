//! Both log outputs, at every level down to trace, while two relays serve posts, subscribes,
//! deliveries, Made, a cancel, a forward, a mux/1 session (Attach, Mail, Ack, Hold, Detach,
//! Resume) and bad requests: no line holds a full key or address, a slate, a signature, a
//! challenge, a txid or a resume token. Client IPs, shortened keys and message ids may appear.
//! Each output keeps its own level. A separate test binary, because it installs the global log
//! subscriber.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

use epicmail::config::{Config, Log};
use epicmail::http::{self, AppState};
use epicmail::logging;
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

async fn recv_type(ws: &mut Ws, ty: &str) -> Value {
    loop {
        let v = recv(ws).await;
        if v["type"] == ty {
            return v;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_level_of_either_output_holds_anything_private() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    // Two outputs as a relay runs them: the console at info, the file at trace in JSON.
    let console = Buf::default();
    let w = console.clone();
    let mut log = Log::default();
    log.file.enabled = true;
    log.file.path = dir.path().join("logs").join("relay.log");
    log.file.level = "trace".into();
    log.file.format = "json".into();
    let guard = logging::init_with(&log, true, logging::filter("info"), move || w.clone(), false, false).unwrap();

    // A second relay, so a slate is forwarded and the forward is logged.
    let other = serve(dir.path(), "other.test", |_| {}).await;
    let addr = serve(dir.path(), "relay.test", |c| {
        c.federation.allow_private = true;
        c.federation.deny_sender_hosts = vec!["pool.test".into()];
        c.federation.peers.insert("other.test:443".into(), format!("ws://{other}/"));
        c.log.summary_interval_s = 1;
        c.log.warn_bad_requests = 1;
    })
    .await;
    let url = format!("ws://{addr}/");

    let (alice, bob) = (Key::new(), Key::new());
    let txid = "0123456789abcdef0123456789abcdef";
    let body =
        json!({"destination":{"public_key":bob.pk,"domain":"relay.test","port":443},"secret":"PAYLOAD"}).to_string();
    let slate_sig = alice.sign(&body);

    let (mut b, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let challenge = recv(&mut b).await["str"].as_str().unwrap().to_string();
    let sub_sig = bob.sign(&challenge);
    send(&mut b, &json!({"type":"Subscribe","address":bob.pk,"ver":"3.1.0","signature":sub_sig})).await;
    assert_eq!(recv(&mut b).await["type"], "Ok");

    let (mut a, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
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

    // mux/1: Attach, Mail, Ack, Hold, Detach; then Resume with the token on a new socket, which
    // fails because Detach left nothing to resume.
    let dave = Key::new();
    let (mut m, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    recv(&mut m).await;
    let details = json!({"type":"ClientDetails","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]});
    send(&mut m, &details).await;
    let mux_challenge = recv_type(&mut m, "Ok").await["challenge"].as_str().unwrap().to_string();
    let attach_sig = dave.sign(&mux_challenge);
    send(&mut m, &json!({"type":"Attach","ref":"1","mailboxes":[{"address":dave.pk,"signature":attach_sig}]})).await;
    let token = recv_type(&mut m, "Attached").await["token"].as_str().unwrap().to_string();
    let mut mux_sigs = vec![];
    for secret in ["MUXONE", "MUXTWO"] {
        let body =
            json!({"destination":{"public_key":dave.pk,"domain":"relay.test","port":443},"secret":secret}).to_string();
        let sig = alice.sign(&body);
        send(&mut a, &json!({"type":"PostSlate","from":alice.pk,"to":dave.pk,"str":body,"signature":sig})).await;
        assert_eq!(recv(&mut a).await["type"], "Ok");
        mux_sigs.push(sig);
    }
    // Both are in flight at once.
    let one = recv_type(&mut m, "Mail").await["id"].as_str().unwrap().to_string();
    let two = recv_type(&mut m, "Mail").await["id"].as_str().unwrap().to_string();
    send(&mut m, &json!({"type":"Ack","ref":"2","ids":[one]})).await;
    recv_type(&mut m, "Ok").await;
    send(&mut m, &json!({"type":"Hold","ref":"3","id":two,"seconds":5})).await;
    recv_type(&mut m, "Ok").await;
    send(&mut m, &json!({"type":"Detach","ref":"4","mailboxes":[dave.pk]})).await;
    recv_type(&mut m, "Ok").await;
    send(&mut m, &json!({"type":"Resume","ref":"5","token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})).await;
    recv_type(&mut m, "Error").await;
    drop(m);
    let (mut m2, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    recv(&mut m2).await;
    send(&mut m2, &details).await;
    recv_type(&mut m2, "Ok").await;
    send(&mut m2, &json!({"type":"Resume","ref":"6","token":token})).await;
    recv_type(&mut m2, "Attached").await;

    // Refused Subscribes and invalid posts; three bad signatures from one network are over the
    // warning threshold of 1.
    for _ in 0..3 {
        send(&mut a, &json!({"type":"Subscribe","address":alice.pk,"ver":"3.0.0","signature":"00"})).await;
        recv(&mut a).await;
    }
    for _ in 0..2 {
        send(&mut a, &json!({"type":"PostSlate","from":alice.pk,"to":bob.pk,"str":"x","signature":"00"})).await;
        recv(&mut a).await;
    }
    // A slate from a denied sender host: the wallet gets an error; the log names the host only.
    let denied_body =
        json!({"destination":{"public_key":bob.pk,"domain":"relay.test","port":443},"secret":"DENIEDPAYLOAD"})
            .to_string();
    let denied_sig = alice.sign(&denied_body);
    send(
        &mut a,
        &json!({"type":"PostSlate","from":format!("{}@pool.test:3425",alice.pk),"to":format!("{}@relay.test",bob.pk),
            "str":denied_body,"signature":denied_sig}),
    )
    .await;
    assert_eq!(recv(&mut a).await["type"], "Error");
    drop((a, b, m2));

    // Wait for the summary (every second here), the warning and the forward line.
    let text = |b: &Buf| String::from_utf8(b.0.lock().unwrap().clone()).unwrap();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let c = text(&console);
        if c.contains(" traffic ") && c.contains("many bad requests") && c.contains("forwarded") {
            break;
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(guard);
    let console = text(&console);
    let file = std::fs::read_to_string(&log.file.path).unwrap();

    // Each output at its own level: the console has no debug or trace lines, the file has all.
    for l in console.lines() {
        assert!(l.contains(" INFO ") || l.contains(" WARN ") || l.contains(" ERROR "), "console line below info: {l}");
    }
    let line = |needle: &str| {
        console.lines().find(|l| l.contains(needle)).unwrap_or_else(|| panic!("no {needle}:\n{console}"))
    };
    assert!(line(" traffic ").contains("posts_stored="));
    assert!(line("many bad requests").contains("net=127.0.0.0/24"));
    let denied = line("denied sender host");
    assert!(denied.contains(" INFO ") && denied.contains("host=pool.test"), "{denied}");
    assert!(line(" traffic ").contains("posts_denied_host="));
    assert!(line("epicmail::forward: forwarded").contains("peer=\"other.test:443\""));

    let events: Vec<Value> = file.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let find = |level: &str, message: &str| {
        events
            .iter()
            .find(|e| e["level"] == level && e["message"] == message)
            .unwrap_or_else(|| panic!("no {level} {message} in the file:\n{file}"))
    };
    assert_eq!(find("DEBUG", "connected")["ip"], "127.0.0.1");
    assert_eq!(find("DEBUG", "disconnected")["transport"], "classic");
    let stored = find("DEBUG", "post");
    assert_eq!((stored["result"].as_str(), stored["id"].as_str()), (Some("stored"), Some(msgid.as_str())));
    assert_eq!(find("DEBUG", "delivered")["id"], msgid.as_str());
    assert_eq!(find("DEBUG", "acked")["id"], msgid.as_str());
    find("DEBUG", "transaction cancelled");
    find("DEBUG", "forward");
    for m in ["frame", "subscribed", "subscribe refused", "attached", "held", "detached", "resumed", "resume refused"] {
        find("TRACE", m);
    }
    find("INFO", "traffic");
    find("WARN", "many bad requests from one network");

    // What no line of either output holds, at any level.
    let mut secrets = vec![
        alice.pk.clone(),
        bob.pk.clone(),
        carol.pk.clone(),
        dave.pk.clone(),
        "PAYLOAD".into(),
        "MUXONE".into(),
        "MUXTWO".into(),
        slate_sig,
        denied_sig,
        "DENIEDPAYLOAD".into(),
        far_sig,
        sub_sig,
        attach_sig,
        cancel_sig,
        challenge,
        mux_challenge,
        token,
        txid.into(),
    ];
    secrets.extend(mux_sigs);
    for secret in &secrets {
        assert!(!console.contains(secret.as_str()), "console holds {secret}:\n{console}");
        assert!(!file.contains(secret.as_str()), "file holds {secret}:\n{file}");
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
    tokio::spawn(epicmail::relay::arrivals(relay.clone()));
    tokio::spawn(epicmail::traffic::run(relay));
    addr
}
