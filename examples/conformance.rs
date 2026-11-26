//! The Epicmail conformance suite: checks that a mailbox (relay) behaves like Epicmail.
//!
//!   conformance epicmail.btlabs.uk
//!   conformance --url http://127.0.0.1:3423 --domain a.test --other-url http://127.0.0.1:3424 --other-domain b.test --staging
//!
//! Every case prints one line: PASS, FAIL (expected vs got) or SKIP (why), with a stable case id.
//! The run ends with a summary line and a JSON summary file. Exit 1 when a case fails that is not
//! in the --expect-fail list, or when a listed case passes (so the list stays exact).
//! Keys are fresh and random on every run and are never printed. Each case acks or Made's what
//! it posted; a cleanup pass after each case removes anything left.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use futures_util::SinkExt;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

#[path = "common/mod.rs"]
mod common;
use common::*;

const T: Duration = Duration::from_secs(10);
const MISSING_FIELDS: &str = "PostSlate requires from, to, str, and signature. epicboxtxid and epicboxtxidsig must either both be absent (legacy) or both be valid (protocol 3.1.0).";

#[derive(Parser)]
#[command(about = "Epicmail conformance suite")]
struct Args {
    /// Host to test (https://HOST, addresses written @HOST). Or use --url and --domain.
    host: Option<String>,
    /// Base URL, for a local relay: http://127.0.0.1:3423
    #[arg(long)]
    url: Option<String>,
    /// Domain written in addresses, with --url.
    #[arg(long)]
    domain: Option<String>,
    /// The other mailbox for the federation cases (a host). Default: the other of the two live hosts.
    #[arg(long)]
    other: Option<String>,
    #[arg(long)]
    other_url: Option<String>,
    #[arg(long)]
    other_domain: Option<String>,
    /// Also run the cases that need a relay with small limits (tools/conformance-staging.toml).
    #[arg(long)]
    staging: bool,
    /// Skip the cases that wait minutes (the watchdog).
    #[arg(long)]
    skip_slow: bool,
    /// File of case ids expected to fail, one per line; # starts a comment.
    #[arg(long)]
    expect_fail: Option<PathBuf>,
    /// Where to write the JSON summary.
    #[arg(long)]
    summary: Option<PathBuf>,
    /// Run only cases whose id contains this text (repeatable).
    #[arg(long)]
    only: Vec<String>,
    /// Staging: the relay's limits.queue_cap.
    #[arg(long, default_value_t = 12)]
    queue_cap: usize,
    /// Staging: the relay's limits.per_sender_cap.
    #[arg(long, default_value_t = 5)]
    sender_cap: usize,
    /// Staging: the relay's limits.posts_burst_per_address.
    #[arg(long, default_value_t = 10)]
    post_burst: usize,
}

// ---------------------------------------------------------------------------------------------
// Targets, context, results

struct Target {
    name: String,
    ws_url: String,
    http: Http,
    domain: String,
}

impl Target {
    fn new(url: &str, domain: &str) -> anyhow::Result<Target> {
        let base = url::Url::parse(url)?;
        let ws_url = format!(
            "{}://{}{}/",
            if base.scheme() == "https" { "wss" } else { "ws" },
            base.host_str().unwrap_or(""),
            base.port().map(|p| format!(":{p}")).unwrap_or_default()
        );
        Ok(Target { name: domain.to_string(), ws_url, http: Http::new(&base)?, domain: domain.to_string() })
    }
    fn host(h: &str) -> anyhow::Result<Target> {
        Target::new(&format!("https://{h}"), h)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Side {
    This,
    Other,
}

/// What every case shares.
struct Shared {
    t: Target,
    other: Option<Target>,
    staging: bool,
    queue_cap: usize,
    sender_cap: usize,
    post_burst: usize,
}

/// One case's view: the shared settings and its own list of mail it posted and has not removed.
struct Ctx {
    sh: Arc<Shared>,
    owed: Mutex<HashMap<String, (Side, Key, i64)>>,
}

impl std::ops::Deref for Ctx {
    type Target = Shared;
    fn deref(&self) -> &Shared {
        &self.sh
    }
}

impl Ctx {
    fn d(&self) -> &str {
        &self.t.domain
    }
    fn target(&self, s: Side) -> &Target {
        match s {
            Side::This => &self.t,
            Side::Other => self.other.as_ref().unwrap_or(&self.t),
        }
    }
    fn owe(&self, side: Side, k: &Key) {
        let mut m = self.owed.lock().unwrap();
        m.entry(format!("{}{}", side == Side::Other, k.pk)).or_insert((side, k.clone(), 0)).2 += 1;
    }
    fn paid(&self, side: Side, k: &Key) {
        if let Some(e) = self.owed.lock().unwrap().get_mut(&format!("{}{}", side == Side::Other, k.pk)) {
            e.2 = (e.2 - 1).max(0);
        }
    }
}

enum E {
    Fail(String),
    Skip(String),
}

impl From<String> for E {
    fn from(s: String) -> E {
        E::Fail(s)
    }
}
impl From<anyhow::Error> for E {
    fn from(e: anyhow::Error) -> E {
        E::Fail(cut(&e.to_string()))
    }
}

type R = Result<(), E>;
type BoxFut = Pin<Box<dyn Future<Output = R> + Send>>;
type CaseFn = fn(Arc<Ctx>) -> BoxFut;

fn cut(s: &str) -> String {
    let t: String = s.chars().take(170).collect();
    if s.chars().count() > 170 {
        format!("{t}...")
    } else {
        t
    }
}

macro_rules! ensure {
    ($c:expr, $($a:tt)+) => {
        if !($c) {
            return Err(E::Fail(cut(&format!($($a)+))));
        }
    };
}

fn skip<T>(why: &str) -> Result<T, E> {
    Err(E::Skip(why.to_string()))
}

fn j(v: &Value) -> String {
    cut(&v.to_string())
}

// ---------------------------------------------------------------------------------------------
// Wire helpers

async fn conn(t: &Target) -> Result<(Ws, String), E> {
    let mut ws = ws_connect(&t.ws_url).await?;
    let ch = challenge(&mut ws).await?;
    Ok((ws, ch))
}

async fn tx(ws: &mut Ws, v: &Value) -> R {
    Ok(send(ws, v).await?)
}

/// Send a frame; the next frame that is not an interval Challenge, as JSON.
async fn call(ws: &mut Ws, v: &Value) -> Result<Value, E> {
    tx(ws, v).await?;
    match answer(ws, T).await {
        Frame::Json(v) => Ok(v),
        f => Err(E::Fail(format!("expected a frame, got {}", f.label()))),
    }
}

/// Frames until one has this type; Ok and Challenge frames are passed over, any other type fails.
async fn until(ws: &mut Ws, ty: &str, secs: f64) -> Result<Value, E> {
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match next_frame(ws, left).await {
            Frame::Json(v) if v["type"] == ty => return Ok(v),
            Frame::Json(v) if v["type"] == "Challenge" || (v["type"] == "Ok" && ty != "Ok") => continue,
            Frame::Json(v) => return Err(E::Fail(format!("expected {ty}, got {}", j(&v)))),
            Frame::Timeout => return Err(E::Fail(format!("expected {ty} within {secs} s, got nothing"))),
            f => return Err(E::Fail(format!("expected {ty}, got {}", f.label()))),
        }
    }
}

/// True when nothing but Ok/Challenge frames arrive for this long.
async fn quiet(ws: &mut Ws, secs: f64) -> Result<(), E> {
    match until(ws, "NoSuchFrame", secs).await {
        Err(E::Fail(m)) if m.contains("got nothing") => Ok(()),
        Err(E::Fail(m)) => {
            Err(E::Fail(format!("expected silence, got {}", m.trim_start_matches("expected NoSuchFrame, got "))))
        }
        _ => Ok(()),
    }
}

fn is_ok(v: &Value) -> bool {
    v["type"] == "Ok"
}

fn want_error(v: &Value, kind: &str, desc: &str) -> R {
    ensure!(
        v["type"] == "Error" && v["kind"] == kind && v["description"] == desc,
        "expected Error {kind} {desc:?}, got {}",
        j(v)
    );
    Ok(())
}

fn want_code(v: &Value, code: &str) -> R {
    ensure!(v["type"] == "Error" && v["code"] == code, "expected Error code {code}, got {}", j(v));
    Ok(())
}

async fn subscribe(ws: &mut Ws, k: &Key, ch: &str, ver: &str) -> Result<Value, E> {
    call(ws, &json!({"type":"Subscribe","address":k.pk,"ver":ver,"signature":k.sign(ch)})).await
}

async fn sub_ok(ws: &mut Ws, k: &Key, ch: &str, ver: &str) -> R {
    let r = subscribe(ws, k, ch, ver).await?;
    ensure!(is_ok(&r), "expected Subscribe Ok, got {}", j(&r));
    Ok(())
}

/// Subscribe when mail is waiting: the Slate arrives in place of the Ok.
async fn sub_get(ws: &mut Ws, k: &Key, ch: &str) -> Result<Value, E> {
    let r = subscribe(ws, k, ch, "3.0.0").await?;
    ensure!(r["type"] == "Slate", "expected a Slate in answer to Subscribe with mail waiting, got {}", j(&r));
    Ok(r)
}

/// Classic PostSlate from a fresh sender socket's point of view: the reply frame.
async fn post_raw(ws: &mut Ws, from: &Key, from_d: &str, to: &Key, to_d: &str, msg: &str) -> Result<Value, E> {
    call(ws, &post_frame(from, from_d, to, to_d, msg)).await
}

/// A post to a mailbox on the relay under test; must be accepted.
async fn post_ok(cx: &Ctx, ws: &mut Ws, from: &Key, to: &Key, msg: &str) -> Result<Value, E> {
    let r = post_raw(ws, from, cx.d(), to, cx.d(), msg).await?;
    ensure!(is_ok(&r), "expected PostSlate Ok, got {}", j(&r));
    cx.owe(Side::This, to);
    Ok(r)
}

fn txid() -> String {
    format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>())
}

fn post_tx(from: &Key, from_d: &str, to: &Key, to_d: &str, msg: &str, txid: &str) -> Value {
    let mut f = post_frame(from, from_d, to, to_d, msg);
    f["epicboxtxid"] = json!(txid);
    f["epicboxtxidsig"] = json!(from.sign(txid));
    f
}

async fn made(cx: &Ctx, ws: &mut Ws, k: &Key, slate: &Value) -> R {
    let id = slate["epicboxmsgid"].as_str().unwrap_or("").to_string();
    let r = call(ws, &json!({"type":"Made","address":k.pk,"signature":k.sign(&id),"epicboxmsgid":id,"ver":"3.0.0"}))
        .await?;
    ensure!(is_ok(&r), "expected Made Ok, got {}", j(&r));
    cx.paid(Side::This, k);
    Ok(())
}

async fn slate(ws: &mut Ws, secs: f64) -> Result<Value, E> {
    until(ws, "Slate", secs).await
}

const MUX: &[&str] = &["mux/1"];
const MUX_ALL: &[&str] = &["mux/1", "txcancel/1", "epicbox-cancel/1", "epicbox-attach/1"];

/// A socket that has offered mux/1 (and more): the socket, its mux challenge and the Ok.
async fn mux_open(t: &Target, ext: &[&str]) -> Result<(Ws, String, Value), E> {
    let (mut ws, _) = conn(t).await?;
    let ok = call(
        &mut ws,
        &json!({"type":"ClientDetails","wallet_version":"conformance","wallet_mode":"listener","protocol_version":"3.0.0","ext":ext}),
    )
    .await?;
    ensure!(is_ok(&ok) && ok["challenge"].is_string(), "expected Ok with a mux challenge, got {}", j(&ok));
    let ch = ok["challenge"].as_str().unwrap().to_string();
    Ok((ws, ch, ok))
}

fn entry(k: &Key, ch: &str) -> Value {
    json!({"address":k.pk,"signature":k.sign(ch)})
}

async fn attach(ws: &mut Ws, r: &str, entries: Vec<Value>) -> Result<Value, E> {
    call(ws, &json!({"type":"Attach","ref":r,"mailboxes":entries})).await
}

async fn attach_ok(ws: &mut Ws, ch: &str, keys: &[&Key]) -> Result<Value, E> {
    let r = attach(ws, "a1", keys.iter().map(|k| entry(k, ch)).collect()).await?;
    ensure!(r["type"] == "Attached", "expected Attached, got {}", j(&r));
    for (i, k) in keys.iter().enumerate() {
        let m = &r["mailboxes"][i];
        ensure!(m["ok"] == true && m["mailbox"] == k.pk.as_str(), "expected mailbox {i} ok, got {}", j(m));
    }
    Ok(r)
}

async fn mail(ws: &mut Ws, secs: f64) -> Result<Value, E> {
    until(ws, "Mail", secs).await
}

async fn ack(cx: &Ctx, ws: &mut Ws, k: &Key, mail: &Value) -> R {
    let r = call(ws, &json!({"type":"Ack","ref":"k1","ids":[mail["id"]]})).await?;
    ensure!(r == json!({"type":"Ok","ref":"k1"}), "expected Ok for the Ack, got {}", j(&r));
    cx.paid(Side::This, k);
    Ok(())
}

/// Remove what is waiting for a key: Subscribe, Made everything until nothing more comes.
async fn drain_key(t: &Target, k: &Key) -> usize {
    let Ok((mut ws, ch)) = conn(t).await else { return 0 };
    let mut n = 0;
    if send(&mut ws, &json!({"type":"Subscribe","address":k.pk,"ver":"3.0.0","signature":k.sign(&ch)})).await.is_err() {
        return 0;
    }
    while let Frame::Json(v) = next_frame(&mut ws, Duration::from_millis(1500)).await {
        if v["type"] == "Slate" {
            let id = v["epicboxmsgid"].as_str().unwrap_or("").to_string();
            let m = json!({"type":"Made","address":k.pk,"signature":k.sign(&id),"epicboxmsgid":id,"ver":"3.0.0"});
            if send(&mut ws, &m).await.is_err() {
                break;
            }
            n += 1;
        }
    }
    n
}

async fn cleanup(cx: &Ctx) -> usize {
    let todo: Vec<(Side, Key)> = {
        let mut m = cx.owed.lock().unwrap();
        let v = m.values().filter(|e| e.2 > 0).map(|e| (e.0, e.1.clone())).collect();
        m.clear();
        v
    };
    let mut n = 0;
    for (side, k) in todo {
        n += drain_key(cx.target(side), &k).await;
    }
    n
}

// ---------------------------------------------------------------------------------------------
// Classic 3.0.0

async fn classic_challenge_random(cx: Arc<Ctx>) -> R {
    let (_a, c1) = conn(&cx.t).await?;
    let (_b, c2) = conn(&cx.t).await?;
    ensure!(c1.len() == 32 && c2.len() == 32, "expected two 32-character challenges, got {c1:?} and {c2:?}");
    ensure!(c1 != c2 && c1 != STATIC && c2 != STATIC, "expected two different random challenges, got {c1} and {c2}");
    Ok(())
}

async fn classic_fixed_challenge_refused(cx: Arc<Ctx>) -> R {
    let k = Key::new();
    for ver in [Some("3.0.0"), None] {
        let (mut ws, _) = conn(&cx.t).await?;
        let mut f = json!({"type":"Subscribe","address":k.pk,"signature":k.sign(STATIC)});
        if let Some(v) = ver {
            f["ver"] = json!(v);
        }
        tx(&mut ws, &f).await?;
        let r = answer(&mut ws, T).await;
        ensure!(
            matches!(&r, Frame::Json(v) if v["type"] == "Error"),
            "expected Error for a Subscribe over the fixed challenge (ver {ver:?}), got {}",
            r.label()
        );
    }
    Ok(())
}

async fn classic_bad_json_closes(cx: Arc<Ctx>) -> R {
    let (mut ws, _) = conn(&cx.t).await?;
    ws.send(Message::Text("{oops".into())).await.ok();
    let r = next_frame(&mut ws, T).await;
    ensure!(matches!(r, Frame::Closed(Some(3000))), "expected close 3000, got {}", r.label());
    Ok(())
}

async fn classic_subscribe_post_made(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut b, ch) = conn(&cx.t).await?;
    sub_ok(&mut b, &bob, &ch, "3.0.0").await?;
    let (mut a, _) = conn(&cx.t).await?;
    let sent = post_ok(&cx, &mut a, &alice, &bob, "conf-1").await?;
    ensure!(sent.get("epicboxtxid").is_none(), "expected a plain Ok for a post without txid, got {}", j(&sent));
    let s = slate(&mut b, 8.0).await?;
    ensure!(s["from"] == alice.at(cx.d()).as_str(), "expected from {}, got {}", alice.at(cx.d()), j(&s["from"]));
    for f in ["str", "signature", "epicboxmsgid"] {
        ensure!(s[f].is_string(), "expected Slate field {f}, got {}", j(&s));
    }
    let id = s["epicboxmsgid"].as_str().unwrap().to_string();
    let r = call(
        &mut b,
        &json!({"type":"Made","address":bob.pk,"signature":alice.sign(&id),"epicboxmsgid":id,"ver":"3.0.0"}),
    )
    .await?;
    want_error(&r, "InvalidSignature", "Invalid signature.")?;
    made(&cx, &mut b, &bob, &s).await
}

async fn classic_waiting_on_subscribe(cx: Arc<Ctx>) -> R {
    let (alice, carol) = (Key::new(), Key::new());
    let (mut a, _) = conn(&cx.t).await?;
    post_ok(&cx, &mut a, &alice, &carol, "conf-offline").await?;
    let (mut c, ch) = conn(&cx.t).await?;
    let s = sub_get(&mut c, &carol, &ch).await?;
    made(&cx, &mut c, &carol, &s).await
}

async fn classic_lease_redelivery(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut p, _) = conn(&cx.t).await?;
    post_ok(&cx, &mut p, &alice, &bob, "conf-lease").await?;
    let (mut a, cha) = conn(&cx.t).await?;
    let first = sub_get(&mut a, &bob, &cha).await?;
    let (mut b, chb) = conn(&cx.t).await?;
    sub_ok(&mut b, &bob, &chb, "3.0.0").await?;
    // While the first socket holds the message, the second gets nothing.
    if let Err(E::Fail(m)) = quiet(&mut b, 1.5).await {
        return Err(E::Fail(format!("expected no Slate while it is leased to another socket, {m}")));
    }
    drop(a);
    let again = loop_resubscribe(&mut b, &bob, &chb).await?;
    ensure!(
        again["epicboxmsgid"] == first["epicboxmsgid"],
        "expected the same message again after the first socket closed, got {}",
        j(&again)
    );
    made(&cx, &mut b, &bob, &again).await
}

/// Subscribe again and wait for the Slate (it may also arrive on its own once the lease ends).
async fn loop_resubscribe(ws: &mut Ws, k: &Key, ch: &str) -> Result<Value, E> {
    tx(ws, &json!({"type":"Subscribe","address":k.pk,"ver":"3.0.0","signature":k.sign(ch)})).await?;
    slate(ws, 8.0).await
}

async fn classic_step_aside(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut p, _) = conn(&cx.t).await?;
    post_ok(&cx, &mut p, &alice, &bob, "conf-step-1").await?;
    post_ok(&cx, &mut p, &alice, &bob, "conf-step-2").await?;
    // A wallet that cannot decrypt the oldest slate drops the socket without Made and reconnects:
    // three times it is offered the same message.
    let mut first = String::new();
    for i in 0..3 {
        let (mut s, ch) = conn(&cx.t).await?;
        let sl = sub_get(&mut s, &bob, &ch).await?;
        let id = sl["epicboxmsgid"].as_str().unwrap_or("").to_string();
        ensure!(i == 0 || id == first, "expected the oldest message again on socket {}, got another", i + 1);
        first = id;
        drop(s);
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let (mut s, ch) = conn(&cx.t).await?;
    let other = sub_get(&mut s, &bob, &ch).await?;
    ensure!(other["epicboxmsgid"] != first.as_str(), "expected the other message after three offers, got the same one");
    made(&cx, &mut s, &bob, &other).await?;
    let (mut s2, ch2) = conn(&cx.t).await?;
    let last = sub_get(&mut s2, &bob, &ch2).await?;
    ensure!(
        last["epicboxmsgid"] == first.as_str(),
        "expected the first message once the other was made, got {}",
        j(&last)
    );
    made(&cx, &mut s2, &bob, &last).await
}

/// Close after 3 ignored challenges. Slow: three challenge intervals.
async fn classic_watchdog(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut p, _) = conn(&cx.t).await?;
    post_ok(&cx, &mut p, &alice, &bob, "conf-watchdog").await?;
    let (mut s, ch) = conn(&cx.t).await?;
    let sl = sub_get(&mut s, &bob, &ch).await?;
    // Ignore every challenge. Learn the interval from the second one.
    let t0 = Instant::now();
    let mut seen = 0;
    let mut interval = 0.0f64;
    loop {
        let limit = if interval > 0.0 { interval * 5.0 + 10.0 } else { 130.0 };
        let left = Duration::from_secs_f64(limit).saturating_sub(t0.elapsed());
        match next_frame(&mut s, left).await {
            Frame::Json(v) if v["type"] == "Challenge" => {
                seen += 1;
                if seen == 1 {
                    interval = t0.elapsed().as_secs_f64();
                }
            }
            Frame::Closed(Some(1001)) => {
                ensure!(seen >= 3, "expected close 1001 after 3 ignored challenges, got it after {seen}");
                break;
            }
            f => {
                return Err(E::Fail(format!(
                    "expected close 1001 after 3 ignored challenges, got {} after {seen} challenges in {:.0} s",
                    f.label(),
                    t0.elapsed().as_secs_f64()
                )))
            }
        }
    }
    let _ = sl;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// 3.1.0

async fn v310_getversion(cx: Arc<Ctx>) -> R {
    let (mut ws, _) = conn(&cx.t).await?;
    let v = call(&mut ws, &json!({"type":"GetVersion"})).await?;
    ensure!(v["str"] == "3.1.0", "expected GetVersion 3.1.0, got {}", j(&v));
    let v = call(&mut ws, &json!({"type":"GetVersion","str":"3.1.0"})).await?;
    ensure!(v["str"] == "3.1.0", "expected GetVersion 3.1.0 for a 3.1.0 client, got {}", j(&v));
    Ok(())
}

async fn v310_fields_both_or_neither(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut a, _) = conn(&cx.t).await?;
    let id = txid();
    let r = call(&mut a, &post_tx(&alice, cx.d(), &bob, cx.d(), "conf-both", &id)).await?;
    ensure!(is_ok(&r) && r["epicboxtxid"] == id.as_str(), "expected Ok echoing the txid, got {}", j(&r));
    cx.owe(Side::This, &bob);
    let mut only_id = post_frame(&alice, cx.d(), &bob, cx.d(), "conf-id");
    only_id["epicboxtxid"] = json!(txid());
    let r = call(&mut a, &only_id).await?;
    ensure!(r["type"] == "Error", "expected Error for a txid without epicboxtxidsig, got {}", j(&r));
    let mut only_sig = post_frame(&alice, cx.d(), &bob, cx.d(), "conf-sig");
    only_sig["epicboxtxidsig"] = json!(alice.sign("x"));
    let r = call(&mut a, &only_sig).await?;
    ensure!(r["type"] == "Error", "expected Error for epicboxtxidsig without a txid, got {}", j(&r));
    let r = post_raw(&mut a, &alice, cx.d(), &bob, cx.d(), "conf-neither").await?;
    ensure!(is_ok(&r), "expected Ok for a post with neither field, got {}", j(&r));
    cx.owe(Side::This, &bob);
    Ok(())
}

/// A pair that has posted under a txid, and the sender's socket.
async fn tx_pair(cx: &Ctx) -> Result<(Key, Key, String, Ws), E> {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut a, _) = conn(&cx.t).await?;
    let id = txid();
    let r = call(&mut a, &post_tx(&alice, cx.d(), &bob, cx.d(), "conf-tx", &id)).await?;
    ensure!(is_ok(&r), "expected Ok for a post with txid, got {}", j(&r));
    cx.owe(Side::This, &bob);
    Ok((alice, bob, id, a))
}

fn cancel_frame(k: &Key, id: &str, signed: &str) -> Value {
    json!({"type":"CancelTx","address":k.pk,"epicboxtxid":id,"signature":k.sign(signed)})
}

async fn v310_cancel(cx: Arc<Ctx>) -> R {
    let (alice, bob, id, mut a) = tx_pair(&cx).await?;
    let mallory = Key::new();
    let r = call(&mut a, &cancel_frame(&mallory, &id, &id)).await?;
    ensure!(r == json!({"type":"Ok"}), "expected a plain Ok for a stranger's CancelTx, got {}", j(&r));
    let r = call(&mut a, &cancel_frame(&alice, &txid(), "x")).await?;
    ensure!(r["type"] == "Error" && r["kind"] == "InvalidSignature", "expected InvalidSignature, got {}", j(&r));
    let other = txid();
    let r = call(&mut a, &cancel_frame(&alice, &other, &other)).await?;
    ensure!(r == json!({"type":"Ok"}), "expected a plain Ok for an unknown txid, got {}", j(&r));
    let wrong = json!({"type":"CancelTx","address":alice.pk,"epicboxtxid":id,"signature":mallory.sign(&id)});
    let r = call(&mut a, &wrong).await?;
    ensure!(
        r["type"] == "Error" && r["kind"] == "InvalidSignature",
        "expected InvalidSignature for another key's signature, got {}",
        j(&r)
    );
    let want = json!({"type":"TransactionCancelled","epicboxtxid":id});
    let r = call(&mut a, &cancel_frame(&alice, &id, &id)).await?;
    ensure!(r == want, "expected TransactionCancelled, got {}", j(&r));
    let r = call(&mut a, &cancel_frame(&alice, &id, &format!("epicbox-cancel/1:{id}"))).await?;
    ensure!(r == want, "expected TransactionCancelled when asked again (epicbox-cancel/1 form), got {}", j(&r));
    // The receiver learns of it on Subscribe, not the Slate.
    let (mut b, ch) = conn(&cx.t).await?;
    tx(&mut b, &json!({"type":"Subscribe","address":bob.pk,"ver":"3.1.0","signature":bob.sign(&ch)})).await?;
    let got = until(&mut b, "TransactionCancelled", 8.0).await?;
    ensure!(got["epicboxtxid"] == id.as_str(), "expected TransactionCancelled for {id} on Subscribe, got {}", j(&got));
    Ok(())
}

async fn v310_post_after_cancel(cx: Arc<Ctx>) -> R {
    let (alice, bob, id, mut a) = tx_pair(&cx).await?;
    let r = call(&mut a, &cancel_frame(&alice, &id, &id)).await?;
    ensure!(r["type"] == "TransactionCancelled", "expected TransactionCancelled, got {}", j(&r));
    let r = call(&mut a, &post_tx(&alice, cx.d(), &bob, cx.d(), "conf-after", &id)).await?;
    ensure!(
        r == json!({"type":"TransactionCancelled","epicboxtxid":id}),
        "expected TransactionCancelled for a post after the cancel, got {}",
        j(&r)
    );
    Ok(())
}

async fn v310_non_participant(cx: Arc<Ctx>) -> R {
    let (_alice, bob, id, _a) = tx_pair(&cx).await?;
    let mallory = Key::new();
    let (mut m, _) = conn(&cx.t).await?;
    let r = call(&mut m, &post_tx(&mallory, cx.d(), &bob, cx.d(), "conf-stranger", &id)).await?;
    want_error(&r, "InvalidRequest", "Posting address is not a participant of epicboxtxid.")
}

async fn v310_cancel_ext(cx: Arc<Ctx>) -> R {
    let details = |ext: Value| json!({"type":"ClientDetails","wallet_version":"conformance","wallet_mode":"listener","protocol_version":"3.1.0","ext":ext});
    let (mut ws, _) = conn(&cx.t).await?;
    let r = call(&mut ws, &details(json!(["epicbox-cancel/1"]))).await?;
    ensure!(
        r == json!({"type":"Ok","ext":["epicbox-cancel/1"]}),
        "expected Ok with ext [epicbox-cancel/1], got {}",
        j(&r)
    );
    let (mut ws, _) = conn(&cx.t).await?;
    let r = call(&mut ws, &details(json!([]))).await?;
    ensure!(r == json!({"type":"Ok"}), "expected a plain Ok without an offer, got {}", j(&r));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// mux/1

async fn mux_ok_limits(cx: Arc<Ctx>) -> R {
    let (_ws, ch, ok) = mux_open(&cx.t, MUX).await?;
    ensure!(ok["ext"] == json!(["mux/1"]), "expected ext [mux/1], got {}", j(&ok));
    ensure!(ch.len() == 22, "expected a 22-character challenge, got {ch:?}");
    let want = json!({"attach_per_frame":64,"mailboxes_per_socket":256,"inflight_per_socket":32,"hold_max_s":3600});
    ensure!(ok["limits"] == want, "expected limits {want}, got {}", j(&ok["limits"]));
    let (_ws, _, ok) = mux_open(&cx.t, MUX_ALL).await?;
    let ext = ok["ext"].as_array().cloned().unwrap_or_default();
    for e in MUX_ALL {
        ensure!(ext.iter().any(|x| x == e), "expected {e} echoed in ext, got {}", j(&ok["ext"]));
    }
    Ok(())
}

async fn mux_attach_waiting(cx: Arc<Ctx>) -> R {
    let (alice, carol) = (Key::new(), Key::new());
    let (mut p, _) = conn(&cx.t).await?;
    post_ok(&cx, &mut p, &alice, &carol, "conf-mux-waiting").await?;
    let (mut m, ch, _) = mux_open(&cx.t, MUX).await?;
    let at = attach_ok(&mut m, &ch, &[&carol]).await?;
    ensure!(at["mailboxes"][0]["waiting"] == 1, "expected waiting 1 in Attached, got {}", j(&at));
    ensure!(
        at["ref"] == "a1" && at["token"].is_string() && at["token_expires"].is_number(),
        "expected ref, token and token_expires, got {}",
        j(&at)
    );
    let ml = mail(&mut m, 8.0).await?;
    ack(&cx, &mut m, &carol, &ml).await
}

async fn mux_mail_push_ack(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut m, ch, _) = mux_open(&cx.t, MUX).await?;
    attach_ok(&mut m, &ch, &[&bob]).await?;
    let (mut p, _) = conn(&cx.t).await?;
    post_ok(&cx, &mut p, &alice, &bob, "conf-mux-push").await?;
    let ml = mail(&mut m, 8.0).await?;
    ensure!(
        ml["mailbox"] == bob.pk.as_str() && ml["from"] == alice.at(cx.d()).as_str(),
        "expected Mail for {} from {}, got {}",
        bob.pk,
        alice.at(cx.d()),
        j(&ml)
    );
    for f in ["id", "str", "signature"] {
        ensure!(ml[f].is_string(), "expected Mail field {f}, got {}", j(&ml));
    }
    ensure!(ml["created"].is_number() || ml["created"].is_string(), "expected Mail field created, got {}", j(&ml));
    ensure!(ml.get("epicboxtxid").is_none(), "expected no epicboxtxid without txcancel/1, got {}", j(&ml));
    ack(&cx, &mut m, &bob, &ml).await
}

async fn mux_waiting(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut m, ch, _) = mux_open(&cx.t, MUX).await?;
    attach_ok(&mut m, &ch, &[&bob]).await?;
    let r = call(&mut m, &json!({"type":"Waiting","ref":"w0"})).await?;
    ensure!(
        r == json!({"type":"Ok","ref":"w0","waiting":{bob.pk.clone():0},"inflight":0,"held":0}),
        "expected an empty Waiting reply, got {}",
        j(&r)
    );
    let (mut p, _) = conn(&cx.t).await?;
    post_ok(&cx, &mut p, &alice, &bob, "conf-waiting").await?;
    let ml = mail(&mut m, 8.0).await?;
    let r = call(&mut m, &json!({"type":"Waiting","ref":"w1"})).await?;
    ensure!(
        r["waiting"][&bob.pk] == 0 && r["inflight"] == 1 && r["held"] == 0,
        "expected waiting 0 inflight 1 held 0, got {}",
        j(&r)
    );
    ack(&cx, &mut m, &bob, &ml).await
}

async fn mux_hold(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut m, ch, _) = mux_open(&cx.t, MUX).await?;
    attach_ok(&mut m, &ch, &[&bob]).await?;
    let (mut p, _) = conn(&cx.t).await?;
    post_ok(&cx, &mut p, &alice, &bob, "conf-hold").await?;
    let first = mail(&mut m, 8.0).await?;
    let r = call(&mut m, &json!({"type":"Hold","ref":"h0","id":"no-such-id","seconds":1})).await?;
    want_code(&r, "unknown_id")?;
    let t0 = Instant::now();
    let r = call(&mut m, &json!({"type":"Hold","ref":"h1","id":first["id"],"seconds":2})).await?;
    ensure!(r == json!({"type":"Ok","ref":"h1"}), "expected Ok for the Hold, got {}", j(&r));
    let w = call(&mut m, &json!({"type":"Waiting","ref":"w1"})).await?;
    ensure!(w["held"] == 1 && w["inflight"] == 0, "expected held 1 inflight 0, got {}", j(&w));
    let again = mail(&mut m, 10.0).await?;
    ensure!(again["id"] == first["id"], "expected the held Mail again, got {}", j(&again));
    ensure!(
        t0.elapsed() >= Duration::from_millis(1500),
        "expected the Mail to wait out the hold, got it after {}",
        ms(t0)
    );
    ack(&cx, &mut m, &bob, &again).await
}

async fn mux_resume_token(cx: Arc<Ctx>) -> R {
    let bob = Key::new();
    let (mut m, ch, _) = mux_open(&cx.t, MUX).await?;
    let at = attach_ok(&mut m, &ch, &[&bob]).await?;
    let token = at["token"].as_str().unwrap_or("").to_string();
    drop(m);
    let (mut m2, _, _) = mux_open(&cx.t, MUX).await?;
    let r = call(&mut m2, &json!({"type":"Resume","ref":"r1","token":token})).await?;
    ensure!(
        r["type"] == "Attached" && r["mailboxes"][0]["mailbox"] == bob.pk.as_str() && r["mailboxes"][0]["ok"] == true,
        "expected Attached for the token, got {}",
        j(&r)
    );
    let (mut m3, _, _) = mux_open(&cx.t, MUX).await?;
    let r = call(&mut m3, &json!({"type":"Resume","ref":"r2","token":token})).await?;
    want_code(&r, "token_unknown")?;
    ensure!(r["kind"] == "InvalidChallenge", "expected kind InvalidChallenge, got {}", j(&r));
    Ok(())
}

async fn mux_replaced(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut m1, ch1, _) = mux_open(&cx.t, MUX).await?;
    attach_ok(&mut m1, &ch1, &[&bob]).await?;
    let (mut m2, ch2, _) = mux_open(&cx.t, MUX).await?;
    attach_ok(&mut m2, &ch2, &[&bob]).await?;
    let d = until(&mut m1, "Detached", 8.0).await?;
    ensure!(d["mailbox"] == bob.pk.as_str() && d["reason"] == "replaced", "expected Detached replaced, got {}", j(&d));
    let (mut p, _) = conn(&cx.t).await?;
    post_ok(&cx, &mut p, &alice, &bob, "conf-replaced").await?;
    let ml = mail(&mut m2, 8.0).await?;
    ack(&cx, &mut m2, &bob, &ml).await
}

async fn mux_too_many_mailboxes(cx: Arc<Ctx>) -> R {
    let (mut m, ch, _) = mux_open(&cx.t, MUX).await?;
    let keys: Vec<Key> = (0..65).map(|_| Key::new()).collect();
    let r = attach(&mut m, "big", keys.iter().map(|k| entry(k, &ch)).collect()).await?;
    want_code(&r, "too_many_mailboxes")?;
    ensure!(r["kind"] == "TooManySubscriptions", "expected kind TooManySubscriptions, got {}", j(&r));
    Ok(())
}

async fn mux_attach_errors(cx: Arc<Ctx>) -> R {
    let (mut m, ch, _) = mux_open(&cx.t, MUX).await?;
    let (good, forged) = (Key::new(), Key::new());
    let r = attach(
        &mut m,
        "e1",
        vec![
            entry(&good, &ch),
            json!({"address":forged.pk,"signature":good.sign(&ch)}),
            json!({"address":"not-an-address","signature":good.sign(&ch)}),
        ],
    )
    .await?;
    let e = &r["mailboxes"];
    ensure!(
        r["type"] == "Attached" && e[0]["ok"] == true,
        "expected Attached with the first mailbox ok, got {}",
        j(&r)
    );
    ensure!(e[1]["ok"] == false && e[1]["code"] == "bad_signature", "expected bad_signature, got {}", j(&e[1]));
    ensure!(e[2]["ok"] == false && e[2]["code"] == "bad_address", "expected bad_address, got {}", j(&e[2]));
    Ok(())
}

async fn mux_wrong_host(cx: Arc<Ctx>) -> R {
    let (mut m, ch, _) = mux_open(&cx.t, MUX_ALL).await?;
    let (gina, ivan) = (Key::new(), Key::new());
    let d = cx.d();
    let r = attach(
        &mut m,
        "h1",
        vec![
            json!({"address":gina.pk,"host":d,"signature":gina.sign(&format!("epicbox-attach/1:{d}:{ch}"))}),
            json!({"address":ivan.pk,"host":"other.example","signature":ivan.sign(&format!("epicbox-attach/1:other.example:{ch}"))}),
        ],
    )
    .await?;
    let e = &r["mailboxes"];
    ensure!(r["type"] == "Attached" && e[0]["ok"] == true, "expected the host-bound entry ok, got {}", j(&r));
    ensure!(
        e[1]["ok"] == false && e[1]["code"] == "wrong_host",
        "expected wrong_host for another host, got {}",
        j(&e[1])
    );
    Ok(())
}

async fn mux_epicbox_cancel(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    let (mut m, _, _) = mux_open(&cx.t, MUX_ALL).await?;
    let id = txid();
    let mut f = post_tx(&alice, cx.d(), &bob, cx.d(), "conf-mux-cancel", &id);
    f["ref"] = json!("p1");
    let r = call(&mut m, &f).await?;
    ensure!(
        r["type"] == "Ok" && r["ref"] == "p1" && r["epicboxtxid"] == id.as_str(),
        "expected Ok with ref and txid, got {}",
        j(&r)
    );
    cx.owe(Side::This, &bob);
    let bad = json!({"type":"CancelTx","ref":"c0","address":alice.pk,"epicboxtxid":id,"signature":bob.sign(&format!("epicbox-cancel/1:{id}"))});
    let r = call(&mut m, &bad).await?;
    want_code(&r, "bad_signature")?;
    let none = json!({"type":"CancelTx","ref":"c0","address":alice.pk,"signature":"00"});
    let r = call(&mut m, &none).await?;
    want_code(&r, "bad_request")?;
    let good = json!({"type":"CancelTx","ref":"c1","address":alice.pk,"epicboxtxid":id,"signature":alice.sign(&format!("epicbox-cancel/1:{id}"))});
    let r = call(&mut m, &good).await?;
    ensure!(
        r == json!({"type":"TransactionCancelled","ref":"c1","epicboxtxid":id}),
        "expected TransactionCancelled with the ref, got {}",
        j(&r)
    );
    let mut f = post_tx(&alice, cx.d(), &bob, cx.d(), "conf-mux-after", &id);
    f["ref"] = json!("p2");
    let r = call(&mut m, &f).await?;
    want_code(&r, "post_refused")?;
    ensure!(
        r["description"] == "Transaction was cancelled.",
        "expected description \"Transaction was cancelled.\", got {}",
        j(&r)
    );
    Ok(())
}

async fn mux_txcancel(cx: Arc<Ctx>) -> R {
    let (alice, bob) = (Key::new(), Key::new());
    // Without txcancel/1 the cancel frames are unknown.
    let (mut plain, _, _) = mux_open(&cx.t, MUX).await?;
    let r = call(&mut plain, &json!({"type":"CancelAck","ref":"x","mailbox":bob.pk,"epicboxtxid":txid()})).await?;
    want_code(&r, "unknown_type")?;
    let (mut m, ch, _) = mux_open(&cx.t, MUX_ALL).await?;
    attach_ok(&mut m, &ch, &[&bob]).await?;
    let (mut p, _) = conn(&cx.t).await?;
    let id = txid();
    let r = call(&mut p, &post_tx(&alice, cx.d(), &bob, cx.d(), "conf-txcancel", &id)).await?;
    ensure!(is_ok(&r), "expected Ok for the post, got {}", j(&r));
    cx.owe(Side::This, &bob);
    let ml = mail(&mut m, 8.0).await?;
    ensure!(ml["epicboxtxid"] == id.as_str(), "expected the Mail to carry epicboxtxid {id}, got {}", j(&ml));
    let r = call(&mut p, &cancel_frame(&alice, &id, &id)).await?;
    ensure!(r["type"] == "TransactionCancelled", "expected TransactionCancelled, got {}", j(&r));
    let c = until(&mut m, "Cancelled", 8.0).await?;
    ensure!(
        c["mailbox"] == bob.pk.as_str() && c["epicboxtxid"] == id.as_str(),
        "expected Cancelled for {id}, got {}",
        j(&c)
    );
    // A new Attach for the same mailbox is told again, before any Mail.
    let (mut m2, ch2, _) = mux_open(&cx.t, MUX_ALL).await?;
    attach_ok(&mut m2, &ch2, &[&bob]).await?;
    let c = until(&mut m2, "Cancelled", 8.0).await?;
    ensure!(c["epicboxtxid"] == id.as_str(), "expected Cancelled again after Attach, got {}", j(&c));
    let r = call(&mut m2, &json!({"type":"CancelAck","ref":"ca","mailbox":bob.pk,"epicboxtxid":id})).await?;
    ensure!(r == json!({"type":"Ok","ref":"ca"}), "expected Ok for CancelAck, got {}", j(&r));
    Ok(())
}

async fn epic1_slot_push(cx: Arc<Ctx>) -> R {
    let (alice, slot) = (Key::new(), Key::new());
    let (mut m, ch, _) = mux_open(&cx.t, MUX_ALL).await?;
    attach_ok(&mut m, &ch, &[&slot]).await?;
    let (mut p, _) = conn(&cx.t).await?;
    let t0 = Instant::now();
    post_ok(&cx, &mut p, &alice, &slot, "conf-epic1").await?;
    let ml = mail(&mut m, 8.0).await?;
    ensure!(ml["mailbox"] == slot.pk.as_str(), "expected the push for the slot, got {}", j(&ml));
    ack(&cx, &mut m, &slot, &ml).await?;
    println!("      (epic1 push {})", ms(t0));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Refusal texts

async fn refuse(cx: &Ctx, f: &Value) -> Result<Value, E> {
    let (mut ws, _) = conn(&cx.t).await?;
    call(&mut ws, f).await
}

/// A signed slate body with a given destination JSON.
fn signed(from: &Key, from_d: &str, to: &Key, to_d: &str, body: &str) -> Value {
    json!({"type":"PostSlate","from":from.at(from_d),"to":to.at(to_d),"str":body,"signature":from.sign(body)})
}

async fn refusal_too_large(cx: Arc<Ctx>) -> R {
    let (a, b) = (Key::new(), Key::new());
    let body = "x".repeat(131_073);
    let r = refuse(&cx, &signed(&a, cx.d(), &b, cx.d(), &body)).await?;
    want_error(&r, "InvalidRequest", "Slate is larger than 131072 bytes.")
}

async fn refusal_missing_fields(cx: Arc<Ctx>) -> R {
    let (a, b) = (Key::new(), Key::new());
    let mut f = post_frame(&a, cx.d(), &b, cx.d(), "x");
    f.as_object_mut().unwrap().remove("to");
    want_error(&refuse(&cx, &f).await?, "InvalidRequest", MISSING_FIELDS)?;
    let mut f = post_frame(&a, cx.d(), &b, cx.d(), "x");
    f["epicboxtxid"] = json!(txid());
    want_error(&refuse(&cx, &f).await?, "InvalidRequest", MISSING_FIELDS)?;
    let mut f = post_frame(&a, cx.d(), &b, cx.d(), "x");
    f["epicboxtxidsig"] = json!(a.sign("x"));
    want_error(&refuse(&cx, &f).await?, "InvalidRequest", MISSING_FIELDS)
}

async fn refusal_wrong_address(cx: Arc<Ctx>) -> R {
    let (a, b) = (Key::new(), Key::new());
    let mut f = post_frame(&a, cx.d(), &b, cx.d(), "x");
    f["from"] = json!("not-an-address");
    let to = f["to"].as_str().unwrap().to_string();
    want_error(
        &refuse(&cx, &f).await?,
        "InvalidRequest",
        &format!("Wrong address format. From: not-an-address, To: {to}"),
    )
}

async fn refusal_bad_post_signature(cx: Arc<Ctx>) -> R {
    let (a, b, mallory) = (Key::new(), Key::new(), Key::new());
    let mut f = post_frame(&a, cx.d(), &b, cx.d(), "x");
    f["signature"] = json!(mallory.sign(f["str"].as_str().unwrap()));
    want_error(&refuse(&cx, &f).await?, "InvalidRequest", "Error postslate signature.")
}

async fn refusal_bad_txid_signature(cx: Arc<Ctx>) -> R {
    let (a, b, mallory) = (Key::new(), Key::new(), Key::new());
    let id = txid();
    let mut f = post_tx(&a, cx.d(), &b, cx.d(), "x", &id);
    f["epicboxtxidsig"] = json!(mallory.sign(&id));
    want_error(&refuse(&cx, &f).await?, "InvalidSignature", "Invalid epicboxtxid signature.")
}

async fn refusal_invalid_payload(cx: Arc<Ctx>) -> R {
    let (a, b) = (Key::new(), Key::new());
    want_error(
        &refuse(&cx, &signed(&a, cx.d(), &b, cx.d(), "this is not json")).await?,
        "InvalidRequest",
        "Invalid Slate payload.",
    )
}

async fn refusal_invalid_destination(cx: Arc<Ctx>) -> R {
    let (a, b) = (Key::new(), Key::new());
    let none = json!({"encrypted_message":"x"}).to_string();
    want_error(
        &refuse(&cx, &signed(&a, cx.d(), &b, cx.d(), &none)).await?,
        "InvalidRequest",
        "Invalid slate destination.",
    )?;
    // A destination domain with no dot names no relay.
    let nodot =
        json!({"destination":{"public_key":b.pk,"domain":"nodot","port":443},"encrypted_message":"x"}).to_string();
    want_error(
        &refuse(&cx, &signed(&a, cx.d(), &b, cx.d(), &nodot)).await?,
        "InvalidRequest",
        "Invalid slate destination.",
    )
}

// ---------------------------------------------------------------------------------------------
// Federation

async fn fed_one_way(cx: &Ctx, from: Side, to: Side) -> R {
    if cx.other.is_none() {
        return skip("no other mailbox: pass --other HOST or --other-url and --other-domain");
    }
    let (ft, tt) = (cx.target(from), cx.target(to));
    let (alice, bob) = (Key::new(), Key::new());
    let (mut b, ch) = conn(tt).await?;
    sub_ok(&mut b, &bob, &ch, "3.0.0").await?;
    let (mut a, _) = conn(ft).await?;
    let r = post_raw(&mut a, &alice, &ft.domain, &bob, &tt.domain, "conf-fed").await?;
    ensure!(is_ok(&r), "expected {} to accept a post for {}, got {}", ft.name, tt.name, j(&r));
    cx.owe(to, &bob);
    let t0 = Instant::now();
    // The push is the expected way. A mailbox that only notices new mail on a Subscribe (the
    // ICP shim) is allowed to deliver by re-Subscribe on a fresh socket; the note says which.
    let mut how = "push";
    let s = match slate(&mut b, 20.0).await {
        Ok(s) => s,
        Err(E::Fail(_)) => {
            how = "re-Subscribe";
            let mut got = None;
            while t0.elapsed() < Duration::from_secs(300) {
                let (mut w, ch) = conn(tt).await?;
                let r = subscribe(&mut w, &bob, &ch, "3.0.0").await?;
                if r["type"] == "Slate" {
                    b = w;
                    got = Some(r);
                    break;
                }
                drop(w);
                if let Ok(s) = slate(&mut b, 25.0).await {
                    how = "push";
                    got = Some(s);
                    break;
                }
            }
            got.ok_or_else(|| {
                E::Fail(format!("{} -> {}: expected a Slate within 300 s, got nothing", ft.name, tt.name))
            })?
        }
        Err(e) => return Err(e),
    };
    println!("      (federation {} -> {} took {} by {how})", ft.name, tt.name, ms(t0));
    ensure!(
        s["from"] == alice.at(&ft.domain).as_str(),
        "expected from {}, got {}",
        alice.at(&ft.domain),
        j(&s["from"])
    );
    let id = s["epicboxmsgid"].as_str().unwrap_or("").to_string();
    let r = call(
        &mut b,
        &json!({"type":"Made","address":bob.pk,"signature":bob.sign(&id),"epicboxmsgid":id,"ver":"3.0.0"}),
    )
    .await?;
    ensure!(is_ok(&r), "expected Made Ok, got {}", j(&r));
    cx.paid(to, &bob);
    Ok(())
}

async fn fed_out(cx: Arc<Ctx>) -> R {
    fed_one_way(&cx, Side::This, Side::Other).await
}

async fn fed_in(cx: Arc<Ctx>) -> R {
    fed_one_way(&cx, Side::Other, Side::This).await
}

// ---------------------------------------------------------------------------------------------
// HTTP

async fn wk_fields(cx: Arc<Ctx>) -> R {
    let r = cx.t.http.once("GET", "/.well-known/epicbox.json", None).await?;
    ensure!(r.status == 200, "expected status 200, got {}", r.status);
    let v = r.json();
    for k in ["features", "federation", "identity", "name", "protocol_versions", "software"] {
        ensure!(
            v.get(k).is_some(),
            "expected field {k}, got keys {}",
            j(&json!(v.as_object().map(|o| o.keys().collect::<Vec<_>>())))
        );
    }
    ensure!(v["software"] == "epicmail", "expected software epicmail, got {}", j(&v["software"]));
    ensure!(
        v["protocol_versions"].to_string().contains("3.1.0"),
        "expected protocol_versions to hold 3.1.0, got {}",
        j(&v["protocol_versions"])
    );
    let lim = &v["features"]["mux/1"]["limits"];
    for k in [
        "attach_frames_per_min",
        "attach_per_frame",
        "hold_max_s",
        "ids_per_ack",
        "inflight_per_socket",
        "mailboxes_per_socket",
        "waiting_frames_per_min",
    ] {
        ensure!(lim.get(k).is_some(), "expected features[mux/1].limits.{k}, got {}", j(lim));
    }
    ensure!(
        v["features"]["epicbox-cancel/1"]["signed_text"] == "epicbox-cancel/1:<txid>",
        "expected signed_text epicbox-cancel/1:<txid>, got {}",
        j(&v["features"]["epicbox-cancel/1"])
    );
    ensure!(v["features"].get("txcancel/1").is_some(), "expected features[txcancel/1], got {}", j(&v["features"]));
    Ok(())
}

async fn http_metrics_private(cx: Arc<Ctx>) -> R {
    if cx.t.http.host == "127.0.0.1" || cx.t.http.host == "localhost" {
        // The relay serves /metrics to loopback peers without X-Forwarded-For.
        return skip("a local relay serves /metrics to loopback by design");
    }
    let r = cx.t.http.once("GET", "/metrics", None).await?;
    ensure!(r.status == 404, "expected status 404 for /metrics, got {}", r.status);
    Ok(())
}

async fn v1_info(cx: Arc<Ctx>) -> R {
    let r = cx.t.http.once("GET", "/v1/info", None).await?;
    ensure!(r.status == 200, "expected status 200, got {}", r.status);
    let v = r.json();
    for k in [
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
        "redeliver_after_seconds",
    ] {
        ensure!(v.get(k).is_some(), "expected /v1/info field {k}, got {}", j(&v));
    }
    Ok(())
}

async fn v1_post_pull_made(cx: Arc<Ctx>) -> R {
    let (alice, frank) = (Key::new(), Key::new());
    let h = &cx.t.http;
    let d = cx.d();
    let mut f = post_frame(&alice, d, &frank, d, "conf-v1");
    f.as_object_mut().unwrap().remove("type");
    let r = h.once("POST", "/v1/post", Some(&f)).await?;
    let id = r.json()["id"].as_str().unwrap_or("").to_string();
    ensure!(r.status == 200 && !id.is_empty(), "expected /v1/post to answer an id, got {} {}", r.status, j(&r.json()));
    cx.owe(Side::This, &frank);
    let pull = json!({"mailboxes":[ebh(&frank, d)],"wait":0});
    let r = h.once("POST", "/v1/pull", Some(&pull)).await?;
    ensure!(
        r.json()["mailboxes"][0]["messages"][0]["id"] == id.as_str(),
        "expected /v1/pull to return {id}, got {}",
        j(&r.json())
    );
    let made = json!({"address":frank.pk,"acks":[{"id":id,"signature":frank.sign(&id)}]});
    let r = h.once("POST", "/v1/made", Some(&made)).await?;
    ensure!(
        r.status == 200 && r.json()["removed"] == 1,
        "expected /v1/made removed 1, got {} {}",
        r.status,
        j(&r.json())
    );
    cx.paid(Side::This, &frank);
    Ok(())
}

async fn v1_proof_reuse(cx: Arc<Ctx>) -> R {
    let k = Key::new();
    let h = &cx.t.http;
    let pull = json!({"mailboxes":[ebh(&k, cx.d())],"wait":0});
    let r = h.once("POST", "/v1/pull", Some(&pull)).await?;
    ensure!(r.status == 200, "expected status 200 for a pull, got {}", r.status);
    let r = h.once("POST", "/v1/pull", Some(&pull)).await?;
    ensure!(
        r.json()["mailboxes"][0]["error"] == "challenge was already used",
        "expected error \"challenge was already used\", got {}",
        j(&r.json())
    );
    let other = json!({"mailboxes":[ebh(&k, "other.example")],"wait":0});
    let r = h.once("POST", "/v1/pull", Some(&other)).await?;
    ensure!(
        r.json()["mailboxes"][0]["error"] == "signature does not verify",
        "expected error \"signature does not verify\" for a proof for another domain, got {}",
        j(&r.json())
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Staging (a relay with small limits)

fn need_staging(cx: &Ctx) -> R {
    if cx.staging {
        Ok(())
    } else {
        skip("needs --staging on a relay with small limits")
    }
}

async fn staging_per_sender_cap(cx: Arc<Ctx>) -> R {
    need_staging(&cx)?;
    let (alice, bob) = (Key::new(), Key::new());
    let (mut a, _) = conn(&cx.t).await?;
    for i in 0..cx.sender_cap {
        post_ok(&cx, &mut a, &alice, &bob, &format!("conf-cap-{i}")).await?;
    }
    let r = post_raw(&mut a, &alice, cx.d(), &bob, cx.d(), "conf-cap-over").await?;
    want_error(&r, "InvalidRequest", "Too many messages from this sender are waiting for the recipient.")
}

async fn staging_queue_cap(cx: Arc<Ctx>) -> R {
    need_staging(&cx)?;
    let bob = Key::new();
    let mut left = cx.queue_cap;
    while left > 0 {
        let sender = Key::new();
        let (mut a, _) = conn(&cx.t).await?;
        for i in 0..left.min(cx.sender_cap) {
            post_ok(&cx, &mut a, &sender, &bob, &format!("conf-q-{i}")).await?;
            left -= 1;
        }
    }
    let (mut a, _) = conn(&cx.t).await?;
    let r = post_raw(&mut a, &Key::new(), cx.d(), &bob, cx.d(), "conf-q-over").await?;
    want_error(&r, "InvalidRequest", "Recipient mailbox is full; try again later.")
}

async fn staging_rate_limit(cx: Arc<Ctx>) -> R {
    need_staging(&cx)?;
    let alice = Key::new();
    let (mut a, _) = conn(&cx.t).await?;
    for i in 0..cx.post_burst + 5 {
        let to = Key::new();
        let r = post_raw(&mut a, &alice, cx.d(), &to, cx.d(), &format!("conf-rate-{i}")).await?;
        if is_ok(&r) {
            cx.owe(Side::This, &to);
            continue;
        }
        let d = r["description"].as_str().unwrap_or("");
        let secs = d.strip_prefix("Rate limit exceeded; retry in ").and_then(|s| s.strip_suffix(" s."));
        ensure!(
            r["kind"] == "InvalidRequest" && secs.is_some_and(|s| s.parse::<u64>().is_ok_and(|n| n > 0)),
            "expected \"Rate limit exceeded; retry in N s.\", got {}",
            j(&r)
        );
        ensure!(i >= cx.post_burst, "expected the limit after {} posts, got it after {i}", cx.post_burst);
        return Ok(());
    }
    Err(E::Fail(format!("expected a rate limit within {} posts, got none", cx.post_burst + 5)))
}

async fn staging_bad_signatures_close(cx: Arc<Ctx>) -> R {
    need_staging(&cx)?;
    let k = Key::new();
    let (mut ws, _) = conn(&cx.t).await?;
    let mut last = String::new();
    for _ in 0..10 {
        let f =
            json!({"type":"Subscribe","address":k.pk,"ver":"3.0.0","signature":Key::new().sign("not the challenge")});
        if tx(&mut ws, &f).await.is_err() {
            break;
        }
        match answer(&mut ws, T).await {
            Frame::Closed(Some(4003)) => return Ok(()),
            Frame::Json(v) if v["type"] == "Error" => {
                last = j(&v);
                if let Frame::Closed(c) = next_frame(&mut ws, Duration::from_millis(300)).await {
                    ensure!(c == Some(4003), "expected close 4003 after bad signatures, got {c:?}");
                    return Ok(());
                }
            }
            f => return Err(E::Fail(format!("expected close 4003 after 8 bad signatures, got {}", f.label()))),
        }
    }
    Err(E::Fail(format!("expected close 4003 after 8 bad signatures, last answer {last}")))
}

async fn staging_bad_attach_close(cx: Arc<Ctx>) -> R {
    need_staging(&cx)?;
    let (mut m, ch, _) = mux_open(&cx.t, MUX).await?;
    let victim = Key::new();
    let entries: Vec<Value> = (0..8).map(|_| json!({"address":victim.pk,"signature":Key::new().sign(&ch)})).collect();
    tx(&mut m, &json!({"type":"Attach","ref":"bad","mailboxes":entries})).await?;
    loop {
        match next_frame(&mut m, T).await {
            Frame::Closed(Some(4003)) => return Ok(()),
            Frame::Json(v) if v["type"] == "Attached" || v["type"] == "Challenge" => continue,
            f => return Err(E::Fail(format!("expected close 4003 after 8 bad Attach entries, got {}", f.label()))),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Registry and runner

macro_rules! case {
    ($id:expr, $slow:expr, $f:ident) => {{
        fn wrap(cx: Arc<Ctx>) -> BoxFut {
            Box::pin($f(cx))
        }
        ($id, $slow, wrap as CaseFn)
    }};
}

fn registry() -> Vec<(&'static str, bool, CaseFn)> {
    vec![
        case!("classic.challenge_random", false, classic_challenge_random),
        case!("classic.fixed_challenge_refused", false, classic_fixed_challenge_refused),
        case!("classic.bad_json_closes", false, classic_bad_json_closes),
        case!("classic.subscribe_post_made", false, classic_subscribe_post_made),
        case!("classic.waiting_on_subscribe", false, classic_waiting_on_subscribe),
        case!("classic.lease_redelivery", false, classic_lease_redelivery),
        case!("classic.step_aside", false, classic_step_aside),
        case!("classic.watchdog_three_missed", true, classic_watchdog),
        case!("v310.getversion", false, v310_getversion),
        case!("v310.fields_both_or_neither", false, v310_fields_both_or_neither),
        case!("v310.cancel_ext", false, v310_cancel_ext),
        case!("v310.cancel", false, v310_cancel),
        case!("v310.post_after_cancel", false, v310_post_after_cancel),
        case!("v310.non_participant", false, v310_non_participant),
        case!("mux.ok_limits", false, mux_ok_limits),
        case!("mux.attach_waiting", false, mux_attach_waiting),
        case!("mux.mail_push_ack", false, mux_mail_push_ack),
        case!("mux.waiting", false, mux_waiting),
        case!("mux.hold", false, mux_hold),
        case!("mux.resume_token", false, mux_resume_token),
        case!("mux.replaced", false, mux_replaced),
        case!("mux.too_many_mailboxes", false, mux_too_many_mailboxes),
        case!("mux.attach_errors", false, mux_attach_errors),
        case!("mux.wrong_host", false, mux_wrong_host),
        case!("mux.epicbox_cancel", false, mux_epicbox_cancel),
        case!("mux.txcancel", false, mux_txcancel),
        case!("epic1.slot_push", false, epic1_slot_push),
        case!("refusal.too_large", false, refusal_too_large),
        case!("refusal.missing_fields", false, refusal_missing_fields),
        case!("refusal.wrong_address", false, refusal_wrong_address),
        case!("refusal.bad_post_signature", false, refusal_bad_post_signature),
        case!("refusal.bad_txid_signature", false, refusal_bad_txid_signature),
        case!("refusal.invalid_payload", false, refusal_invalid_payload),
        case!("refusal.invalid_destination", false, refusal_invalid_destination),
        case!("fed.out", true, fed_out),
        case!("fed.in", true, fed_in),
        case!("http.wellknown_fields", false, wk_fields),
        case!("http.metrics_private", false, http_metrics_private),
        case!("v1.info", false, v1_info),
        case!("v1.post_pull_made", false, v1_post_pull_made),
        case!("v1.proof_reuse", false, v1_proof_reuse),
        case!("staging.per_sender_cap", false, staging_per_sender_cap),
        case!("staging.queue_cap", false, staging_queue_cap),
        case!("staging.rate_limit", false, staging_rate_limit),
        case!("staging.bad_signatures_close", false, staging_bad_signatures_close),
        case!("staging.bad_attach_close", false, staging_bad_attach_close),
    ]
}

#[derive(Clone)]
enum Res {
    Pass,
    Fail(String),
    Skip(String),
}

struct Done {
    id: &'static str,
    res: Res,
    ms: u128,
    cleaned: usize,
}

async fn run_one(sh: Arc<Shared>, id: &'static str, slow: bool, f: CaseFn) -> Done {
    let t0 = Instant::now();
    let cx = Arc::new(Ctx { sh, owed: Mutex::new(HashMap::new()) });
    let limit = Duration::from_secs(if slow { 900 } else { 120 });
    let res = match tokio::time::timeout(limit, f(cx.clone())).await {
        Err(_) => Res::Fail(format!("timed out after {} s", limit.as_secs())),
        Ok(Ok(())) => Res::Pass,
        Ok(Err(E::Fail(m))) => Res::Fail(m),
        Ok(Err(E::Skip(m))) => Res::Skip(m),
    };
    let cleaned = cleanup(&cx).await;
    Done { id, res, ms: t0.elapsed().as_millis(), cleaned }
}

fn expected_list(path: &Option<PathBuf>) -> anyhow::Result<Vec<String>> {
    let Some(p) = path else { return Ok(Vec::new()) };
    let text = std::fs::read_to_string(p)?;
    Ok(text.lines().map(|l| l.split('#').next().unwrap_or("").trim().to_string()).filter(|l| !l.is_empty()).collect())
}

fn show(d: &Done, listed: bool) {
    let note = if d.cleaned > 0 { format!("  [cleanup removed {}]", d.cleaned) } else { String::new() };
    match &d.res {
        Res::Pass if listed => println!("PASS  {}  UNEXPECTED PASS: listed in the expect-fail file{note}", d.id),
        Res::Pass => println!("PASS  {}  ({} ms){note}", d.id, d.ms),
        Res::Fail(m) if listed => println!("FAIL  {}  {m}  [expected]{note}", d.id),
        Res::Fail(m) => println!("FAIL  {}  {m}{note}", d.id),
        Res::Skip(m) => println!("SKIP  {}  {m}", d.id),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let t = match (&args.host, &args.url, &args.domain) {
        (Some(h), None, None) => Target::host(h)?,
        (None, Some(u), Some(d)) => Target::new(u, d)?,
        _ => anyhow::bail!("give a HOST, or --url and --domain"),
    };
    const EPICMAIL: &str = "epicmail.btlabs.uk";
    const ICP: &str = "icpepicbox.btlabs.uk";
    let other = match (&args.other, &args.other_url, &args.other_domain) {
        (Some(h), _, _) => Some(Target::host(h)?),
        (None, Some(u), Some(d)) => Some(Target::new(u, d)?),
        _ if t.name == EPICMAIL => Some(Target::host(ICP)?),
        _ if t.name == ICP => Some(Target::host(EPICMAIL)?),
        _ => None,
    };
    let expect = expected_list(&args.expect_fail)?;
    let reg = registry();
    let known: Vec<&str> = reg.iter().map(|c| c.0).collect();
    let mut problems = Vec::new();
    for e in &expect {
        if !known.contains(&e.as_str()) {
            problems.push(format!("expect-fail lists an unknown case: {e}"));
        }
    }
    let cx = Arc::new(Shared {
        t,
        other,
        staging: args.staging,
        queue_cap: args.queue_cap,
        sender_cap: args.sender_cap,
        post_burst: args.post_burst,
    });
    println!(
        "conformance: {} (other mailbox: {}){}",
        cx.t.name,
        cx.other.as_ref().map(|o| o.name.as_str()).unwrap_or("none"),
        if args.staging { ", staging" } else { "" }
    );
    let mut dones: Vec<Done> = Vec::new();
    let mut slow = Vec::new();
    let mut fast = Vec::new();
    for (id, is_slow, f) in reg {
        if !args.only.is_empty() && !args.only.iter().any(|o| id.contains(o.as_str())) {
            continue;
        }
        if is_slow && args.skip_slow {
            dones.push(Done { id, res: Res::Skip("slow case, --skip-slow".into()), ms: 0, cleaned: 0 });
            continue;
        }
        if is_slow {
            slow.push((id, f));
        } else {
            fast.push((id, f));
        }
    }
    // Slow cases run alongside the fast ones and are reported when they finish.
    let handles: Vec<_> = slow
        .into_iter()
        .map(|(id, f)| {
            let cx = cx.clone();
            tokio::spawn(async move { run_one(cx, id, true, f).await })
        })
        .collect();
    for (id, f) in fast {
        let d = run_one(cx.clone(), id, false, f).await;
        show(&d, expect.iter().any(|e| e == id));
        dones.push(d);
    }
    for h in handles {
        let d = h.await?;
        show(&d, expect.iter().any(|e| e == d.id));
        dones.push(d);
    }
    for d in dones.iter().filter(|d| matches!(&d.res, Res::Skip(m) if m.starts_with("slow"))) {
        show(d, false);
    }

    let listed = |id: &str| expect.iter().any(|e| e == id);
    let pass = dones.iter().filter(|d| matches!(d.res, Res::Pass)).count();
    let fail = dones.iter().filter(|d| matches!(d.res, Res::Fail(_))).count();
    let skipped = dones.iter().filter(|d| matches!(d.res, Res::Skip(_))).count();
    let expected_fail = dones.iter().filter(|d| matches!(d.res, Res::Fail(_)) && listed(d.id)).count();
    let unexpected_fail = fail - expected_fail;
    let unexpected_pass = dones.iter().filter(|d| matches!(d.res, Res::Pass) && listed(d.id)).count();
    let summary_line = format!(
        "SUMMARY {}: {} cases, {pass} pass, {fail} fail ({expected_fail} expected), {skipped} skip; {unexpected_fail} unexpected fail, {unexpected_pass} unexpected pass",
        cx.t.name,
        dones.len()
    );
    println!("{summary_line}");
    for p in &problems {
        println!("PROBLEM  {p}");
    }
    let path = args.summary.clone().unwrap_or_else(|| {
        PathBuf::from(format!("target/conformance/{}-{}.json", cx.t.name.replace([':', '/'], "_"), now_s()))
    });
    let cases: Vec<Value> = dones
        .iter()
        .map(|d| {
            let (r, detail) = match &d.res {
                Res::Pass => ("pass", String::new()),
                Res::Fail(m) => ("fail", m.clone()),
                Res::Skip(m) => ("skip", m.clone()),
            };
            json!({"id":d.id,"result":r,"detail":detail,"ms":d.ms,"expected_fail":listed(d.id),"cleaned":d.cleaned})
        })
        .collect();
    let doc = json!({
        "host": cx.t.name, "other": cx.other.as_ref().map(|o| o.name.clone()), "staging": args.staging,
        "time": now_s(), "summary": summary_line,
        "counts": {"pass":pass,"fail":fail,"expected_fail":expected_fail,"skip":skipped,"unexpected_fail":unexpected_fail,"unexpected_pass":unexpected_pass},
        "cases": cases,
    });
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    println!("summary file: {}", path.display());
    if unexpected_fail > 0 || unexpected_pass > 0 || !problems.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}
