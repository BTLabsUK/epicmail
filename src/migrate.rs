//! JSON Lines import and export, for moving queued messages between relays.
//!
//! The format is the one written by `tools/export-node-pg.py`: one JSON object per line, kind
//! `slate` or `forward`, times in unix seconds. The store itself uses milliseconds.

use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{Context, Result};
use rand::RngCore;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::address;
use crate::config::Config;
use crate::ids::{is_msgid, is_txid};
use crate::store::{ForwardKind, NewForward, NewMessage, PutOutcome, Store};

const MAX_ERRORS: usize = 100;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportError {
    pub line: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportStats {
    /// Slates stored.
    pub slates: u64,
    /// Forwards stored.
    pub forwards: u64,
    /// Lines already present in the store.
    pub duplicates: u64,
    /// Lines not imported: bad JSON, unknown kind, bad queue, expired.
    pub skipped: u64,
    pub expired: u64,
    /// First 100 problems with their line numbers.
    pub errors: Vec<ImportError>,
}

impl ImportStats {
    fn skip(&mut self, line: usize, reason: impl Into<String>) {
        self.skipped += 1;
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(ImportError { line, reason: reason.into() });
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Line {
    Slate(SlateLine),
    Forward(ForwardLine),
}

#[derive(Debug, Deserialize)]
struct SlateLine {
    queue: String,
    #[serde(default)]
    from: String,
    str: String,
    signature: String,
    #[serde(default)]
    challenge: String,
    #[serde(default)]
    messageid: Option<String>,
    created_at: i64,
    expires_at: i64,
    #[serde(default)]
    deliveries: i64,
    /// 3.1.0 transaction id and its signature; absent for legacy slates.
    #[serde(default)]
    epicboxtxid: Option<String>,
    #[serde(default)]
    epicboxtxidsig: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ForwardLine {
    target_host: String,
    target_port: u16,
    frame: String,
    #[serde(default)]
    attempts: i64,
    created_at: i64,
}

fn sender_key(from: &str) -> String {
    let s = from.strip_prefix("epicbox://").unwrap_or(from);
    s.split('@').next().unwrap_or("").to_string()
}

fn random_msgid() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn secs_to_ms(s: i64) -> Option<i64> {
    s.checked_mul(1000)
}

/// `domain:port` of the relay named in a `from` address, when that is not this relay.
fn sender_endpoint(cfg: &Config, from: &str) -> Option<String> {
    let a = address::parse_address(from).ok()?;
    let domain = a.domain?.to_ascii_lowercase();
    let port = a.port.unwrap_or(443);
    (!cfg.is_local(&domain, port)).then(|| format!("{domain}:{port}"))
}

/// A queued forward is a CancelTx when its frame is one; anything else is a PostSlate.
fn forward_kind(frame: &str) -> ForwardKind {
    let ty = serde_json::from_str::<serde_json::Value>(frame)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_ascii_lowercase));
    if ty.as_deref() == Some("canceltx") {
        ForwardKind::CancelTx
    } else {
        ForwardKind::PostSlate
    }
}

/// Reads JSON Lines from `input` into the store: `slate` lines become queued messages, `forward`
/// lines become forwards. Bad lines and lines already expired at `now_ms` are skipped and counted.
pub async fn import_jsonl<R: BufRead>(store: &dyn Store, cfg: &Config, input: R, now_ms: i64) -> Result<ImportStats> {
    let mut st = ImportStats::default();
    let recipient_suffix = if cfg.server.port == 443 {
        cfg.server.domain.clone()
    } else {
        format!("{}:{}", cfg.server.domain, cfg.server.port)
    };
    for (i, line) in input.lines().enumerate() {
        let n = i + 1;
        let line = line.with_context(|| format!("reading line {n}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Line = match serde_json::from_str(&line) {
            Ok(l) => l,
            Err(e) => {
                st.skip(n, format!("bad line: {e}"));
                continue;
            }
        };
        match parsed {
            Line::Slate(s) => {
                if address::parse_address(&s.queue).is_err() || s.queue.len() != 52 {
                    st.skip(n, "queue is not a valid address key");
                    continue;
                }
                let (Some(created), Some(expires)) = (secs_to_ms(s.created_at), secs_to_ms(s.expires_at)) else {
                    st.skip(n, "time out of range");
                    continue;
                };
                if expires <= now_ms {
                    st.expired += 1;
                    st.skip(n, "expired");
                    continue;
                }
                // Wallets can only acknowledge ids of the form they accept; any other id would
                // sit until it expires.
                let msgid = match s.messageid {
                    Some(m) if is_msgid(&m) => m,
                    _ => random_msgid(),
                };
                let (txid, txidsig) = match (s.epicboxtxid, s.epicboxtxidsig) {
                    (None, None) => (None, None),
                    (Some(t), Some(ts)) if is_txid(&t) => (Some(t), Some(ts)),
                    _ => {
                        st.skip(n, "epicboxtxid and epicboxtxidsig must both be valid or both absent");
                        continue;
                    }
                };
                // As for a posted slate: the sender's relay, when it is another one, is where a
                // cancel of this transaction must be forwarded.
                let remote_endpoint = txid.as_ref().and_then(|_| sender_endpoint(cfg, &s.from));
                let m = NewMessage {
                    sender_key: sender_key(&s.from),
                    recipient: format!("{}@{}", s.queue, recipient_suffix),
                    queue: s.queue,
                    sender: s.from,
                    body: s.str,
                    signature: s.signature,
                    challenge: s.challenge,
                    txid,
                    txidsig,
                    remote_endpoint,
                    msgid,
                    created_at: created,
                    expires_at: expires,
                    deliveries: s.deliveries,
                    queue_cap: u32::MAX,
                    per_sender_cap: u32::MAX,
                };
                match store.put_message(m).await? {
                    PutOutcome::Stored { .. } => st.slates += 1,
                    PutOutcome::Duplicate { .. } => st.duplicates += 1,
                    other => st.skip(n, format!("store refused: {other:?}")),
                }
            }
            Line::Forward(f) => {
                if f.target_host.is_empty() {
                    st.skip(n, "empty target_host");
                    continue;
                }
                let Some(created) = secs_to_ms(f.created_at) else {
                    st.skip(n, "time out of range");
                    continue;
                };
                let expires = created.saturating_add(cfg.retention_secs().saturating_mul(1000));
                if expires <= now_ms {
                    st.expired += 1;
                    st.skip(n, "expired");
                    continue;
                }
                let nf = NewForward {
                    peer: format!("{}:{}", f.target_host, f.target_port).to_lowercase(),
                    kind: forward_kind(&f.frame),
                    frame: f.frame,
                    txid: None,
                    tx_keys: vec![],
                    created_at: created,
                    expires_at: expires,
                    attempts: f.attempts,
                };
                if store.put_forward(nf).await? {
                    st.forwards += 1;
                } else {
                    st.duplicates += 1;
                }
            }
        }
    }
    Ok(st)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ExportStats {
    pub slates: u64,
    pub forwards: u64,
}

#[derive(Serialize)]
struct SlateOut<'a> {
    kind: &'static str,
    queue: &'a str,
    from: &'a str,
    str: &'a str,
    signature: &'a str,
    challenge: &'a str,
    messageid: &'a str,
    created_at: i64,
    expires_at: i64,
    deliveries: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    epicboxtxid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epicboxtxidsig: Option<&'a str>,
}

#[derive(Serialize)]
struct ForwardOut<'a> {
    kind: &'static str,
    target_host: &'a str,
    target_port: u16,
    frame: &'a str,
    attempts: i64,
    created_at: i64,
}

/// Write every waiting message and queued forward of the SQLite file at `db_path` as JSON Lines.
/// The file is opened read only. Cancel tombstones are not exported.
pub fn export_jsonl<W: Write>(db_path: &Path, mut out: W) -> Result<ExportStats> {
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .with_context(|| format!("opening {} read only", db_path.display()))?;
    let mut st = ExportStats::default();

    let mut q = conn.prepare(
        "SELECT queue,sender,body,signature,challenge,msgid,created_at,expires_at,deliveries,txid,txidsig \
         FROM messages ORDER BY created_at, id",
    )?;
    let mut rows = q.query([])?;
    while let Some(r) = rows.next()? {
        let (queue, sender, body, sig, ch, msgid): (String, String, String, String, String, String) =
            (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?);
        let (txid, txidsig): (Option<String>, Option<String>) = (r.get(9)?, r.get(10)?);
        let rec = SlateOut {
            kind: "slate",
            queue: &queue,
            from: &sender,
            str: &body,
            signature: &sig,
            challenge: &ch,
            messageid: &msgid,
            created_at: r.get::<_, i64>(6)? / 1000,
            expires_at: r.get::<_, i64>(7)? / 1000,
            deliveries: r.get(8)?,
            epicboxtxid: txid.as_deref(),
            epicboxtxidsig: txidsig.as_deref(),
        };
        serde_json::to_writer(&mut out, &rec)?;
        out.write_all(b"\n")?;
        st.slates += 1;
    }
    drop(rows);

    let mut q = conn.prepare("SELECT peer,frame,attempts,created_at FROM forwards ORDER BY created_at, id")?;
    let mut rows = q.query([])?;
    while let Some(r) = rows.next()? {
        let peer: String = r.get(0)?;
        let frame: String = r.get(1)?;
        let Some((host, port)) = peer.rsplit_once(':').and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?))) else {
            continue;
        };
        let rec = ForwardOut {
            kind: "forward",
            target_host: host,
            target_port: port,
            frame: &frame,
            attempts: r.get(2)?,
            created_at: r.get::<_, i64>(3)? / 1000,
        };
        serde_json::to_writer(&mut out, &rec)?;
        out.write_all(b"\n")?;
        st.forwards += 1;
    }
    out.flush()?;
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;
    use crate::store::ClaimMode;
    use std::io::Cursor;

    const Q1: &str = "9rGnvFq1uG7aMNGGdhCWVn5yqVXCCRVqNtkBTXq3C9ykaZ4fDoMd";
    const Q2: &str = "9sFh7mTzXk3G1aQvQmGQ7ZJRnWp5uJ8c4t2LdYh6BxEeVa3UrKfN";
    const NOW: i64 = 1_700_000_000_000;

    fn input() -> String {
        let now_s = NOW / 1000;
        let l = [
            format!(
                r#"{{"kind":"slate","queue":"{Q1}","from":"epicbox://{Q2}@old.example:443","str":"body1","signature":"s1","challenge":"c1","messageid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at":{},"expires_at":{},"deliveries":2}}"#,
                now_s - 10,
                now_s + 1000
            ),
            format!(
                r#"{{"kind":"slate","queue":"{Q2}","from":"","str":"body2","signature":"s2","challenge":"","messageid":null,"created_at":{},"expires_at":{},"deliveries":0}}"#,
                now_s - 5,
                now_s + 1000
            ),
            format!(
                r#"{{"kind":"forward","target_host":"Peer.Example","target_port":8443,"frame":"{{\"x\":1}}","attempts":3,"created_at":{}}}"#,
                now_s - 20
            ),
            "not json".to_string(),
            format!(
                r#"{{"kind":"slate","queue":"{Q1}","from":"","str":"old","signature":"s3","challenge":"","messageid":null,"created_at":{},"expires_at":{},"deliveries":0}}"#,
                now_s - 5000,
                now_s - 1
            ),
        ];
        l.join("\n") + "\n"
    }

    fn cfg() -> Config {
        let mut c = Config::default();
        c.server.domain = "relay.test".into();
        c
    }

    #[tokio::test]
    async fn import_repeat_export_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("a.db");
        let s = SqliteStore::open(&db, 2, 64).unwrap();
        let cfg = cfg();

        let st = import_jsonl(&s, &cfg, Cursor::new(input()), NOW).await.unwrap();
        assert_eq!((st.slates, st.forwards, st.duplicates, st.skipped, st.expired), (2, 1, 0, 2, 1));
        assert_eq!(st.errors.len(), 2);
        assert_eq!(st.errors[0].line, 4);
        assert_eq!(s.stats(NOW).await.unwrap().messages_waiting, 2);
        assert_eq!(s.stats(NOW).await.unwrap().forwards_waiting, 1);

        let st2 = import_jsonl(&s, &cfg, Cursor::new(input()), NOW).await.unwrap();
        // The random-msgid slate has the same dedupe key, so it is a duplicate too.
        assert_eq!((st2.slates, st2.forwards, st2.duplicates, st2.skipped), (0, 0, 3, 2));
        assert_eq!(s.stats(NOW).await.unwrap().messages_waiting, 2);
        assert_eq!(s.stats(NOW).await.unwrap().forwards_waiting, 1);

        let got = s.claim(Q1, NOW, 10, vec![], ClaimMode::Offer { lease_ms: 0 }).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msgid, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        // Imported with 2 deliveries; this offer is the third.
        assert_eq!(got[0].deliveries, 3);

        let mut buf = Vec::new();
        let es = export_jsonl(&db, &mut buf).unwrap();
        assert_eq!((es.slates, es.forwards), (2, 1));
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains(r#""target_host":"peer.example","target_port":8443"#));

        let db2 = dir.path().join("b.db");
        let s2 = SqliteStore::open(&db2, 2, 64).unwrap();
        let st3 = import_jsonl(&s2, &cfg, Cursor::new(text), NOW).await.unwrap();
        assert_eq!((st3.slates, st3.forwards, st3.skipped), (2, 1, 0));
        let g1 = s.claim(Q2, NOW + 1, 10, vec![], ClaimMode::Consume).await.unwrap();
        let g2 = s2.claim(Q2, NOW + 1, 10, vec![], ClaimMode::Consume).await.unwrap();
        assert_eq!(g1.len(), 1);
        assert_eq!((&g1[0].msgid, &g1[0].queue, &g1[0].body), (&g2[0].msgid, &g2[0].queue, &g2[0].body));
        let g2 = s2.claim(Q1, NOW + 1, 10, vec![], ClaimMode::Consume).await.unwrap();
        assert_eq!(g2[0].msgid, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(g2[0].body, "body1");
        assert_eq!(g2[0].sender, format!("epicbox://{Q2}@old.example:443"));
    }

    #[tokio::test]
    async fn transaction_ids_survive_export_and_import() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("a.db");
        let s = SqliteStore::open(&db, 1, 64).unwrap();
        let now_s = NOW / 1000;
        let txid = "T".repeat(32);
        let lines = [
            format!(
                r#"{{"kind":"slate","queue":"{Q1}","from":"{Q2}@other.example:443","str":"b","signature":"s","messageid":null,"created_at":{now_s},"expires_at":{},"epicboxtxid":"{txid}","epicboxtxidsig":"ts"}}"#,
                now_s + 1000
            ),
            format!(
                r#"{{"kind":"slate","queue":"{Q1}","from":"","str":"c","signature":"s","created_at":{now_s},"expires_at":{},"epicboxtxid":"short","epicboxtxidsig":"ts"}}"#,
                now_s + 1000
            ),
        ];
        let st = import_jsonl(&s, &cfg(), Cursor::new(lines.join("\n")), NOW).await.unwrap();
        assert_eq!((st.slates, st.skipped), (1, 1));
        let info = s.tx_info(&txid).await.unwrap();
        assert_eq!(info.participants.len(), 2);
        assert_eq!(info.endpoints, ["other.example:443"]);

        let mut buf = Vec::new();
        export_jsonl(&db, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains(&format!(r#""epicboxtxid":"{txid}","epicboxtxidsig":"ts""#)), "{text}");

        let s2 = SqliteStore::open(&dir.path().join("b.db"), 1, 64).unwrap();
        assert_eq!(import_jsonl(&s2, &cfg(), Cursor::new(text), NOW).await.unwrap().slates, 1);
        let got = s2.claim(Q1, NOW, 1, vec![], ClaimMode::Consume).await.unwrap();
        assert_eq!(got[0].txid.as_deref(), Some(txid.as_str()));
    }

    #[test]
    fn forward_kind_follows_the_frame() {
        assert_eq!(forward_kind(r#"{"type":"CancelTx","epicboxtxid":"x"}"#), ForwardKind::CancelTx);
        assert_eq!(forward_kind(r#"{"type":"PostSlate"}"#), ForwardKind::PostSlate);
        assert_eq!(forward_kind("not json"), ForwardKind::PostSlate);
    }

    #[tokio::test]
    async fn import_replaces_ids_wallets_cannot_ack() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("a.db"), 1, 64).unwrap();
        let now_s = NOW / 1000;
        let line = format!(
            r#"{{"kind":"slate","queue":"{Q1}","from":"","str":"b","signature":"s","messageid":"bad id/with spaces","created_at":{},"expires_at":{}}}"#,
            now_s,
            now_s + 1000
        );
        let st = import_jsonl(&s, &cfg(), Cursor::new(line), NOW).await.unwrap();
        assert_eq!(st.slates, 1);
        let got = s.claim(Q1, NOW, 10, vec![], ClaimMode::Consume).await.unwrap();
        assert!(is_msgid(&got[0].msgid) && got[0].msgid != "bad id/with spaces", "{}", got[0].msgid);
    }
}
