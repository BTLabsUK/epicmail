//! SQLite store. One writer thread owns the only write connection and commits in groups: it takes
//! every write that is waiting (up to `group_commit_max`), runs each in its own savepoint inside
//! one transaction, commits once, and only then answers the callers. Readers use a small pool of
//! read-only connections; WAL lets them read while the writer commits.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

use super::*;

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY,
  msgid TEXT NOT NULL UNIQUE,
  queue TEXT NOT NULL,
  sender TEXT NOT NULL,
  sender_key TEXT NOT NULL,
  recipient TEXT NOT NULL,
  body TEXT NOT NULL,
  signature TEXT NOT NULL,
  challenge TEXT NOT NULL DEFAULT '',
  txid TEXT,
  txidsig TEXT,
  deliveries INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_offered_at INTEGER NOT NULL DEFAULT 0,
  not_before INTEGER NOT NULL DEFAULT 0,
  dedupe BLOB NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS messages_queue ON messages(queue, created_at);
CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires_at);
CREATE INDEX IF NOT EXISTS messages_txid ON messages(txid) WHERE txid IS NOT NULL;
CREATE TABLE IF NOT EXISTS forwards(
  id INTEGER PRIMARY KEY,
  peer TEXT NOT NULL,
  kind INTEGER NOT NULL,
  frame TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_error TEXT,
  dedupe BLOB NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS forwards_due ON forwards(peer, next_at);
CREATE INDEX IF NOT EXISTS forwards_next ON forwards(next_at);
CREATE TABLE IF NOT EXISTS txlinks(
  txid TEXT NOT NULL,
  kind INTEGER NOT NULL,
  value TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(txid, kind, value)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS txlinks_age ON txlinks(created_at);
CREATE TABLE IF NOT EXISTS cancels(
  txid TEXT PRIMARY KEY,
  participants TEXT NOT NULL,
  receiver TEXT,
  acknowledged INTEGER NOT NULL,
  created_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cancels_receiver ON cancels(receiver, acknowledged, created_at);
CREATE TABLE IF NOT EXISTS used_challenges(key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL) WITHOUT ROWID;
"#;

const LINK_KEY: i64 = 0;
const LINK_ENDPOINT: i64 = 1;

type Done = Box<dyn FnOnce(std::result::Result<(), String>) + Send>;
type Job = Box<dyn FnOnce(&Connection) -> Done + Send>;

/// The [`Store`] on one SQLite file.
pub struct SqliteStore {
    tx: mpsc::Sender<Job>,
    readers: Arc<Vec<Mutex<Connection>>>,
    next_reader: AtomicUsize,
}

fn open(path: &Path, flags: OpenFlags) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, flags).with_context(|| format!("opening {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    Ok(conn)
}

fn dedupe_message(queue: &str, sender: &str, body: &str, signature: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    for part in [queue, sender, body, signature] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().to_vec()
}

fn dedupe_forward(peer: &str, frame: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update((peer.len() as u64).to_le_bytes());
    h.update(peer.as_bytes());
    h.update(frame.as_bytes());
    h.finalize().to_vec()
}

impl SqliteStore {
    /// Open or create the database, apply the schema, start the writer thread and open
    /// `readers` read connections. `group_max` caps the writes in one commit. Fails on a database
    /// whose schema is newer than this binary.
    ///
    /// If the writer thread panics, the process exits with status 70: every later write would
    /// fail, and a supervisor (systemd `Restart=on-failure`, Docker `--restart`) restarts a
    /// process that exits, not one that stays up. Uncommitted work is rolled back by SQLite
    /// and no caller got `Ok` for it.
    pub fn open(path: &Path, readers: usize, group_max: usize) -> Result<Self> {
        Self::open_with(path, readers, group_max, || {
            tracing::error!("store writer thread panicked; exiting so the relay is restarted");
            std::process::exit(70);
        })
    }

    /// `open`, with what to do when the writer thread panics.
    fn open_with(
        path: &Path,
        readers: usize,
        group_max: usize,
        on_writer_panic: impl FnOnce() + Send + 'static,
    ) -> Result<Self> {
        let rw = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let writer = open(path, rw)?;
        // auto_vacuum must be set before the first table exists.
        writer.execute_batch(
            "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; \
             PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;",
        )?;
        writer.execute_batch(SCHEMA)?;
        let version: Option<String> =
            writer.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| r.get(0)).optional()?;
        match version {
            None => {
                writer.execute("INSERT INTO meta(key,value) VALUES('schema',?1)", [SCHEMA_VERSION.to_string()])?;
            }
            Some(v) if v == SCHEMA_VERSION.to_string() => {}
            Some(v) => return Err(anyhow!("database schema {v} is newer than this binary ({SCHEMA_VERSION})")),
        }

        let ro = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut pool = Vec::new();
        for _ in 0..readers.max(1) {
            let c = open(path, ro)?;
            c.execute_batch("PRAGMA temp_store=MEMORY;")?;
            pool.push(Mutex::new(c));
        }

        let (tx, rx) = mpsc::channel::<Job>(8192);
        std::thread::Builder::new().name("store-writer".into()).spawn(move || {
            let run = std::panic::AssertUnwindSafe(|| writer_loop(writer, rx, group_max.max(1)));
            if std::panic::catch_unwind(run).is_err() {
                on_writer_panic();
            }
        })?;
        Ok(Self { tx, readers: Arc::new(pool), next_reader: AtomicUsize::new(0) })
    }

    async fn write<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let (reply, rx) = oneshot::channel::<Result<T>>();
        let job: Job = Box::new(move |conn: &Connection| {
            let r = run_savepoint(conn, f);
            Box::new(move |committed| {
                let out = match committed {
                    Ok(()) => r.map_err(anyhow::Error::from),
                    Err(e) => Err(anyhow!("commit failed: {e}")),
                };
                let _ = reply.send(out);
            })
        });
        self.tx.send(job).await.map_err(|_| anyhow!("store writer stopped"))?;
        rx.await.map_err(|_| anyhow!("store writer dropped the reply"))?
    }

    async fn read<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let readers = self.readers.clone();
        let i = self.next_reader.fetch_add(1, Ordering::Relaxed) % readers.len();
        tokio::task::spawn_blocking(move || {
            let conn = readers[i].lock();
            f(&conn).map_err(anyhow::Error::from)
        })
        .await?
    }
}

fn run_savepoint<T>(conn: &Connection, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
    conn.execute_batch("SAVEPOINT job")?;
    match f(conn) {
        Ok(v) => {
            conn.execute_batch("RELEASE job")?;
            Ok(v)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO job; RELEASE job");
            Err(e)
        }
    }
}

/// Delete `msgid` if it sits in one of `queues`. When it carries a txid, the other waiting states
/// of that transaction in the same queue go too (the cancel fork's Made rule). Returns the queue.
fn made_one(c: &Connection, queues: &[&str], msgid: &str) -> rusqlite::Result<Option<String>> {
    let row: Option<(String, Option<String>)> = c
        .prepare_cached("SELECT queue, txid FROM messages WHERE msgid=?1")?
        .query_row([msgid], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let Some((queue, txid)) = row else { return Ok(None) };
    if !queues.contains(&queue.as_str()) {
        return Ok(None);
    }
    c.prepare_cached("DELETE FROM messages WHERE msgid=?1")?.execute([msgid])?;
    if let Some(t) = txid {
        c.prepare_cached("DELETE FROM messages WHERE queue=?1 AND txid=?2")?.execute(params![queue, t])?;
    }
    Ok(Some(queue))
}

fn writer_loop(conn: Connection, mut rx: mpsc::Receiver<Job>, group_max: usize) {
    while let Some(first) = rx.blocking_recv() {
        let mut batch = Vec::with_capacity(16);
        batch.push(first);
        while batch.len() < group_max {
            match rx.try_recv() {
                Ok(j) => batch.push(j),
                Err(_) => break,
            }
        }
        let started = Instant::now();
        let n = batch.len();
        let begun = conn.execute_batch("BEGIN IMMEDIATE");
        let mut done = Vec::with_capacity(n);
        if begun.is_err() {
            // The jobs never ran. Dropping them closes their reply channels, so each caller
            // gets an error and no Ok goes out.
            metrics::counter!("epicbox_store_commit_errors_total").increment(1);
            drop(batch);
            continue;
        }
        for job in batch {
            done.push(job(&conn));
        }
        let res = conn.execute_batch("COMMIT").map_err(|e| e.to_string());
        if res.is_err() {
            let _ = conn.execute_batch("ROLLBACK");
        }
        metrics::histogram!("epicbox_store_commit_seconds").record(started.elapsed().as_secs_f64());
        metrics::histogram!("epicbox_store_commit_batch").record(n as f64);
        if res.is_err() {
            metrics::counter!("epicbox_store_commit_errors_total").increment(1);
        }
        for d in done {
            d(res.clone());
        }
    }
}

fn row_to_message(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessage> {
    Ok(StoredMessage {
        id: r.get(0)?,
        msgid: r.get(1)?,
        queue: r.get(2)?,
        sender: r.get(3)?,
        body: r.get(4)?,
        signature: r.get(5)?,
        challenge: r.get(6)?,
        txid: r.get(7)?,
        deliveries: r.get(8)?,
        created_at: r.get(9)?,
    })
}

const MSG_COLS: &str = "id, msgid, queue, sender, body, signature, challenge, txid, deliveries, created_at";
const OFFER_ORDER: &str = "ORDER BY CASE WHEN deliveries>=3 THEN 1 ELSE 0 END, \
     CASE WHEN deliveries>=3 THEN last_offered_at ELSE created_at END, id";

fn link_tx(conn: &Connection, txid: &str, keys: &[&str], endpoint: Option<&str>, now: i64) -> rusqlite::Result<()> {
    let mut st =
        conn.prepare_cached("INSERT OR IGNORE INTO txlinks(txid,kind,value,created_at) VALUES(?1,?2,?3,?4)")?;
    for k in keys {
        st.execute(params![txid, LINK_KEY, k, now])?;
    }
    if let Some(e) = endpoint {
        st.execute(params![txid, LINK_ENDPOINT, e, now])?;
    }
    Ok(())
}

fn tx_participants(conn: &Connection, txid: &str) -> rusqlite::Result<Vec<String>> {
    let mut st = conn.prepare_cached("SELECT value FROM txlinks WHERE txid=?1 AND kind=?2 ORDER BY value")?;
    let rows = st.query_map(params![txid, LINK_KEY], |r| r.get::<_, String>(0))?;
    rows.collect()
}

#[async_trait]
impl Store for SqliteStore {
    async fn put_message(&self, m: NewMessage) -> Result<PutOutcome> {
        self.write(move |c| {
            if let Some(txid) = &m.txid {
                let cancelled: bool = c.prepare_cached("SELECT 1 FROM cancels WHERE txid=?1")?.exists([txid])?;
                if cancelled {
                    return Ok(PutOutcome::Cancelled);
                }
                let parts = tx_participants(c, txid)?;
                if !parts.is_empty() && !parts.iter().any(|p| p == &m.sender_key) {
                    return Ok(PutOutcome::NotParticipant);
                }
            }
            let dedupe = dedupe_message(&m.queue, &m.sender, &m.body, &m.signature);
            if let Some(msgid) = c
                .prepare_cached("SELECT msgid FROM messages WHERE dedupe=?1")?
                .query_row([&dedupe], |r| r.get::<_, String>(0))
                .optional()?
            {
                return Ok(PutOutcome::Duplicate { msgid });
            }
            if let Some(msgid) = c
                .prepare_cached("SELECT msgid FROM messages WHERE msgid=?1")?
                .query_row([&m.msgid], |r| r.get::<_, String>(0))
                .optional()?
            {
                return Ok(PutOutcome::Duplicate { msgid });
            }
            let (in_queue, from_sender): (i64, i64) = c
                .prepare_cached("SELECT count(*), coalesce(sum(sender_key=?2),0) FROM messages WHERE queue=?1")?
                .query_row(params![m.queue, m.sender_key], |r| Ok((r.get(0)?, r.get(1)?)))?;
            if in_queue >= i64::from(m.queue_cap) {
                return Ok(PutOutcome::QueueFull);
            }
            if from_sender >= i64::from(m.per_sender_cap) {
                return Ok(PutOutcome::SenderCapped);
            }
            c.prepare_cached(
                "INSERT INTO messages(msgid,queue,sender,sender_key,recipient,body,signature,challenge,\
                 txid,txidsig,deliveries,created_at,expires_at,dedupe) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            )?
            .execute(params![
                m.msgid,
                m.queue,
                m.sender,
                m.sender_key,
                m.recipient,
                m.body,
                m.signature,
                m.challenge,
                m.txid,
                m.txidsig,
                m.deliveries,
                m.created_at,
                m.expires_at,
                dedupe
            ])?;
            if let Some(txid) = &m.txid {
                link_tx(
                    c,
                    txid,
                    &[m.sender_key.as_str(), m.queue.as_str()],
                    m.remote_endpoint.as_deref(),
                    m.created_at,
                )?;
            }
            Ok(PutOutcome::Stored { msgid: m.msgid })
        })
        .await
    }

    async fn has_offerable(&self, queue: &str, now: i64, exclude: Vec<i64>) -> Result<bool> {
        let queue = queue.to_string();
        self.read(move |c| {
            let mut st = c.prepare_cached(
                "SELECT id FROM messages WHERE queue=?1 AND not_before<=?2 AND expires_at>?2 LIMIT ?3",
            )?;
            let ids = st.query_map(params![queue, now, exclude.len() as i64 + 1], |r| r.get::<_, i64>(0))?;
            for id in ids {
                if !exclude.contains(&id?) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .await
    }

    async fn waiting(&self, queue: &str, now: i64) -> Result<i64> {
        let queue = queue.to_string();
        self.read(move |c| {
            c.prepare_cached("SELECT count(*) FROM messages WHERE queue=?1 AND not_before<=?2 AND expires_at>?2")?
                .query_row(params![queue, now], |r| r.get(0))
        })
        .await
    }

    async fn waiting_many(&self, queues: Vec<String>, now: i64) -> Result<std::collections::HashMap<String, i64>> {
        if queues.is_empty() {
            return Ok(Default::default());
        }
        let list = serde_json::to_string(&queues).map_err(|e| anyhow!(e))?;
        self.read(move |c| {
            let mut st = c.prepare_cached(
                "SELECT queue, count(*) FROM messages                  WHERE queue IN (SELECT value FROM json_each(?1)) AND not_before<=?2 AND expires_at>?2                  GROUP BY queue",
            )?;
            let rows = st.query_map(params![list, now], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
            rows.collect()
        })
        .await
    }

    async fn claim(
        &self,
        queue: &str,
        now: i64,
        limit: usize,
        exclude: Vec<i64>,
        mode: ClaimMode,
    ) -> Result<Vec<StoredMessage>> {
        if limit == 0 {
            return Ok(vec![]);
        }
        let queue = queue.to_string();
        self.write(move |c| {
            let sql = format!(
                "SELECT {MSG_COLS} FROM messages WHERE queue=?1 AND not_before<=?2 AND expires_at>?2 \
                 {OFFER_ORDER} LIMIT ?3"
            );
            let mut st = c.prepare_cached(&sql)?;
            let rows = st.query_map(
                params![queue, now, (limit + exclude.len()) as i64],
                row_to_message,
            )?;
            let mut out = Vec::new();
            for r in rows {
                let m = r?;
                if exclude.contains(&m.id) {
                    continue;
                }
                out.push(m);
                if out.len() == limit {
                    break;
                }
            }
            drop(st);
            for m in &mut out {
                match mode {
                    ClaimMode::Consume => {
                        c.prepare_cached("DELETE FROM messages WHERE id=?1")?.execute([m.id])?;
                    }
                    ClaimMode::Offer { lease_ms } => {
                        let nb = if lease_ms > 0 { now + lease_ms } else { 0 };
                        c.prepare_cached(
                            "UPDATE messages SET deliveries=deliveries+1, last_offered_at=?2, not_before=?3 WHERE id=?1",
                        )?
                        .execute(params![m.id, now, nb])?;
                        m.deliveries += 1;
                    }
                }
            }
            Ok(out)
        })
        .await
    }

    async fn release(&self, ids: Vec<i64>) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        self.write(move |c| {
            let mut st = c.prepare_cached("UPDATE messages SET not_before=0 WHERE id=?1")?;
            for id in ids {
                st.execute([id])?;
            }
            Ok(())
        })
        .await
    }

    async fn hold(&self, queue: &str, msgid: &str, until: i64) -> Result<bool> {
        let (queue, msgid) = (queue.to_string(), msgid.to_string());
        self.write(move |c| {
            let n = c
                .prepare_cached("UPDATE messages SET not_before=?3 WHERE queue=?1 AND msgid=?2")?
                .execute(params![queue, msgid, until])?;
            Ok(n == 1)
        })
        .await
    }

    async fn made(&self, queue: &str, msgids: Vec<String>) -> Result<Vec<bool>> {
        let queue = queue.to_string();
        self.write(move |c| {
            let mut out = Vec::with_capacity(msgids.len());
            for id in msgids {
                out.push(made_one(c, &[queue.as_str()], &id)?.is_some());
            }
            Ok(out)
        })
        .await
    }

    async fn made_in(&self, queues: Vec<String>, msgids: Vec<String>) -> Result<u64> {
        self.write(move |c| {
            let qs: Vec<&str> = queues.iter().map(String::as_str).collect();
            let mut n = 0;
            for id in msgids {
                n += made_one(c, &qs, &id)?.is_some() as u64;
            }
            Ok(n)
        })
        .await
    }

    async fn put_forward(&self, f: NewForward) -> Result<bool> {
        self.write(move |c| {
            let dedupe = dedupe_forward(&f.peer, &f.frame);
            let n = c
                .prepare_cached(
                    "INSERT OR IGNORE INTO forwards(peer,kind,frame,attempts,next_at,created_at,expires_at,dedupe) \
                     VALUES(?1,?2,?3,?4,?5,?5,?6,?7)",
                )?
                .execute(params![f.peer, f.kind as i64, f.frame, f.attempts, f.created_at, f.expires_at, dedupe])?;
            if let Some(txid) = &f.txid {
                let keys: Vec<&str> = f.tx_keys.iter().map(|s| s.as_str()).collect();
                link_tx(c, txid, &keys, Some(&f.peer), f.created_at)?;
            }
            Ok(n == 1)
        })
        .await
    }

    async fn forward_peers_due(&self, now: i64) -> Result<Vec<String>> {
        self.read(move |c| {
            let mut st =
                c.prepare_cached("SELECT DISTINCT peer FROM forwards WHERE next_at<=?1 AND expires_at>?1 LIMIT 1000")?;
            let rows = st.query_map([now], |r| r.get::<_, String>(0))?;
            rows.collect()
        })
        .await
    }

    async fn forwards_due(&self, peer: &str, now: i64, limit: usize) -> Result<Vec<ForwardRow>> {
        let peer = peer.to_string();
        self.read(move |c| {
            let mut st = c.prepare_cached(
                "SELECT id, peer, kind, frame, attempts, created_at FROM forwards \
                 WHERE peer=?1 AND next_at<=?2 AND expires_at>?2 ORDER BY created_at, id LIMIT ?3",
            )?;
            let rows = st.query_map(params![peer, now, limit as i64], |r| {
                Ok(ForwardRow {
                    id: r.get(0)?,
                    peer: r.get(1)?,
                    kind: if r.get::<_, i64>(2)? == 1 { ForwardKind::CancelTx } else { ForwardKind::PostSlate },
                    frame: r.get(3)?,
                    attempts: r.get(4)?,
                    created_at: r.get(5)?,
                })
            })?;
            rows.collect()
        })
        .await
    }

    async fn forward_done(&self, id: i64) -> Result<()> {
        self.write(move |c| {
            c.prepare_cached("DELETE FROM forwards WHERE id=?1")?.execute([id])?;
            Ok(())
        })
        .await
    }

    async fn forward_failed(&self, id: i64, next_at: i64, error: &str, drop: bool) -> Result<()> {
        let error: String = error.chars().take(200).collect();
        self.write(move |c| {
            if drop {
                c.prepare_cached("DELETE FROM forwards WHERE id=?1")?.execute([id])?;
            } else {
                c.prepare_cached("UPDATE forwards SET attempts=attempts+1, next_at=?2, last_error=?3 WHERE id=?1")?
                    .execute(params![id, next_at, error])?;
            }
            Ok(())
        })
        .await
    }

    async fn tx_info(&self, txid: &str) -> Result<TxInfo> {
        let txid = txid.to_string();
        self.read(move |c| {
            let mut info = TxInfo { participants: tx_participants(c, &txid)?, ..Default::default() };
            let mut st = c.prepare_cached("SELECT value FROM txlinks WHERE txid=?1 AND kind=?2 ORDER BY value")?;
            info.endpoints = st
                .query_map(params![txid, LINK_ENDPOINT], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<_>>()?;
            // Messages stored before links existed (imports) still name their participants.
            let mut st = c.prepare_cached("SELECT queue, sender_key FROM messages WHERE txid=?1")?;
            for row in st.query_map([&txid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
                let (q, s) = row?;
                for k in [q, s] {
                    if !info.participants.contains(&k) {
                        info.participants.push(k);
                    }
                }
            }
            info.tombstone = c
                .prepare_cached("SELECT participants, receiver, acknowledged FROM cancels WHERE txid=?1")?
                .query_row([&txid], |r| {
                    let p: String = r.get(0)?;
                    Ok(Tombstone {
                        participants: p.split(',').filter(|s| !s.is_empty()).map(String::from).collect(),
                        receiver: r.get(1)?,
                        acknowledged: r.get::<_, i64>(2)? != 0,
                    })
                })
                .optional()?;
            Ok(info)
        })
        .await
    }

    async fn cancel_tx(
        &self,
        txid: &str,
        participants: Vec<String>,
        receiver: Option<String>,
        now: i64,
    ) -> Result<Vec<String>> {
        let txid = txid.to_string();
        self.write(move |c| {
            c.prepare_cached(
                "INSERT OR IGNORE INTO cancels(txid,participants,receiver,acknowledged,created_at) VALUES(?1,?2,?3,?4,?5)",
            )?
            .execute(params![txid, participants.join(","), receiver, receiver.is_none() as i64, now])?;
            let mut st = c.prepare_cached("SELECT DISTINCT queue FROM messages WHERE txid=?1")?;
            let queues: Vec<String> =
                st.query_map([&txid], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            drop(st);
            c.prepare_cached("DELETE FROM messages WHERE txid=?1")?.execute([&txid])?;
            Ok(queues)
        })
        .await
    }

    async fn pending_cancel(&self, receiver: &str) -> Result<Option<String>> {
        let receiver = receiver.to_string();
        self.read(move |c| {
            c.prepare_cached(
                "SELECT txid FROM cancels WHERE receiver=?1 AND acknowledged=0 ORDER BY created_at LIMIT 1",
            )?
            .query_row([receiver], |r| r.get(0))
            .optional()
        })
        .await
    }

    async fn ack_cancel(&self, receiver: &str, txid: &str) -> Result<()> {
        let (receiver, txid) = (receiver.to_string(), txid.to_string());
        self.write(move |c| {
            c.prepare_cached("UPDATE cancels SET acknowledged=1 WHERE txid=?1 AND receiver=?2")?
                .execute(params![txid, receiver])?;
            Ok(())
        })
        .await
    }

    async fn use_challenge(&self, key: &str, expires_at: i64) -> Result<bool> {
        let key = key.to_string();
        self.write(move |c| {
            let n = c
                .prepare_cached("INSERT OR IGNORE INTO used_challenges(key,expires_at) VALUES(?1,?2)")?
                .execute(params![key, expires_at])?;
            Ok(n == 1)
        })
        .await
    }

    async fn sweep(&self, now: i64, retention_ms: i64) -> Result<SweepStats> {
        self.write(move |c| {
            let cutoff = now - retention_ms;
            Ok(SweepStats {
                messages_expired: c.execute("DELETE FROM messages WHERE expires_at<=?1", [now])? as u64,
                forwards_expired: c.execute("DELETE FROM forwards WHERE expires_at<=?1", [now])? as u64,
                tombstones_expired: c.execute("DELETE FROM cancels WHERE created_at<=?1", [cutoff])? as u64,
                challenges_expired: c.execute("DELETE FROM used_challenges WHERE expires_at<=?1", [now])? as u64,
                txlinks_expired: c.execute("DELETE FROM txlinks WHERE created_at<=?1", [cutoff])? as u64,
            })
        })
        .await
    }

    async fn vacuum(&self) -> Result<()> {
        // The pragma returns rows, so it runs as a query (`execute` refuses statements that
        // return rows) and is stepped to the end, which is when the pages are freed.
        self.write(|c| {
            let mut st = c.prepare("PRAGMA incremental_vacuum(2000)")?;
            let mut rows = st.query([])?;
            while rows.next()?.is_some() {}
            Ok(())
        })
        .await
    }

    async fn stats(&self, now: i64) -> Result<Stats> {
        self.read(move |c| {
            let (n, q, oldest): (i64, i64, Option<i64>) = c.query_row(
                "SELECT count(*), count(DISTINCT queue), min(created_at) FROM messages WHERE expires_at>?1",
                [now],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            let oldest_unoffered: Option<i64> = c.query_row(
                "SELECT min(created_at) FROM messages WHERE deliveries=0 AND not_before<=?1 AND expires_at>?1",
                [now],
                |r| r.get(0),
            )?;
            let (f, fp, fo): (i64, i64, Option<i64>) =
                c.query_row("SELECT count(*), count(DISTINCT peer), min(created_at) FROM forwards", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
            let t: i64 = c.query_row("SELECT count(*) FROM cancels", [], |r| r.get(0))?;
            let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            let psize: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
            Ok(Stats {
                messages_waiting: n,
                mailboxes_waiting: q,
                oldest_waiting_ms: oldest.map(|o| (now - o).max(0)).unwrap_or(0),
                oldest_unoffered_ms: oldest_unoffered.map(|o| (now - o).max(0)).unwrap_or(0),
                forwards_waiting: f,
                forward_peers: fp,
                oldest_forward_ms: fo.map(|o| (now - o).max(0)).unwrap_or(0),
                tombstones: t,
                db_bytes: pages * psize,
            })
        })
        .await
    }

    async fn check_writable(&self) -> Result<()> {
        self.write(|c| {
            c.execute(
                "INSERT INTO meta(key,value) VALUES('ready_probe',strftime('%s','now')) \
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(queue: &str, sender: &str, body: &str, now: i64) -> NewMessage {
        NewMessage {
            queue: queue.into(),
            sender: format!("{sender}@relay.test"),
            sender_key: sender.into(),
            recipient: format!("{queue}@relay.test"),
            body: body.into(),
            signature: "sig".into(),
            challenge: String::new(),
            txid: None,
            txidsig: None,
            remote_endpoint: None,
            msgid: format!("m{body}"),
            created_at: now,
            expires_at: now + 1000,
            deliveries: 0,
            queue_cap: 3,
            per_sender_cap: 2,
        }
    }

    #[tokio::test]
    async fn put_claim_made_dedupe_caps() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("t.db"), 2, 64).unwrap();
        assert_eq!(s.put_message(msg("q", "a", "1", 10)).await.unwrap(), PutOutcome::Stored { msgid: "m1".into() });
        assert_eq!(s.put_message(msg("q", "a", "1", 11)).await.unwrap(), PutOutcome::Duplicate { msgid: "m1".into() });
        assert_eq!(s.put_message(msg("q", "a", "2", 12)).await.unwrap(), PutOutcome::Stored { msgid: "m2".into() });
        assert_eq!(s.put_message(msg("q", "a", "3", 13)).await.unwrap(), PutOutcome::SenderCapped);
        assert_eq!(s.put_message(msg("q", "b", "3", 13)).await.unwrap(), PutOutcome::Stored { msgid: "m3".into() });
        assert_eq!(s.put_message(msg("q", "c", "4", 14)).await.unwrap(), PutOutcome::QueueFull);

        let got = s.claim("q", 20, 1, vec![], ClaimMode::Offer { lease_ms: 100 }).await.unwrap();
        assert_eq!(got[0].msgid, "m1");
        // Leased: next claim skips it.
        let got2 = s.claim("q", 21, 5, vec![], ClaimMode::Offer { lease_ms: 100 }).await.unwrap();
        assert_eq!(got2.iter().map(|m| m.msgid.as_str()).collect::<Vec<_>>(), ["m2", "m3"]);
        assert!(!s.has_offerable("q", 22, vec![]).await.unwrap());
        assert!(s.has_offerable("q", 200, vec![]).await.unwrap());
        let w = s.waiting_many(vec!["q".into(), "empty".into()], 22).await.unwrap();
        assert_eq!((w.get("q"), w.get("empty")), (None, None), "all three are leased at 22");
        let w = s.waiting_many(vec!["q".into(), "empty".into()], 200).await.unwrap();
        assert_eq!((w.get("q"), w.len()), (Some(&3), 1));
        assert_eq!(s.made("q", vec!["m1".into(), "nope".into()]).await.unwrap(), [true, false]);
        assert_eq!(s.made("other", vec!["m2".into()]).await.unwrap(), [false]);
        let st = s.stats(30).await.unwrap();
        assert_eq!(st.messages_waiting, 2);
        // Expiry
        let sw = s.sweep(5000, 1_000_000).await.unwrap();
        assert_eq!(sw.messages_expired, 2);
        s.check_writable().await.unwrap();
        s.vacuum().await.unwrap();
    }

    #[tokio::test]
    async fn a_panicking_writer_calls_the_hook_and_fails_writes() {
        let dir = tempfile::tempdir().unwrap();
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = fired.clone();
        let s =
            SqliteStore::open_with(&dir.path().join("t.db"), 1, 64, move || f.store(true, Ordering::SeqCst)).unwrap();
        let r = s.write(|_| -> rusqlite::Result<()> { panic!("test panic in a store job") }).await;
        assert!(r.is_err());
        for _ in 0..100 {
            if fired.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(fired.load(Ordering::SeqCst), "the panic hook did not run");
        assert!(s.check_writable().await.is_err());
    }

    #[tokio::test]
    async fn poison_message_steps_aside() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("t.db"), 1, 64).unwrap();
        s.put_message(msg("q", "a", "1", 10)).await.unwrap();
        s.put_message(msg("q", "b", "2", 11)).await.unwrap();
        for t in 0..3 {
            let g = s.claim("q", 100 + t, 1, vec![], ClaimMode::Offer { lease_ms: 0 }).await.unwrap();
            assert_eq!(g[0].msgid, "m1");
        }
        let g = s.claim("q", 200, 1, vec![], ClaimMode::Offer { lease_ms: 0 }).await.unwrap();
        assert_eq!(g[0].msgid, "m2");
    }

    #[tokio::test]
    async fn cancel_blocks_and_tracks_participants() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("t.db"), 1, 64).unwrap();
        let mut m = msg("bob", "alice", "1", 10);
        m.txid = Some("t".repeat(32));
        assert!(matches!(s.put_message(m.clone()).await.unwrap(), PutOutcome::Stored { .. }));
        let mut intruder = msg("bob", "eve", "2", 11);
        intruder.txid = m.txid.clone();
        assert_eq!(s.put_message(intruder).await.unwrap(), PutOutcome::NotParticipant);
        let info = s.tx_info(&"t".repeat(32)).await.unwrap();
        assert_eq!(info.participants, ["alice", "bob"]);
        let q = s.cancel_tx(&"t".repeat(32), info.participants, Some("bob".into()), 20).await.unwrap();
        assert_eq!(q, ["bob"]);
        let mut again = msg("bob", "alice", "3", 21);
        again.txid = m.txid.clone();
        assert_eq!(s.put_message(again).await.unwrap(), PutOutcome::Cancelled);
        assert_eq!(s.pending_cancel("bob").await.unwrap(), Some("t".repeat(32)));
        s.ack_cancel("bob", &"t".repeat(32)).await.unwrap();
        assert_eq!(s.pending_cancel("bob").await.unwrap(), None);
        assert!(s.use_challenge("c1", 100).await.unwrap());
        assert!(!s.use_challenge("c1", 100).await.unwrap());
    }
}
