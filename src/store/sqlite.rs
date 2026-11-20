//! SQLite store. One writer thread owns the only write connection and commits in groups: it takes
//! every write that is waiting (up to `group_commit_max`), runs each in its own savepoint inside
//! one transaction, commits once, and only then answers the callers. Readers use a small pool of
//! read-only connections; WAL lets them read while the writer commits.

use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
CREATE TABLE IF NOT EXISTS cancel_forwards(
  txid TEXT NOT NULL,
  peer TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(txid, peer)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS used_challenges(key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL) WITHOUT ROWID;
"#;

const LINK_KEY: i64 = 0;
const LINK_ENDPOINT: i64 = 1;
/// The sender of the first slate stored under a txid; `created_at` is when it was stored.
const LINK_ORIGIN: i64 = 2;
/// Set once when the other party's first slate under the txid was stored.
const LINK_ANSWER: i64 = 3;
/// Most incremental vacuum rounds of 2000 pages in one daily vacuum (about 32 GiB).
const VACUUM_MAX_ROUNDS: usize = 4096;

type Done = Box<dyn FnOnce(std::result::Result<(), String>) + Send>;
type Job = Box<dyn FnOnce(&Connection) -> Done + Send>;

/// The [`Store`] on one SQLite file.
pub struct SqliteStore {
    tx: mpsc::Sender<Job>,
    readers: Arc<Vec<Mutex<Connection>>>,
    next_reader: AtomicUsize,
    /// Live data bytes, updated by the writer after each commit.
    used: Arc<AtomicU64>,
}

/// Bytes in pages that hold data: page count less free pages, times the page size.
fn used_bytes_of(c: &Connection) -> rusqlite::Result<u64> {
    let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let psize: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok(((pages - free).max(0) * psize) as u64)
}

fn open(path: &Path, flags: OpenFlags) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, flags).with_context(|| format!("opening {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    Ok(conn)
}

/// Dedupe key of a message: the mailbox, the key that signed it, the body and the signature.
/// Not the `from` text, which nobody signs: the same slate re-posted with `from` written
/// another way (`K`, `K@x`, `K@y:1`) is still the same message.
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
            "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA secure_delete=FAST; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; \
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

        let used = Arc::new(AtomicU64::new(used_bytes_of(&writer)?));
        let (tx, rx) = mpsc::channel::<Job>(8192);
        let used_w = used.clone();
        std::thread::Builder::new().name("store-writer".into()).spawn(move || {
            let run = std::panic::AssertUnwindSafe(|| writer_loop(writer, rx, group_max.max(1), used_w));
            if std::panic::catch_unwind(run).is_err() {
                on_writer_panic();
            }
        })?;
        Ok(Self { tx, readers: Arc::new(pool), next_reader: AtomicUsize::new(0), used })
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

fn writer_loop(conn: Connection, mut rx: mpsc::Receiver<Job>, group_max: usize, used: Arc<AtomicU64>) {
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
        } else if let Ok(u) = used_bytes_of(&conn) {
            used.store(u, Ordering::Relaxed);
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

/// Round trip of a payment: remember who sent the first slate under `txid` and when, and when
/// the other party's first slate arrives record the time between them, once. Transactions
/// first seen before this existed have no origin and are skipped. Nothing here leaves the
/// store but the duration.
fn round_trip(conn: &Connection, txid: &str, sender: &str, first: bool, now: i64) -> rusqlite::Result<()> {
    if first {
        conn.prepare_cached("INSERT OR IGNORE INTO txlinks(txid,kind,value,created_at) VALUES(?1,?2,?3,?4)")?
            .execute(params![txid, LINK_ORIGIN, sender, now])?;
        return Ok(());
    }
    let origin: Option<(String, i64)> = conn
        .prepare_cached("SELECT value, created_at FROM txlinks WHERE txid=?1 AND kind=?2")?
        .query_row(params![txid, LINK_ORIGIN], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    if let Some((origin, since)) = origin {
        if origin != sender {
            let added = conn
                .prepare_cached("INSERT OR IGNORE INTO txlinks(txid,kind,value,created_at) VALUES(?1,?2,'1',?3)")?
                .execute(params![txid, LINK_ANSWER, now])?;
            if added == 1 {
                metrics::histogram!("epicbox_roundtrip_seconds").record(((now - since).max(0) as f64) / 1000.0);
            }
        }
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
            let mut first_of_tx = false;
            if let Some(txid) = &m.txid {
                let cancelled: bool = c.prepare_cached("SELECT 1 FROM cancels WHERE txid=?1")?.exists([txid])?;
                if cancelled {
                    return Ok(PutOutcome::Cancelled);
                }
                let parts = tx_participants(c, txid)?;
                if !parts.is_empty() && !parts.iter().any(|p| p == &m.sender_key) {
                    return Ok(PutOutcome::NotParticipant);
                }
                first_of_tx = parts.is_empty();
            }
            let dedupe = dedupe_message(&m.queue, &m.sender_key, &m.body, &m.signature);
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
                round_trip(c, txid, &m.sender_key, first_of_tx, m.created_at)?;
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
                "SELECT queue, count(*) FROM messages \
                 WHERE queue IN (SELECT value FROM json_each(?1)) AND not_before<=?2 AND expires_at>?2 \
                 GROUP BY queue",
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
            let mut st = c.prepare_cached(
                "SELECT peer FROM forwards WHERE next_at<=?1 AND expires_at>?1 \
                     GROUP BY peer ORDER BY min(next_at) LIMIT 1000",
            )?;
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

    async fn forward_deferred(&self, id: i64, next_at: i64, error: &str) -> Result<()> {
        let error: String = error.chars().take(200).collect();
        self.write(move |c| {
            c.prepare_cached("UPDATE forwards SET next_at=?2, last_error=?3 WHERE id=?1")?
                .execute(params![id, next_at, error])?;
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
        forwards: Vec<NewForward>,
    ) -> Result<CancelWrite> {
        let txid = txid.to_string();
        // One writer job runs in one savepoint: any error below undoes all of it.
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
            let mut forwards_queued = 0;
            for f in forwards {
                // Each peer is queued once per transaction, ever: a retry fills gaps and a cancel
                // that comes back from a peer is not sent to it again.
                let first = c
                    .prepare_cached("INSERT OR IGNORE INTO cancel_forwards(txid,peer,created_at) VALUES(?1,?2,?3)")?
                    .execute(params![txid, f.peer, now])?;
                if first == 0 {
                    continue;
                }
                let dedupe = dedupe_forward(&f.peer, &f.frame);
                forwards_queued += c
                    .prepare_cached(
                        "INSERT OR IGNORE INTO forwards(peer,kind,frame,attempts,next_at,created_at,expires_at,dedupe) \
                         VALUES(?1,?2,?3,?4,?5,?5,?6,?7)",
                    )?
                    .execute(params![f.peer, f.kind as i64, f.frame, f.attempts, f.created_at, f.expires_at, dedupe])?;
            }
            Ok(CancelWrite { queues, forwards_queued })
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

    async fn pending_cancels(&self, receiver: &str) -> Result<Vec<String>> {
        let receiver = receiver.to_string();
        self.read(move |c| {
            let mut st = c.prepare_cached(
                "SELECT txid FROM cancels WHERE receiver=?1 AND acknowledged=0 ORDER BY created_at LIMIT 64",
            )?;
            let rows = st.query_map([receiver], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>();
            rows
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
        let stats = self.write(move |c| {
            let cutoff = now - retention_ms;
            // Which peers a cancel was queued for lives as long as its tombstone.
            c.execute("DELETE FROM cancel_forwards WHERE created_at<=?1", [cutoff])?;
            Ok(SweepStats {
                messages_expired: c.execute("DELETE FROM messages WHERE expires_at<=?1", [now])? as u64,
                forwards_expired: c.execute("DELETE FROM forwards WHERE expires_at<=?1", [now])? as u64,
                tombstones_expired: c.execute("DELETE FROM cancels WHERE created_at<=?1", [cutoff])? as u64,
                challenges_expired: c.execute("DELETE FROM used_challenges WHERE expires_at<=?1", [now])? as u64,
                txlinks_expired: c.execute("DELETE FROM txlinks WHERE created_at<=?1", [cutoff])? as u64,
            })
        })
        .await?;
        // Forwards that were never delivered and ran out their retention: otherwise they leave no trace.
        metrics::counter!("epicbox_forwards_expired_total").increment(stats.forwards_expired);
        Ok(stats)
    }

    async fn vacuum(&self) -> Result<()> {
        // Return every free page, 2000 (8 MiB) per writer job so other writes run in between.
        // After a flood that can be gigabytes; the cap only bounds a runaway loop.
        for _ in 0..VACUUM_MAX_ROUNDS {
            let left = self
                .write(|c| {
                    // The pragma returns rows, so it runs as a query (`execute` refuses
                    // statements that return rows) and is stepped to the end, which is when the
                    // pages are freed.
                    let mut st = c.prepare("PRAGMA incremental_vacuum(2000)")?;
                    let mut rows = st.query([])?;
                    while rows.next()?.is_some() {}
                    c.query_row("PRAGMA freelist_count", [], |r| r.get::<_, i64>(0))
                })
                .await?;
            if left == 0 {
                break;
            }
        }
        Ok(())
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
            let used_bytes = used_bytes_of(c)? as i64;
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
                used_bytes,
            })
        })
        .await
    }

    async fn unanswered(&self, before: i64) -> Result<i64> {
        self.read(move |c| {
            c.query_row(
                "SELECT count(*) FROM txlinks o WHERE o.kind=?2 AND o.created_at<=?1 \
                 AND NOT EXISTS (SELECT 1 FROM txlinks a WHERE a.txid=o.txid AND a.kind=?3) \
                 AND NOT EXISTS (SELECT 1 FROM cancels k WHERE k.txid=o.txid)",
                params![before, LINK_ORIGIN, LINK_ANSWER],
                |r| r.get(0),
            )
        })
        .await
    }

    fn used_bytes(&self) -> Option<u64> {
        Some(self.used.load(Ordering::Relaxed))
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
    async fn vacuum_returns_every_free_page() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("t.db"), 2, 64).unwrap();
        // About 6 MiB in 30 slates, then delete them: more than one 2000-page round.
        for i in 0..30 {
            let mut m = msg("q", &format!("s{i}"), &format!("{i}{}", "x".repeat(200_000)), 10);
            m.msgid = format!("m{i}");
            m.queue_cap = 100;
            m.per_sender_cap = 100;
            s.put_message(m).await.unwrap();
        }
        let ids: Vec<String> = (0..30).map(|i| format!("m{i}")).collect();
        s.made("q", ids).await.unwrap();
        s.vacuum().await.unwrap();
        let free: i64 = s.read(|c| c.query_row("PRAGMA freelist_count", [], |r| r.get(0))).await.unwrap();
        assert_eq!(free, 0);
        let st = s.stats(10).await.unwrap();
        assert!(st.db_bytes < 1 << 20, "file did not shrink: {} bytes", st.db_bytes);
    }

    fn cancel_forward(peer: &str) -> NewForward {
        NewForward {
            peer: peer.into(),
            kind: ForwardKind::CancelTx,
            frame: format!("{{\"type\":\"CancelTx\",\"to\":\"{peer}\"}}"),
            txid: None,
            tx_keys: vec![],
            created_at: 10,
            expires_at: 1_000_000,
            attempts: 0,
        }
    }

    #[tokio::test]
    async fn a_cancel_queues_each_peer_once_with_the_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("t.db"), 2, 64).unwrap();
        let t = "t".repeat(32);
        let parts = vec!["alice".to_string(), "bob".to_string()];
        let w = s.cancel_tx(&t, parts.clone(), Some("bob".into()), 10, vec![cancel_forward("a:443")]).await.unwrap();
        assert_eq!(w.forwards_queued, 1);
        assert!(s.tx_info(&t).await.unwrap().tombstone.is_some());
        // Again, with a peer learned since: only the new one is queued.
        let w = s
            .cancel_tx(&t, parts, Some("bob".into()), 11, vec![cancel_forward("a:443"), cancel_forward("b:443")])
            .await
            .unwrap();
        assert_eq!(w.forwards_queued, 1);
        let due = |p: &'static str| {
            let s = &s;
            async move { s.forwards_due(p, 1_000, 10).await.unwrap().len() }
        };
        assert_eq!((due("a:443").await, due("b:443").await), (1, 1));
    }

    #[tokio::test]
    async fn used_bytes_follow_commits() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("t.db"), 2, 64).unwrap();
        let empty = s.used_bytes().unwrap();
        assert!(empty > 0);
        let mut m = msg("q", "a", &"x".repeat(200_000), 10);
        m.msgid = "big".into();
        assert_eq!(s.put_message(m).await.unwrap(), PutOutcome::Stored { msgid: "big".into() });
        let full = s.used_bytes().unwrap();
        assert!(full >= empty + 180_000, "{empty} -> {full}");
        assert_eq!(s.made("q", vec!["big".into()]).await.unwrap(), vec![true]);
        let after = s.used_bytes().unwrap();
        assert!(after + 150_000 < full, "pages were not freed: {full} -> {after}");
        let stats = s.stats(10).await.unwrap().used_bytes as u64;
        assert!(stats.abs_diff(after) <= 8192, "stats {stats}, writer {after}");
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
    async fn round_trips_are_counted_once_and_unanswered_ones_age_into_the_gauge() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("t.db"), 2, 64).unwrap();
        let tx = |mut m: NewMessage, t: &str| {
            m.txid = Some(t.into());
            m
        };
        // t1: S1 from a to b at 1000, answered by b at 5000. t2: S1 never answered. t3: cancelled.
        s.put_message(tx(msg("b", "a", "s1", 1000), "t1")).await.unwrap();
        s.put_message(tx(msg("a", "b", "s2", 5000), "t1")).await.unwrap();
        s.put_message(tx(msg("c", "d", "x1", 1000), "t2")).await.unwrap();
        s.put_message(tx(msg("f", "e", "y1", 1000), "t3")).await.unwrap();
        s.cancel_tx("t3", vec!["e".into(), "f".into()], Some("f".into()), 1500, vec![]).await.unwrap();
        assert_eq!(s.unanswered(999).await.unwrap(), 0, "nothing is old enough yet");
        assert_eq!(s.unanswered(1000).await.unwrap(), 1, "only t2: t1 is answered, t3 is cancelled");
        // A second answer is not a second round trip.
        s.put_message(tx(msg("a", "b", "s2b", 6000), "t1")).await.unwrap();
        let answers: i64 = s
            .read(|c| c.query_row("SELECT count(*) FROM txlinks WHERE kind=3", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(answers, 1);
        // The other party answering t2 closes it.
        s.put_message(tx(msg("c", "e2", "x2", 7000), "t2")).await.unwrap();
        assert_eq!(s.unanswered(1000).await.unwrap(), 1, "e2 is not a participant: still open");
        s.put_message(tx(msg("d", "c", "x3", 7000), "t2")).await.unwrap();
        assert_eq!(s.unanswered(1000).await.unwrap(), 0);
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
        let q = s.cancel_tx(&"t".repeat(32), info.participants, Some("bob".into()), 20, vec![]).await.unwrap().queues;
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
