//! A store held by the ICP store canister (docs/icp-mailbox.md, "Epicmail in front of the
//! canister"). The canister keeps the messages, forwards, tombstones and challenges; it is the
//! one copy, shared with the writers that post to it directly (other canisters, the legacy
//! Epicbox API).
//!
//! This process keeps a mirror of what waits there, without bodies: ids, queues, txids and
//! times, read with `fe_snapshot` at start and kept current by polling `fe_changes` (queries,
//! which cost no cycles). Delivery state (offers, leases, holds) lives only in the mirror; it
//! is lost on restart, which means a message is offered again. Bodies are fetched when a
//! message is claimed and checked against the sender's signature, so a replica that answers a
//! query falsely cannot hand a wallet a forged message.
//!
//! Writes that answer a wallet (`put_message`, `put_forward`, `cancel_tx`, `use_challenge`) are
//! update calls that return once the canister has committed. Delivery bookkeeping (`made`,
//! `made_in`, a Consume claim's removal and the `forward_*` results) is applied to the mirror
//! at once and sent to the canister in batches every `batch_ms`; `flush` sends what is held.
//!
//! Ids: the canister's message id `n` is the wallet's msgid `icp<n>` and the row id `n`.

pub mod api;
mod config;

pub use self::config::IcpCfg;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use candid::Principal;
use epicmail_core::address::parse_address;
use epicmail_core::limits::offer_key;
use epicmail_core::{refusal, sig};
use ic_agent::identity::{BasicIdentity, Secp256k1Identity};
use ic_agent::{Agent, Identity};
use parking_lot::Mutex;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;

use self::api::{Canister, FeMessage, ForwardOutcome, MsgMeta};
use super::{
    CancelWrite, ClaimMode, ForwardKind, ForwardRow, NewForward, NewMessage, PutOutcome, Stats, Store, StoredMessage,
    SweepStats, Tombstone, TxInfo,
};

/// Ids per batched call: well under the 2 MiB ingress limit.
const BATCH_IDS: usize = 2000;
/// The longest a forward stays hidden after its result was sent: query replicas may lag
/// behind it.
const RESULT_LAG: Duration = Duration::from_secs(30);
const SNAPSHOT_PAGE: u32 = 1000;
/// Not offerable while a claim fetches the body.
const CLAIMING: i64 = i64::MAX;

fn ns(ms: i64) -> u64 {
    (ms.max(0) as u64).saturating_mul(1_000_000)
}

fn ms(ns: u64) -> i64 {
    (ns / 1_000_000) as i64
}

fn msgid(id: u64) -> String {
    format!("icp{id}")
}

fn parse_msgid(s: &str) -> Option<u64> {
    let d = s.strip_prefix("icp")?;
    if d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    d.parse().ok()
}

struct Entry {
    queue: String,
    txid: Option<String>,
    created: i64,
    expires: i64,
    deliveries: i64,
    last_offered: i64,
    not_before: i64,
}

impl Entry {
    fn new(m: &MsgMeta) -> Self {
        Entry {
            queue: m.queue.clone(),
            txid: m.txid.clone(),
            created: ms(m.posted_ns),
            expires: ms(m.expires_ns),
            deliveries: 0,
            last_offered: 0,
            not_before: 0,
        }
    }

    fn offerable(&self, now: i64) -> bool {
        self.not_before <= now && self.expires > now
    }
}

#[derive(Default)]
struct Mirror {
    /// The change sequence this mirror is current to.
    seq: u64,
    msgs: HashMap<u64, Entry>,
    queues: HashMap<String, BTreeSet<u64>>,
    /// Removed here and not yet reported removed by the canister: a Put read from a replica
    /// that is behind must not bring them back.
    removed: HashSet<u64>,
}

impl Mirror {
    /// Add or refresh a message, keeping its delivery state. True when it is new.
    fn put(&mut self, m: &MsgMeta) -> bool {
        if self.removed.contains(&m.id) {
            return false;
        }
        if let Some(e) = self.msgs.get_mut(&m.id) {
            let fresh = Entry::new(m);
            e.created = fresh.created;
            e.expires = fresh.expires;
            return false;
        }
        self.queues.entry(m.queue.clone()).or_default().insert(m.id);
        self.msgs.insert(m.id, Entry::new(m));
        true
    }

    fn take(&mut self, id: u64) -> Option<Entry> {
        let e = self.msgs.remove(&id)?;
        if let Some(q) = self.queues.get_mut(&e.queue) {
            q.remove(&id);
            if q.is_empty() {
                self.queues.remove(&e.queue);
            }
        }
        Some(e)
    }

    /// Remove `id` if it sits in one of `queues`, with the other waiting states of its txid in
    /// that queue (SQLite's `made_one`). Returns its queue.
    fn made(&mut self, queues: &[&str], id: u64) -> Option<String> {
        let e = self.msgs.get(&id).filter(|e| queues.contains(&e.queue.as_str()))?;
        let (queue, txid) = (e.queue.clone(), e.txid.clone());
        let mut gone = vec![id];
        if let Some(t) = txid {
            gone.extend(self.in_queue(&queue).filter(|(_, e)| e.txid.as_ref() == Some(&t)).map(|(i, _)| i));
        }
        for i in gone {
            self.take(i);
            self.removed.insert(i);
        }
        Some(queue)
    }

    fn in_queue<'a>(&'a self, queue: &str) -> impl Iterator<Item = (u64, &'a Entry)> + 'a {
        self.queues.get(queue).into_iter().flatten().filter_map(|id| Some((*id, self.msgs.get(id)?)))
    }

    fn offerable<'a>(&'a self, queue: &str, now: i64) -> impl Iterator<Item = (u64, &'a Entry)> + 'a {
        self.in_queue(queue).filter(move |(_, e)| e.offerable(now))
    }
}

#[derive(Default)]
struct Pending {
    acks: HashMap<String, BTreeSet<u64>>,
    results: HashMap<u64, ForwardOutcome>,
    /// Results in a call now.
    sending: HashSet<u64>,
    /// Results sent, hidden until then.
    recent: HashMap<u64, Instant>,
}

impl Pending {
    fn hidden(&mut self) -> HashSet<u64> {
        let now = Instant::now();
        self.recent.retain(|_, t| *t > now);
        self.results.keys().chain(&self.sending).chain(self.recent.keys()).copied().collect()
    }
}

struct Inner {
    api: Canister,
    poll: Duration,
    batch: Duration,
    mirror: Mutex<Mirror>,
    pending: Mutex<Pending>,
    arrivals: UnboundedSender<String>,
    /// The last batched call went through.
    batch_ok: AtomicBool,
    flushing: tokio::sync::Mutex<()>,
    wake: Notify,
}

pub struct IcpStore {
    inner: Arc<Inner>,
    arrivals: Mutex<Option<UnboundedReceiver<String>>>,
}

fn identity(path: &std::path::Path) -> Result<Box<dyn Identity>> {
    // The parse errors are left out: they could quote the file.
    if let Ok(i) = Secp256k1Identity::from_pem_file(path) {
        return Ok(Box::new(i));
    }
    if let Ok(i) = BasicIdentity::from_pem_file(path) {
        return Ok(Box::new(i));
    }
    bail!("store.icp.identity_pem {}: not a readable secp256k1 or Ed25519 PEM key", path.display())
}

impl IcpStore {
    /// Connect, check the canister's API version, read the snapshot, and start polling.
    pub async fn connect(cfg: &IcpCfg) -> Result<Self> {
        let agent = Agent::builder()
            .with_url(cfg.url.clone())
            .with_boxed_identity(identity(&cfg.identity_pem)?)
            .build()
            .context("icp agent")?;
        if cfg.local_replica {
            agent.fetch_root_key().await.context("icp: fetching the local replica's root key")?;
        }
        let id = Principal::from_text(&cfg.canister).context("store.icp.canister is not a principal")?;
        let api = Canister { agent, id, timeout: Duration::from_secs(cfg.call_timeout_s) };
        let v = api.version().await.context("icp: version")?;
        if v.api_version < api::API_VERSION {
            bail!("canister {id} has front-end API {}, this relay needs {}", v.api_version, api::API_VERSION);
        }
        // The principal the canister's `set_frontends` must list.
        let frontend = api.agent.get_principal().map_err(|e| anyhow!("icp identity: {e}"))?;
        tracing::info!(canister = %id, %frontend, version = %v.canister, core = %v.core, "icp store");
        let (tx, rx) = unbounded_channel();
        let inner = Arc::new(Inner {
            api,
            poll: Duration::from_millis(cfg.poll_ms),
            batch: Duration::from_millis(cfg.batch_ms),
            mirror: Mutex::new(Mirror::default()),
            pending: Mutex::new(Pending::default()),
            arrivals: tx,
            batch_ok: AtomicBool::new(true),
            flushing: tokio::sync::Mutex::new(()),
            wake: Notify::new(),
        });
        inner.resnapshot().await?;
        tokio::spawn(inner.clone().poller());
        tokio::spawn(inner.clone().flusher());
        Ok(IcpStore { inner, arrivals: Mutex::new(Some(rx)) })
    }
}

impl Inner {
    fn arrived(&self, queues: impl IntoIterator<Item = String>) {
        let mut seen = HashSet::new();
        for q in queues {
            if seen.insert(q.clone()) {
                let _ = self.arrivals.send(q);
            }
        }
    }

    /// Read the whole snapshot and replace the mirror with it, keeping the delivery state of
    /// messages still there.
    async fn resnapshot(&self) -> Result<()> {
        let mut after = None;
        let mut seq = None;
        let mut msgs = Vec::new();
        loop {
            let page = self.api.snapshot(after, SNAPSHOT_PAGE).await.context("icp: snapshot")?;
            seq.get_or_insert(page.seq);
            after = page.msgs.last().map(|m| m.id).or(after);
            let done = page.done || page.msgs.is_empty();
            msgs.extend(page.msgs);
            if done {
                break;
            }
        }
        let mut new = Vec::new();
        {
            let mut m = self.mirror.lock();
            let old = std::mem::take(&mut *m);
            m.seq = seq.unwrap_or(0);
            let mut old_msgs = old.msgs;
            for meta in &msgs {
                if old.removed.contains(&meta.id) {
                    m.removed.insert(meta.id);
                    continue;
                }
                m.put(meta);
                match old_msgs.remove(&meta.id) {
                    Some(o) => {
                        let e = m.msgs.get_mut(&meta.id).expect("just put");
                        (e.deliveries, e.last_offered, e.not_before) = (o.deliveries, o.last_offered, o.not_before);
                    }
                    None => new.push(meta.queue.clone()),
                }
            }
        }
        metrics::counter!("epicbox_icp_snapshots_total").increment(1);
        self.arrived(new);
        Ok(())
    }

    async fn poller(self: Arc<Self>) {
        loop {
            let seq = self.mirror.lock().seq;
            let more = match self.api.changes(seq).await {
                Ok(Some(c)) if c.seq > seq => {
                    let more = !c.changes.is_empty();
                    self.apply(c.seq, c.changes);
                    more
                }
                Ok(Some(_)) => false,
                Ok(None) => {
                    tracing::warn!(seq, "icp change log moved past this relay; reading a new snapshot");
                    if let Err(e) = self.resnapshot().await {
                        crate::sampled!(error, error = %e, "icp snapshot failed");
                    }
                    false
                }
                Err(e) => {
                    crate::sampled!(warn, error = %e, "icp change poll failed");
                    false
                }
            };
            if !more {
                tokio::time::sleep(self.poll).await;
            }
        }
    }

    fn apply(&self, seq: u64, changes: Vec<api::Change>) {
        let mut new = Vec::new();
        {
            let mut m = self.mirror.lock();
            if seq <= m.seq {
                return;
            }
            m.seq = seq;
            for c in changes {
                match c {
                    api::Change::Put(meta) => {
                        if m.put(&meta) {
                            new.push(meta.queue);
                        }
                    }
                    api::Change::Removed { ids, .. } => {
                        for id in ids {
                            m.take(id);
                            m.removed.remove(&id);
                        }
                    }
                }
            }
        }
        self.arrived(new);
    }

    fn ack(&self, queue: &str, id: u64) {
        self.pending.lock().acks.entry(queue.to_string()).or_default().insert(id);
        self.wake.notify_one();
    }

    fn result(&self, id: i64, outcome: ForwardOutcome) {
        self.pending.lock().results.insert(id as u64, outcome);
        self.wake.notify_one();
    }

    async fn flusher(self: Arc<Self>) {
        loop {
            self.wake.notified().await;
            tokio::time::sleep(self.batch).await;
            let mut pause = Duration::from_millis(500);
            while let Err(e) = self.flush_now().await {
                crate::sampled!(error, error = %e, "icp batched write failed; retrying");
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(Duration::from_secs(30));
            }
        }
    }

    /// Send everything held back. On an error what was not sent is held again.
    async fn flush_now(&self) -> Result<()> {
        let _one = self.flushing.lock().await;
        loop {
            let (acks, results) = {
                let mut p = self.pending.lock();
                let mut acks = Vec::new();
                let mut n = 0;
                while n < BATCH_IDS {
                    let Some(queue) = p.acks.keys().next().cloned() else { break };
                    let ids = p.acks.remove(&queue).unwrap_or_default();
                    n += ids.len();
                    acks.push(api::QueueAck { queue, ids: ids.into_iter().collect() });
                }
                let ids: Vec<u64> = p.results.keys().take(BATCH_IDS).copied().collect();
                let results: Vec<api::ForwardResult> = ids
                    .into_iter()
                    .filter_map(|id| Some(api::ForwardResult { id, outcome: p.results.remove(&id)? }))
                    .collect();
                p.sending.extend(results.iter().map(|r| r.id));
                (acks, results)
            };
            if acks.is_empty() && results.is_empty() {
                return Ok(());
            }
            let sent = async {
                if !acks.is_empty() {
                    self.api.ack(&acks).await?;
                }
                if !results.is_empty() {
                    self.api.forward_results(&results).await?;
                }
                anyhow::Ok(())
            }
            .await;
            let mut p = self.pending.lock();
            for r in &results {
                p.sending.remove(&r.id);
            }
            if let Err(e) = sent {
                self.batch_ok.store(false, Ordering::Relaxed);
                // An ack sent twice removes nothing the second time, so all go back.
                for a in acks {
                    p.acks.entry(a.queue).or_default().extend(a.ids);
                }
                for r in results {
                    // A result recorded since is newer.
                    p.results.entry(r.id).or_insert(r.outcome);
                }
                return Err(e);
            }
            let (now, wall) = (Instant::now(), crate::clock::now_ms());
            p.recent.extend(results.iter().map(|r| (r.id, now + hide_for(&r.outcome, wall))));
            self.batch_ok.store(true, Ordering::Relaxed);
            metrics::counter!("epicbox_icp_batches_total").increment(1);
        }
    }
}

/// How long a row stays hidden once its result is sent. A retried row is due again at its
/// `next_ns` whether or not the replica asked has seen the result yet; until then, and for
/// `RESULT_LAG` after a row is removed, a lagging replica could hand it back too early.
fn hide_for(outcome: &ForwardOutcome, now_ms: i64) -> Duration {
    match outcome {
        ForwardOutcome::Failed { next_ns, drop: false, .. } | ForwardOutcome::Deferred { next_ns, .. } => {
            Duration::from_millis((ms(*next_ns) - now_ms).max(0) as u64).min(RESULT_LAG)
        }
        _ => RESULT_LAG,
    }
}

/// The body belongs to the entry claimed and carries its sender's signature.
fn genuine(b: &FeMessage, queue: &str) -> bool {
    b.queue == queue && parse_address(&b.from).is_ok_and(|a| sig::verify(&a.public_key, &b.str, &b.signature).is_ok())
}

fn forward(f: NewForward) -> api::FeForward {
    api::FeForward {
        peer: f.peer,
        kind: match f.kind {
            ForwardKind::PostSlate => api::ForwardKind::PostSlate,
            ForwardKind::CancelTx => api::ForwardKind::CancelTx,
        },
        frame: f.frame,
        txid: f.txid,
        tx_keys: f.tx_keys,
        expires_ns: ns(f.expires_at),
    }
}

#[async_trait]
impl Store for IcpStore {
    async fn put_message(&self, m: NewMessage) -> Result<PutOutcome> {
        let r = self
            .inner
            .api
            .put(&api::FePut {
                from: m.sender,
                to: m.recipient,
                str: m.body,
                signature: m.signature,
                txid: m.txid.clone(),
                txidsig: m.txidsig,
                remote_endpoint: m.remote_endpoint,
            })
            .await?;
        Ok(match r {
            api::FePutResult::Stored(id) => {
                self.inner.mirror.lock().put(&MsgMeta {
                    id,
                    queue: m.queue,
                    sender_key: m.sender_key,
                    txid: m.txid,
                    bytes: 0,
                    posted_ns: ns(m.created_at),
                    expires_ns: ns(m.expires_at),
                });
                PutOutcome::Stored { msgid: msgid(id) }
            }
            api::FePutResult::Duplicate(id) => PutOutcome::Duplicate { msgid: msgid(id) },
            api::FePutResult::QueueFull => PutOutcome::QueueFull,
            api::FePutResult::SenderCapped => PutOutcome::SenderCapped,
            api::FePutResult::Cancelled => PutOutcome::Cancelled,
            api::FePutResult::NotParticipant => PutOutcome::NotParticipant,
            api::FePutResult::Refused(t) if t == refusal::STORE_FULL => PutOutcome::StoreFull,
            // This relay checked the post already: the two disagree on the rules.
            api::FePutResult::Refused(t) => bail!("fe_put: canister refused a post this relay accepted: {t}"),
        })
    }

    async fn has_offerable(&self, queue: &str, now: i64, exclude: Vec<i64>) -> Result<bool> {
        Ok(self.inner.mirror.lock().offerable(queue, now).any(|(id, _)| !exclude.contains(&(id as i64))))
    }

    async fn waiting(&self, queue: &str, now: i64) -> Result<i64> {
        Ok(self.inner.mirror.lock().offerable(queue, now).count() as i64)
    }

    async fn waiting_many(&self, queues: Vec<String>, now: i64) -> Result<HashMap<String, i64>> {
        let m = self.inner.mirror.lock();
        Ok(queues
            .into_iter()
            .filter_map(|q| {
                let n = m.offerable(&q, now).count() as i64;
                (n > 0).then_some((q, n))
            })
            .collect())
    }

    async fn claim(
        &self,
        queue: &str,
        now: i64,
        limit: usize,
        exclude: Vec<i64>,
        mode: ClaimMode,
    ) -> Result<Vec<StoredMessage>> {
        // Pick and mark under the lock, so a second claim cannot take the same messages while
        // the bodies are fetched.
        let picked: Vec<(u64, i64)> = {
            let mut m = self.inner.mirror.lock();
            let mut c: Vec<_> = m
                .offerable(queue, now)
                .filter(|(id, _)| !exclude.contains(&(*id as i64)))
                .map(|(id, e)| (offer_key(e.deliveries, e.last_offered, e.created, id as i64), id))
                .collect();
            c.sort_unstable();
            c.truncate(limit);
            c.into_iter()
                .map(|(_, id)| {
                    let e = m.msgs.get_mut(&id).expect("listed");
                    (id, std::mem::replace(&mut e.not_before, CLAIMING))
                })
                .collect()
        };
        if picked.is_empty() {
            return Ok(vec![]);
        }
        let ids: Vec<u64> = picked.iter().map(|p| p.0).collect();
        let fetched = self.inner.api.fetch(&ids).await;
        let mut m = self.inner.mirror.lock();
        let mut bodies: HashMap<u64, FeMessage> = match fetched {
            Ok(b) => b.into_iter().map(|b| (b.id, b)).collect(),
            Err(e) => {
                for (id, nb) in &picked {
                    if let Some(e) = m.msgs.get_mut(id) {
                        e.not_before = *nb;
                    }
                }
                return Err(e);
            }
        };
        let mut out = Vec::with_capacity(picked.len());
        for (id, nb) in picked {
            // Gone meanwhile (acknowledged by another writer, cancelled, expired): not offered.
            let Some(e) = m.msgs.get_mut(&id) else { continue };
            let Some(b) = bodies.remove(&id).filter(|b| genuine(b, queue)) else {
                // Left out of a reply at its size cap, or not what was asked for: offered later.
                if bodies.contains_key(&id) {
                    crate::sampled!(warn, id, "icp body failed its signature check; not offered");
                }
                e.not_before = nb;
                continue;
            };
            let deliveries = match mode {
                ClaimMode::Offer { lease_ms } => {
                    e.deliveries += 1;
                    e.last_offered = now;
                    e.not_before = if lease_ms > 0 { now + lease_ms } else { 0 };
                    e.deliveries
                }
                ClaimMode::Consume => {
                    let d = e.deliveries;
                    m.take(id);
                    m.removed.insert(id);
                    self.inner.ack(queue, id);
                    d
                }
            };
            out.push(StoredMessage {
                id: id as i64,
                msgid: msgid(id),
                queue: b.queue,
                sender: b.from,
                body: b.str,
                signature: b.signature,
                challenge: String::new(),
                txid: b.txid,
                deliveries,
                created_at: ms(b.posted_ns),
            });
        }
        Ok(out)
    }

    async fn release(&self, ids: Vec<i64>) -> Result<()> {
        let mut m = self.inner.mirror.lock();
        for id in ids {
            if let Some(e) = m.msgs.get_mut(&(id as u64)) {
                e.not_before = 0;
            }
        }
        Ok(())
    }

    async fn hold(&self, queue: &str, msgid: &str, until: i64) -> Result<bool> {
        let mut m = self.inner.mirror.lock();
        let e = parse_msgid(msgid).and_then(|id| m.msgs.get_mut(&id)).filter(|e| e.queue == queue);
        Ok(e.map(|e| e.not_before = until).is_some())
    }

    async fn made(&self, queue: &str, msgids: Vec<String>) -> Result<Vec<bool>> {
        Ok(msgids.iter().map(|s| self.made_one(&[queue], s)).collect())
    }

    async fn made_in(&self, queues: Vec<String>, msgids: Vec<String>) -> Result<u64> {
        let qs: Vec<&str> = queues.iter().map(String::as_str).collect();
        Ok(msgids.iter().filter(|s| self.made_one(&qs, s)).count() as u64)
    }

    async fn put_forward(&self, f: NewForward) -> Result<bool> {
        self.inner.api.put_forward(&forward(f)).await
    }

    async fn forward_peers_due(&self, _now: i64) -> Result<Vec<String>> {
        self.inner.api.forward_peers_due().await
    }

    async fn forwards_due(&self, peer: &str, _now: i64, limit: usize) -> Result<Vec<ForwardRow>> {
        // Rows whose result is not in the canister's view yet stay hidden, or the forward
        // loop would send them again.
        let hidden = self.inner.pending.lock().hidden();
        let ask = u32::try_from(limit + hidden.len()).unwrap_or(u32::MAX);
        let rows = self.inner.api.forwards_due(peer, ask).await?;
        Ok(rows
            .into_iter()
            .filter(|r| !hidden.contains(&r.id))
            .take(limit)
            .map(|r| ForwardRow {
                id: r.id as i64,
                peer: r.peer,
                kind: match r.kind {
                    api::ForwardKind::PostSlate => ForwardKind::PostSlate,
                    api::ForwardKind::CancelTx => ForwardKind::CancelTx,
                },
                frame: r.frame,
                attempts: i64::from(r.attempts),
                created_at: ms(r.created_ns),
            })
            .collect())
    }

    async fn forward_done(&self, id: i64) -> Result<()> {
        self.inner.result(id, ForwardOutcome::Done);
        Ok(())
    }

    async fn forward_failed(&self, id: i64, next_at: i64, error: &str, drop: bool) -> Result<()> {
        self.inner.result(id, ForwardOutcome::Failed { next_ns: ns(next_at), error: error.into(), drop });
        Ok(())
    }

    async fn forward_deferred(&self, id: i64, next_at: i64, error: &str) -> Result<()> {
        self.inner.result(id, ForwardOutcome::Deferred { next_ns: ns(next_at), error: error.into() });
        Ok(())
    }

    async fn tx_info(&self, txid: &str) -> Result<TxInfo> {
        let t = self.inner.api.tx_info(txid).await?;
        Ok(TxInfo {
            participants: t.participants,
            endpoints: t.endpoints,
            tombstone: t.tombstone.map(|t| Tombstone {
                participants: t.participants,
                receiver: t.receiver,
                acknowledged: t.acknowledged,
            }),
        })
    }

    async fn cancel_tx(
        &self,
        txid: &str,
        participants: Vec<String>,
        receiver: Option<String>,
        _now: i64,
        forwards: Vec<NewForward>,
    ) -> Result<CancelWrite> {
        let w = self
            .inner
            .api
            .cancel(&api::FeCancel {
                txid: txid.into(),
                participants,
                receiver,
                forwards: forwards.into_iter().map(forward).collect(),
            })
            .await?;
        let mut m = self.inner.mirror.lock();
        let gone: Vec<u64> =
            m.msgs.iter().filter(|(_, e)| e.txid.as_deref() == Some(txid)).map(|(id, _)| *id).collect();
        for id in gone {
            m.take(id);
            m.removed.insert(id);
        }
        Ok(CancelWrite { queues: w.queues, forwards_queued: w.forwards_queued as usize })
    }

    async fn pending_cancel(&self, receiver: &str) -> Result<Option<String>> {
        Ok(self.inner.api.pending_cancels(receiver).await?.into_iter().next())
    }

    async fn pending_cancels(&self, receiver: &str) -> Result<Vec<String>> {
        self.inner.api.pending_cancels(receiver).await
    }

    async fn ack_cancel(&self, receiver: &str, txid: &str) -> Result<()> {
        self.inner.api.ack_cancel(receiver, txid).await
    }

    async fn use_challenge(&self, key: &str, expires_at: i64) -> Result<bool> {
        self.inner.api.use_challenge(key, ns(expires_at)).await
    }

    /// The canister expires its own rows.
    async fn sweep(&self, _now: i64, _retention_ms: i64) -> Result<SweepStats> {
        Ok(SweepStats::default())
    }

    async fn vacuum(&self) -> Result<()> {
        Ok(())
    }

    async fn stats(&self, now: i64) -> Result<Stats> {
        let s = self.inner.api.stats().await?;
        let age = |t: Option<u64>| t.map_or(0, |t| (now - ms(t)).max(0));
        let oldest_unoffered = {
            let m = self.inner.mirror.lock();
            m.msgs.values().filter(|e| e.deliveries == 0 && e.offerable(now)).map(|e| e.created).min()
        };
        Ok(Stats {
            messages_waiting: s.messages_waiting as i64,
            mailboxes_waiting: s.mailboxes_waiting as i64,
            oldest_waiting_ms: age(s.oldest_waiting_ns),
            oldest_unoffered_ms: oldest_unoffered.map_or(0, |c| (now - c).max(0)),
            forwards_waiting: s.forwards_waiting as i64,
            forward_peers: s.forward_peers as i64,
            oldest_forward_ms: age(s.oldest_forward_ns),
            tombstones: s.tombstones as i64,
            db_bytes: s.bytes as i64,
            used_bytes: s.bytes as i64,
        })
    }

    async fn unanswered(&self, before: i64) -> Result<i64> {
        Ok(self.inner.api.unanswered(ns(before)).await? as i64)
    }

    /// A query round trip (an update per /ready would cost cycles), and the batched writes
    /// going through.
    async fn check_writable(&self) -> Result<()> {
        self.inner.api.version().await?;
        if !self.inner.batch_ok.load(Ordering::Relaxed) {
            bail!("icp: batched acknowledgements are failing");
        }
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        self.inner.flush_now().await
    }

    fn take_arrivals(&self) -> Option<UnboundedReceiver<String>> {
        self.arrivals.lock().take()
    }
}

impl IcpStore {
    fn made_one(&self, queues: &[&str], msgid: &str) -> bool {
        let Some(id) = parse_msgid(msgid) else { return false };
        let Some(queue) = self.inner.mirror.lock().made(queues, id) else { return false };
        self.inner.ack(&queue, id);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: u64, queue: &str, txid: Option<&str>, posted_ms: i64) -> MsgMeta {
        MsgMeta {
            id,
            queue: queue.into(),
            sender_key: "s".into(),
            txid: txid.map(Into::into),
            bytes: 1,
            posted_ns: ns(posted_ms),
            expires_ns: ns(i64::MAX / 2_000_000),
        }
    }

    #[test]
    fn msgids_are_icp_and_digits() {
        assert_eq!(parse_msgid(&msgid(42)), Some(42));
        for bad in ["icp", "icp-1", "icp1a", "ICP1", "1", "icp 1"] {
            assert_eq!(parse_msgid(bad), None, "{bad}");
        }
    }

    #[test]
    fn made_takes_the_txid_siblings_in_that_queue_only() {
        let mut m = Mirror::default();
        m.put(&meta(1, "a", Some("t"), 1));
        m.put(&meta(2, "a", Some("t"), 2));
        m.put(&meta(3, "b", Some("t"), 3));
        m.put(&meta(4, "a", None, 4));
        assert_eq!(m.made(&["b"], 1), None);
        assert_eq!(m.made(&["a"], 1).as_deref(), Some("a"));
        let left: Vec<u64> = m.msgs.keys().copied().collect::<BTreeSet<_>>().into_iter().collect();
        assert_eq!(left, [3, 4]);
        assert!(m.removed.contains(&1) && m.removed.contains(&2));
    }

    #[test]
    fn a_stale_put_does_not_bring_back_a_removed_message() {
        let mut m = Mirror::default();
        assert!(m.put(&meta(1, "a", None, 1)));
        m.made(&["a"], 1);
        assert!(!m.put(&meta(1, "a", None, 1)));
        assert!(m.msgs.is_empty());
    }

    #[test]
    fn a_refreshed_put_keeps_the_delivery_state() {
        let mut m = Mirror::default();
        m.put(&meta(1, "a", None, 1));
        m.msgs.get_mut(&1).unwrap().deliveries = 2;
        assert!(!m.put(&meta(1, "a", None, 1)));
        assert_eq!(m.msgs[&1].deliveries, 2);
    }
}
