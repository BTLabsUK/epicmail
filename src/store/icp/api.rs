//! The canister's front-end API (`docs/icp-frontend.did`) and the calls that carry it, retried
//! through the ICP errors that pass by themselves (a subnet or canister upgrade, a boundary node
//! at its limit). Every method here is safe to retry: the canister keeps one copy of a post or a
//! forward however often it comes, and removing what is already gone is a no-op.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use candid::utils::{ArgumentDecoder, ArgumentEncoder};
use candid::{CandidType, Deserialize, Principal};
use ic_agent::agent::RejectCode;
use ic_agent::{Agent, AgentError};
use tokio::time::{sleep, timeout_at, Instant};

/// The `api_version` this front-end needs at least.
pub const API_VERSION: u32 = 1;

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardKind {
    PostSlate,
    CancelTx,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct MsgMeta {
    pub id: u64,
    pub queue: String,
    pub sender_key: String,
    pub txid: Option<String>,
    pub bytes: u32,
    pub posted_ns: u64,
    pub expires_ns: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct FeMessage {
    pub id: u64,
    pub queue: String,
    pub from: String,
    pub str: String,
    pub signature: String,
    pub txid: Option<String>,
    pub posted_ns: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct FePut {
    pub from: String,
    pub to: String,
    pub str: String,
    pub signature: String,
    pub txid: Option<String>,
    pub txidsig: Option<String>,
    pub remote_endpoint: Option<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum FePutResult {
    Stored(u64),
    Duplicate(u64),
    QueueFull,
    SenderCapped,
    Cancelled,
    NotParticipant,
    Refused(String),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct FeForward {
    pub peer: String,
    pub kind: ForwardKind,
    pub frame: String,
    pub txid: Option<String>,
    pub tx_keys: Vec<String>,
    pub expires_ns: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ForwardRow {
    pub id: u64,
    pub peer: String,
    pub kind: ForwardKind,
    pub frame: String,
    pub attempts: u32,
    pub created_ns: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum ForwardOutcome {
    Done,
    Failed { next_ns: u64, error: String, drop: bool },
    Deferred { next_ns: u64, error: String },
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ForwardResult {
    pub id: u64,
    pub outcome: ForwardOutcome,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum Change {
    Put(MsgMeta),
    Removed { queue: String, ids: Vec<u64> },
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Snapshot {
    pub msgs: Vec<MsgMeta>,
    pub seq: u64,
    pub done: bool,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Changes {
    pub seq: u64,
    pub changes: Vec<Change>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum ChangesReply {
    Ok(Changes),
    Gap,
    Err(String),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Tombstone {
    pub participants: Vec<String>,
    pub receiver: Option<String>,
    pub acknowledged: bool,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct TxInfo {
    pub participants: Vec<String>,
    pub endpoints: Vec<String>,
    pub tombstone: Option<Tombstone>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct FeCancel {
    pub txid: String,
    pub participants: Vec<String>,
    pub receiver: Option<String>,
    pub forwards: Vec<FeForward>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CancelWrite {
    pub queues: Vec<String>,
    pub forwards_queued: u32,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct FeStats {
    pub messages_waiting: u64,
    pub mailboxes_waiting: u64,
    pub oldest_waiting_ns: Option<u64>,
    pub forwards_waiting: u64,
    pub forward_peers: u64,
    pub oldest_forward_ns: Option<u64>,
    pub tombstones: u64,
    pub bytes: u64,
    pub max_bytes: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Version {
    pub canister: String,
    pub core: String,
    pub api_version: u32,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct QueueAck {
    pub queue: String,
    pub ids: Vec<u64>,
}

/// The canister, called as a front-end. The outer error is ICP failing to answer after retries,
/// or the canister refusing the call (`Err text`).
pub struct Canister {
    pub agent: Agent,
    pub id: Principal,
    /// The most one call may take, retries included.
    pub timeout: Duration,
}

fn ok<T>(r: Result<T, String>, method: &str) -> Result<T> {
    r.map_err(|e| anyhow!("{method}: canister refused: {e}"))
}

impl Canister {
    async fn call<A, R>(&self, update: bool, method: &str, args: A) -> Result<R>
    where
        A: ArgumentEncoder,
        R: for<'a> ArgumentDecoder<'a>,
    {
        let arg = candid::encode_args(args)?;
        let deadline = Instant::now() + self.timeout;
        let mut wait = Duration::from_millis(250);
        loop {
            let call = async {
                if update {
                    self.agent.update(&self.id, method).with_arg(arg.clone()).call_and_wait().await
                } else {
                    self.agent.query(&self.id, method).with_arg(arg.clone()).call().await
                }
            };
            match timeout_at(deadline, call).await {
                Ok(Ok(bytes)) => return Ok(candid::decode_args(&bytes)?),
                Ok(Err(e)) if transient(&e) && Instant::now() + wait < deadline => {
                    crate::sampled!(warn, method, error = %e, "icp call failed; retrying");
                    sleep(wait).await;
                    wait = (wait * 2).min(Duration::from_secs(4));
                }
                Ok(Err(e)) => bail!("{method}: {e}"),
                Err(_) => bail!("{method}: no answer within {:?}", self.timeout),
            }
        }
    }

    async fn query<A: ArgumentEncoder, T: CandidType + for<'a> Deserialize<'a>>(
        &self,
        method: &str,
        args: A,
    ) -> Result<T> {
        let (r,): (Result<T, String>,) = self.call(false, method, args).await?;
        ok(r, method)
    }

    async fn update<A: ArgumentEncoder, T: CandidType + for<'a> Deserialize<'a>>(
        &self,
        method: &str,
        args: A,
    ) -> Result<T> {
        let (r,): (Result<T, String>,) = self.call(true, method, args).await?;
        ok(r, method)
    }

    pub async fn version(&self) -> Result<Version> {
        let (v,): (Version,) = self.call(false, "version", ()).await?;
        Ok(v)
    }

    pub async fn put(&self, p: &FePut) -> Result<FePutResult> {
        self.update("fe_put", (p,)).await
    }

    pub async fn put_forward(&self, f: &FeForward) -> Result<bool> {
        self.update("fe_put_forward", (f,)).await
    }

    pub async fn snapshot(&self, after: Option<u64>, limit: u32) -> Result<Snapshot> {
        self.query("fe_snapshot", (after, limit)).await
    }

    /// `None`: `seq` is older than the canister's log keeps.
    pub async fn changes(&self, seq: u64) -> Result<Option<Changes>> {
        let (r,): (ChangesReply,) = self.call(false, "fe_changes", (seq,)).await?;
        match r {
            ChangesReply::Ok(c) => Ok(Some(c)),
            ChangesReply::Gap => Ok(None),
            ChangesReply::Err(e) => bail!("fe_changes: canister refused: {e}"),
        }
    }

    pub async fn fetch(&self, ids: &[u64]) -> Result<Vec<FeMessage>> {
        self.query("fe_fetch", (ids,)).await
    }

    pub async fn ack(&self, acks: &[QueueAck]) -> Result<u64> {
        self.update("fe_ack", (acks,)).await
    }

    pub async fn forward_peers_due(&self) -> Result<Vec<String>> {
        self.query("fe_forward_peers_due", ()).await
    }

    pub async fn forwards_due(&self, peer: &str, limit: u32) -> Result<Vec<ForwardRow>> {
        self.query("fe_forwards_due", (peer, limit)).await
    }

    pub async fn forward_results(&self, results: &[ForwardResult]) -> Result<()> {
        self.update("fe_forward_results", (results,)).await
    }

    pub async fn tx_info(&self, txid: &str) -> Result<TxInfo> {
        self.query("fe_tx_info", (txid,)).await
    }

    pub async fn cancel(&self, c: &FeCancel) -> Result<CancelWrite> {
        self.update("fe_cancel", (c,)).await
    }

    pub async fn pending_cancels(&self, receiver: &str) -> Result<Vec<String>> {
        self.query("fe_pending_cancels", (receiver,)).await
    }

    pub async fn ack_cancel(&self, receiver: &str, txid: &str) -> Result<()> {
        self.update("fe_ack_cancel", (receiver, txid)).await
    }

    pub async fn use_challenge(&self, key: &str, expires_ns: u64) -> Result<bool> {
        self.update("fe_use_challenge", (key, expires_ns)).await
    }

    pub async fn stats(&self) -> Result<FeStats> {
        self.query("fe_stats", ()).await
    }

    pub async fn unanswered(&self, before_ns: u64) -> Result<u64> {
        self.query("fe_unanswered", (before_ns,)).await
    }
}

/// An error that a later identical call may not get.
fn transient(e: &AgentError) -> bool {
    match e {
        AgentError::TransportError(_)
        | AgentError::TimeoutWaitingForResponse()
        | AgentError::CertificateOutdated(_) => true,
        AgentError::HttpError(p) => p.status == 429 || p.status >= 500,
        AgentError::CertifiedReject { reject, .. } | AgentError::UncertifiedReject { reject, .. } => {
            // IC0508 and IC0509: the canister is stopped or stopping, as during an upgrade.
            reject.reject_code == RejectCode::SysTransient
                || matches!(reject.error_code.as_deref(), Some("IC0508" | "IC0509"))
        }
        _ => false,
    }
}
