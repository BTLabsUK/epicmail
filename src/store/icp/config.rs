//! `[store.icp]`: the settings of the ICP store.

use std::path::PathBuf;

use anyhow::{bail, Result};
use serde::Deserialize;

/// `[store.icp]`: the ICP store canister, called through its front-end API
/// (`docs/icp-frontend.did`). The canister owns caps, retention and the byte cap; this relay
/// keeps a mirror of what waits there and answers wallets from it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IcpCfg {
    /// Canister id (principal text).
    pub canister: String,
    /// The ICP API endpoint.
    pub url: String,
    /// PEM file of the front-end identity (secp256k1 or Ed25519), one of the canister's
    /// `frontends`. Read once at start.
    pub identity_pem: PathBuf,
    /// A local replica (PocketIC, dfx): fetch its root key. Never on mainnet.
    pub local_replica: bool,
    /// Milliseconds between reads of the canister's change log, for mail other writers posted.
    pub poll_ms: u64,
    /// Milliseconds acknowledgements and forward results are held to go in one call.
    pub batch_ms: u64,
    /// Seconds one call may take, retries included, before it fails.
    pub call_timeout_s: u64,
}

impl Default for IcpCfg {
    fn default() -> Self {
        Self {
            canister: String::new(),
            url: "https://icp-api.io".into(),
            identity_pem: PathBuf::new(),
            local_replica: false,
            poll_ms: 1000,
            batch_ms: 200,
            call_timeout_s: 30,
        }
    }
}

impl IcpCfg {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.canister.is_empty() || self.identity_pem.as_os_str().is_empty() {
            bail!("store.icp needs canister and identity_pem");
        }
        if !(self.url.starts_with("https://") || self.local_replica && self.url.starts_with("http://")) {
            bail!("store.icp.url must start with https:// (http:// only with local_replica)");
        }
        if self.poll_ms == 0 || self.batch_ms == 0 || self.call_timeout_s == 0 {
            bail!("store.icp.poll_ms, batch_ms and call_timeout_s must be at least 1");
        }
        Ok(())
    }
}
