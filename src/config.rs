//! Configuration, read from one TOML file. Every field has a default, so an empty file plus
//! `server.domain` is a working relay.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: Server,
    pub store: StoreCfg,
    pub protocol: Protocol,
    pub limits: Limits,
    pub federation: Federation,
    pub http_api: HttpApi,
    pub log: Log,
    pub test: TestCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    /// Websocket and HTTP listener.
    pub listen: SocketAddr,
    /// Separate listener for /metrics. When unset, /metrics is served on `listen` to loopback
    /// and trusted-proxy peers only.
    pub metrics_listen: Option<SocketAddr>,
    /// The domain wallets write in their addresses for this relay (epicbox_domain).
    pub domain: String,
    /// The port wallets write in their addresses (epicbox_port), usually 443.
    pub port: u16,
    /// Other `domain` or `domain:port` names that mean this relay (old names, onion, IP).
    pub aliases: Vec<String>,
    /// Peers whose X-Forwarded-For is trusted (the reverse proxy). Never trust it from others.
    pub trusted_proxies: Vec<IpNet>,
    /// Seconds a SIGTERM drain waits for sockets to close.
    pub drain_seconds: u64,
    /// Name shown in the info document and status JSON.
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StoreCfg {
    pub path: PathBuf,
    /// Days a message is kept when nobody collects it. 7 is the protocol minimum.
    pub retention_days: u32,
    /// Most writes per commit.
    pub group_commit_max: usize,
    /// Reader connections.
    pub readers: usize,
    /// UTC hour of the nightly sweep (incremental vacuum).
    pub vacuum_hour_utc: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirstChallenge {
    /// The fixed constant of the stock relay. Needed by wallets older than 3.5.2.
    Static,
    /// A fresh random challenge per socket.
    Random,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Protocol {
    pub first_challenge: FirstChallenge,
    /// Seconds between Challenge rounds on 3.0.0 sockets.
    pub challenge_interval_s: u64,
    /// Version answered to GetVersion.
    pub getversion: String,
    /// Accept the 3.1.0 cancel fields and CancelTx.
    pub cancel: bool,
    /// Offer mux/1.
    pub mux: bool,
    /// Websocket ping interval, seconds.
    pub ping_interval_s: u64,
    /// Close a socket with no pong (or any frame) for this long, seconds.
    pub idle_timeout_s: u64,
    /// Unanswered Challenges, with mail waiting, before the watchdog closes a socket with 1001.
    pub watchdog_misses: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub max_str_bytes: usize,
    pub posts_per_min_per_address: u32,
    pub posts_burst_per_address: u32,
    pub posts_per_min_per_ip: u32,
    pub posts_burst_per_ip: u32,
    pub bytes_per_min_per_ip: u64,
    pub frames_per_min_per_socket: u32,
    pub queue_cap: u32,
    pub per_sender_cap: u32,
    pub sockets_per_ip: u32,
    pub sockets_per_address: u32,
    pub failed_sigs_per_min_per_ip: u32,
    pub mux_mailboxes_per_socket: u32,
    pub mux_attach_per_frame: u32,
    pub mux_inflight: u32,
    pub mux_attach_frames_per_min: u32,
    /// Prefix length used to group IPv4 clients.
    pub ipv4_prefix: u8,
    /// Prefix length used to group IPv6 clients.
    pub ipv6_prefix: u8,
    pub max_sockets: u32,
    /// Sources many users share (Tor exits, the onion service's loopback). Per-prefix limits are
    /// multiplied by `shared_multiplier` for them.
    pub shared_sources: Vec<IpNet>,
    pub shared_multiplier: u32,
    /// mux/1 sockets per IP prefix.
    pub mux_sockets_per_ip: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Federation {
    pub enabled: bool,
    /// Only these domains (lowercase `domain` or `domain:port`) are forwarded to. Empty means any
    /// domain that resolves to public addresses only.
    pub allow: Vec<String>,
    /// Never forward to these.
    pub deny: Vec<String>,
    /// Allow destinations that resolve to private, loopback or link-local addresses.
    /// Only for test rigs.
    pub allow_private: bool,
    /// Map `domain:port` to an explicit URL (ws:// or wss://). For test rigs and aliases.
    pub peers: BTreeMap<String, String>,
    /// Seconds to wait for connect, Challenge and Ok.
    pub timeout_s: u64,
    /// Parallel peers being delivered to.
    pub max_lanes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpApi {
    pub enabled: bool,
    pub max_mailboxes: usize,
    pub max_per_mailbox: usize,
    pub max_wait_s: u64,
    pub challenge_window_s: u64,
    pub lease_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    /// "text" or "json".
    pub format: String,
    /// tracing filter, e.g. "info" or "epicbox_relay=debug".
    pub level: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TestCfg {
    /// Enables POST /test/stall on loopback: stops Challenges and pushes to an address's sockets,
    /// to reproduce the stock relay's stalled delivery. Never enable on a public relay.
    pub stall_endpoint: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: Server::default(),
            store: StoreCfg::default(),
            protocol: Protocol::default(),
            limits: Limits::default(),
            federation: Federation::default(),
            http_api: HttpApi::default(),
            log: Log::default(),
            test: TestCfg::default(),
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3423".parse().unwrap(),
            metrics_listen: None,
            domain: String::new(),
            port: 443,
            aliases: vec![],
            trusted_proxies: vec![],
            drain_seconds: 10,
            name: "epicbox-relay".into(),
        }
    }
}

impl Default for StoreCfg {
    fn default() -> Self {
        Self {
            path: "epicbox-relay.db".into(),
            retention_days: 7,
            group_commit_max: 256,
            readers: 4,
            vacuum_hour_utc: 3,
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Self {
            first_challenge: FirstChallenge::Static,
            challenge_interval_s: 60,
            getversion: "3.0.0".into(),
            cancel: true,
            mux: true,
            ping_interval_s: 30,
            idle_timeout_s: 90,
            watchdog_misses: 3,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1 << 20,
            max_str_bytes: 128 << 10,
            posts_per_min_per_address: 60,
            posts_burst_per_address: 120,
            posts_per_min_per_ip: 240,
            posts_burst_per_ip: 480,
            bytes_per_min_per_ip: 16 << 20,
            frames_per_min_per_socket: 1200,
            queue_cap: 2000,
            per_sender_cap: 200,
            sockets_per_ip: 256,
            sockets_per_address: 4,
            failed_sigs_per_min_per_ip: 120,
            mux_mailboxes_per_socket: 256,
            mux_attach_per_frame: 64,
            mux_inflight: 32,
            mux_attach_frames_per_min: 30,
            ipv4_prefix: 24,
            ipv6_prefix: 48,
            max_sockets: 150_000,
            shared_sources: vec![],
            shared_multiplier: 16,
            mux_sockets_per_ip: 64,
        }
    }
}

impl Default for Federation {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: vec![],
            deny: vec![],
            allow_private: false,
            peers: BTreeMap::new(),
            timeout_s: 15,
            max_lanes: 64,
        }
    }
}

impl Default for HttpApi {
    fn default() -> Self {
        Self {
            enabled: true,
            max_mailboxes: 64,
            max_per_mailbox: 50,
            max_wait_s: 25,
            challenge_window_s: 20 * 60,
            lease_s: 30,
        }
    }
}

impl Default for Log {
    fn default() -> Self {
        Self { format: "text".into(), level: "info".into() }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.server.domain.is_empty() {
            bail!("server.domain must be set: the domain wallets use in their addresses");
        }
        if !self.server.domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') {
            bail!("server.domain may hold only letters, digits and dots (the address format)");
        }
        if self.store.retention_days < 7 {
            bail!("store.retention_days must be at least 7");
        }
        if self.protocol.challenge_interval_s < 5 {
            bail!("protocol.challenge_interval_s must be at least 5");
        }
        if self.limits.max_str_bytes > self.limits.max_frame_bytes {
            bail!("limits.max_str_bytes must not exceed limits.max_frame_bytes");
        }
        if !(8..=32).contains(&self.limits.ipv4_prefix) || !(16..=128).contains(&self.limits.ipv6_prefix) {
            bail!("limits.ipv4_prefix must be 8..32 and ipv6_prefix 16..128");
        }
        for (k, v) in &self.federation.peers {
            if !(v.starts_with("ws://") || v.starts_with("wss://")) {
                bail!("federation.peers.{k}: URL must start with ws:// or wss://");
            }
        }
        Ok(())
    }

    pub fn retention_secs(&self) -> i64 {
        i64::from(self.store.retention_days) * 86_400
    }

    /// True when `domain`/`port` from a destination names this relay.
    pub fn is_local(&self, domain: &str, port: u16) -> bool {
        let d = domain.to_ascii_lowercase();
        if d == self.server.domain.to_ascii_lowercase() && port == self.server.port {
            return true;
        }
        let with_port = format!("{d}:{port}");
        self.server.aliases.iter().any(|a| {
            let a = a.to_ascii_lowercase();
            if a.contains(':') { a == with_port } else { a == d && port == self.server.port }
        })
    }
}
