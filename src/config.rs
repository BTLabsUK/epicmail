//! Configuration, read from one TOML file. Every field has a default, so an empty file plus
//! `server.domain` is a working relay.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

/// The whole file. Each field is one `[section]`.
#[derive(Debug, Clone, Default, Deserialize)]
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

/// `[server]`: listeners and the relay's identity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    /// Websocket and HTTP listener.
    pub listen: SocketAddr,
    /// Separate listener for /metrics. When unset, /metrics is served on `listen` to loopback
    /// peers whose request has no X-Forwarded-For.
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

/// `[store]`: the SQLite database.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StoreCfg {
    /// The database file. Created if missing.
    pub path: PathBuf,
    /// Days a message is kept when nobody collects it. 7 is the protocol minimum.
    pub retention_days: u32,
    /// Most writes per commit.
    pub group_commit_max: usize,
    /// Reader connections.
    pub readers: usize,
    /// UTC hour of the daily incremental vacuum.
    pub vacuum_hour_utc: u8,
}

/// The Challenge sent when a socket opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirstChallenge {
    /// The fixed constant of the stock relay. Needed by wallets older than 3.5.2.
    Static,
    /// A fresh random challenge per socket.
    Random,
}

/// `[protocol]`: the websocket protocol.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Protocol {
    /// The Challenge sent when a socket opens.
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
    /// Also forward CancelTx signed over the bare txid (the 3.1.0 form) to other relays. When
    /// off, only CancelTx signed over `epicbox-cancel/1:<txid>` is forwarded: a signature over
    /// the bare txid is the same one the PostSlate carried, so it does not show that the sender
    /// asked to cancel.
    pub forward_bare_cancel: bool,
}

/// `[limits]`. "Per IP" means per IP prefix (`ipv4_prefix`, `ipv6_prefix`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Largest websocket frame, bytes.
    pub max_frame_bytes: usize,
    /// Largest string field (a slate), bytes. Not above `max_frame_bytes`.
    pub max_str_bytes: usize,
    /// PostSlate rate per sender address.
    pub posts_per_min_per_address: u32,
    /// Burst allowance for `posts_per_min_per_address`.
    pub posts_burst_per_address: u32,
    /// PostSlate rate per IP.
    pub posts_per_min_per_ip: u32,
    /// Burst allowance for `posts_per_min_per_ip`.
    pub posts_burst_per_ip: u32,
    /// Posted bytes per IP per minute.
    pub bytes_per_min_per_ip: u64,
    /// Frames one socket may send per minute.
    pub frames_per_min_per_socket: u32,
    /// Waiting messages per mailbox.
    pub queue_cap: u32,
    /// Waiting messages per mailbox from one sender.
    pub per_sender_cap: u32,
    /// Open sockets per IP.
    pub sockets_per_ip: u32,
    /// Classic sockets kept per subscribed address.
    pub sockets_per_address: u32,
    /// Failed signature checks per IP per minute before posts from it are refused.
    pub failed_sigs_per_min_per_ip: u32,
    /// Mailboxes one mux/1 socket may attach.
    pub mux_mailboxes_per_socket: u32,
    /// Mailboxes in one Attach or Resume frame.
    pub mux_attach_per_frame: u32,
    /// Mail pushed on one mux/1 socket and not yet acked or held.
    pub mux_inflight: u32,
    /// Attach and Resume frames per mux/1 socket per minute.
    pub mux_attach_frames_per_min: u32,
    /// Prefix length used to group IPv4 clients.
    pub ipv4_prefix: u8,
    /// Prefix length used to group IPv6 clients.
    pub ipv6_prefix: u8,
    /// Open sockets in total.
    pub max_sockets: u32,
    /// Sources many users share (Tor exits, the onion service's loopback). Per-prefix limits are
    /// multiplied by `shared_multiplier` for them.
    pub shared_sources: Vec<IpNet>,
    /// Factor for `shared_sources`.
    pub shared_multiplier: u32,
    /// mux/1 sockets per IP prefix.
    pub mux_sockets_per_ip: u32,
}

/// `[federation]`: forwarding mail to other relays.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Federation {
    /// Forward mail addressed to other relays. When off, such posts are refused.
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

/// `[http_api]`: the /v1 HTTPS mailbox API.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpApi {
    /// Serve /v1.
    pub enabled: bool,
    /// Mailboxes per request.
    pub max_mailboxes: usize,
    /// Messages per mailbox per pull.
    pub max_per_mailbox: usize,
    /// Longest long poll, seconds.
    pub max_wait_s: u64,
    /// Seconds a client-made challenge stays valid.
    pub challenge_window_s: u64,
    /// Seconds a pulled message stays leased to the puller.
    pub lease_s: u64,
}

/// `[log]`: logging to stderr.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    /// "text" or "json".
    pub format: String,
    /// tracing filter, e.g. "info" or "epicmail=debug".
    pub level: String,
}

/// `[test]`: switches for test rigs.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TestCfg {
    /// Enables POST /test/stall on loopback: stops Challenges and pushes to an address's sockets
    /// for a while, to test how wallets handle a relay that stops delivering. Never enable on a
    /// public relay.
    pub stall_endpoint: bool,
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
            name: "epicmail".into(),
        }
    }
}

impl Default for StoreCfg {
    fn default() -> Self {
        Self {
            path: "epicmail.db".into(),
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
            forward_bare_cancel: false,
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
    /// Reads, parses and validates a config file.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Checks the values serde cannot: required fields, ranges and cross-field rules.
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

    /// `store.retention_days` in seconds.
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
