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
    /// Answer a browser's `GET /` with the landing page: what the relay is, with live checks.
    pub landing_page: bool,
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
    /// Posts are refused while the database holds this many bytes of live data (pages in use,
    /// not the file size); 0 means no cap. Mail for self-made addresses is limited only per
    /// prefix and per minute, so without a cap enough prefixes could fill the disk.
    pub max_bytes: u64,
    /// Hours after which a payment slate with a txid that has had no answer under that txid is
    /// counted in `epicbox_roundtrip_unanswered`. At most `retention_days` in hours.
    pub unanswered_hours: u32,
}

/// `[protocol]`: the websocket protocol. Every Challenge, the first included, is fresh and
/// random. Wallets older than 3.5.2 sign the original relay's fixed constant instead and so
/// cannot subscribe; a signature over a fixed value never expires and anyone who has seen it
/// could replay it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Protocol {
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
    /// Close a socket with no pong (or any frame) for this long, seconds. Also the longest one
    /// write may wait for a client that does not read.
    pub idle_timeout_s: u64,
    /// Unanswered Challenges, with mail waiting, before the watchdog closes a socket with 1001.
    pub watchdog_misses: u32,
    /// Forward CancelTx signed over the bare txid (the 3.1.0 form wallets use) to the other
    /// relays that hold the transaction. On by default, as the reference cancel relay does:
    /// without it a wallet's cancel never reaches a relay holding a forwarded slate. Off
    /// forwards only CancelTx signed over `epicbox-cancel/1:<txid>`; a bare signature is the
    /// same one the PostSlate carried, so it does not show that the sender asked to cancel.
    pub forward_bare_cancel: bool,
    /// Accept CancelTx signed over the bare txid (the 3.1.0 form stock wallets use). On by
    /// default. Off accepts only the `epicbox-cancel/1:<txid>` form: the bare signature is the
    /// one every PostSlate carries as `epicboxtxidsig`, so anyone who saw the slate holds it.
    pub accept_bare_cancel: bool,
    /// Accept a mux/1 Attach signed over the bare challenge (the first mux/1 form). On by
    /// default. Off accepts only `epicbox-attach/1:<host>:<challenge>`, with `host` one of this
    /// relay's names (`server.domain` and the host part of `server.aliases`).
    pub accept_bare_attach: bool,
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
    /// Bytes per IP per minute: slate bodies posted, plus every websocket frame that is not a
    /// PostSlate.
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
    /// Signature checks per IP per minute, passed or failed: Subscribe, Made, CancelTx and each
    /// mailbox of a mux/1 Attach. Each costs a secp256k1 verification.
    pub sig_checks_per_min_per_ip: u32,
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
    /// /v1 work per IP per minute: each mailbox in a pull and each id in a made costs one.
    pub http_per_min_per_ip: u32,
    /// Mailboxes held by all mux/1 resume tokens together. Past this the oldest tokens are
    /// dropped. Tokens outlive their sockets, so the socket limits do not bound them.
    pub mux_token_mailboxes: u32,
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
    /// Refuse slates for this relay's own mailboxes whose sender address (`es…@host[:port]`)
    /// names one of these hosts. Plain host names; case and port are ignored. The host is what
    /// the sender's wallet wrote in `from`: it is not signed.
    pub deny_sender_hosts: Vec<String>,
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
    /// Long polls (`wait` > 0) waiting at once per IP prefix.
    pub max_waiting_per_ip: u32,
    /// Long polls waiting at once in total.
    pub max_waiting: u32,
}

/// `[log]`: logging to stderr (journald under systemd), and optionally to a file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    /// "text" or "json".
    pub format: String,
    /// tracing filter for stderr, e.g. "info" or "info,epicmail=debug". `RUST_LOG` overrides it.
    pub level: String,
    /// Seconds between traffic summaries at info. A summary is written only when something
    /// changed since the last one.
    pub summary_interval_s: u64,
    /// Bad signatures, or invalid posts, from one network prefix in one summary interval above
    /// which a warning names the prefix. 0: never.
    pub warn_bad_requests: u64,
    /// `[log.file]`: a second output, to a file the relay rotates itself.
    pub file: LogFile,
}

/// `[log.file]`: the log file output, with its own level and format.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogFile {
    pub enabled: bool,
    pub path: PathBuf,
    /// tracing filter for the file; it may be more verbose than `log.level`.
    pub level: String,
    /// "json" or "text".
    pub format: String,
    /// "hourly", "daily" or "size".
    pub rotate: String,
    /// A file is rotated before it grows past this; with "size" it is the only trigger.
    pub max_size_mb: u64,
    /// Rotated files kept.
    pub keep: u32,
    /// Gzip rotated files.
    pub compress: bool,
}

impl Default for LogFile {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "/var/log/epicmail/epicmail.log".into(),
            level: "trace".into(),
            format: "json".into(),
            rotate: "daily".into(),
            max_size_mb: 100,
            keep: 14,
            compress: true,
        }
    }
}

/// `[test]`: switches for test rigs.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TestCfg {
    /// Enables POST /test/stall on loopback: stops Challenges and pushes to an address's sockets
    /// for a while, to test how wallets handle a relay that stops delivering. Never enable on a
    /// public relay.
    pub stall_endpoint: bool,
    /// Base of the per-peer back-off in milliseconds (0: the default, 5000). Lets a test see a
    /// busy peer retried without waiting half a minute.
    pub forward_backoff_ms: i64,
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
            landing_page: true,
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
            max_bytes: 2 << 30,
            unanswered_hours: 24,
        }
    }
}

impl Protocol {
    /// The version answered to GetVersion. With `cancel` off it is capped at 3.0.0: a wallet
    /// that builds its Made `ver` from this answer must not send 3.1.0 to a relay that does not
    /// speak it.
    pub fn getversion_answer(&self) -> &str {
        fn parts(v: &str) -> Option<Vec<u64>> {
            v.split('.').map(|p| p.parse().ok()).collect()
        }
        const CAP: &str = "3.0.0";
        match (self.cancel, parts(&self.getversion), parts(CAP)) {
            (false, Some(v), Some(cap)) if v > cap => CAP,
            _ => &self.getversion,
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Self {
            challenge_interval_s: 60,
            getversion: "3.1.0".into(),
            cancel: true,
            mux: true,
            ping_interval_s: 30,
            idle_timeout_s: 90,
            watchdog_misses: 3,
            forward_bare_cancel: true,
            accept_bare_cancel: true,
            accept_bare_attach: true,
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
            sig_checks_per_min_per_ip: 1200,
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
            http_per_min_per_ip: 1200,
            mux_token_mailboxes: 1_000_000,
        }
    }
}

impl Default for Federation {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: vec![],
            deny: vec![],
            deny_sender_hosts: vec![],
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
            max_waiting_per_ip: 64,
            max_waiting: 10_000,
        }
    }
}

impl Default for Log {
    fn default() -> Self {
        Self {
            format: "text".into(),
            level: "info".into(),
            summary_interval_s: 300,
            warn_bad_requests: 30,
            file: LogFile::default(),
        }
    }
}

impl Config {
    /// Reads, parses and validates a config file.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
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
        if !(1..=self.store.retention_days.saturating_mul(24)).contains(&self.store.unanswered_hours) {
            bail!("store.unanswered_hours must be 1 to store.retention_days * 24");
        }
        if self.store.retention_days < 7 {
            bail!("store.retention_days must be at least 7");
        }
        if self.store.vacuum_hour_utc > 23 {
            bail!("store.vacuum_hour_utc must be 0..23");
        }
        if self.store.readers == 0 || self.store.group_commit_max == 0 {
            bail!("store.readers and store.group_commit_max must be at least 1");
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
        let biggest_v1 = self.http_api.max_mailboxes.max(self.http_api.max_per_mailbox);
        if (self.limits.http_per_min_per_ip as usize) < biggest_v1 {
            bail!("limits.http_per_min_per_ip must be at least http_api.max_mailboxes and http_api.max_per_mailbox");
        }
        if !matches!(self.log.format.as_str(), "text" | "json") {
            bail!("log.format must be \"text\" or \"json\"");
        }
        if let Err(e) = tracing_subscriber::EnvFilter::try_new(&self.log.level) {
            bail!("log.level is not a valid filter: {e}");
        }
        if !(1..=86_400).contains(&self.log.summary_interval_s) {
            bail!("log.summary_interval_s must be 1 to 86400");
        }
        let f = &self.log.file;
        if !matches!(f.format.as_str(), "text" | "json") {
            bail!("log.file.format must be \"text\" or \"json\"");
        }
        if let Err(e) = tracing_subscriber::EnvFilter::try_new(&f.level) {
            bail!("log.file.level is not a valid filter: {e}");
        }
        if crate::logfile::Rotate::parse(&f.rotate).is_none() {
            bail!("log.file.rotate must be \"hourly\", \"daily\" or \"size\"");
        }
        if !(1..=1_000_000).contains(&f.max_size_mb) {
            bail!("log.file.max_size_mb must be 1 to 1000000");
        }
        if !(1..=10_000).contains(&f.keep) {
            bail!("log.file.keep must be 1 to 10000");
        }
        if f.enabled && f.path.file_name().is_none() {
            bail!("log.file.path must name a file");
        }
        for h in &self.federation.deny_sender_hosts {
            let ok = !h.contains(':')
                && normalize_domain(h)
                    .is_some_and(|d| d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'));
            if !ok {
                bail!("federation.deny_sender_hosts: \"{h}\" must be a plain host name such as \"epicbox.example.org\", without a port");
            }
        }
        for (k, v) in &self.federation.peers {
            if !(v.starts_with("ws://") || v.starts_with("wss://")) {
                bail!("federation.peers.{k}: URL must start with ws:// or wss://");
            }
            // Forward rows name peers as lower-case `domain:port`; any other spelling of a key
            // would never match and be ignored without a word.
            let normal = k
                .rsplit_once(':')
                .filter(|(_, p)| p.parse::<u16>().is_ok())
                .and_then(|(d, p)| Some(format!("{}:{p}", normalize_domain(d)?)));
            if normal.as_deref() != Some(k.as_str()) {
                bail!("federation.peers: key \"{k}\" must be lower-case domain:port without a trailing dot");
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
        let Some(d) = normalize_domain(domain) else { return false };
        if Some(d.clone()) == normalize_domain(&self.server.domain) && port == self.server.port {
            return true;
        }
        let with_port = format!("{d}:{port}");
        self.server.aliases.iter().any(|a| {
            let a = a.to_ascii_lowercase();
            let a = a.strip_suffix('.').unwrap_or(&a).to_string();
            if a.contains(':') {
                a == with_port
            } else {
                a == d && port == self.server.port
            }
        })
    }
}

impl Config {
    /// True when `host` (a host name without a port, any case, trailing dot ignored) is one of
    /// the names wallets dial this relay by: `server.domain` or the host part of an alias.
    pub fn is_public_host(&self, host: &str) -> bool {
        let Some(h) = normalize_domain(host) else { return false };
        if normalize_domain(&self.server.domain).as_deref() == Some(h.as_str()) {
            return true;
        }
        self.server.aliases.iter().any(|a| {
            let name = a.rsplit_once(':').map_or(a.as_str(), |(d, _)| d);
            normalize_domain(name).as_deref() == Some(h.as_str())
        })
    }

    /// The listed host in `federation.deny_sender_hosts` that `domain` (the host part of a
    /// sender address) names, in its normal form. Exact match, case-insensitive, trailing dot
    /// ignored; the port is not part of `domain`.
    pub fn denied_sender_host(&self, domain: Option<&str>) -> Option<String> {
        let d = normalize_domain(domain?)?;
        self.federation
            .deny_sender_hosts
            .iter()
            .any(|h| normalize_domain(h).as_deref() == Some(d.as_str()))
            .then_some(d)
    }
}

/// A relay domain in one form: lower case, without the trailing dot of an absolute name.
/// None when it is empty or not a plausible host name (empty labels, leading dot).
pub fn normalize_domain(domain: &str) -> Option<String> {
    let d = domain.to_ascii_lowercase();
    let d = d.strip_suffix('.').unwrap_or(&d);
    if d.is_empty() || d.len() > 253 || d.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return None;
    }
    Some(d.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_have_one_normal_form() {
        assert_eq!(normalize_domain("Relay.Example.org."), Some("relay.example.org".into()));
        assert_eq!(normalize_domain("relay.example.org"), Some("relay.example.org".into()));
        for bad in ["", ".", "a..b", ".a.b", "a.b..", "a.b.."] {
            assert_eq!(normalize_domain(bad), None, "{bad}");
        }
        let mut c = Config::default();
        c.server.domain = "relay.example.org".into();
        c.server.aliases = vec!["old.example.org.".into()];
        assert!(c.is_local("relay.example.org.", 443));
        assert!(c.is_local("RELAY.example.org", 443));
        assert!(c.is_local("old.example.org", 443));
        assert!(!c.is_local("relay.example.org.", 444));
    }

    fn base() -> Config {
        let mut c = Config::default();
        c.server.domain = "relay.example.org".into();
        c
    }

    #[test]
    fn defaults_validate_and_bad_values_are_refused() {
        base().validate().unwrap();
        let cases: [fn(&mut Config); 16] = [
            |c| c.server.domain.clear(),
            |c| c.store.vacuum_hour_utc = 24,
            |c| c.store.readers = 0,
            |c| c.store.retention_days = 6,
            |c| c.store.unanswered_hours = 0,
            |c| c.store.unanswered_hours = 7 * 24 + 1,
            |c| c.limits.http_per_min_per_ip = 10,
            |c| c.log.format = "jsn".into(),
            |c| c.log.level = "epicmail=loud".into(),
            |c| c.log.summary_interval_s = 0,
            |c| c.log.file.rotate = "weekly".into(),
            |c| c.log.file.keep = 0,
            |c| c.log.file.level = "epicmail=loud".into(),
            |c| {
                c.federation.peers.insert("a.example:443".into(), "http://a.example".into());
            },
            |c| {
                c.federation.peers.insert("A.example:443".into(), "wss://a.example/".into());
            },
            |c| {
                c.federation.peers.insert("a.example.:443".into(), "wss://a.example/".into());
            },
        ];
        for (i, f) in cases.iter().enumerate() {
            let mut c = base();
            f(&mut c);
            assert!(c.validate().is_err(), "case {i} passed validation");
        }
    }

    #[test]
    fn denied_sender_hosts_match_the_host_only() {
        let mut c = base();
        assert_eq!(c.denied_sender_host(Some("epicbox.epicmine.io")), None, "empty list denies nothing");
        c.federation.deny_sender_hosts = vec!["Epicbox.Epicmine.io".into()];
        c.validate().unwrap();
        for yes in ["epicbox.epicmine.io", "EPICBOX.EPICMINE.IO", "epicbox.epicmine.io."] {
            assert_eq!(c.denied_sender_host(Some(yes)).as_deref(), Some("epicbox.epicmine.io"), "{yes}");
        }
        for no in
            ["epicmine.io", "x.epicbox.epicmine.io", "epicbox.epicmine.io.evil.example", "epicbox.epicmine.com", ""]
        {
            assert_eq!(c.denied_sender_host(Some(no)), None, "{no}");
        }
        assert_eq!(c.denied_sender_host(None), None);
        for bad in ["epicbox.epicmine.io:443", "", "a..b", "has space.io", "https://x.io"] {
            let mut c = base();
            c.federation.deny_sender_hosts = vec![bad.into()];
            assert!(c.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_keys_are_refused() {
        let err = toml::from_str::<Config>(
            "[server]
domain = \"a.example\"
listen_typo = 1
",
        );
        assert!(err.is_err());
    }
}
