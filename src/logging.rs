//! Logging setup and the helpers that keep log lines useful, bounded and private.
//!
//! The policy (also in docs/operating.md, "Logging"):
//!
//! - `error`: the relay cannot do its job (store writes failing, a listener stopped, a panic).
//! - `warn`: something bad outside the relay (a peer relay unreachable or refusing, the store
//!   full), a network prefix sending more bad signatures or invalid posts in a summary interval
//!   than `log.warn_bad_requests`, the log file falling behind.
//! - `info`: lifecycle (start, drain, stop); a traffic summary every `log.summary_interval_s`
//!   when something changed ([`crate::traffic`]); expiry sweeps that removed messages, forwards
//!   or cancel records; forwards delivered, sampled per peer relay. Nothing per client.
//! - `debug`: the life of each message (post, delivery, ack, cancel, forward, each with its id
//!   and result) and each connection opened and closed, with the client IP.
//! - `trace`: every frame, Subscribe, Attach, Resume, Hold, Detach and limit refusal, with the
//!   reason when refused and the client IP.
//!
//! `warn` and `error` lines that can repeat under load or attack go through
//! [`sampled!`](crate::sampled): at most [`SAMPLE_PER_MIN`] per call site a minute, each carrying
//! `suppressed`, the number dropped since the last one written.
//!
//! What a line may hold: mailbox keys and txids shortened with [`short`], peer relay host names
//! and counts at every level; client IPs and message ids at `debug` and `trace` only. Never, at
//! any level: full addresses or keys, slates, signatures, challenges or resume tokens.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::sync::{Mutex, OnceLock};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::address::parse_address;
use crate::config::Log;
use crate::logfile::{self, FileLog};

/// Lines one sampled call site may write per minute.
pub const SAMPLE_PER_MIN: u32 = 10;

/// Keeps the log file's writer thread running; dropping it writes what is queued and stops it.
pub struct LogGuard(#[allow(dead_code)] Option<logfile::Guard>);

/// The file output, once started, for [`file_dropped`].
static FILE: OnceLock<FileLog> = OnceLock::new();

/// Lines the file output dropped since start (queue full or file not writable); 0 without one.
pub fn file_dropped() -> u64 {
    FILE.get().map_or(0, FileLog::dropped)
}

/// Install the global subscriber: stderr with `log.level` (`RUST_LOG` overrides it), and with
/// `with_file` and `log.file.enabled` the log file with its own level and format. When the file
/// cannot be opened (no permission for /var/log when run by hand, say), the relay logs one
/// warning on stderr and runs without it. Text on stderr
/// has no colour codes unless stderr is a terminal, and no timestamp when stderr goes to
/// journald, which stamps every line itself. A panic is logged at error before the default hook
/// runs.
pub fn init(cfg: &Log, with_file: bool) -> anyhow::Result<LogGuard> {
    let journald = std::env::var_os("JOURNAL_STREAM").is_some();
    let console = EnvFilter::try_from_default_env().unwrap_or_else(|_| filter(&cfg.level));
    init_with(cfg, with_file, console, std::io::stderr, std::io::stderr().is_terminal(), journald)
}

/// [`init`] with the stderr writer, its filter and its options given, for tests.
pub fn init_with<W>(
    cfg: &Log,
    with_file: bool,
    console_filter: EnvFilter,
    console: W,
    ansi: bool,
    no_time: bool,
) -> anyhow::Result<LogGuard>
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let mut layers: Vec<Boxed> = vec![output(&cfg.format, console, ansi, no_time).with_filter(console_filter).boxed()];
    let mut guard = None;
    let mut file_error = None;
    if with_file && cfg.file.enabled {
        let f = &cfg.file;
        let policy = logfile::Policy {
            rotate: logfile::Rotate::parse(&f.rotate).unwrap_or(logfile::Rotate::Daily),
            max_bytes: f.max_size_mb.saturating_mul(1 << 20),
            keep: f.keep as usize,
            compress: f.compress,
        };
        match FileLog::start(f.path.clone(), policy) {
            Ok((log, g)) => {
                let _ = FILE.set(log.clone());
                layers.push(output(&f.format, log, false, false).with_filter(filter(&f.level)).boxed());
                guard = Some(g);
            }
            Err(e) => file_error = Some(e),
        }
    }
    tracing_subscriber::registry().with(layers).try_init()?;
    if let Some(e) = file_error {
        tracing::warn!(
            path = %cfg.file.path.display(),
            error = %e,
            "cannot write the log file; logging to stderr only (set log.file.path, or log.file.enabled = false)"
        );
    }
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "panic");
        default_hook(info);
    }));
    Ok(LogGuard(guard))
}

/// The filter for a `level` setting. A bare `trace` or `debug` applies to the relay only, with
/// the libraries at `info`: their own debug and trace output (HTTP, websocket, TLS) can hold
/// whole frames, so it is not turned on by accident. A full filter such as
/// `"debug,tungstenite=trace"` is used as written.
pub fn filter(level: &str) -> EnvFilter {
    match level.trim() {
        l @ ("trace" | "debug") => EnvFilter::new(format!("info,epicmail={l}")),
        other => EnvFilter::new(other),
    }
}

type Boxed = Box<dyn Layer<Registry> + Send + Sync>;

/// One output: text or JSON lines to `w`.
fn output<W>(format: &str, w: W, ansi: bool, no_time: bool) -> Boxed
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let base = tracing_subscriber::fmt::layer().with_writer(w).with_ansi(ansi);
    if format == "json" {
        base.json().flatten_event(true).boxed()
    } else if no_time {
        base.without_time().boxed()
    } else {
        base.boxed()
    }
}

/// A key, txid or other long identifier as a log line shows it: the first and last six
/// characters. Enough to tell mailboxes apart and to match a user's report, not enough to
/// address mail or link a line to a full address without the user's help.
pub fn short(id: &str) -> String {
    let n = id.chars().count();
    if n <= 12 {
        return "…".repeat(n.min(1));
    }
    let head: String = id.chars().take(6).collect();
    let tail: String = id.chars().skip(n - 6).collect();
    format!("{head}…{tail}")
}

/// An Epicbox address as a log line shows it: the shortened key and the relay it names.
pub fn short_addr(addr: &str) -> String {
    match parse_address(addr) {
        Ok(a) => match (a.domain, a.port) {
            (Some(d), Some(p)) => format!("{}@{d}:{p}", short(&a.public_key)),
            (Some(d), None) => format!("{}@{d}", short(&a.public_key)),
            _ => short(&a.public_key),
        },
        Err(_) => "malformed".into(),
    }
}

/// Text from outside (a peer's error description) made safe for one log line: control
/// characters dropped, at most 200 characters.
pub fn clean(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// The budget of one sampled call site.
pub struct Gate {
    state: Mutex<GateState>,
}

struct GateState {
    window_start_ms: i64,
    used: u32,
    suppressed: u64,
}

impl Gate {
    pub const fn new() -> Self {
        Self { state: Mutex::new(GateState::new()) }
    }

    /// Some(events dropped since the last one admitted) when this one may be written.
    pub fn admit(&self, now_ms: i64) -> Option<u64> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).admit(now_ms)
    }
}

impl GateState {
    const fn new() -> Self {
        Self { window_start_ms: i64::MIN, used: 0, suppressed: 0 }
    }

    fn admit(&mut self, now_ms: i64) -> Option<u64> {
        if now_ms.saturating_sub(self.window_start_ms) >= 60_000 {
            self.window_start_ms = now_ms;
            self.used = 0;
        }
        if self.used < SAMPLE_PER_MIN {
            self.used += 1;
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed += 1;
            None
        }
    }
}

/// A [`Gate`] per key, such as a peer relay's name: each key gets its own budget a minute.
pub struct KeyedGate {
    keys: Mutex<BTreeMap<String, GateState>>,
}

/// Keys a [`KeyedGate`] keeps; past it, keys idle for a minute are dropped.
const KEYED_GATE_KEYS: usize = 1024;

impl KeyedGate {
    pub const fn new() -> Self {
        Self { keys: Mutex::new(BTreeMap::new()) }
    }

    /// Some(events of `key` dropped since its last one admitted) when this one may be written.
    pub fn admit(&self, key: &str, now_ms: i64) -> Option<u64> {
        let mut m = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if !m.contains_key(key) && m.len() >= KEYED_GATE_KEYS {
            m.retain(|_, s| now_ms.saturating_sub(s.window_start_ms) < 60_000 || s.suppressed > 0);
        }
        m.entry(key.to_string()).or_insert(GateState::new()).admit(now_ms)
    }
}

impl Default for KeyedGate {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

/// A `tracing` event limited to [`SAMPLE_PER_MIN`] a minute at this call site, with a
/// `suppressed` field: `sampled!(warn, peer, error = %e, "forward failed")`.
#[macro_export]
macro_rules! sampled {
    ($level:ident, $($rest:tt)+) => {{
        static GATE: $crate::logging::Gate = $crate::logging::Gate::new();
        if let Some(suppressed) = GATE.admit($crate::clock::now_ms()) {
            ::tracing::$level!(suppressed, $($rest)+);
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_forms_hide_most_of_the_key() {
        let k = "9rGnvFq1uG7aMNGGdhCWVn5yqVXCCRVqNtkBTXq3C9ykaZ4fDoMd";
        assert_eq!(short(k), "9rGnvF…4fDoMd");
        assert_eq!(short_addr(&format!("epicbox://{k}@relay.example:443")), "9rGnvF…4fDoMd@relay.example:443");
        assert_eq!(short_addr(&format!("{k}@relay.example")), "9rGnvF…4fDoMd@relay.example");
        assert_eq!(short_addr("not an address"), "malformed");
        assert_eq!(short("abc"), "…");
        assert_eq!(short(""), "");
    }

    #[test]
    fn clean_drops_control_characters() {
        assert_eq!(clean("bad\nline\r\x1b[31mred"), "badline[31mred");
        assert_eq!(clean(&"x".repeat(500)).len(), 200);
    }

    #[test]
    fn a_keyed_gate_gives_each_key_its_own_budget() {
        let g = KeyedGate::new();
        for _ in 0..SAMPLE_PER_MIN {
            assert_eq!(g.admit("a.example:443", 1_000), Some(0));
        }
        assert_eq!(g.admit("a.example:443", 1_001), None);
        assert_eq!(g.admit("b.example:443", 1_002), Some(0));
        assert_eq!(g.admit("a.example:443", 61_001), Some(1));
    }

    #[test]
    fn the_gate_admits_a_budget_a_minute_and_counts_the_rest() {
        let g = Gate::new();
        for _ in 0..SAMPLE_PER_MIN {
            assert_eq!(g.admit(1_000), Some(0));
        }
        assert_eq!(g.admit(1_001), None);
        assert_eq!(g.admit(30_000), None);
        assert_eq!(g.admit(61_000), Some(2));
        assert_eq!(g.admit(61_001), Some(0));
    }
}
