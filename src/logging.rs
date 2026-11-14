//! Logging setup and the helpers that keep log lines useful, bounded and private.
//!
//! The policy (also in docs/operating.md, "Logging"):
//!
//! - `error`: the relay cannot do its job (store writes failing, a listener stopped).
//! - `warn`: something outside the relay misbehaves (a peer relay unreachable or refusing).
//! - `info`: lifecycle (start, drain, stop), expiry sweeps that removed something, and limits
//!   that refused a request, with the client's network prefix so an operator can act on abuse.
//! - `debug`: one line per post, subscribe, cancel, attach and socket, for tracing a problem.
//!
//! Lines that can repeat under load or attack go through [`sampled!`](crate::sampled): at most
//! [`SAMPLE_PER_MIN`] per call site a minute, each carrying `suppressed`, the number dropped
//! since the last one written.
//!
//! What a line may hold: mailbox keys and txids shortened with [`short`], peer relay host
//! names, network prefixes (never a full client IP) and counts. Never: full addresses or keys,
//! slates, signatures, challenges, resume tokens, message ids or client IPs.

use std::io::IsTerminal;
use std::sync::Mutex;

use tracing_subscriber::EnvFilter;

use crate::address::parse_address;
use crate::config::Log;

/// Lines one sampled call site may write per minute.
pub const SAMPLE_PER_MIN: u32 = 10;

/// Install the global subscriber: stderr, the configured filter (`RUST_LOG` overrides it), and
/// text or JSON lines. Text has no colour codes unless stderr is a terminal, and no timestamp
/// when stderr goes to journald, which stamps every line itself.
pub fn init(cfg: &Log) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.level));
    let b = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal());
    if cfg.format == "json" {
        b.json().flatten_event(true).init();
    } else if std::env::var_os("JOURNAL_STREAM").is_some() {
        b.without_time().init();
    } else {
        b.init();
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
        Self { state: Mutex::new(GateState { window_start_ms: i64::MIN, used: 0, suppressed: 0 }) }
    }

    /// Some(events dropped since the last one admitted) when this one may be written.
    pub fn admit(&self, now_ms: i64) -> Option<u64> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if now_ms.saturating_sub(s.window_start_ms) >= 60_000 {
            s.window_start_ms = now_ms;
            s.used = 0;
        }
        if s.used < SAMPLE_PER_MIN {
            s.used += 1;
            Some(std::mem::take(&mut s.suppressed))
        } else {
            s.suppressed += 1;
            None
        }
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
