//! The log file is on by default, and a relay that cannot write it (run by hand without access
//! to /var/log, say) still starts: one warning on stderr, then stderr only. A separate test
//! binary, because it installs the global log subscriber.

use std::io::Write;
use std::sync::{Arc, Mutex};

use epicmail::config::Log;
use epicmail::logging;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_unwritable_log_file_is_a_warning_not_a_failure() {
    let mut log = Log::default();
    assert!(log.file.enabled, "the log file is on by default");
    assert_eq!(log.file.path, std::path::Path::new("/var/log/epicmail/epicmail.log"));
    assert_eq!((log.file.level.as_str(), log.file.format.as_str()), ("info", "json"));

    // A directory that cannot be created: its parent is a regular file.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("blocker"), "").unwrap();
    log.file.path = dir.path().join("blocker").join("logs").join("relay.log");

    let console = Buf::default();
    let w = console.clone();
    let guard = logging::init_with(&log, true, logging::filter("info"), move || w.clone(), false, false);
    assert!(guard.is_ok(), "a log file that cannot be written must not stop the relay");
    tracing::info!("still logging");

    let out = String::from_utf8(console.0.lock().unwrap().clone()).unwrap();
    let warning = out.lines().find(|l| l.contains("cannot write the log file")).unwrap_or_else(|| panic!("{out}"));
    assert!(warning.contains(" WARN ") && warning.contains("relay.log"), "{warning}");
    assert!(out.contains("still logging"), "{out}");
    assert_eq!(logging::file_dropped(), 0);
}
