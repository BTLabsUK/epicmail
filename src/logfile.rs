//! The log file output (`[log.file]`). Log lines go through a bounded queue to one writer
//! thread, which rotates the file by the hour, the day or its size, gzips rotated files and
//! keeps the newest `keep` of them. Logging never waits for the disk: when the queue is full
//! the line is dropped and counted, and housekeeping logs the count.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use tracing_subscriber::fmt::MakeWriter;

use crate::clock::now_ms;

/// Lines that may wait for the writer thread.
pub const QUEUE_LINES: usize = 16_384;

/// When a new file is started, besides `max_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotate {
    Hourly,
    Daily,
    /// Only by size.
    Size,
}

impl Rotate {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hourly" => Some(Self::Hourly),
            "daily" => Some(Self::Daily),
            "size" => Some(Self::Size),
            _ => None,
        }
    }

    /// The UTC hour or day `ms` falls in; one period for `Size`.
    fn period(self, ms: i64) -> i64 {
        match self {
            Self::Hourly => ms.div_euclid(3_600_000),
            Self::Daily => ms.div_euclid(86_400_000),
            Self::Size => 0,
        }
    }
}

/// How the file is rotated and how many rotated files are kept.
#[derive(Debug, Clone)]
pub struct Policy {
    pub rotate: Rotate,
    /// A file is rotated before it grows past this.
    pub max_bytes: u64,
    /// Rotated files kept; older ones are deleted.
    pub keep: usize,
    /// Gzip rotated files.
    pub compress: bool,
}

enum Msg {
    Line(Vec<u8>),
    Flush(SyncSender<()>),
    /// Write what came before, then end the thread. Copies of [`FileLog`] live on in the
    /// subscriber, so the channel never closes by itself.
    Stop,
}

/// The file output's `MakeWriter`. Each log event is one message to the writer thread.
#[derive(Clone)]
pub struct FileLog {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
}

/// Stops the writer thread after the queued lines are written. Held for the life of the process.
pub struct Guard {
    tx: Option<SyncSender<Msg>>,
    thread: Option<JoinHandle<()>>,
}

impl FileLog {
    /// Open the file (creating its directory) and start the writer thread. A path that cannot
    /// be written fails here, at start, rather than losing every line later.
    pub fn start(path: PathBuf, policy: Policy) -> io::Result<(FileLog, Guard)> {
        Self::start_with(path, policy, QUEUE_LINES)
    }

    fn start_with(path: PathBuf, policy: Policy, queue: usize) -> io::Result<(FileLog, Guard)> {
        let out = Rotator::open(path, policy)?;
        let (tx, rx) = mpsc::sync_channel(queue);
        let dropped = Arc::new(AtomicU64::new(0));
        let d = dropped.clone();
        let thread = std::thread::Builder::new().name("log-file".into()).spawn(move || out.run(rx, d))?;
        Ok((FileLog { tx: tx.clone(), dropped }, Guard { tx: Some(tx), thread: Some(thread) }))
    }

    /// Lines dropped since start: the queue was full, or the file could not be written.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Relaxed)
    }

    /// Wait (at most 5 s) until every line queued so far is written.
    pub fn flush(&self) {
        let (ack, done) = mpsc::sync_channel(1);
        if self.tx.send(Msg::Flush(ack)).is_ok() {
            let _ = done.recv_timeout(Duration::from_secs(5));
        }
    }

    fn send(&self, line: Vec<u8>) {
        match self.tx.try_send(Msg::Line(line)) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Relaxed);
            }
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Msg::Stop);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// One log event's bytes, sent to the writer thread when the event is done.
pub struct Line<'a> {
    buf: Vec<u8>,
    log: &'a FileLog,
}

impl Write for Line<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Line<'_> {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            self.log.send(std::mem::take(&mut self.buf));
        }
    }
}

impl<'a> MakeWriter<'a> for FileLog {
    type Writer = Line<'a>;

    fn make_writer(&'a self) -> Line<'a> {
        Line { buf: Vec::with_capacity(256), log: self }
    }
}

/// The open log file, and the rotation of it. Runs on the writer thread.
struct Rotator {
    path: PathBuf,
    policy: Policy,
    file: Option<File>,
    size: u64,
    period: i64,
}

impl Rotator {
    fn open(path: PathBuf, policy: Policy) -> io::Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)?;
        }
        let mut r = Rotator { path, policy, file: None, size: 0, period: 0 };
        // A file left from an earlier hour or day is rotated before new lines go in.
        if let Ok(m) = fs::metadata(&r.path) {
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(now_ms(), |d| d.as_millis() as i64);
            if m.len() > 0 && r.policy.rotate.period(mtime) != r.policy.rotate.period(now_ms()) {
                r.rotate(mtime);
            }
        }
        r.open_file()?;
        Ok(r)
    }

    fn open_file(&mut self) -> io::Result<()> {
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o640);
        let f = o.open(&self.path)?;
        self.size = f.metadata()?.len();
        self.period = self.policy.rotate.period(now_ms());
        self.file = Some(f);
        Ok(())
    }

    fn write(&mut self, line: &[u8]) -> io::Result<()> {
        let now = now_ms();
        let new_period = self.policy.rotate.period(now) != self.period;
        let too_big = self.size > 0 && self.size + line.len() as u64 > self.policy.max_bytes;
        if self.file.is_some() && (new_period || too_big) {
            self.rotate(now);
        }
        if self.file.is_none() {
            self.open_file()?;
        }
        let f = self.file.as_mut().expect("opened above");
        f.write_all(line)?;
        self.size += line.len() as u64;
        Ok(())
    }

    /// Close the file, rename it with the time, and gzip and prune in the background.
    fn rotate(&mut self, at_ms: i64) {
        if let Some(f) = self.file.take() {
            let _ = f.sync_all();
        }
        let Some(target) = self.rotated_name(at_ms) else { return };
        if fs::rename(&self.path, &target).is_err() {
            return;
        }
        let (path, keep, compress) = (self.path.clone(), self.policy.keep, self.policy.compress);
        let work = move || {
            if compress {
                let _ = gzip(&target);
            }
            prune(&path, keep);
        };
        if compress {
            if std::thread::Builder::new().name("log-gzip".into()).spawn(work).is_err() {
                // No thread to spare: the file stays uncompressed and is still pruned.
                prune(&self.path, self.policy.keep);
            }
        } else {
            work();
        }
    }

    /// `<stem>-<UTC time>.<ext>` next to the log file, with `_001`, `_002`... when that name is
    /// taken; both sort after the plain name, so the names still sort by age.
    fn rotated_name(&self, at_ms: i64) -> Option<PathBuf> {
        let (dir, stem, ext) = parts(&self.path)?;
        let base = format!("{stem}-{}", utc_stamp(at_ms));
        (0..1000).map(|n| if n == 0 { base.clone() } else { format!("{base}_{n:03}") }).find_map(|b| {
            let p = dir.join(format!("{b}{ext}"));
            let gz = dir.join(format!("{b}{ext}.gz"));
            (!p.exists() && !gz.exists()).then_some(p)
        })
    }

    fn run(mut self, rx: Receiver<Msg>, dropped: Arc<AtomicU64>) {
        for msg in rx {
            match msg {
                Msg::Line(l) => {
                    if self.write(&l).is_err() {
                        dropped.fetch_add(1, Relaxed);
                        // Reopen on the next line: the file may have been removed or the disk freed.
                        self.file = None;
                    }
                }
                Msg::Flush(ack) => {
                    if let Some(f) = self.file.as_mut() {
                        let _ = f.flush();
                    }
                    let _ = ack.send(());
                }
                Msg::Stop => break,
            }
        }
        if let Some(f) = self.file.as_mut() {
            let _ = f.sync_all();
        }
    }
}

/// The directory, the file name without its extension, and the extension with its dot ("" if
/// none) of the log path.
fn parts(path: &Path) -> Option<(PathBuf, String, String)> {
    let dir = path.parent().map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let stem = path.file_stem()?.to_str()?.to_string();
    let ext = path.extension().and_then(|e| e.to_str()).map_or(String::new(), |e| format!(".{e}"));
    Some((dir, stem, ext))
}

/// Gzip `file` to `file.gz` and remove `file`. On any error `file` is left as it is.
fn gzip(file: &Path) -> io::Result<()> {
    let mut gz_name = file.as_os_str().to_owned();
    gz_name.push(".gz");
    let gz = PathBuf::from(gz_name);
    let mut tmp_name = gz.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    let res = (|| {
        let mut enc = flate2::write::GzEncoder::new(File::create(&tmp)?, flate2::Compression::default());
        io::copy(&mut File::open(file)?, &mut enc)?;
        enc.finish()?.sync_all()?;
        fs::rename(&tmp, &gz)
    })();
    match res {
        Ok(()) => fs::remove_file(file),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Delete all but the newest `keep` rotated files of `path`. Rotated names start with the
/// stem, a dash and the time, so they sort by age.
fn prune(path: &Path, keep: usize) {
    let Some((dir, stem, ext)) = parts(path) else { return };
    let prefix = format!("{stem}-");
    let Ok(entries) = fs::read_dir(&dir) else { return };
    let mut rotated: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| {
            n.strip_prefix(&prefix).is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
                && (n.ends_with(&ext) || n.ends_with(&format!("{ext}.gz")))
        })
        .collect();
    rotated.sort_unstable_by(|a, b| b.cmp(a));
    for old in rotated.iter().skip(keep) {
        let _ = fs::remove_file(dir.join(old));
    }
}

/// `YYYYmmddTHHMMSSZ` for unix milliseconds, in UTC.
fn utc_stamp(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn policy(rotate: Rotate, max_bytes: u64, keep: usize, compress: bool) -> Policy {
        Policy { rotate, max_bytes, keep, compress }
    }

    fn rotated(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("relay-"))
            .collect();
        v.sort();
        v
    }

    fn wait_for(mut f: impl FnMut() -> bool) {
        for _ in 0..200 {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("timed out");
    }

    #[test]
    fn utc_stamps() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(1_763_168_645_000), "20251115T010405Z");
        assert_eq!(utc_stamp(951_782_400_000), "20000229T000000Z");
    }

    #[test]
    fn size_rotation_compresses_and_keeps_the_newest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.log");
        let (log, guard) = FileLog::start(path.clone(), policy(Rotate::Size, 100, 2, true)).unwrap();
        // Four files' worth: 40-byte lines, two to a file.
        for i in 0..8 {
            let mut w = log.make_writer();
            writeln!(w, "line {i:02} {}", "x".repeat(31)).unwrap();
        }
        log.flush();
        // Three rotations happened; the oldest was pruned once the others were compressed.
        wait_for(|| {
            let r = rotated(dir.path());
            r.len() == 2 && r.iter().all(|n| n.ends_with(".log.gz"))
        });
        let r = rotated(dir.path());
        let mut text = String::new();
        flate2::read::GzDecoder::new(File::open(dir.path().join(&r[1])).unwrap()).read_to_string(&mut text).unwrap();
        assert!(text.starts_with("line 04 ") && text.contains("line 05 "), "{text}");
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
        assert_eq!(log.dropped(), 0);
        drop(guard);
    }

    #[test]
    fn a_file_from_an_earlier_day_is_rotated_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.log");
        fs::write(&path, "old\n").unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(2 * 86_400);
        File::options().write(true).open(&path).unwrap().set_modified(old).unwrap();
        let (log, _guard) = FileLog::start(path.clone(), policy(Rotate::Daily, 1 << 20, 5, false)).unwrap();
        writeln!(log.make_writer(), "new").unwrap();
        log.flush();
        let r = rotated(dir.path());
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(fs::read_to_string(dir.path().join(&r[0])).unwrap(), "old\n");
        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    }

    #[test]
    fn a_full_queue_drops_lines_and_counts_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.log");
        let (log, guard) = FileLog::start_with(path.clone(), policy(Rotate::Size, 1 << 20, 5, false), 4).unwrap();
        // Hold the writer thread on a flush it cannot answer until the queue is read again.
        let (ack, done) = mpsc::sync_channel(0);
        log.tx.send(Msg::Flush(ack)).unwrap();
        for i in 0..20 {
            writeln!(log.make_writer(), "line {i}").unwrap();
        }
        let dropped = log.dropped();
        assert!(dropped >= 15, "dropped {dropped}");
        done.recv().unwrap();
        log.flush();
        let written = fs::read_to_string(&path).unwrap().lines().count() as u64;
        assert_eq!(written + dropped, 20);
        drop(guard);
    }
}
