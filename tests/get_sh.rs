//! tools/get.sh refuses an install.sh or packaging file that does not match the signed
//! SHA256SUMS, before it runs anything. Uses a throwaway minisign key and a local release
//! directory (EPICMAIL_DOWNLOAD); skipped when minisign is not installed.

use std::path::Path;
use std::process::{Command, Output};

fn have(cmd: &str) -> bool {
    Command::new(cmd).arg("-v").output().is_ok() || Command::new(cmd).arg("--help").output().is_ok()
}

fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" }
}

struct Rel {
    _dir: tempfile::TempDir,
    rel: std::path::PathBuf,
    pubkey: String,
}

/// A signed release 9.9.9 whose install.sh writes `ran` next to itself and exits 7.
fn release() -> Rel {
    let dir = tempfile::tempdir().unwrap();
    let rel = dir.path().join("rel");
    std::fs::create_dir(&rel).unwrap();
    let bin = format!("epicmail-9.9.9-linux-{}", arch());
    std::fs::write(rel.join(&bin), "fake binary").unwrap();
    std::fs::write(rel.join("install.sh"), "#!/bin/sh\ntouch \"$(dirname \"$0\")/ran\"\nexit 7\n").unwrap();
    std::fs::write(rel.join("epicmail.service"), "[Unit]\n").unwrap();
    std::fs::write(rel.join("epicmail.example.toml"), "# example\n").unwrap();
    let ok = |c: &mut Command| assert!(c.status().unwrap().success());
    ok(Command::new("sh").current_dir(&rel).arg("-c").arg(format!(
        "sha256sum {bin} install.sh epicmail.service epicmail.example.toml > SHA256SUMS"
    )));
    let (sk, pk) = (dir.path().join("k.sec"), dir.path().join("k.pub"));
    ok(Command::new("minisign").args(["-G", "-W", "-f", "-s"]).arg(&sk).arg("-p").arg(&pk));
    ok(Command::new("minisign").args(["-S", "-s"]).arg(&sk).arg("-m").arg(rel.join("SHA256SUMS")));
    std::fs::rename(rel.join("SHA256SUMS.minisig"), rel.join("SHA256SUMS.sig")).unwrap();
    let pubkey = std::fs::read_to_string(&pk).unwrap().lines().nth(1).unwrap().to_string();
    Rel { _dir: dir, rel, pubkey }
}

fn run_get(r: &Rel, source: Option<&Path>) -> Output {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/get.sh");
    let mut c = Command::new("sh");
    c.arg(script)
        .args(["--domain", "relay.test", "--no-tls", "--version", "9.9.9"])
        .env("EPICMAIL_DOWNLOAD", format!("file://{}", r.rel.display()))
        .env("EPICMAIL_MINISIGN_KEY", &r.pubkey);
    if let Some(s) = source {
        c.env("EPICMAIL_SOURCE", format!("file://{}", s.display()));
    }
    c.output().unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// A checkout-shaped source dir (tools/install.sh, packaging/...) copied from the release dir.
fn source_of(r: &Rel, root: &Path) -> std::path::PathBuf {
    let s = root.join("src");
    std::fs::create_dir_all(s.join("tools")).unwrap();
    std::fs::create_dir_all(s.join("packaging")).unwrap();
    std::fs::copy(r.rel.join("install.sh"), s.join("tools/install.sh")).unwrap();
    for f in ["epicmail.service", "epicmail.example.toml"] {
        std::fs::copy(r.rel.join(f), s.join("packaging").join(f)).unwrap();
    }
    s
}

#[test]
fn tampered_install_files_are_refused_before_anything_runs() {
    if !have("minisign") {
        eprintln!("skipped: minisign is not installed");
        return;
    }
    // Untampered: the checks pass and the (stub) install.sh runs, exiting 7.
    let r = release();
    let o = run_get(&r, None);
    assert!(text(&o).contains("install files checked"), "{}", text(&o));
    assert_eq!(o.status.code(), Some(7), "{}", text(&o));

    // Each of the three files, tampered after signing, is refused and install.sh never runs.
    for f in ["install.sh", "epicmail.service", "epicmail.example.toml"] {
        let r = release();
        std::fs::write(r.rel.join(f), "#!/bin/sh\ntouch \"$(dirname \"$0\")/ran\"\n# evil\n").unwrap();
        let o = run_get(&r, None);
        assert_eq!(o.status.code(), Some(1), "{f}: {}", text(&o));
        assert!(text(&o).contains(&format!("checksum mismatch: {f}")), "{f}: {}", text(&o));
        assert!(text(&o).contains("Nothing was installed"), "{f}: {}", text(&o));
        assert!(!text(&o).contains("install files checked"));
    }

    // The EPICMAIL_SOURCE route is checked the same way.
    let r = release();
    let root = tempfile::tempdir().unwrap();
    let s = source_of(&r, root.path());
    assert_eq!(run_get(&r, Some(&s)).status.code(), Some(7));
    std::fs::write(s.join("tools/install.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    let o = run_get(&r, Some(&s));
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("checksum mismatch: install.sh"), "{}", text(&o));

    // A release that does not list the files (before 0.1.7) is refused, not run unchecked.
    let r = release();
    let bin = format!("epicmail-9.9.9-linux-{}", arch());
    std::fs::write(r.rel.join("SHA256SUMS"), std::fs::read_to_string(r.rel.join("SHA256SUMS")).unwrap()
        .lines().filter(|l| l.contains(&bin)).collect::<Vec<_>>().join("\n") + "\n").unwrap();
    // The signature no longer matches the edited list: refused earlier, still nothing runs.
    let o = run_get(&r, None);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(!r.rel.join("ran").exists());
}
