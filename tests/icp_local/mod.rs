//! The tests' local ICP: `tools/icp-local` started once per test binary, asked for a fresh store
//! canister per relay. Its binary is `EPICMAIL_ICP_LOCAL`, or the release build in the tool's
//! directory; the canister wasm is `EPICMAIL_TEST_ICP_WASM`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

use epicmail::config::IcpCfg;
use serde_json::{json, Value};

struct Tool {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Tool {
    fn start() -> Tool {
        let bin = std::env::var_os("EPICMAIL_ICP_LOCAL").map(PathBuf::from).unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/icp-local/target/release/icp-local")
        });
        let mut child = Command::new(&bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("starting {}: {e}", bin.display()));
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let ready = read(&mut stdout);
        assert!(ready["url"].is_string(), "icp-local did not start: {ready}");
        Tool { _child: child, stdin, stdout }
    }

    fn ask(&mut self, req: Value) -> Value {
        writeln!(self.stdin, "{req}").unwrap();
        self.stdin.flush().unwrap();
        let v = read(&mut self.stdout);
        assert!(v["error"].is_null(), "icp-local: {}", v["error"]);
        v
    }
}

fn read(r: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|_| json!({ "error": format!("bad reply {line:?}") }))
}

fn tool() -> &'static Mutex<Tool> {
    static TOOL: OnceLock<Mutex<Tool>> = OnceLock::new();
    TOOL.get_or_init(|| Mutex::new(Tool::start()))
}

/// `[store.icp]` for a fresh canister whose local domains are `domains`, its identity in `dir`.
/// Blocking: call it from `spawn_blocking`.
pub fn store_cfg(dir: &Path, domains: &[String]) -> IcpCfg {
    let wasm = std::env::var("EPICMAIL_TEST_ICP_WASM").expect("EPICMAIL_TEST_ICP_WASM");
    let v = tool().lock().unwrap_or_else(|e| e.into_inner()).ask(json!({
        "op": "new", "wasm": wasm, "dir": dir, "domains": domains,
    }));
    IcpCfg {
        canister: v["canister"].as_str().unwrap().into(),
        url: v["url"].as_str().unwrap().into(),
        identity_pem: v["identity_pem"].as_str().unwrap().into(),
        local_replica: true,
        poll_ms: 100,
        batch_ms: 20,
        ..IcpCfg::default()
    }
}
