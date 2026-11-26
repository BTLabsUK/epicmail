//! The tests' local ICP: `tools/icp-local` started once per test binary, asked for a store
//! canister per relay store path (a relay restarted on the same path finds its canister). Its binary is `EPICMAIL_ICP_LOCAL`, or the release build in the tool's
//! directory; the canister wasm is `EPICMAIL_TEST_ICP_WASM`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use epicmail::store::icp::IcpCfg;
use serde_json::{json, Value};

struct Tool {
    /// The canister per relay store path.
    stores: HashMap<PathBuf, Value>,
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
        Tool { stores: HashMap::new(), _child: child, stdin, stdout }
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

/// `[store.icp]` for the canister of the relay whose SQLite path would be `path`, made on first
/// use with its identity beside `path`, `domains` as its local domains and `max_bytes` as its
/// cap. Blocking: call it from `spawn_blocking`.
pub fn store_cfg(path: &Path, domains: &[String], max_bytes: u64) -> IcpCfg {
    let dir = path.parent().unwrap();
    let wasm = std::env::var("EPICMAIL_TEST_ICP_WASM").expect("EPICMAIL_TEST_ICP_WASM");
    let mut tool = tool().lock().unwrap_or_else(|e| e.into_inner());
    let v = match tool.stores.get(path) {
        Some(v) => v.clone(),
        None => {
            let v = tool.ask(json!({
                "op": "new", "wasm": wasm, "dir": dir, "domains": domains, "max_bytes": max_bytes,
            }));
            tool.stores.insert(path.to_path_buf(), v.clone());
            v
        }
    };
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
