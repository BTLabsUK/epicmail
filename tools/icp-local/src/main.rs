//! A local ICP for Epicmail's tests and staging runs: one PocketIC instance, live on a local HTTP
//! gateway, with a store canister per front-end on request.
//!
//! Needs `POCKET_IC_BIN` (the pocket-ic server binary). Prints `{"url": …}` once the gateway is
//! up, then answers one JSON request per stdin line with one JSON line on stdout:
//!
//! - `{"op":"new","wasm":PATH,"dir":DIR,"domains":[…]}`: a fresh canister from `wasm` with a new
//!   Ed25519 front-end identity written to `dir`, and `domains` as its local domains. Answers
//!   `{"canister":ID,"url":URL,"identity_pem":PATH}`.
//! - `{"op":"cycles","canister":ID}`: answers `{"cycles":N}`.
//!
//! Errors answer `{"error":TEXT}`. It ends at end of input, and the instance with it.

use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use candid::{Decode, Encode, Principal};
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde_json::{json, Value};

/// Cycles given to each canister: enough for any test run.
const CYCLES: u128 = 100_000_000_000_000;

fn main() -> Result<()> {
    if std::env::var_os("POCKET_IC_BIN").is_none() {
        bail!("POCKET_IC_BIN is not set: point it at the pocket-ic server binary");
    }
    let mut pic = PocketIcBuilder::new().with_application_subnet().build();
    let url = pic.make_live(None).to_string().trim_end_matches('/').to_string();
    let controller = Principal::from_slice(&[0xC0, 0x01]);
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", json!({ "url": url }))?;
    out.flush()?;
    for line in std::io::stdin().lock().lines() {
        let reply = match answer(&pic, controller, &url, &line?) {
            Ok(v) => v,
            Err(e) => json!({ "error": format!("{e:#}") }),
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
    Ok(())
}

fn answer(pic: &PocketIc, controller: Principal, url: &str, line: &str) -> Result<Value> {
    let req: Value = serde_json::from_str(line).context("request is not JSON")?;
    let text = |k: &str| req[k].as_str().ok_or_else(|| anyhow!("missing {k}"));
    match text("op")? {
        "new" => {
            let dir = Path::new(text("dir")?);
            let pem = dir.join(format!("icp-frontend-{:016x}.pem", rand::random::<u64>()));
            let frontend = write_identity(&pem)?;
            let domains: Vec<String> = req["domains"]
                .as_array()
                .ok_or_else(|| anyhow!("missing domains"))?
                .iter()
                .filter_map(|d| d.as_str().map(String::from))
                .collect();
            let id = canister(pic, controller, Path::new(text("wasm")?), frontend, &domains)?;
            Ok(json!({ "canister": id.to_text(), "url": url, "identity_pem": pem }))
        }
        "cycles" => {
            let id = Principal::from_text(text("canister")?)?;
            Ok(json!({ "cycles": pic.cycle_balance(id) as u64 }))
        }
        op => bail!("unknown op {op}"),
    }
}

/// A fresh store canister from `wasm` that answers `frontend` and treats `domains` as its own.
fn canister(
    pic: &PocketIc,
    controller: Principal,
    wasm: &Path,
    frontend: Principal,
    domains: &[String],
) -> Result<Principal> {
    let code = std::fs::read(wasm).with_context(|| format!("reading {}", wasm.display()))?;
    let id = pic.create_canister_with_settings(Some(controller), None);
    pic.add_cycles(id, CYCLES);
    pic.install_canister(id, code, Encode!()?, Some(controller));
    let set = |method: &str, arg: Vec<u8>| -> Result<()> {
        let reply = pic.update_call(id, controller, method, arg).map_err(|e| anyhow!("{method}: {e:?}"))?;
        Decode!(&reply, Result<(), String>)?.map_err(|e| anyhow!("{method}: {e}"))
    };
    set("set_frontends", Encode!(&vec![frontend])?)?;
    set("set_local_domains", Encode!(&domains.to_vec())?)?;
    Ok(id)
}

/// Writes a new Ed25519 identity to `path` as PKCS#8 PEM and returns its principal.
fn write_identity(path: &Path) -> Result<Principal> {
    // PKCS#8 v1 for Ed25519: a fixed 16-byte header, then the 32-byte seed.
    let mut der = hex::decode("302e020100300506032b657004220420")?;
    der.extend_from_slice(&rand::random::<[u8; 32]>());
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    std::fs::write(path, format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n"))?;
    let id = BasicIdentity::from_pem_file(path).map_err(|_| anyhow!("the identity just written does not load"))?;
    id.sender().map_err(|e| anyhow!("{e}"))
}
