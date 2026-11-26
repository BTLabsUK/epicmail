//! Differential test: `sig::verify` must agree with the stock oracle's recorded answers, with
//! whichever backend the build selected (`secp256k1` or `k256`). Run it once per feature:
//!
//!   cargo test -p epicmail-core
//!   cargo test -p epicmail-core --no-default-features --features k256
//!
//! The cases are the relay's own: tests/data/sigcases.jsonl at the repository root.

use epicmail_core::sig;

const CASES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/data/sigcases.jsonl");

#[test]
fn generated_cases_match_oracle() {
    let text = std::fs::read_to_string(CASES).unwrap();
    let (mut n, mut mism, mut trues) = (0, 0, 0);
    for line in text.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let (pk, msg, sg) = (v["pk"].as_str().unwrap(), v["msg"].as_str().unwrap(), v["sig"].as_str().unwrap());
        let expected = v["expected"].as_bool().unwrap();
        let got = sig::verify(pk, msg, sg).is_ok();
        n += 1;
        trues += expected as usize;
        if got != expected {
            mism += 1;
            eprintln!("MISMATCH pk={pk:?} msg.len={} sig={sg:?} expected={expected} got={got}", msg.len());
        }
    }
    println!("generated cases: {n} (oracle true: {trues}), mismatches: {mism}");
    assert!(n >= 3310, "need at least 3310 cases, have {n}");
    assert_eq!(mism, 0);
}
