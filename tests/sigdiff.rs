//! Differential test: `sig::verify` must agree with the stock oracle's recorded answers.
//! Generated cases: tests/data/sigcases.jsonl (throwaway keys).
//! Real corpus: $SIGDIFF_CORPUS (jsonl built by `sigdiff-gen corpus`), skipped when unset.

use epicmail::sig;

fn check(path: &str) -> (usize, usize, usize) {
    let text = std::fs::read_to_string(path).unwrap();
    let (mut n, mut mism, mut trues) = (0, 0, 0);
    for line in text.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let (pk, msg, sg) = (
            v["pk"].as_str().unwrap(),
            v["msg"].as_str().unwrap(),
            v["sig"].as_str().unwrap(),
        );
        let expected = v["expected"].as_bool().unwrap();
        let got = sig::verify(pk, msg, sg).is_ok();
        n += 1;
        trues += expected as usize;
        if got != expected {
            mism += 1;
            eprintln!("MISMATCH pk={pk:?} msg.len={} sig={sg:?} expected={expected} got={got}", msg.len());
        }
    }
    (n, mism, trues)
}

#[test]
fn generated_cases_match_oracle() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/sigcases.jsonl");
    let (n, m, t) = check(p);
    println!("generated cases: {n} (oracle true: {t}), mismatches: {m}");
    assert!(n >= 3310, "need at least 3310 cases, have {n}");
    assert_eq!(m, 0);
}

#[test]
fn real_corpus_matches_oracle() {
    let Ok(p) = std::env::var("SIGDIFF_CORPUS") else {
        println!("SIGDIFF_CORPUS unset: skipping real-corpus differential");
        return;
    };
    let (n, m, t) = check(&p);
    println!("corpus checks: {n} (oracle true: {t}), mismatches: {m}");
    assert!(n > 0);
    assert_eq!(m, 0);
}
