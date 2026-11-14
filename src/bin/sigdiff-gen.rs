//! Differential-test helper: builds signature cases and records the stock
//! oracle's answer for each.
//!
//!   sigdiff-gen gen    <out.jsonl>               generated cases (fixed seed, throwaway keys)
//!   sigdiff-gen corpus <slates.sql> <out.jsonl>  cases derived from a pg_dump `slates` COPY block
//!
//! The oracle is `epicboxlib verifysignature`: the path comes from `$ORACLE`, default
//! `epicboxlib` on `PATH`. Only `true` on stdout counts as valid.
//! See tools/sigdiff/README.md for the whole procedure.

use epicmail::sig::{self, encode_public_key, VERSION_FLOONET, VERSION_MAINNET};
use rand::{rngs::StdRng, Rng, SeedableRng};
use secp256k1::{
    ecdsa::{self, Signature},
    Message, PublicKey, SecretKey,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{Arc, Mutex};

const N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC,
    0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

type Case = (String, String, String); // pk, msg, sig

fn oracle_path() -> String {
    std::env::var("ORACLE").unwrap_or_else(|_| "epicboxlib".to_string())
}

fn run_oracle(c: &Case) -> bool {
    let out = std::process::Command::new(oracle_path())
        .args(["verifysignature", &c.0, &c.1, &c.2])
        .output()
        .expect("oracle spawn");
    out.status.success() && out.stdout == b"true"
}

fn run_all(cases: Vec<Case>, out: &str) {
    let total = cases.len();
    let queue = Arc::new(Mutex::new(cases.into_iter().enumerate().collect::<Vec<_>>()));
    let results = Arc::new(Mutex::new(vec![None; total]));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let (q, r) = (queue.clone(), results.clone());
            std::thread::spawn(move || loop {
                let item = q.lock().unwrap().pop();
                let Some((i, c)) = item else { break };
                let e = run_oracle(&c);
                r.lock().unwrap()[i] = Some((c, e));
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let mut f = std::fs::File::create(out).unwrap();
    let (mut t, mut fl) = (0, 0);
    for r in results.lock().unwrap().iter() {
        let (c, e) = r.clone().unwrap();
        if e {
            t += 1
        } else {
            fl += 1
        }
        writeln!(f, "{}", json!({"pk": c.0, "msg": c.1, "sig": c.2, "expected": e})).unwrap();
    }
    println!("{total} cases, oracle true={t} false={fl} -> {out}");
}

fn der_int(v: &[u8], extra_zeros: usize) -> Vec<u8> {
    let mut v: Vec<u8> = v.iter().skip_while(|b| **b == 0).cloned().collect();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    for _ in 0..extra_zeros {
        v.insert(0, 0);
    }
    let mut o = vec![0x02, v.len() as u8];
    o.extend(v);
    o
}

fn der_seq(body: Vec<u8>) -> Vec<u8> {
    let mut o = vec![0x30, body.len() as u8];
    o.extend(body);
    o
}

fn sub_n(s: &[u8]) -> [u8; 32] {
    let mut r = [0u8; 32];
    let mut borrow = 0i32;
    for i in (0..32).rev() {
        let mut d = N[i] as i32 - s[i] as i32 - borrow;
        borrow = if d < 0 {
            d += 256;
            1
        } else {
            0
        };
        r[i] = d as u8;
    }
    r
}

fn variants_sig(sig_hex: &str, compact: &[u8]) -> Vec<String> {
    let (r, s) = (&compact[..32], &compact[32..]);
    let hs = sub_n(s);
    let mut v = vec![sig_hex.to_string()];
    let base_body = |r: &[u8], s: &[u8]| [der_int(r, 0), der_int(s, 0)].concat();
    // high-S twin
    v.push(hex::encode(der_seq(base_body(r, &hs))));
    // extra leading zeros in r / s / both
    v.push(hex::encode(der_seq([der_int(r, 1), der_int(s, 0)].concat())));
    v.push(hex::encode(der_seq([der_int(r, 0), der_int(s, 1)].concat())));
    v.push(hex::encode(der_seq([der_int(r, 2), der_int(s, 2)].concat())));
    // trailing bytes
    v.push(format!("{sig_hex}00"));
    v.push(format!("{sig_hex}ff"));
    // sequence length too long / too short
    let der = hex::decode(sig_hex).unwrap();
    let mut d = der.clone();
    d[1] = d[1].wrapping_add(1);
    v.push(hex::encode(&d));
    let mut d = der.clone();
    d[1] = d[1].wrapping_sub(1);
    v.push(hex::encode(&d));
    // BER long-form length
    let mut d = vec![0x30, 0x81, der[1]];
    d.extend(&der[2..]);
    v.push(hex::encode(&d));
    let mut d = vec![0x30, 0x82, 0x00, der[1]];
    d.extend(&der[2..]);
    v.push(hex::encode(&d));
    // wrong tag
    let mut d = der.clone();
    d[0] = 0x31;
    v.push(hex::encode(&d));
    // truncated / dropped last byte
    v.push(sig_hex[..sig_hex.len() - 2].to_string());
    // r = 0, s = 0, r = n
    v.push(hex::encode(der_seq(base_body(&[0], s))));
    v.push(hex::encode(der_seq(base_body(r, &[0]))));
    v.push(hex::encode(der_seq(base_body(&N, s))));
    // negative integer (no 0x00 pad)
    let mut body = vec![0x02, 32];
    body.extend(r);
    body.extend([0x02, 32]);
    body.extend(s);
    if r[0] & 0x80 != 0 || s[0] & 0x80 != 0 {
        v.push(hex::encode(der_seq(body)));
    }
    // hex-level variants
    v.push(format!("0x{sig_hex}"));
    v.push(format!("0X{sig_hex}"));
    v.push(format!("0x{}", sig_hex.to_uppercase()));
    v.push(sig_hex.to_uppercase());
    v.push(format!("  {sig_hex}"));
    v.push(format!(" {sig_hex}"));
    v.push(format!("{sig_hex}  "));
    v.push(format!("{sig_hex} "));
    v.push(format!("\t\n{sig_hex}"));
    v.push(format!("{sig_hex}\r\n"));
    v.push(format!("0x  {sig_hex}"));
    v.push(format!("0x{sig_hex}  "));
    v.push(format!("  0x{sig_hex}"));
    v.push(format!("\u{a0}\u{a0}{sig_hex}"));
    v.push(format!("\u{3000} {sig_hex}"));
    v.push(format!("{sig_hex}\u{a0}\u{a0}"));
    v.push(format!("{}  {}", &sig_hex[..10], &sig_hex[10..]));
    v.push(format!("{} ", &sig_hex[..sig_hex.len() - 1]));
    v.push(format!("00{sig_hex}"));
    v.push(sig_hex[..sig_hex.len() - 1].to_string()); // odd
    v.push(format!("{sig_hex}0")); // odd
    v.push(format!("0x{}", &sig_hex[..sig_hex.len() - 1]));
    v.push(String::new());
    v.push("  ".into());
    v.push("0x".into());
    v.push("0x  ".into());
    v.push("0".into());
    v.push("zz".into());
    v.push("\u{e9}\u{e9}".into());
    v.push(format!("\u{e9}{sig_hex}"));
    v.push(format!("{sig_hex}\u{e9}"));
    // '+' in hex pairs: replace a leading '0' of a pair with '+'
    let b = sig_hex.as_bytes();
    let mut plus = 0;
    for i in (0..b.len()).step_by(2) {
        if b[i] == b'0' && plus < 3 {
            let mut s2 = sig_hex.to_string();
            s2.replace_range(i..i + 1, "+");
            v.push(s2);
            plus += 1;
        }
    }
    let mut s2 = sig_hex.to_string();
    s2.replace_range(0..1, "+"); // "+0" is fine, but 0x30 -> "+0" changes value
    v.push(s2);
    let mut s2 = sig_hex.to_string();
    s2.replace_range(0..1, "-");
    v.push(s2);
    let mut s2 = sig_hex.to_string();
    s2.replace_range(2..4, "++");
    v.push(s2);
    v.push(format!("0x+{}", &sig_hex[1..]));
    v
}

fn find_off_curve(rng: &mut StdRng) -> Vec<u8> {
    loop {
        let mut x = [0u8; 33];
        x[0] = 2;
        rng.fill(&mut x[1..]);
        if PublicKey::from_slice(&x).is_err() {
            return x.to_vec();
        }
    }
}

fn b58check(payload: &[u8]) -> String {
    let mut p = payload.to_vec();
    let c = Sha256::digest(Sha256::digest(&p));
    p.extend_from_slice(&c[..4]);
    bs58::encode(p).into_string()
}

fn variants_key(pk: &PublicKey, rng: &mut StdRng) -> Vec<(String, bool)> {
    // (key string, is_the_right_key)
    let mut v = vec![];
    for ver in [VERSION_MAINNET, VERSION_FLOONET, [0, 0], [255, 255], [1, 1], [0, 1], [7, 0]] {
        v.push((encode_public_key(pk, ver), true));
    }
    let good = encode_public_key(pk, VERSION_FLOONET);
    // bad checksum: change last char
    let mut c = good.clone();
    let last = c.pop().unwrap();
    c.push(if last == 'z' { 'y' } else { 'z' });
    v.push((c, true));
    let mut c = good.clone();
    c.replace_range(10..11, if &good[10..11] == "2" { "3" } else { "2" });
    v.push((c, true));
    // short / truncated
    v.push((good[..good.len() - 1].to_string(), true));
    v.push((good[..20].to_string(), true));
    v.push((String::new(), true));
    v.push(("1".into(), true));
    v.push(("11111".into(), true));
    v.push((format!("1{good}"), true));
    v.push((format!("{good}1"), true));
    // invalid base58 chars
    for ch in ['0', 'O', 'I', 'l', ' ', '+'] {
        let mut c = good.clone();
        c.replace_range(5..6, &ch.to_string());
        v.push((c, true));
    }
    v.push((format!("{good}\u{e9}"), true));
    v.push((format!(" {good}"), true));
    v.push((format!("{good}\n"), true));
    // payload shapes
    let ser = pk.serialize();
    let unc = pk.serialize_uncompressed();
    let mut hyb = unc;
    hyb[0] = 0x06 | (unc[64] & 1);
    let off = find_off_curve(rng);
    let cases: Vec<Vec<u8>> = vec![
        [&[1u8, 136][..], &unc[..]].concat(),
        [&[1u8, 0][..], &unc[..]].concat(),
        [&[1u8, 136][..], &hyb[..]].concat(),
        [&[1u8, 136][..], &off[..]].concat(),
        [&[1u8, 136][..], &[0u8; 33][..]].concat(),
        [&[1u8, 136][..], &[0x04u8; 1][..], &ser[1..]].concat(), // 33 bytes with 0x04
        [&[1u8][..], &ser[..]].concat(),                         // 1 version byte
        [&[1u8, 136, 0][..], &ser[..]].concat(),                 // 3 version-ish bytes
        [&[1u8, 136][..], &ser[..32]].concat(),
        [&[1u8, 136][..], &unc[..64]].concat(),
        [&[0u8, 0][..], &ser[..]].concat(),
        [&[0u8, 0, 0, 0][..], &ser[..]].concat(),
        ser.to_vec(), // no version at all
        vec![1, 136],
        vec![],
        vec![1, 136, 2],
    ];
    for p in cases {
        v.push((b58check(&p), true));
    }
    v
}

fn gen_cases() -> Vec<Case> {
    let mut rng = StdRng::seed_from_u64(0x5167_D1FF);
    let msgs: Vec<String> = vec![
        "hello".into(),
        String::new(),
        "{\"destination\":{\"public_key\":\"x\",\"domain\":\"d\",\"port\":null}}".into(),
        "h\u{e9}llo w\u{f6}rld \u{4e2d}\u{6587} \u{1f980}".into(),
        "a".repeat(600),
        "line1\nline2\ttab".into(),
    ];
    let mut cases: Vec<Case> = vec![];
    let keys: Vec<(SecretKey, PublicKey)> = (0..8)
        .map(|_| {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            let sk = SecretKey::from_secret_bytes(b).unwrap();
            (sk, PublicKey::from_secret_key(&sk))
        })
        .collect();
    for (ki, (sk, pk)) in keys.iter().enumerate() {
        let other = &keys[(ki + 1) % keys.len()].1;
        let good_pk = encode_public_key(pk, VERSION_FLOONET);
        for (mi, m) in msgs.iter().enumerate() {
            let sig_hex = sig::sign(sk, m);
            let compact =
                ecdsa::sign(Message::from_digest(Sha256::digest(m.as_bytes()).into()), sk).serialize_compact();
            let _ = Signature::from_compact(&compact).unwrap();
            for s in variants_sig(&sig_hex, &compact) {
                cases.push((good_pk.clone(), m.clone(), s));
            }
            // message mutations
            cases.push((good_pk.clone(), format!("{m}x"), sig_hex.clone()));
            cases.push((good_pk.clone(), format!(" {m}"), sig_hex.clone()));
            cases.push((good_pk.clone(), m.to_uppercase() + "!", sig_hex.clone()));
            // wrong key
            cases.push((encode_public_key(other, VERSION_FLOONET), m.clone(), sig_hex.clone()));
            // key variants only on the first two messages
            if mi < 2 {
                for (k, _) in variants_key(pk, &mut rng) {
                    cases.push((k, m.clone(), sig_hex.clone()));
                }
            }
        }
    }
    cases
}

fn corpus_cases(path: &str) -> Vec<Case> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut cases = vec![];
    let mut rows = 0;
    let mut in_copy = false;
    for line in text.lines() {
        if line.starts_with("COPY public.slates") {
            in_copy = true;
            continue;
        }
        if !in_copy {
            continue;
        }
        if line == "\\." {
            break;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 8 {
            continue;
        }
        let Some(hexs) = f[3].strip_prefix("\\\\x") else { continue };
        let Ok(bytes) = hex::decode(hexs) else { continue };
        let Ok(j) = serde_json::from_slice::<serde_json::Value>(&bytes) else { continue };
        let (Some(st), Some(sg)) = (j["str"].as_str(), j["signature"].as_str()) else { continue };
        let ch = j["challenge"].as_str().unwrap_or("");
        let pk = f[4].split('@').next().unwrap().to_string();
        rows += 1;
        cases.push((pk.clone(), st.to_string(), sg.to_string())); // the real PostSlate check
        cases.push((pk.clone(), format!("{st}x"), sg.to_string()));
        cases.push((pk.clone(), ch.to_string(), sg.to_string()));
        cases.push((pk.clone(), st.to_string(), format!("0x{sg}")));
        cases.push((pk.clone(), st.to_string(), sg.to_uppercase()));
        if let Ok(der) = hex::decode(sg) {
            if let Ok(s) = Signature::from_der(&der) {
                let c = s.serialize_compact();
                let hs = sub_n(&c[32..]);
                let body = [der_int(&c[..32], 0), der_int(&hs, 0)].concat();
                cases.push((pk.clone(), st.to_string(), hex::encode(der_seq(body))));
            }
        }
        let mut flipped = sg.to_string();
        let i = flipped.len() / 2;
        let ch0 = flipped.as_bytes()[i];
        flipped.replace_range(i..i + 1, if ch0 == b'0' { "1" } else { "0" });
        cases.push((pk.clone(), st.to_string(), flipped));
    }
    eprintln!("corpus rows: {rows}");
    cases
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match (a.get(1).map(String::as_str), a.len()) {
        (Some("gen"), 3) => run_all(gen_cases(), &a[2]),
        (Some("corpus"), 4) => run_all(corpus_cases(&a[2]), &a[3]),
        _ => eprintln!("usage: sigdiff-gen gen <out> | corpus <slates.sql> <out>"),
    }
}
