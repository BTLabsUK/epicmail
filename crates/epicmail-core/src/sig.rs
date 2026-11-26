//! Signature verification, bit-compatible with the stock relay's oracle
//! (`epicboxlib verifysignature`): SHA-256 of the UTF-8 message, strict-DER
//! secp256k1 ECDSA, low-S only; hex is decoded exactly as the oracle decodes it.
//!
//! Two backends do the curve work: `secp256k1` (libsecp256k1, what Epicmail uses) and `k256`
//! (pure Rust, for wasm32). Everything else here is shared, so both accept the same inputs.

#[cfg(not(any(feature = "secp256k1", feature = "k256")))]
compile_error!("epicmail-core needs a signature backend: enable the feature `secp256k1` (default) or `k256`");

use sha2::{Digest, Sha256};

#[cfg(feature = "k256")]
#[cfg_attr(feature = "secp256k1", allow(dead_code))]
mod k256_backend;
#[cfg(feature = "secp256k1")]
mod secp_backend;

#[cfg(all(feature = "k256", not(feature = "secp256k1")))]
use k256_backend as backend;
#[cfg(feature = "secp256k1")]
use secp_backend as backend;

/// The public key type of the active backend (`secp256k1::PublicKey`, or
/// `k256::ecdsa::VerifyingKey` when only `k256` is on).
pub use backend::PublicKey;
#[cfg(feature = "secp256k1")]
pub use backend::{encode_public_key, sign};

/// Version bytes of mainnet Epicbox addresses.
pub const VERSION_MAINNET: [u8; 2] = [1, 0];
/// Version bytes of floonet (testnet) Epicbox addresses.
pub const VERSION_FLOONET: [u8; 2] = [1, 136];

/// Why a signature check failed (metric labels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigReject {
    BadKey,
    BadHex,
    BadDer,
    /// Includes high-S, wrong message and wrong key.
    Invalid,
}

impl SigReject {
    /// The `reason` label value.
    pub fn as_str(&self) -> &'static str {
        match self {
            SigReject::BadKey => "bad_key",
            SigReject::BadHex => "bad_hex",
            SigReject::BadDer => "bad_der",
            SigReject::Invalid => "invalid",
        }
    }
}

impl core::fmt::Display for SigReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for SigReject {}

pub(crate) fn double_sha256(data: &[u8]) -> [u8; 32] {
    let h = Sha256::digest(Sha256::digest(data));
    h.into()
}

/// Decode a base58check string with `n_version` version bytes; returns
/// (version, payload). Same acceptance as the stock decoder.
pub fn decode_base58check(s: &str, n_version: usize) -> Result<(Vec<u8>, Vec<u8>), SigReject> {
    let mut payload = bs58::decode(s).into_vec().map_err(|_| SigReject::BadKey)?;
    if payload.len() < 5 {
        return Err(SigReject::BadKey);
    }
    let split = payload.len() - 4;
    let provided = payload.split_off(split);
    if double_sha256(&payload)[..4] != provided[..] {
        return Err(SigReject::BadKey);
    }
    if payload.len() < n_version {
        return Err(SigReject::BadKey);
    }
    let key = payload.split_off(n_version);
    Ok((payload, key))
}

/// Parse an Epicbox public key (any 2 version bytes accepted, as the oracle does).
pub fn parse_public_key(b58: &str) -> Result<PublicKey, SigReject> {
    let (_, key) = decode_base58check(b58, 2)?;
    backend::parse_key(&key).ok_or(SigReject::BadKey)
}

/// The permissive decoding (`0x`, trim, `+`) is deliberate: compatibility with the old relay.
///
/// Port of the stock `from_hex`: length parity is checked on the raw string,
/// then an optional `0x` is dropped, the rest trimmed and split into byte
/// pairs parsed with `u8::from_str_radix` (which accepts a leading `+`).
/// Every input the oracle does not decode is `BadHex`.
fn oracle_from_hex(s: &str) -> Result<Vec<u8>, SigReject> {
    if s.len() % 2 == 1 || s.len() < 2 {
        return Err(SigReject::BadHex);
    }
    // `get`, because slicing would panic when byte 2 is not a char boundary.
    let rest = match s.get(..2) {
        None => return Err(SigReject::BadHex),
        Some("0x") => &s[2..],
        Some(_) => s,
    };
    let t = rest.trim();
    // The oracle does not decode an empty or odd-length trimmed string.
    if t.len() < 2 || t.len() % 2 == 1 {
        return Err(SigReject::BadHex);
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    for i in 0..t.len() / 2 {
        let pair = t.get(2 * i..2 * i + 2).ok_or(SigReject::BadHex)?;
        out.push(u8::from_str_radix(pair, 16).map_err(|_| SigReject::BadHex)?);
    }
    Ok(out)
}

fn digest(message: &str) -> [u8; 32] {
    Sha256::digest(message.as_bytes()).into()
}

/// `verify` with the key already decoded.
pub fn verify_with_key(pk: &PublicKey, message: &str, signature_hex: &str) -> Result<(), SigReject> {
    let der = oracle_from_hex(signature_hex)?;
    backend::verify(pk, digest(message), &der)
}

/// Ok(()) exactly when the oracle prints `true`.
pub fn verify(public_key_b58: &str, message: &str, signature_hex: &str) -> Result<(), SigReject> {
    let pk = parse_public_key(public_key_b58)?;
    verify_with_key(&pk, message, signature_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway key from `tests/data/sigcases.jsonl`, with a signature over "hello".
    const PK: &str = "zzNqXNSX6bQ5CeMkmoLbbjLgQk158SRgC3Q6bwjfsAvTxovY9uBv";
    const SIG: &str = "30440220685fa8e28957fb984b2dddcbd4ab52962704e851071e196b43c55cd6c084271e022043d8741a1fb9125e38472f87bb21ba8b74efbba92ec8f084b2fd30ab6051563f";

    #[test]
    fn known_signature_verifies() {
        assert_eq!(verify(PK, "hello", SIG), Ok(()));
        assert_eq!(verify(PK, "other", SIG), Err(SigReject::Invalid));
    }

    #[test]
    fn rejects_by_stage() {
        assert_eq!(verify("not a key", "hello", SIG), Err(SigReject::BadKey));
        assert_eq!(verify(PK, "hello", "zz"), Err(SigReject::BadHex));
        assert_eq!(verify(PK, "hello", "3000"), Err(SigReject::BadDer));
        // The permissive hex forms the oracle decodes.
        assert_eq!(verify(PK, "hello", &format!("0x{SIG}")), Ok(()));
    }

    #[test]
    fn high_s_is_refused() {
        // Same r, s' = n - s: a valid ECDSA signature that libsecp256k1 refuses.
        let high = "30450220685fa8e28957fb984b2dddcbd4ab52962704e851071e196b43c55cd6c084271e022100bc278be5e046eda1c7b8d07844de457345bf213d807fafb70cd52de16fe4eb02";
        assert_eq!(verify(PK, "hello", high), Err(SigReject::Invalid));
    }

    #[test]
    fn short_key_payloads_do_not_panic() {
        for s in ["", "1", "11111", "zzzz"] {
            assert!(parse_public_key(s).is_err(), "{s:?}");
        }
    }

    /// With both backends built, they must agree on acceptance for every case and on mutations of each
    /// signature (flipped bytes, truncations, appended bytes), not only on the oracle's answers.
    #[cfg(all(feature = "secp256k1", feature = "k256"))]
    #[test]
    fn the_two_backends_agree() {
        use super::{k256_backend as k, secp_backend as s};

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/data/sigcases.jsonl");
        let text = std::fs::read_to_string(path).unwrap();
        let (mut n, mut accepted) = (0usize, 0usize);
        for line in text.lines().filter(|l| !l.is_empty()) {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let (pk, msg, sg) = (v["pk"].as_str().unwrap(), v["msg"].as_str().unwrap(), v["sig"].as_str().unwrap());
            let Ok((payload, _)) = decode_base58check(pk, 2).map(|(a, b)| (b, a)) else { continue };
            let (pk_s, pk_k) = (s::parse_key(&payload), k::parse_key(&payload));
            assert_eq!(pk_s.is_some(), pk_k.is_some(), "key {pk}");
            let (Some(pk_s), Some(pk_k)) = (pk_s, pk_k) else { continue };
            let d = digest(msg);
            let mut variants = vec![sg.to_string()];
            let bytes = hex::decode(sg).unwrap_or_default();
            for i in 0..bytes.len() {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut b = bytes.clone();
                    b[i] ^= flip;
                    variants.push(hex::encode(&b));
                }
                variants.push(hex::encode(&bytes[..i]));
            }
            for extra in [0u8, 1, 0xff] {
                let mut b = bytes.clone();
                b.push(extra);
                variants.push(hex::encode(&b));
            }
            for var in variants {
                let Ok(der) = oracle_from_hex(&var) else { continue };
                let (a, b) = (s::verify(&pk_s, d, &der), k::verify(&pk_k, d, &der));
                // Both must accept or both refuse; the reason may differ (a negative DER integer is
                // BadDer for k256 and Invalid for libsecp256k1), and clients never see it.
                assert_eq!(a.is_ok(), b.is_ok(), "pk {pk} msg {msg:?} sig {var}");
                n += 1;
                accepted += a.is_ok() as usize;
            }
        }
        println!("backend comparison: {n} checks, {accepted} accepted");
        assert!(n > 10_000);
    }
}
