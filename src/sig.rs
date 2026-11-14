//! Signature verification, bit-compatible with the stock relay's oracle
//! (`epicboxlib verifysignature`): SHA-256 of the UTF-8 message, strict-DER
//! secp256k1 ECDSA, low-S only; hex is decoded exactly as the oracle decodes it.

use secp256k1::ecdsa::{self, Signature};
use secp256k1::{Message, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

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

impl std::fmt::Display for SigReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for SigReject {}

fn double_sha256(data: &[u8]) -> [u8; 32] {
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
    PublicKey::from_slice(&key).map_err(|_| SigReject::BadKey)
}

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

fn digest(message: &str) -> Message {
    Message::from_digest(Sha256::digest(message.as_bytes()).into())
}

/// `verify` with the key already decoded.
pub fn verify_with_key(pk: &PublicKey, message: &str, signature_hex: &str) -> Result<(), SigReject> {
    let der = oracle_from_hex(signature_hex)?;
    let sig = Signature::from_der(&der).map_err(|_| SigReject::BadDer)?;
    // libsecp256k1 verify rejects high-S signatures.
    ecdsa::verify(&sig, digest(message), pk).map_err(|_| SigReject::Invalid)
}

/// Ok(()) exactly when the oracle prints `true`.
pub fn verify(public_key_b58: &str, message: &str, signature_hex: &str) -> Result<(), SigReject> {
    let pk = parse_public_key(public_key_b58)?;
    verify_with_key(&pk, message, signature_hex)
}

/// DER hex, low-S.
pub fn sign(secret: &SecretKey, message: &str) -> String {
    let sig = ecdsa::sign(digest(message), secret);
    hex::encode(sig.serialize_der())
}

/// base58check of the compressed key with the given version bytes.
pub fn encode_public_key(pk: &PublicKey, version: [u8; 2]) -> String {
    let mut p = version.to_vec();
    p.extend_from_slice(&pk.serialize());
    let c = double_sha256(&p);
    p.extend_from_slice(&c[..4]);
    bs58::encode(p).into_string()
}
