//! libsecp256k1 through the `secp256k1` crate: Epicmail's backend.

use secp256k1::ecdsa::{self, Signature};
pub use secp256k1::PublicKey;
use secp256k1::{Message, SecretKey};

use super::{double_sha256, SigReject};

pub(super) fn parse_key(bytes: &[u8]) -> Option<PublicKey> {
    PublicKey::from_slice(bytes).ok()
}

pub(super) fn verify(pk: &PublicKey, digest: [u8; 32], der: &[u8]) -> Result<(), SigReject> {
    let sig = Signature::from_der(der).map_err(|_| SigReject::BadDer)?;
    // libsecp256k1 verify rejects high-S signatures.
    ecdsa::verify(&sig, Message::from_digest(digest), pk).map_err(|_| SigReject::Invalid)
}

/// DER hex, low-S.
pub fn sign(secret: &SecretKey, message: &str) -> String {
    let sig = ecdsa::sign(Message::from_digest(super::digest(message)), secret);
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
