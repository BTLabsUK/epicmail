//! Pure-Rust `k256`: the backend for wasm32. It must accept exactly what libsecp256k1 accepts,
//! so the points libsecp256k1 and k256 treat differently are handled here, not left to defaults.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;

use super::SigReject;

pub type PublicKey = VerifyingKey;

/// A SEC1 key as libsecp256k1 reads it: 33 bytes compressed (tag 2 or 3), 65 bytes
/// uncompressed (tag 4) or 65 bytes hybrid (tag 6 or 7, where the tag's low bit must equal the
/// parity of y). The point must be on the curve.
pub(super) fn parse_key(bytes: &[u8]) -> Option<PublicKey> {
    match bytes {
        [tag @ (6 | 7), rest @ ..] if rest.len() == 64 => {
            if tag & 1 != rest[63] & 1 {
                return None;
            }
            let mut b = [0u8; 65];
            b[0] = 4;
            b[1..].copy_from_slice(rest);
            VerifyingKey::from_sec1_bytes(&b).ok()
        }
        [2 | 3, ..] if bytes.len() == 33 => VerifyingKey::from_sec1_bytes(bytes).ok(),
        [4, ..] if bytes.len() == 65 => VerifyingKey::from_sec1_bytes(bytes).ok(),
        _ => None,
    }
}

pub(super) fn verify(pk: &PublicKey, digest: [u8; 32], der: &[u8]) -> Result<(), SigReject> {
    // `from_der` is strict DER: no non-minimal integers, no trailing bytes, r and s in 1..n.
    let sig = Signature::from_der(der).map_err(|_| SigReject::BadDer)?;
    // Low-S only, as libsecp256k1 verifies. Stated here, not left to the library's defaults.
    if bool::from(sig.s().is_high()) {
        return Err(SigReject::Invalid);
    }
    pk.verify_prehash(&digest, &sig).map_err(|_| SigReject::Invalid)
}
