//! The pure protocol rules of Epicmail, shared by the relay and by an ICP canister.
//!
//! No clock, no randomness, no I/O and no async runtime in here: every function takes plain data
//! and returns plain data, so the same rules run in the relay (native) and in a canister
//! (`wasm32-unknown-unknown`, `--no-default-features --features k256`).
//!
//! * `address`: the Epicbox address grammar, key decoding and relay domain names.
//! * `sig`: Epicbox signature verification (secp256k1 or k256 backend, same acceptance).
//! * `ids`: the txid and msgid formats.
//! * `text`: the texts clients sign and the extension names.
//! * `refusal`: the refusal texts, byte for byte as the stock relay words them.
//! * `post`: the pure steps of PostSlate and the typed refusal each can end in.
//! * `tx`: tombstone, participant and queue-cap rules over plain data.
//! * `limits`: default limits and the order messages are offered in.

#![forbid(unsafe_code)]

pub mod address;
pub mod ids;
pub mod limits;
pub mod post;
pub mod refusal;
pub mod sig;
pub mod text;
pub mod tx;
