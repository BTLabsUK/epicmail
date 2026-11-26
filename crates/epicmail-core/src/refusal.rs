//! Refusal texts, byte for byte as the stock relay words them (clients show or match them),
//! and the error kinds that go with them.

/// `kind` of most refusals.
pub const KIND_INVALID_REQUEST: &str = "InvalidRequest";
/// `kind` of a refused signature on a cancel or on `epicboxtxidsig`.
pub const KIND_INVALID_SIGNATURE: &str = "InvalidSignature";
/// `kind` of a store error.
pub const KIND_UNKNOWN: &str = "UnknownError";

/// A PostSlate with missing fields or half the 3.1.0 fields.
pub const MISSING_FIELDS: &str = "PostSlate requires from, to, str, and signature. epicboxtxid and epicboxtxidsig \
                                  must either both be absent (legacy) or both be valid (protocol 3.1.0).";
pub const BAD_POST_SIGNATURE: &str = "Error postslate signature.";
pub const BAD_TXID_SIGNATURE: &str = "Invalid epicboxtxid signature.";
pub const INVALID_PAYLOAD: &str = "Invalid Slate payload.";
pub const INVALID_DESTINATION: &str = "Invalid slate destination.";
pub const QUEUE_FULL: &str = "Recipient mailbox is full; try again later.";
pub const SENDER_CAPPED: &str = "Too many messages from this sender are waiting for the recipient.";
pub const NOT_PARTICIPANT: &str = "Posting address is not a participant of epicboxtxid.";
pub const STORE_FULL: &str = "Relay storage is full; try again later.";
pub const NO_FORWARDING: &str = "This relay does not forward to other relays.";
pub const INTERNAL: &str = "Internal error; try again.";

pub const CANCEL_NO_ADDRESS: &str = "Missing cancellation address.";
pub const CANCEL_BAD_TXID: &str = "Invalid or missing 32-character epicboxtxid.";
pub const CANCEL_NO_SIGNATURE: &str = "Missing signature.";
pub const CANCEL_BAD_SIGNATURE: &str = "Invalid signature.";

pub fn slate_too_large(max: usize) -> String {
    format!("Slate is larger than {max} bytes.")
}

pub fn wrong_address(from: &str, to: &str) -> String {
    format!("Wrong address format. From: {from}, To: {to}")
}

/// `dest` is `domain:port`.
pub fn forwarding_not_allowed(dest: &str) -> String {
    format!("Forwarding to {dest} is not allowed.")
}

pub fn rate_limited(retry_secs: u64) -> String {
    format!("Rate limit exceeded; retry in {retry_secs} s.")
}

pub fn sender_host_denied(host: &str) -> String {
    format!("This relay does not accept slates from {host}.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts_are_fixed() {
        assert_eq!(slate_too_large(10), "Slate is larger than 10 bytes.");
        assert_eq!(wrong_address("a", "b"), "Wrong address format. From: a, To: b");
        assert_eq!(forwarding_not_allowed("p:1"), "Forwarding to p:1 is not allowed.");
        assert_eq!(rate_limited(3), "Rate limit exceeded; retry in 3 s.");
        assert_eq!(sender_host_denied("h"), "This relay does not accept slates from h.");
        assert_eq!(
            MISSING_FIELDS,
            "PostSlate requires from, to, str, and signature. epicboxtxid and epicboxtxidsig must either both be absent (legacy) or both be valid (protocol 3.1.0)."
        );
    }
}
