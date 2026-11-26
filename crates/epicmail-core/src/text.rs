//! The texts clients sign, and the extension names that announce them.

/// Domain separation prefix for cancel signatures that may travel between relays.
pub const CANCEL_SIG_PREFIX: &str = "epicbox-cancel/1:";
/// The extension token a wallet offers in `ClientDetails` and the relay echoes in its `Ok`:
/// the relay verifies cancels signed over `CANCEL_SIG_PREFIX` + txid, and the wallet may sign
/// that form. It is also the feature name in `/.well-known/epicbox.json`.
pub const CANCEL_SEPARATED_EXT: &str = "epicbox-cancel/1";
/// The extension token a mux/1 client offers in `ClientDetails` and the relay echoes in its
/// `Ok`: the relay checks Attach signatures over `ATTACH_SIG_PREFIX` + host + `:` + challenge,
/// bound to one of its public names, and the client may sign that form. It is also the feature
/// name in `/.well-known/epicbox.json`.
pub const ATTACH_HOST_EXT: &str = "epicbox-attach/1";
/// Domain separation prefix for Attach signatures bound to the relay's host name.
pub const ATTACH_SIG_PREFIX: &str = "epicbox-attach/1:";

/// What a mux/1 client signs for Attach: `epicbox-attach/1:<host>:<challenge>`.
pub fn attach_text(host: &str, challenge: &str) -> String {
    format!("{ATTACH_SIG_PREFIX}{host}:{challenge}")
}

/// What a client signs to cancel a transaction with domain separation:
/// `epicbox-cancel/1:<txid>`. The bare txid is accepted too (policy of the relay, not of the
/// protocol text).
pub fn cancel_text(txid: &str) -> String {
    format!("{CANCEL_SIG_PREFIX}{txid}")
}

/// What a client signs for `/v1/pull`: the challenge bound to the relay's identity
/// (`domain:port`, lower case), so the proof is useless at any other relay.
pub fn v1_proof_text(challenge: &str, domain: &str, port: u16) -> String {
    format!("{challenge}@{}:{port}", domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts_are_what_clients_sign() {
        assert_eq!(attach_text("relay.example", "abc"), "epicbox-attach/1:relay.example:abc");
        let txid = "a".repeat(32);
        assert_eq!(cancel_text(&txid), format!("epicbox-cancel/1:{txid}"));
        assert_eq!(v1_proof_text("chal", "Relay.Example", 443), "chal@relay.example:443");
    }
}
