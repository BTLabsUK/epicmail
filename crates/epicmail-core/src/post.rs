//! The pure steps of PostSlate: read the request, check sizes, fields, addresses and
//! signatures, and find the destination inside the signed slate.
//!
//! The relay runs the steps around its rate limiters in a fixed order:
//!
//! 1. per-IP post limit, then the signature block (relay)
//! 2. [`check_envelope`]: size, 3.1.0 fields, addresses, signatures
//! 3. per-address post limit (relay), only once the signatures are good
//! 4. [`route`]: payload and destination
//!
//! A refusal from step 2 that [`PostRefusal::is_failed_signature`] counts against the sender's
//! failed-signature budget; a missing signature does not.

use serde_json::Value;

use crate::address::{normalize_domain, parse_address, EpicboxAddress};
use crate::ids::is_txid;
use crate::refusal;
use crate::sig;

/// A PostSlate, from any entry point.
#[derive(Debug, Clone, Default)]
pub struct PostReq {
    pub from: Option<String>,
    pub to: Option<String>,
    pub str_: Option<String>,
    pub signature: Option<String>,
    pub txid: Option<Value>,
    pub txidsig: Option<Value>,
}

impl PostReq {
    /// Read the fields from a PostSlate frame or `/v1/post` body. Missing or mistyped fields are
    /// None; `check_envelope` decides what that means.
    pub fn from_json(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
        Self {
            from: s("from"),
            to: s("to"),
            str_: s("str"),
            signature: s("signature"),
            txid: v.get("epicboxtxid").filter(|x| !x.is_null()).cloned(),
            txidsig: v.get("epicboxtxidsig").filter(|x| !x.is_null()).cloned(),
        }
    }

    /// Bytes in `str`, the size the limits count.
    pub fn body_len(&self) -> usize {
        self.str_.as_ref().map_or(0, String::len)
    }
}

/// Why a PostSlate was refused by the pure steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostRefusal {
    /// `str` is longer than the limit.
    TooLarge { max: usize },
    /// Missing fields, or half the 3.1.0 fields.
    MissingFields,
    /// An address does not parse or its key does not decode.
    WrongAddress { from: String, to: String },
    /// `str` or `signature` is missing: nothing to check, so not a failed signature.
    NoSignature,
    /// The slate signature does not verify.
    BadPostSignature,
    /// `epicboxtxidsig` does not verify.
    BadTxidSignature,
    /// `str` is not JSON.
    InvalidPayload,
    /// The destination inside the slate is missing or malformed.
    InvalidDestination,
}

impl PostRefusal {
    /// The error kind clients see.
    pub fn kind(&self) -> &'static str {
        match self {
            PostRefusal::BadTxidSignature => refusal::KIND_INVALID_SIGNATURE,
            _ => refusal::KIND_INVALID_REQUEST,
        }
    }

    /// The refusal text, byte for byte as the stock relay words it.
    pub fn text(&self) -> String {
        match self {
            PostRefusal::TooLarge { max } => refusal::slate_too_large(*max),
            PostRefusal::MissingFields => refusal::MISSING_FIELDS.into(),
            PostRefusal::WrongAddress { from, to } => refusal::wrong_address(from, to),
            PostRefusal::NoSignature | PostRefusal::BadPostSignature => refusal::BAD_POST_SIGNATURE.into(),
            PostRefusal::BadTxidSignature => refusal::BAD_TXID_SIGNATURE.into(),
            PostRefusal::InvalidPayload => refusal::INVALID_PAYLOAD.into(),
            PostRefusal::InvalidDestination => refusal::INVALID_DESTINATION.into(),
        }
    }

    /// A signature was present and did not verify: it counts against the sender's failed
    /// signatures.
    pub fn is_failed_signature(&self) -> bool {
        matches!(self, PostRefusal::BadPostSignature | PostRefusal::BadTxidSignature)
    }
}

/// A slate that passed [`check_envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// `from` and `to` as the wallet wrote them.
    pub from_s: String,
    pub to_s: String,
    pub from: EpicboxAddress,
    pub body: String,
    pub signature: String,
    pub txid: Option<String>,
    pub txidsig: Option<String>,
}

/// Where a slate goes, from the destination inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub dest_key: String,
    pub dest_domain: String,
    pub dest_port: u16,
}

/// Size, 3.1.0 fields, addresses and signatures, in that order. `cancel_fields` says the 3.1.0
/// fields are accepted on this entry point.
pub fn check_envelope(req: PostReq, max_str_bytes: usize, cancel_fields: bool) -> Result<Envelope, PostRefusal> {
    if req.body_len() > max_str_bytes {
        return Err(PostRefusal::TooLarge { max: max_str_bytes });
    }
    let PostReq { from, to, str_, signature, txid, txidsig } = req;
    let (all_present, from_s, to_s) = (
        str_.is_some() && signature.is_some() && from.is_some() && to.is_some(),
        from.unwrap_or_default(),
        to.unwrap_or_default(),
    );

    // 3.1.0 fields: both absent (legacy) or both valid.
    let (txid, txidsig) = if cancel_fields {
        match (txid, txidsig) {
            (None, None) => (None, None),
            (Some(Value::String(t)), Some(Value::String(s))) if is_txid(&t) => (Some(t), Some(s)),
            _ => return Err(PostRefusal::MissingFields),
        }
    } else {
        (None, None)
    };
    if cancel_fields && !all_present {
        return Err(PostRefusal::MissingFields);
    }

    let wrong = || PostRefusal::WrongAddress { from: from_s.clone(), to: to_s.clone() };
    let (Ok(from), Ok(to)) = (parse_address(&from_s), parse_address(&to_s)) else {
        return Err(wrong());
    };
    if !from.public_key_valid() || !to.public_key_valid() {
        return Err(wrong());
    }
    let (Some(body), Some(signature)) = (str_, signature) else {
        return Err(PostRefusal::NoSignature);
    };
    if sig::verify(&from.public_key, &body, &signature).is_err() {
        return Err(PostRefusal::BadPostSignature);
    }
    if let (Some(t), Some(ts)) = (&txid, &txidsig) {
        if sig::verify(&from.public_key, t, ts).is_err() {
            return Err(PostRefusal::BadTxidSignature);
        }
    }
    Ok(Envelope { from_s, to_s, from, body, signature, txid, txidsig })
}

/// Route by the destination inside the signed slate, as the stock relay does.
pub fn route(body: &str) -> Result<Route, PostRefusal> {
    let Ok(payload) = serde_json::from_str::<Value>(body) else {
        return Err(PostRefusal::InvalidPayload);
    };
    let Some((dest_key, dest_domain, dest_port)) = destination(&payload) else {
        return Err(PostRefusal::InvalidDestination);
    };
    Ok(Route { dest_key, dest_domain, dest_port })
}

/// `destination{public_key, domain, port}` from a slate body. Port may be a number or a numeric
/// string; it defaults to 443.
pub fn destination(payload: &Value) -> Option<(String, String, u16)> {
    let d = payload.get("destination")?;
    let key = d.get("public_key")?.as_str()?;
    let domain = d.get("domain")?.as_str()?;
    let port = match d.get("port") {
        None | Some(Value::Null) => 443,
        Some(Value::Number(n)) => u16::try_from(n.as_u64()?).ok()?,
        Some(Value::String(s)) => s.parse().ok()?,
        _ => return None,
    };
    if domain.is_empty() || !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return None;
    }
    // `relay.example.org.` is the same host as `relay.example.org`: route both the same way, or
    // an absolute name makes this relay forward to itself and slips past `federation.deny`.
    let domain = normalize_domain(domain)?;
    let addr = parse_address(key).ok()?;
    if addr.domain.is_some() || !addr.public_key_valid() {
        return None;
    }
    Some((addr.public_key, domain, port))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const KEY: &str = "zzNqXNSX6bQ5CeMkmoLbbjLgQk158SRgC3Q6bwjfsAvTxovY9uBv";

    #[test]
    fn from_json_reads_the_fields() {
        let r = PostReq::from_json(
            &json!({"from":"a","to":"b","str":"s","signature":"g","epicboxtxid":null,"epicboxtxidsig":5}),
        );
        assert_eq!(
            (r.from.as_deref(), r.to.as_deref(), r.str_.as_deref(), r.signature.as_deref()),
            (Some("a"), Some("b"), Some("s"), Some("g"))
        );
        assert!(r.txid.is_none());
        assert_eq!(r.txidsig, Some(json!(5)));
        assert_eq!(r.body_len(), 1);
        assert_eq!(PostReq::default().body_len(), 0);
        let r = PostReq::from_json(&json!({"from":3}));
        assert!(r.from.is_none());
    }

    #[test]
    fn size_comes_first() {
        let req = PostReq { str_: Some("x".repeat(11)), ..Default::default() };
        assert_eq!(check_envelope(req, 10, true), Err(PostRefusal::TooLarge { max: 10 }));
        let req = PostReq { str_: Some("x".repeat(10)), ..Default::default() };
        assert_eq!(check_envelope(req, 10, true), Err(PostRefusal::MissingFields));
    }

    #[test]
    fn txid_fields_are_both_or_neither() {
        let t = "a".repeat(32);
        let base = PostReq {
            from: Some(KEY.into()),
            to: Some(KEY.into()),
            str_: Some("{}".into()),
            signature: Some("00".into()),
            ..Default::default()
        };
        let half = PostReq { txid: Some(json!(t)), ..base.clone() };
        assert_eq!(check_envelope(half, 100, true), Err(PostRefusal::MissingFields));
        let bad_id = PostReq { txid: Some(json!("short")), txidsig: Some(json!("00")), ..base.clone() };
        assert_eq!(check_envelope(bad_id, 100, true), Err(PostRefusal::MissingFields));
        let not_str = PostReq { txid: Some(json!(7)), txidsig: Some(json!("00")), ..base.clone() };
        assert_eq!(check_envelope(not_str, 100, true), Err(PostRefusal::MissingFields));
        // Legacy entry points ignore the 3.1.0 fields and do not need the full set.
        let legacy = PostReq { txid: Some(json!("short")), ..base.clone() };
        assert_eq!(check_envelope(legacy, 100, false), Err(PostRefusal::BadPostSignature));
        assert_eq!(
            check_envelope(PostReq::default(), 100, false),
            Err(PostRefusal::WrongAddress { from: String::new(), to: String::new() })
        );
    }

    #[test]
    fn address_and_signature_stages() {
        let req = PostReq {
            from: Some("nope".into()),
            to: Some(KEY.into()),
            str_: Some("{}".into()),
            signature: Some("00".into()),
            ..Default::default()
        };
        let e = check_envelope(req, 100, true).unwrap_err();
        assert_eq!(e.text(), "Wrong address format. From: nope, To: ".to_string() + KEY);
        assert!(!e.is_failed_signature());
        // A key that is well formed but does not decode.
        let req = PostReq {
            from: Some("1".repeat(52)),
            to: Some(KEY.into()),
            str_: Some("{}".into()),
            signature: Some("00".into()),
            ..Default::default()
        };
        assert!(matches!(check_envelope(req, 100, true), Err(PostRefusal::WrongAddress { .. })));
        // No `str` or `signature` on a legacy post: not a failed signature.
        let req = PostReq { from: Some(KEY.into()), to: Some(KEY.into()), ..Default::default() };
        let e = check_envelope(req, 100, false).unwrap_err();
        assert_eq!(e, PostRefusal::NoSignature);
        assert!(!e.is_failed_signature());
        assert_eq!(e.text(), "Error postslate signature.");
        // A signature that does not verify is counted.
        let req = PostReq {
            from: Some(KEY.into()),
            to: Some(KEY.into()),
            str_: Some("{}".into()),
            signature: Some("00".into()),
            ..Default::default()
        };
        let e = check_envelope(req, 100, true).unwrap_err();
        assert_eq!(e, PostRefusal::BadPostSignature);
        assert!(e.is_failed_signature());
        assert_eq!((e.kind(), PostRefusal::BadTxidSignature.kind()), ("InvalidRequest", "InvalidSignature"));
        assert_eq!(PostRefusal::BadTxidSignature.text(), "Invalid epicboxtxid signature.");
        assert!(PostRefusal::BadTxidSignature.is_failed_signature());
    }

    #[test]
    fn route_finds_the_destination() {
        let body = |d: Value| json!({ "destination": d }).to_string();
        let r = route(&body(json!({"public_key": KEY, "domain": "Relay.Example.org.", "port": 8080}))).unwrap();
        assert_eq!((r.dest_key.as_str(), r.dest_domain.as_str(), r.dest_port), (KEY, "relay.example.org", 8080));
        assert_eq!(route(&body(json!({"public_key": KEY, "domain": "a.b", "port": "9"}))).unwrap().dest_port, 9);
        assert_eq!(route(&body(json!({"public_key": KEY, "domain": "a.b"}))).unwrap().dest_port, 443);
        assert_eq!(route(&body(json!({"public_key": KEY, "domain": "a.b", "port": null}))).unwrap().dest_port, 443);
        for bad in [
            json!({"public_key": KEY, "domain": "a.b", "port": 70000}),
            json!({"public_key": KEY, "domain": "a.b", "port": -1}),
            json!({"public_key": KEY, "domain": "a.b", "port": true}),
            json!({"public_key": KEY, "domain": ""}),
            json!({"public_key": KEY, "domain": "a b"}),
            json!({"public_key": KEY, "domain": "a..b"}),
            json!({"public_key": format!("{KEY}@x.y"), "domain": "a.b"}),
            json!({"public_key": "1".repeat(52), "domain": "a.b"}),
            json!({"domain": "a.b"}),
            json!(null),
        ] {
            assert_eq!(route(&body(bad.clone())), Err(PostRefusal::InvalidDestination), "{bad}");
        }
        assert_eq!(route("not json"), Err(PostRefusal::InvalidPayload));
        assert_eq!(route("{}"), Err(PostRefusal::InvalidDestination));
        assert_eq!(PostRefusal::InvalidPayload.text(), "Invalid Slate payload.");
        assert_eq!(PostRefusal::InvalidDestination.text(), "Invalid slate destination.");
    }
}
