//! Epicbox address parsing (same grammar as the stock relay).

use once_cell::sync::Lazy;
use regex::Regex;

use crate::sig;

const ADDRESS_REGEX: &str = r"^(epicbox://)?(?P<public_key>[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{52})(@(?P<domain>[a-zA-Z0-9\.]+)(:(?P<port>[0-9]*))?)?$";

static RE: Lazy<Regex> = Lazy::new(|| Regex::new(ADDRESS_REGEX).unwrap());

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpicboxAddress {
    pub public_key: String,
    pub domain: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("address does not match the epicbox address grammar")]
    Malformed,
    /// A port that is present but empty or above 65535.
    #[error("port is empty or not a valid u16")]
    BadPort,
}

pub fn parse_address(s: &str) -> Result<EpicboxAddress, AddressError> {
    let caps = RE.captures(s).ok_or(AddressError::Malformed)?;
    let port = match caps.name("port") {
        None => None,
        Some(m) => Some(m.as_str().parse::<u16>().map_err(|_| AddressError::BadPort)?),
    };
    Ok(EpicboxAddress {
        public_key: caps["public_key"].to_string(),
        domain: caps.name("domain").map(|m| m.as_str().to_string()),
        port,
    })
}

impl EpicboxAddress {
    /// The key part base58check-decodes to a valid secp256k1 key.
    pub fn public_key_valid(&self) -> bool {
        sig::parse_public_key(&self.public_key).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn key() -> String {
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        sig::encode_public_key(&pk, sig::VERSION_FLOONET)
    }

    #[test]
    fn plain_key() {
        let k = key();
        assert_eq!(k.len(), 52);
        let a = parse_address(&k).unwrap();
        assert_eq!(a, EpicboxAddress { public_key: k, domain: None, port: None });
        assert!(a.public_key_valid());
    }

    #[test]
    fn scheme_domain_port() {
        let k = key();
        let a = parse_address(&format!("epicbox://{k}@epicbox.example.com:8080")).unwrap();
        assert_eq!(a.domain.as_deref(), Some("epicbox.example.com"));
        assert_eq!(a.port, Some(8080));
        let a = parse_address(&format!("{k}@host")).unwrap();
        assert_eq!((a.domain.as_deref(), a.port), (Some("host"), None));
        assert_eq!(parse_address(&format!("{k}@host:65535")).unwrap().port, Some(65535));
    }

    #[test]
    fn empty_and_big_port_refused() {
        let k = key();
        assert_eq!(parse_address(&format!("{k}@host:")), Err(AddressError::BadPort));
        assert_eq!(parse_address(&format!("{k}@host:70000")), Err(AddressError::BadPort));
        assert_eq!(parse_address(&format!("{k}@host:65536")), Err(AddressError::BadPort));
    }

    #[test]
    fn bad_shapes_refused() {
        let k = key();
        assert_eq!(parse_address(&k[..51]), Err(AddressError::Malformed));
        assert_eq!(parse_address(&format!("{k}1")), Err(AddressError::Malformed));
        assert_eq!(parse_address(""), Err(AddressError::Malformed));
        for bad in ['0', 'O', 'I', 'l'] {
            let s = format!("{}{}", bad, &k[1..]);
            assert_eq!(parse_address(&s), Err(AddressError::Malformed), "{bad}");
        }
        assert_eq!(parse_address(&format!("{k}@")), Err(AddressError::Malformed));
        assert_eq!(parse_address(&format!("{k}@ho st")), Err(AddressError::Malformed));
        assert_eq!(parse_address(&format!(" {k}")), Err(AddressError::Malformed));
        assert_eq!(parse_address(&format!("{k}\n")), Err(AddressError::Malformed));
    }

    #[test]
    fn well_formed_but_invalid_key() {
        let a = parse_address(&"1".repeat(52)).unwrap();
        assert!(!a.public_key_valid());
        let mut k = key();
        k.replace_range(3..4, if &k[3..4] == "2" { "3" } else { "2" });
        assert!(!parse_address(&k).unwrap().public_key_valid());
    }
}
