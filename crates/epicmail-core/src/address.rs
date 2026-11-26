//! Epicbox address parsing (same grammar as the stock relay) and relay domain names.
//!
//! The grammar is
//! `^(epicbox://)?[base58]{52}(@[a-zA-Z0-9.]+(:[0-9]*)?)?$`
//! (base58 is the Bitcoin alphabet). It is parsed by hand: a regex engine costs wasm size and
//! cycles per message. `tests` checks the parser against that regex.

use crate::sig;

/// The Bitcoin base58 alphabet: no `0`, `O`, `I` or `l`.
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const KEY_LEN: usize = 52;
const SCHEME: &str = "epicbox://";

/// `[epicbox://]<public key>[@domain[:port]]`, split into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpicboxAddress {
    pub public_key: String,
    pub domain: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Malformed,
    /// A port that is present but empty or above 65535.
    BadPort,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            AddressError::Malformed => "address does not match the epicbox address grammar",
            AddressError::BadPort => "port is empty or not a valid u16",
        })
    }
}

impl std::error::Error for AddressError {}

/// Split an address by the grammar alone. The key is not decoded; see `public_key_valid`.
pub fn parse_address(s: &str) -> Result<EpicboxAddress, AddressError> {
    let rest = s.strip_prefix(SCHEME).unwrap_or(s);
    // The key is ASCII, so a split at KEY_LEN is on a char boundary once the bytes check out.
    let key = rest.as_bytes().get(..KEY_LEN).ok_or(AddressError::Malformed)?;
    if !key.iter().all(|b| BASE58.contains(b)) {
        return Err(AddressError::Malformed);
    }
    let (public_key, tail) = rest.split_at(KEY_LEN);
    if tail.is_empty() {
        return Ok(EpicboxAddress { public_key: public_key.into(), domain: None, port: None });
    }
    let tail = tail.strip_prefix('@').ok_or(AddressError::Malformed)?;
    let (domain, port) = match tail.split_once(':') {
        Some((d, p)) => (d, Some(p)),
        None => (tail, None),
    };
    if domain.is_empty() || !domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.') {
        return Err(AddressError::Malformed);
    }
    let port = match port {
        None => None,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => Some(p.parse::<u16>().map_err(|_| AddressError::BadPort)?),
        Some(_) => return Err(AddressError::Malformed),
    };
    Ok(EpicboxAddress { public_key: public_key.into(), domain: Some(domain.into()), port })
}

impl EpicboxAddress {
    /// The key part base58check-decodes to a valid secp256k1 key.
    pub fn public_key_valid(&self) -> bool {
        sig::parse_public_key(&self.public_key).is_ok()
    }
}

/// A relay domain in one form: lower case, without the trailing dot of an absolute name.
/// None when it is empty or not a plausible host name (empty labels, leading dot).
pub fn normalize_domain(domain: &str) -> Option<String> {
    let d = domain.to_ascii_lowercase();
    let d = d.strip_suffix('.').unwrap_or(&d);
    if d.is_empty() || d.len() > 253 || d.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return None;
    }
    Some(d.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    /// A throwaway key from `tests/data/sigcases.jsonl`: 52 characters, decodes to a key.
    const KEY: &str = "zzNqXNSX6bQ5CeMkmoLbbjLgQk158SRgC3Q6bwjfsAvTxovY9uBv";

    fn key() -> String {
        KEY.to_string()
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

    #[test]
    fn domains_have_one_normal_form() {
        assert_eq!(normalize_domain("Relay.Example.org."), Some("relay.example.org".into()));
        assert_eq!(normalize_domain("relay.example.org"), Some("relay.example.org".into()));
        for bad in ["", ".", "a..b", ".a.b", "a.b..", "a.b.."] {
            assert_eq!(normalize_domain(bad), None, "{bad}");
        }
        assert_eq!(normalize_domain(&"a".repeat(64)), None);
        assert_eq!(normalize_domain(&format!("{0}.{0}.{0}.{0}.{0}", "a".repeat(62))), None);
    }

    // The regex the parser replaced, kept as the reference for the comparison below.
    const REGEX: &str = r"^(epicbox://)?(?P<public_key>[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{52})(@(?P<domain>[a-zA-Z0-9\.]+)(:(?P<port>[0-9]*))?)?$";

    fn by_regex(re: &Regex, s: &str) -> Result<EpicboxAddress, AddressError> {
        let caps = re.captures(s).ok_or(AddressError::Malformed)?;
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

    /// xorshift64: a fixed seed, so a failure is the same on every run.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[test]
    fn parser_matches_the_regex() {
        let re = Regex::new(REGEX).unwrap();
        let k = key();
        let mut inputs: Vec<String> = vec![
            k.clone(),
            format!("epicbox://{k}"),
            format!("epicbox://{k}@epicbox.example.com:8080"),
            format!("{k}@host"),
            format!("{k}@host:65535"),
            format!("{k}@host:"),
            format!("{k}@host:70000"),
            format!("{k}@host:65536"),
            format!("{k}@host:00080"),
            format!("{k}@host:{}", "9".repeat(40)),
            format!("{k}@host:80:90"),
            format!("{k}@host:+80"),
            format!("{k}@:80"),
            format!("{k}@"),
            format!("{k}@ho st"),
            format!("{k}@h-st"),
            format!("{k}@h_st"),
            format!("{k}@.."),
            format!("{k}@é"),
            format!("{k}é"),
            format!("é{}", &k[1..]),
            format!(" {k}"),
            format!("{k}\n"),
            format!("{k}@host\n"),
            format!("epicbox://epicbox://{k}"),
            format!("epicbox:/{k}"),
            format!("EPICBOX://{k}"),
            k[..51].to_string(),
            format!("{k}1"),
            "1".repeat(52),
            "1".repeat(53),
            String::new(),
            "epicbox://".to_string(),
            "@".to_string(),
        ];
        for bad in ['0', 'O', 'I', 'l'] {
            inputs.push(format!("{}{}", bad, &k[1..]));
        }
        // Random strings and mutations of valid ones, over the characters that matter to the
        // grammar plus a few outside it (non-ASCII, whitespace, NUL).
        let alphabet: Vec<char> = format!("{k}0OIl@:./-_ \n\0é€xyz09epicbox").chars().collect();
        let seeds = [k.clone(), format!("epicbox://{k}@host.example:8080"), format!("{k}@a.b:1")];
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for i in 0..20_000 {
            let mut chars: Vec<char> = if i % 4 == 0 {
                (0..rng.below(80)).map(|_| alphabet[rng.below(alphabet.len())]).collect()
            } else {
                seeds[rng.below(seeds.len())].chars().collect()
            };
            if i % 4 != 0 {
                for _ in 0..1 + rng.below(3) {
                    let at = rng.below(chars.len() + 1);
                    match rng.below(3) {
                        0 if at < chars.len() => {
                            chars.remove(at);
                        }
                        1 => chars.insert(at, alphabet[rng.below(alphabet.len())]),
                        _ if at < chars.len() => chars[at] = alphabet[rng.below(alphabet.len())],
                        _ => {}
                    }
                }
            }
            inputs.push(chars.into_iter().collect());
        }
        let mut accepted = 0;
        for s in &inputs {
            let (got, want) = (parse_address(s), by_regex(&re, s));
            assert_eq!(got, want, "input {s:?}");
            accepted += got.is_ok() as usize;
        }
        assert!(accepted > 1000, "the generated set should hold plenty of accepted addresses: {accepted}");
    }
}
