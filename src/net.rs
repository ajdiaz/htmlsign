//! Network operations for `hs`.
//!
//! When the input to the `verify` command is a URL (for instance
//! `https://example.org`), the HTML is fetched over HTTPS — verifying the
//! TLS certificate unless `--ignore-tls-errors` is given — and the signing
//! public key is resolved from the DNS TXT record `_hs_key.example.org`.
//!
//! The record holds a **pin** — the SHA3-256 fingerprint of the public key
//! and the URL where the key itself is served:
//!
//! ```text
//! HSPIN:SHA3-256:<64-hex-fingerprint>:https://example.org/.well-known/hs.pub
//! ```
//!
//! `hs` downloads the key from that URL (over HTTPS, TLS validated unless
//! `--ignore-tls-errors`) and requires its SHA3-256 fingerprint to match
//! the pinned digest exactly. Because the pin lives in DNS (the trust
//! anchor), a compromised web server cannot swap in a different key — the
//! fingerprint check would fail. Legacy records that publish the key
//! directly (armored `-----BEGIN HS PUBLIC KEY-----` or the ASCII85
//! `HS85:...` form, which `hs export` used before) are still accepted.

use crate::keys;
use crate::keys::KeyInfo;
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// DNS label prefix used to discover `hs` signing keys.
///
/// For host `example.org` the lookup name is `_hs_key.example.org`.
pub const DNS_KEY_PREFIX: &str = "_hs_key";

/// Marker prefix of the DNS key-pin record produced by `hs export --txt`.
pub const DNS_PIN_PREFIX: &str = "HSPIN";

/// Maximum length of a single DNS TXT character-string (RFC 1035 §3.3.14).
pub const DNS_TXT_MAX: usize = 255;

/// Global timeout for HTTP requests, mirroring the `pqp` behaviour of
/// enforcing a bounded fetch to prevent slow-loris stalls.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// A DNS-pinned signing key: a SHA3-256 fingerprint and the URL of the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsKeyPin {
    /// Hex SHA3-256 fingerprint of `kem_pk || dsa_pk` (as in `KeyInfo::fingerprint`).
    pub fingerprint: String,
    /// URL from which the public key is served.
    pub url: String,
}

/// A public key resolved from DNS, along with where it came from.
#[derive(Debug, Clone)]
pub struct DnsKey {
    /// The resolved public key.
    pub info: KeyInfo,
    /// The DNS record name that held the key or pin (`_hs_key.<host>`).
    pub record: String,
    /// URL the key was downloaded from, when a pin record was used.
    pub url: Option<String>,
}

/// Errors produced by the `net` module.
#[derive(Error, Debug)]
pub enum NetError {
    /// The input could not be parsed as a URL.
    #[error("invalid URL {0}: {1}")]
    InvalidUrl(String, String),
    /// The URL scheme is not HTTP(S).
    #[error("unsupported URL scheme {0}: only http:// and https:// are supported")]
    UnsupportedScheme(String),
    /// The URL does not carry a host name.
    #[error("URL {0} has no host name")]
    MissingHost(String),
    /// An HTTP request failed at the transport level.
    #[error("HTTP request failed for {0}: {1}")]
    Transport(String, String),
    /// The server returned a non-success status code.
    #[error("HTTP status {status} for {url}")]
    HttpStatus {
        /// Status code returned by the server.
        status: u16,
        /// URL that was requested.
        url: String,
    },
    /// A DNS operation failed.
    #[error("DNS lookup failed: {0}")]
    Dns(String),
    /// No TXT record was published at the expected DNS name.
    #[error("no _hs_key TXT record found for {0}")]
    NoKey(String),
    /// The TXT record payload is not a valid public key or pin.
    #[error("key in DNS for {0} is invalid: {1}")]
    InvalidKey(String, String),
    /// The DNS pin record is malformed.
    #[error("invalid DNS key pin: {0}")]
    InvalidPin(String),
    /// The key downloaded from the pinned URL does not match the digest.
    #[error("key at {url} does not match the DNS pin: expected SHA3-256 {expected}, got {got}")]
    PinMismatch {
        /// URL the key was downloaded from.
        url: String,
        /// Fingerprint recorded in DNS.
        expected: String,
        /// Fingerprint of the downloaded key.
        got: String,
    },
}

/// Return whether `input` looks like an `http://` or `https://` URL.
///
/// Local file paths are treated as such and are not fetched from the
/// network.
pub fn is_url(input: &str) -> bool {
    parse_url(input).is_ok()
}

/// Parse and validate an HTTP(S) URL.
fn parse_url(input: &str) -> Result<Url, NetError> {
    let url =
        Url::parse(input).map_err(|e| NetError::InvalidUrl(input.to_string(), e.to_string()))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        scheme => Err(NetError::UnsupportedScheme(scheme.to_string())),
    }
}

/// Extract the host name from an URL.
///
/// Returns an error if the URL is malformed, uses a non-HTTP scheme, or
/// carries no host component.
pub fn host_of(url: &str) -> Result<String, NetError> {
    let url = parse_url(url)?;
    url.host_str()
        .map(str::to_string)
        .ok_or_else(|| NetError::MissingHost(url.to_string()))
}

/// Build the DNS name that holds the `hs` public key for `host`.
///
/// For `example.org` this returns `_hs_key.example.org`.
pub fn dns_key_name(host: &str) -> String {
    format!("{}.{}", DNS_KEY_PREFIX, host)
}

/// Fetch the body of an URL over HTTP(S).
///
/// Server certificates are verified unless `ignore_tls_errors` is set.
/// Returns an error for non-2xx status codes.
pub fn fetch_html(url: &str, ignore_tls_errors: bool) -> Result<String, NetError> {
    let mut builder = ureq::Agent::config_builder().timeout_global(Some(HTTP_TIMEOUT));
    if ignore_tls_errors {
        let tls = ureq::tls::TlsConfig::builder()
            .disable_verification(true)
            .build();
        builder = builder.tls_config(tls);
    }
    let agent: ureq::Agent = builder.build().into();

    let response = agent
        .get(url)
        .call()
        .map_err(|e| NetError::Transport(url.to_string(), e.to_string()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(NetError::HttpStatus {
            status,
            url: url.to_string(),
        });
    }
    response
        .into_body()
        .read_to_string()
        .map_err(|e| NetError::Transport(url.to_string(), e.to_string()))
}

/// Resolve TXT records for `name`, concatenating the character-strings of
/// each record into a single `String`.
pub fn dns_txt(name: &str) -> Result<Vec<String>, NetError> {
    let runtime = tokio::runtime::Runtime::new().map_err(|e| NetError::Dns(e.to_string()))?;
    runtime.block_on(async {
        let resolver = hickory_resolver::Resolver::builder_tokio()
            .map_err(|e| NetError::Dns(e.to_string()))?
            .build()
            .map_err(|e| NetError::Dns(e.to_string()))?;
        let lookup = resolver
            .txt_lookup(name)
            .await
            .map_err(|e| NetError::Dns(e.to_string()))?;

        let mut records = Vec::new();
        for record in lookup.answers() {
            if let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data {
                let joined: String = txt
                    .txt_data
                    .iter()
                    .map(|s| String::from_utf8_lossy(s))
                    .collect();
                records.push(joined);
            }
        }
        Ok(records)
    })
}

/// Resolve the `hs` public key for `host` via the DNS TXT record
/// `_hs_key.<host>`.
///
/// If the record is a pin (`HSPIN:SHA3-256:<fingerprint>:<url>`), the key
/// is downloaded from `url` and its SHA3-256 fingerprint is validated
/// against the pin (see [`DnsKeyPin`]); the first matching pin is used.
/// Legacy records that carry the public key itself (armored or ASCII85,
/// see [`keys::parse_public_key`]) are also accepted. The returned
/// [`DnsKey`] records which DNS name and, for pin records, which URL the
/// key was resolved from.
pub fn resolve_key_from_dns(host: &str, ignore_tls_errors: bool) -> Result<DnsKey, NetError> {
    let name = dns_key_name(host);
    let records = dns_txt(&name)?;
    for record in &records {
        if let Ok(pin) = parse_dns_pin(record) {
            let info = resolve_pin(&pin, ignore_tls_errors)?;
            return Ok(DnsKey {
                info,
                record: name.clone(),
                url: Some(pin.url),
            });
        }
        if let Ok(info) = keys::parse_public_key(record) {
            return Ok(DnsKey {
                info,
                record: name.clone(),
                url: None,
            });
        }
    }
    if records.is_empty() {
        Err(NetError::NoKey(name))
    } else {
        Err(NetError::InvalidKey(
            name,
            "no record contained a valid key or pin".into(),
        ))
    }
}

/// Download the key pinned by `pin` and validate its fingerprint.
///
/// The key body is fetched over HTTP(S) — validating TLS unless
/// `ignore_tls_errors` is set — parsed as a public key (armored or ASCII85)
/// and checked against the pinned SHA3-256 digest.
fn resolve_pin(pin: &DnsKeyPin, ignore_tls_errors: bool) -> Result<KeyInfo, NetError> {
    let body = fetch_html(&pin.url, ignore_tls_errors)?;
    let info = keys::parse_public_key(&body)
        .map_err(|e| NetError::InvalidKey(pin.url.clone(), e.to_string()))?;
    check_pin(pin, &info)?;
    Ok(info)
}

/// Verify that `info`'s fingerprint matches the pinned digest.
fn check_pin(pin: &DnsKeyPin, info: &KeyInfo) -> Result<(), NetError> {
    if !info.fingerprint.eq_ignore_ascii_case(&pin.fingerprint) {
        return Err(NetError::PinMismatch {
            url: pin.url.clone(),
            expected: pin.fingerprint.clone(),
            got: info.fingerprint.clone(),
        });
    }
    Ok(())
}

/// Format the DNS pin record that pins a signing key.
///
/// The record is a single short line of the form
/// `HSPIN:SHA3-256:<fingerprint>:<url>` — well under the 255-byte DNS TXT
/// character-string limit — where `<fingerprint>` is the hex SHA3-256
/// digest of `kem_pk || dsa_pk` and `<url>` serves the public key itself.
pub fn dns_pin(info: &KeyInfo, url: &str) -> String {
    format!("{}:SHA3-256:{}:{}", DNS_PIN_PREFIX, info.fingerprint, url)
}

/// Parse a DNS key-pin record into its components.
///
/// The record must start with [`DNS_PIN_PREFIX`] followed by
/// `:<hash>:<hex-fingerprint>:<url>`. Only `SHA3-256` is accepted, the
/// fingerprint must be exactly 64 hex characters, and the URL must use the
/// `http://` or `https://` scheme.
pub fn parse_dns_pin(record: &str) -> Result<DnsKeyPin, NetError> {
    let body = record
        .trim()
        .strip_prefix(DNS_PIN_PREFIX)
        .ok_or_else(|| NetError::InvalidPin("missing HSPIN prefix".into()))?
        .strip_prefix(':')
        .ok_or_else(|| NetError::InvalidPin("missing hash algorithm".into()))?;
    let mut parts = body.splitn(3, ':');
    let algo = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| NetError::InvalidPin("missing hash algorithm".into()))?;
    let digest = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| NetError::InvalidPin("missing fingerprint".into()))?;
    let url = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| NetError::InvalidPin("missing key URL".into()))?;

    if algo != "SHA3-256" {
        return Err(NetError::InvalidPin(format!(
            "unsupported hash algorithm {}",
            algo
        )));
    }
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetError::InvalidPin(
            "fingerprint must be 64 hex characters".into(),
        ));
    }
    parse_url(url)?;

    Ok(DnsKeyPin {
        fingerprint: digest.to_ascii_lowercase(),
        url: url.to_string(),
    })
}

/// Split a public-key payload into DNS TXT character-strings of at most
/// [`DNS_TXT_MAX`] bytes each.
///
/// The payload (armored text or the ASCII85 `HS85:...` line) is first
/// collapsed to a single line and then sliced into consecutive ≤255-byte
/// pieces. A DNS operator publishes one TXT record whose character-strings
/// are the returned lines; [`dns_txt`] concatenates them back into the
/// single-line payload, which [`keys::parse_public_key`] accepts. The
/// pieces contain no newlines, so providers that mangle embedded line
/// breaks still round-trip correctly.
pub fn txt_chunks(text: &str) -> Vec<String> {
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized
        .as_bytes()
        .chunks(DNS_TXT_MAX)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen;
    use crate::crypto::{DsaVariant, KemVariant};
    use std::io::{Read, Write};

    fn sample_armor() -> (String, String) {
        let pair = keygen::generate(KemVariant::MlKem512, DsaVariant::MlDsa44).unwrap();
        let info = keys::KeyInfo {
            kem_variant: KemVariant::MlKem512,
            dsa_variant: DsaVariant::MlDsa44,
            kem_public_key: pair.kem_public.to_bytes(),
            dsa_public_key: pair.sign_public.to_bytes(),
            fingerprint: String::new(),
        };
        (keys::armor_public_key(&info), info.fingerprint.clone())
    }

    #[test]
    fn is_url_accepts_http_and_https() {
        assert!(is_url("https://example.org"));
        assert!(is_url("http://example.org/page"));
        assert!(!is_url("index.html"));
        assert!(!is_url("ftp://example.org"));
        assert!(!is_url("not a url"));
    }

    #[test]
    fn host_of_extracts_host() {
        assert_eq!(host_of("https://example.org/path").unwrap(), "example.org");
        assert_eq!(
            host_of("https://www.example.org:8443/x").unwrap(),
            "www.example.org"
        );
        assert!(matches!(
            host_of("ftp://example.org"),
            Err(NetError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn dns_key_name_prefixes_host() {
        assert_eq!(dns_key_name("example.org"), "_hs_key.example.org");
    }

    #[test]
    fn txt_chunks_stay_within_255_bytes_and_join_losslessly() {
        let (armor, _fingerprint) = sample_armor();
        let chunks = txt_chunks(&armor);
        assert!(!chunks.is_empty());
        let expected: String = armor.split_whitespace().collect::<Vec<_>>().join(" ");
        for chunk in &chunks {
            assert!(chunk.len() <= DNS_TXT_MAX, "chunk exceeds 255 bytes");
            assert!(!chunk.contains('\n'), "chunk must not embed newlines");
        }
        let joined: String = chunks.concat();
        assert_eq!(joined, expected);
        let info = keys::unarmor_public_key(&joined).unwrap();
        assert_eq!(info.fingerprint.len(), 64);
    }

    #[test]
    fn ascii85_txt_chunks_join_and_parse_without_pem() {
        let pair = keygen::generate(KemVariant::MlKem768, DsaVariant::MlDsa65).unwrap();
        let info = keys::KeyInfo {
            kem_variant: KemVariant::MlKem768,
            dsa_variant: DsaVariant::MlDsa65,
            kem_public_key: pair.kem_public.to_bytes(),
            dsa_public_key: pair.sign_public.to_bytes(),
            fingerprint: String::new(),
        };
        let line = keys::ascii85_public_key(&info);
        assert!(
            line.len() <= 4096,
            "must fit DNS TXT limit, got {}",
            line.len()
        );
        let chunks = txt_chunks(&line);
        let joined: String = chunks.concat();
        assert_eq!(joined, line);
        let parsed = keys::parse_public_key(&joined).unwrap();
        assert_eq!(parsed.fingerprint.len(), 64);
        assert_eq!(parsed.kem_public_key, info.kem_public_key);
    }

    #[test]
    fn parse_armor_from_single_line_txt() {
        let (armor, _fingerprint) = sample_armor();
        let single_line = armor.replace('\n', " ");
        let info = keys::unarmor_public_key(&single_line).unwrap();
        assert!(info.fingerprint.len() == 64);
    }

    #[test]
    fn parse_armor_when_strings_spliced() {
        let (armor, _fingerprint) = sample_armor();
        let split: String = armor
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 100 == 0 {
                    Vec::from(['\n', c])
                } else {
                    Vec::from([c])
                }
            })
            .collect();
        let info = keys::unarmor_public_key(&split).unwrap();
        assert!(info.fingerprint.len() == 64);
    }

    #[test]
    fn public_key_from_dns_rejects_garbage() {
        let err = keys::unarmor_public_key("not a key").unwrap_err();
        assert!(err.to_string().contains("invalid armored public key"));
    }

    #[test]
    fn dns_pin_round_trips_through_parse() {
        let (armor, _fingerprint) = sample_armor();
        let info = keys::unarmor_public_key(&armor).unwrap();
        let url = "https://example.org/.well-known/hs.pub";
        let record = dns_pin(&info, url);
        assert!(record.starts_with("HSPIN:SHA3-256:"));
        assert!(record.len() < DNS_TXT_MAX, "pin must fit one TXT string");
        let pin = parse_dns_pin(&record).unwrap();
        assert_eq!(pin.url, url);
        assert_eq!(pin.fingerprint, info.fingerprint);
        assert_eq!(pin.fingerprint.len(), 64);
    }

    #[test]
    fn parse_dns_pin_rejects_bad_records() {
        let hex64 = "a".repeat(64);
        let err = parse_dns_pin("nope").unwrap_err();
        assert!(err.to_string().contains("missing HSPIN prefix"));
        let err = parse_dns_pin("HSPIN:SHA3-256:zz:https://x/").unwrap_err();
        assert!(err.to_string().contains("64 hex"));
        let err = parse_dns_pin(&format!("HSPIN:MD5:{}:https://x", hex64)).unwrap_err();
        assert!(err.to_string().contains("unsupported hash algorithm"));
        let err = parse_dns_pin(&format!("HSPIN:SHA3-256:{}:ftp://x", hex64)).unwrap_err();
        assert!(matches!(err, NetError::UnsupportedScheme(_)));
        let err = parse_dns_pin(&format!("HSPIN:SHA3-256:{}", hex64)).unwrap_err();
        assert!(err.to_string().contains("missing key URL"));
    }

    #[test]
    fn check_pin_detects_mismatch() {
        let (armor, _fingerprint) = sample_armor();
        let info = keys::unarmor_public_key(&armor).unwrap();
        let url = "https://example.org/key.pub".to_string();
        let good = DnsKeyPin {
            fingerprint: info.fingerprint.clone(),
            url: url.clone(),
        };
        assert!(check_pin(&good, &info).is_ok());
        let bad = DnsKeyPin {
            fingerprint: "0".repeat(64),
            url,
        };
        assert!(matches!(
            check_pin(&bad, &info),
            Err(NetError::PinMismatch { .. })
        ));
    }

    #[test]
    fn resolve_pin_downloads_and_validates_key() {
        let (armor, _fingerprint) = sample_armor();
        let info = keys::unarmor_public_key(&armor).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = armor.clone();
        let thread = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).unwrap();
            }
        });

        let url = format!("http://127.0.0.1:{}/key.pub", port);
        let good = DnsKeyPin {
            fingerprint: info.fingerprint.clone(),
            url: url.clone(),
        };
        let resolved = resolve_pin(&good, true).unwrap();
        assert_eq!(resolved.fingerprint, info.fingerprint);
        assert_eq!(resolved.kem_public_key, info.kem_public_key);

        let bad = DnsKeyPin {
            fingerprint: "0".repeat(64),
            url,
        };
        assert!(matches!(
            resolve_pin(&bad, true),
            Err(NetError::PinMismatch { .. })
        ));
        thread.join().unwrap();
    }
}
