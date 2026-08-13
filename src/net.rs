//! Network operations for `hs`.
//!
//! When the input to the `verify` command is a URL (for instance
//! `https://example.org`), the HTML is fetched over HTTPS — verifying the
//! TLS certificate unless `--ignore-tls-errors` is given — and the signing
//! public key is resolved from the DNS TXT record `_hs_key.example.org`.
//!
//! The DNS record holds the public key in the compact ASCII85 TXT format
//! produced by `hs export --txt`
//! (`HS85:<KEM>:<DSA>:<ascii85(kem_pk || dsa_pk)>`, no PEM markers).
//! Multiple TXT character-strings within a record are concatenated, so the
//! payload may be split across the DNS 255-byte character-string
//! boundaries. Legacy records holding the armored
//! `-----BEGIN HS PUBLIC KEY-----` block are still accepted.

use crate::keys;
use crate::keys::KeyInfo;
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// DNS label prefix used to discover `hs` signing keys.
///
/// For host `example.org` the lookup name is `_hs_key.example.org`.
pub const DNS_KEY_PREFIX: &str = "_hs_key";

/// Maximum length of a single DNS TXT character-string (RFC 1035 §3.3.14).
pub const DNS_TXT_MAX: usize = 255;

/// Global timeout for HTTP requests, mirroring the `pqp` behaviour of
/// enforcing a bounded fetch to prevent slow-loris stalls.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// The TXT record payload is not a valid armored public key.
    #[error("key in DNS for {0} is invalid: {1}")]
    InvalidKey(String, String),
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
/// Each record is parsed with [`keys::parse_public_key`], which accepts
/// both the ASCII85 TXT format (`HS85:...`) and the legacy armored form;
/// the first parseable record is used.
pub fn public_key_from_dns(host: &str) -> Result<KeyInfo, NetError> {
    let name = dns_key_name(host);
    let records = dns_txt(&name)?;
    for record in &records {
        if let Ok(info) = keys::parse_public_key(record) {
            return Ok(info);
        }
    }
    if records.is_empty() {
        Err(NetError::NoKey(name))
    } else {
        Err(NetError::InvalidKey(
            name,
            "no record contained a valid public key".into(),
        ))
    }
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
}
