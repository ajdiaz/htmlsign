//! Signature attribute format for `hs` signed blocks.
//!
//! A block is signed by embedding a `data-hs-signature` attribute whose
//! value has the self-describing form:
//!
//! ```text
//! <AlgorithmList>:<encoded payload>
//! ```
//!
//! where the `AlgorithmList` is a `+`-joined canonical list ending in the
//! encoding algorithm, for example `SHA3-256+ML-DSA-65+BASE64`. The encoded
//! payload (BASE64 for now) contains, in order:
//!
//! 1. ML-DSA signature over the SHA3-256 digest of the canonical block
//!
//! The public key is deliberately **not** embedded: verification uses the
//! key supplied by the user (`verify -k`), the default key, or the DNS
//! `_hs_key` pin. Signing follows a hash-then-sign construction: the block
//! is reduced to its 32-byte SHA3-256 digest first, and that digest is what
//! the ML-DSA signature covers. The `SHA3-256` marker in the algorithm list
//! records this for verifiers. Signatures produced before this scheme
//! (algorithm list without `SHA3-256`) covered the raw block bytes; they
//! still parse with `decode_signature` reporting `prehashed == false`, so
//! verifiers can accept legacy blocks too.

use crate::crypto::{DsaVariant, KemVariant};
use base64::Engine;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Errors that can occur while parsing or encoding signature attributes.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// The algorithm list is empty.
    #[error("empty algorithm list")]
    EmptyAlgorithmList,
    /// An unknown algorithm component was encountered.
    #[error("unknown algorithm: {0}")]
    UnknownAlgorithm(String),
    /// The algorithm list is missing a required component.
    #[error("missing {0} in algorithm list")]
    MissingAlgorithm(&'static str),
    /// The encoding algorithm is unsupported.
    #[error("unsupported encoding: {0}")]
    UnsupportedEncoding(String),
    /// The signature attribute is malformed (missing `:` separator).
    #[error("signature attribute missing ':' separator")]
    MissingSeparator,
    /// The payload could not be base64-decoded.
    #[error("invalid base64 payload: {0}")]
    InvalidBase64(String),
    /// The payload is shorter than the sum of its components.
    #[error("payload too short for its algorithm list")]
    PayloadTooShort,
}

/// Canonical algorithm identifiers used in an [`AlgorithmList`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    /// Generic ML-KEM marker.
    MlKem,
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
    /// Generic ML-DSA marker.
    MlDsa,
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
    /// XChaCha20-Poly1305 (reserved for future encryption support).
    XChaCha20Poly1305,
    /// SHA3-256.
    Sha3256,
    /// Argon2id.
    Argon2id,
    /// BASE64 encoding.
    Base64,
    /// ASCII85 encoding (reserved for future support).
    Ascii85,
}

impl Algorithm {
    /// Return the canonical string name for this algorithm.
    pub fn canonical_name(&self) -> &'static str {
        match self {
            Algorithm::MlKem => "ML-KEM",
            Algorithm::MlKem512 => "ML-KEM-512",
            Algorithm::MlKem768 => "ML-KEM-768",
            Algorithm::MlKem1024 => "ML-KEM-1024",
            Algorithm::MlDsa => "ML-DSA",
            Algorithm::MlDsa44 => "ML-DSA-44",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
            Algorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Algorithm::Sha3256 => "SHA3-256",
            Algorithm::Argon2id => "Argon2id",
            Algorithm::Base64 => "BASE64",
            Algorithm::Ascii85 => "ASCII85",
        }
    }

    /// If this is a KEM-variant algorithm, return the `KemVariant`.
    pub fn to_kem_variant(&self) -> Option<KemVariant> {
        match self {
            Algorithm::MlKem512 => Some(KemVariant::MlKem512),
            Algorithm::MlKem768 => Some(KemVariant::MlKem768),
            Algorithm::MlKem1024 => Some(KemVariant::MlKem1024),
            _ => None,
        }
    }

    /// If this is a DSA-variant algorithm, return the `DsaVariant`.
    pub fn to_dsa_variant(&self) -> Option<DsaVariant> {
        match self {
            Algorithm::MlDsa44 => Some(DsaVariant::MlDsa44),
            Algorithm::MlDsa65 => Some(DsaVariant::MlDsa65),
            Algorithm::MlDsa87 => Some(DsaVariant::MlDsa87),
            _ => None,
        }
    }

    /// Create a KEM-variant algorithm from a `KemVariant`.
    pub fn from_kem_variant(v: KemVariant) -> Self {
        match v {
            KemVariant::MlKem512 => Algorithm::MlKem512,
            KemVariant::MlKem768 => Algorithm::MlKem768,
            KemVariant::MlKem1024 => Algorithm::MlKem1024,
        }
    }

    /// Create a DSA-variant algorithm from a `DsaVariant`.
    pub fn from_dsa_variant(v: DsaVariant) -> Self {
        match v {
            DsaVariant::MlDsa44 => Algorithm::MlDsa44,
            DsaVariant::MlDsa65 => Algorithm::MlDsa65,
            DsaVariant::MlDsa87 => Algorithm::MlDsa87,
        }
    }
}

impl FromStr for Algorithm {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ML-KEM" => Ok(Algorithm::MlKem),
            "ML-KEM-512" => Ok(Algorithm::MlKem512),
            "ML-KEM-768" => Ok(Algorithm::MlKem768),
            "ML-KEM-1024" => Ok(Algorithm::MlKem1024),
            "ML-DSA" => Ok(Algorithm::MlDsa),
            "ML-DSA-44" => Ok(Algorithm::MlDsa44),
            "ML-DSA-65" => Ok(Algorithm::MlDsa65),
            "ML-DSA-87" => Ok(Algorithm::MlDsa87),
            "XChaCha20-Poly1305" => Ok(Algorithm::XChaCha20Poly1305),
            "SHA3-256" => Ok(Algorithm::Sha3256),
            "Argon2id" => Ok(Algorithm::Argon2id),
            "BASE64" => Ok(Algorithm::Base64),
            "ASCII85" => Ok(Algorithm::Ascii85),
            _ => Err(FormatError::UnknownAlgorithm(s.to_string())),
        }
    }
}

/// Ordered list of algorithms applied to a payload.
///
/// The encoding algorithm always appears last in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmList {
    algorithms: Vec<Algorithm>,
}

impl AlgorithmList {
    /// Create a new algorithm list from the given algorithms in canonical order.
    pub fn new(algorithms: Vec<Algorithm>) -> Self {
        Self { algorithms }
    }

    /// Return a slice of all algorithms in this list.
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.algorithms
    }

    /// Return the KEM variant in the list, if any.
    pub fn kem(&self) -> Option<KemVariant> {
        self.algorithms.iter().find_map(|a| a.to_kem_variant())
    }

    /// Return the DSA variant in the list, if any.
    pub fn dsa(&self) -> Option<DsaVariant> {
        self.algorithms.iter().find_map(|a| a.to_dsa_variant())
    }

    /// Parse a `+`-separated algorithm string into an [`AlgorithmList`].
    pub fn parse(s: &str) -> Result<Self, FormatError> {
        let parts: Vec<&str> = s.split('+').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Err(FormatError::EmptyAlgorithmList);
        }
        let algorithms = parts
            .iter()
            .map(|p| Algorithm::from_str(p.trim()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { algorithms })
    }
}

/// Format as `+`-separated canonical names.
impl fmt::Display for AlgorithmList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.algorithms
                .iter()
                .map(|a| a.canonical_name())
                .collect::<Vec<_>>()
                .join("+")
        )
    }
}

impl FromStr for AlgorithmList {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AlgorithmList::parse(s)
    }
}

/// The decoded components of a signature attribute payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePayload {
    /// DSA variant used for the signature.
    pub dsa_variant: DsaVariant,
    /// ML-DSA signature over the SHA3-256 digest of the block bytes.
    pub signature: Vec<u8>,
    /// Whether the signature covers the SHA3-256 digest of the block
    /// (true, current scheme) or the raw canonical bytes (false, legacy
    /// scheme without a `SHA3-256` marker in the algorithm list).
    pub prehashed: bool,
}

/// Encode a signature into a `data-hs-signature` value.
///
/// The value has the form `<DSA>+SHA3-256+BASE64:<base64 payload>`, e.g.
/// `ML-DSA-65+SHA3-256+BASE64:QWsd...`. The payload is the ML-DSA signature
/// only — the public key is deliberately not embedded; verification uses
/// the key supplied by the user (`verify -k`), the default key, or the DNS
/// `_hs_key` pin. The signature length is validated against the variant.
pub fn encode_signature(dsa_variant: DsaVariant, signature: &[u8]) -> Result<String, FormatError> {
    if signature.len() != dsa_variant.signature_len() {
        return Err(FormatError::PayloadTooShort);
    }

    let encoded = base64::engine::general_purpose::STANDARD.encode(signature);
    let algs = AlgorithmList::new(vec![
        Algorithm::Sha3256,
        Algorithm::from_dsa_variant(dsa_variant),
        Algorithm::Base64,
    ]);
    Ok(format!("{}:{}", algs, encoded))
}

/// Decode a `data-hs-signature` attribute value into its components.
///
/// Validates that the algorithm list names the DSA variant and that the
/// base64 payload is exactly the signature for that variant. Values that
/// embed the public keys (the pre-2026 layout `kem_pk || dsa_pk ||
/// signature`) are rejected by the length check. A `SHA3-256` entry in the
/// list marks the signature as covering the block's digest; its absence
/// (legacy values) is reported through [`SignaturePayload::prehashed`].
pub fn decode_signature(value: &str) -> Result<SignaturePayload, FormatError> {
    let sep = value.find(':').ok_or(FormatError::MissingSeparator)?;
    let alg_str = &value[..sep];
    let encoded = &value[sep + 1..];

    let algs = AlgorithmList::parse(alg_str)?;
    let dsa_variant = algs.dsa().ok_or(FormatError::MissingAlgorithm("DSA"))?;
    let prehashed = algs.algorithms().contains(&Algorithm::Sha3256);

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| FormatError::InvalidBase64(e.to_string()))?;

    let sig_len = dsa_variant.signature_len();
    if bytes.len() != sig_len {
        return Err(FormatError::PayloadTooShort);
    }

    Ok(SignaturePayload {
        dsa_variant,
        signature: bytes,
        prehashed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KemVariant;

    #[test]
    fn algorithm_list_round_trip() {
        let algs = AlgorithmList::new(vec![
            Algorithm::MlKem768,
            Algorithm::MlDsa65,
            Algorithm::Base64,
        ]);
        let s = algs.to_string();
        assert_eq!(s, "ML-KEM-768+ML-DSA-65+BASE64");
        let parsed = AlgorithmList::parse(&s).unwrap();
        assert_eq!(parsed, algs);
    }

    #[test]
    fn algorithm_list_unknown_algorithm() {
        let err = AlgorithmList::parse("ML-KEM-768+FOO").unwrap_err();
        assert!(matches!(err, FormatError::UnknownAlgorithm(_)));
    }

    #[test]
    fn algorithm_list_empty() {
        let err = AlgorithmList::parse("").unwrap_err();
        assert!(matches!(err, FormatError::EmptyAlgorithmList));
    }

    #[test]
    fn signature_round_trip() {
        let sig = vec![0x43u8; DsaVariant::MlDsa65.signature_len()];

        let encoded = encode_signature(DsaVariant::MlDsa65, &sig).unwrap();
        assert!(encoded.starts_with("SHA3-256+ML-DSA-65+BASE64:"));
        let decoded = decode_signature(&encoded).unwrap();

        assert_eq!(decoded.dsa_variant, DsaVariant::MlDsa65);
        assert_eq!(decoded.signature, sig);
        assert!(decoded.prehashed, "current scheme is hash-then-sign");
    }

    #[test]
    fn legacy_signature_decode_reports_unhashed() {
        let sig = vec![0x43u8; DsaVariant::MlDsa65.signature_len()];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&sig);
        let legacy = format!("ML-DSA-65+BASE64:{}", encoded);

        let decoded = decode_signature(&legacy).unwrap();
        assert_eq!(decoded.signature, sig);
        assert!(!decoded.prehashed, "legacy scheme signs raw block bytes");
    }

    #[test]
    fn signature_embedding_keys_is_rejected() {
        let kem_pk = vec![0x41u8; KemVariant::MlKem768.public_key_len()];
        let dsa_pk = vec![0x42u8; DsaVariant::MlDsa65.public_key_len()];
        let sig = vec![0x43u8; DsaVariant::MlDsa65.signature_len()];
        let mut payload = Vec::new();
        payload.extend_from_slice(&kem_pk);
        payload.extend_from_slice(&dsa_pk);
        payload.extend_from_slice(&sig);
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let legacy = format!("SHA3-256+ML-KEM-768+ML-DSA-65+BASE64:{}", encoded);
        assert!(matches!(
            decode_signature(&legacy),
            Err(FormatError::PayloadTooShort)
        ));
    }

    #[test]
    fn signature_missing_separator() {
        let err = decode_signature("ML-DSA-65+BASE64notbase64").unwrap_err();
        assert!(matches!(err, FormatError::MissingSeparator));
    }

    #[test]
    fn signature_wrong_payload_length() {
        let value = "ML-DSA-65+BASE64:AQID";
        let err = decode_signature(value).unwrap_err();
        assert!(matches!(err, FormatError::PayloadTooShort));
    }

    #[test]
    fn signature_invalid_base64() {
        let value = "ML-DSA-65+BASE64:!!!";
        let err = decode_signature(value).unwrap_err();
        assert!(matches!(err, FormatError::InvalidBase64(_)));
    }
}
