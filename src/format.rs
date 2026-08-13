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
//! encoding algorithm, for example `ML-KEM-768+ML-DSA-65+BASE64`. The
//! encoded payload (BASE64 for now) contains, in order:
//!
//! 1. ML-KEM public key (binds the encapsulation key to the block)
//! 2. ML-DSA public key (used to verify the signature)
//! 3. ML-DSA signature over the canonical block bytes

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
    /// KEM variant used for the encapsulated key.
    pub kem_variant: KemVariant,
    /// DSA variant used for the signature.
    pub dsa_variant: DsaVariant,
    /// ML-KEM public key bytes.
    pub kem_public_key: Vec<u8>,
    /// ML-DSA public key bytes.
    pub dsa_public_key: Vec<u8>,
    /// ML-DSA signature over the canonical block bytes.
    pub signature: Vec<u8>,
}

/// Encode the components of a signature into a `data-hs-signature` value.
///
/// The value has the form `<KEM>+<DSA>+BASE64:<base64 payload>`, e.g.
/// `ML-KEM-768+ML-DSA-65+BASE64:QWsd...`. The public key lengths are
/// validated against the given variants.
pub fn encode_signature(
    kem_variant: KemVariant,
    dsa_variant: DsaVariant,
    kem_public_key: &[u8],
    dsa_public_key: &[u8],
    signature: &[u8],
) -> Result<String, FormatError> {
    if kem_public_key.len() != kem_variant.public_key_len() {
        return Err(FormatError::PayloadTooShort);
    }
    if dsa_public_key.len() != dsa_variant.public_key_len()
        || signature.len() != dsa_variant.signature_len()
    {
        return Err(FormatError::PayloadTooShort);
    }

    let mut payload =
        Vec::with_capacity(kem_public_key.len() + dsa_public_key.len() + signature.len());
    payload.extend_from_slice(kem_public_key);
    payload.extend_from_slice(dsa_public_key);
    payload.extend_from_slice(signature);

    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let algs = AlgorithmList::new(vec![
        Algorithm::from_kem_variant(kem_variant),
        Algorithm::from_dsa_variant(dsa_variant),
        Algorithm::Base64,
    ]);
    Ok(format!("{}:{}", algs, encoded))
}

/// Decode a `data-hs-signature` attribute value into its components.
///
/// Validates that the algorithm list names the exact KEM/DSA variants and
/// that the payload length matches the expected public key and signature
/// sizes.
pub fn decode_signature(value: &str) -> Result<SignaturePayload, FormatError> {
    let sep = value.find(':').ok_or(FormatError::MissingSeparator)?;
    let alg_str = &value[..sep];
    let encoded = &value[sep + 1..];

    let algs = AlgorithmList::parse(alg_str)?;
    let kem_variant = algs.kem().ok_or(FormatError::MissingAlgorithm("KEM"))?;
    let dsa_variant = algs.dsa().ok_or(FormatError::MissingAlgorithm("DSA"))?;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| FormatError::InvalidBase64(e.to_string()))?;

    let kem_len = kem_variant.public_key_len();
    let dsa_len = dsa_variant.public_key_len();
    let sig_len = dsa_variant.signature_len();
    let total = kem_len + dsa_len + sig_len;
    if bytes.len() != total {
        return Err(FormatError::PayloadTooShort);
    }

    let kem_public_key = bytes[..kem_len].to_vec();
    let dsa_public_key = bytes[kem_len..kem_len + dsa_len].to_vec();
    let signature = bytes[kem_len + dsa_len..].to_vec();

    Ok(SignaturePayload {
        kem_variant,
        dsa_variant,
        kem_public_key,
        dsa_public_key,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let kem_pk = vec![0x41u8; KemVariant::MlKem768.public_key_len()];
        let dsa_pk = vec![0x42u8; DsaVariant::MlDsa65.public_key_len()];
        let sig = vec![0x43u8; DsaVariant::MlDsa65.signature_len()];

        let encoded = encode_signature(
            KemVariant::MlKem768,
            DsaVariant::MlDsa65,
            &kem_pk,
            &dsa_pk,
            &sig,
        )
        .unwrap();
        let decoded = decode_signature(&encoded).unwrap();

        assert_eq!(decoded.kem_variant, KemVariant::MlKem768);
        assert_eq!(decoded.dsa_variant, DsaVariant::MlDsa65);
        assert_eq!(decoded.kem_public_key, kem_pk);
        assert_eq!(decoded.dsa_public_key, dsa_pk);
        assert_eq!(decoded.signature, sig);
    }

    #[test]
    fn signature_missing_separator() {
        let err = decode_signature("ML-KEM-768+ML-DSA-65+BASE64notbase64").unwrap_err();
        assert!(matches!(err, FormatError::MissingSeparator));
    }

    #[test]
    fn signature_wrong_payload_length() {
        let value = "ML-KEM-768+ML-DSA-65+BASE64:AQID";
        let err = decode_signature(value).unwrap_err();
        assert!(matches!(err, FormatError::PayloadTooShort));
    }

    #[test]
    fn signature_invalid_base64() {
        let value = "ML-KEM-768+ML-DSA-65+BASE64:!!!";
        let err = decode_signature(value).unwrap_err();
        assert!(matches!(err, FormatError::InvalidBase64(_)));
    }
}
