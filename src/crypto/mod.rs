//! Post-quantum cryptographic primitives for `hs`.
//!
//! This module provides safe wrappers around:
//! - [`kem`] — ML-KEM (Kyber) key encapsulation
//! - [`sign`] — ML-DSA (Dilithium) digital signatures
//! - [`sym`] — XChaCha20-Poly1305 symmetric encryption and Argon2id KDF
//! - [`keygen`] — Combined PQ key pair generation
//! - [`keyfile`] — Passphrase-encrypted secret key file format
//!
//! All randomness uses [`rand::rngs::OsRng`]. Secret material is zeroized on drop.

pub mod kem;
pub mod keyfile;
pub mod keygen;
pub mod sign;
pub mod sym;

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    #[allow(dead_code)]
    KeyGeneration(String),
    /// Encryption (or key encapsulation) failed.
    #[error("encryption failed: {0}")]
    Encrypt(String),
    /// Decryption (or key decapsulation) failed.
    #[error("decryption failed: {0}")]
    Decrypt(String),
    /// Signing failed.
    #[error("signing failed: {0}")]
    Sign(String),
    /// Signature verification failed.
    #[error("verification failed: {0}")]
    Verify(String),
    /// Key material has an unexpected size or encoding.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// ML-KEM (Kyber) parameter set variants as defined in FIPS 203.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemVariant {
    /// ML-KEM-512 (NIST Level 1).
    MlKem512,
    /// ML-KEM-768 (NIST Level 3) — recommended default.
    MlKem768,
    /// ML-KEM-1024 (NIST Level 5).
    MlKem1024,
}

impl KemVariant {
    /// Returns the public key byte length for this variant.
    pub fn public_key_len(self) -> usize {
        match self {
            KemVariant::MlKem512 => 800,
            KemVariant::MlKem768 => 1184,
            KemVariant::MlKem1024 => 1568,
        }
    }

    /// Returns the secret key seed byte length (always 64).
    pub fn secret_key_len(self) -> usize {
        64
    }

    /// Returns the ciphertext byte length for this variant.
    pub fn ciphertext_len(self) -> usize {
        match self {
            KemVariant::MlKem512 => 768,
            KemVariant::MlKem768 => 1088,
            KemVariant::MlKem1024 => 1568,
        }
    }

    /// Returns the canonical name (e.g. "ML-KEM-768").
    pub fn as_str(self) -> &'static str {
        match self {
            KemVariant::MlKem512 => "ML-KEM-512",
            KemVariant::MlKem768 => "ML-KEM-768",
            KemVariant::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// Parse a canonical name into a variant.
    pub fn parse(s: &str) -> Option<Self> {
        s.parse().ok()
    }

    /// All supported variants.
    pub fn all() -> &'static [KemVariant] {
        &[
            KemVariant::MlKem512,
            KemVariant::MlKem768,
            KemVariant::MlKem1024,
        ]
    }
}

impl std::str::FromStr for KemVariant {
    type Err = &'static str;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "ML-KEM-512" => Ok(KemVariant::MlKem512),
            "ML-KEM-768" => Ok(KemVariant::MlKem768),
            "ML-KEM-1024" => Ok(KemVariant::MlKem1024),
            _ => Err("unknown KEM variant"),
        }
    }
}

/// ML-DSA (Dilithium) parameter set variants as defined in FIPS 204.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsaVariant {
    /// ML-DSA-44 (NIST Level 2).
    MlDsa44,
    /// ML-DSA-65 (NIST Level 3) — recommended default.
    MlDsa65,
    /// ML-DSA-87 (NIST Level 5).
    MlDsa87,
}

impl DsaVariant {
    /// Returns the public key byte length for this variant.
    pub fn public_key_len(self) -> usize {
        match self {
            DsaVariant::MlDsa44 => 1312,
            DsaVariant::MlDsa65 => 1952,
            DsaVariant::MlDsa87 => 2592,
        }
    }

    /// Returns the secret key seed byte length (always 32).
    pub fn secret_key_len(self) -> usize {
        32
    }

    /// Returns the canonical name (e.g. "ML-DSA-65").
    pub fn as_str(self) -> &'static str {
        match self {
            DsaVariant::MlDsa44 => "ML-DSA-44",
            DsaVariant::MlDsa65 => "ML-DSA-65",
            DsaVariant::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Returns the encoded signature byte length for this variant
    /// (FIPS 204 signature sizes: 2420/3309/4627 bytes).
    pub fn signature_len(self) -> usize {
        match self {
            DsaVariant::MlDsa44 => 2420,
            DsaVariant::MlDsa65 => 3309,
            DsaVariant::MlDsa87 => 4627,
        }
    }

    /// Parse a canonical name into a variant.
    pub fn parse(s: &str) -> Option<Self> {
        s.parse().ok()
    }

    /// All supported variants.
    pub fn all() -> &'static [DsaVariant] {
        &[
            DsaVariant::MlDsa44,
            DsaVariant::MlDsa65,
            DsaVariant::MlDsa87,
        ]
    }
}

impl std::str::FromStr for DsaVariant {
    type Err = &'static str;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "ML-DSA-44" => Ok(DsaVariant::MlDsa44),
            "ML-DSA-65" => Ok(DsaVariant::MlDsa65),
            "ML-DSA-87" => Ok(DsaVariant::MlDsa87),
            _ => Err("unknown DSA variant"),
        }
    }
}
