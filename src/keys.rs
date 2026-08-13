//! Key generation, storage, and public key formatting for `hs`.
//!
//! Secret keys are stored in passphrase-encrypted `.hskey` files (see
//! [`crypto::keyfile`]). Public keys can be exported as an armored
//! `-----BEGIN HS PUBLIC KEY-----` block for out-of-band distribution.

use crate::crypto::keyfile::{self, KdfParams, UnlockedKey};
use crate::crypto::{kem, keygen, sign, CryptoError, DsaVariant, KemVariant};
use base64::Engine;
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroize;

/// Header marker for armored public keys.
pub const ARMOR_BEGIN: &str = "-----BEGIN HS PUBLIC KEY-----";
/// Footer marker for armored public keys.
pub const ARMOR_END: &str = "-----END HS PUBLIC KEY-----";
/// Default file name for the default signing key.
pub const DEFAULT_KEY_FILE: &str = "default.hskey";

/// Errors produced by the keys module.
#[derive(Error, Debug)]
pub enum KeyError {
    /// The armored public key is malformed.
    #[error("invalid armored public key: {0}")]
    InvalidArmor(String),
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// An I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Public information about a key pair.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    /// KEM variant.
    pub kem_variant: KemVariant,
    /// DSA variant.
    pub dsa_variant: DsaVariant,
    /// ML-KEM public key bytes.
    pub kem_public_key: Vec<u8>,
    /// ML-DSA public key bytes.
    pub dsa_public_key: Vec<u8>,
    /// Fingerprint `hex(SHA3-256(kem_pk || dsa_pk))`.
    pub fingerprint: String,
}

/// A fully unlocked signing key loaded from a key file.
pub struct SigningKey {
    /// Public key information.
    pub info: KeyInfo,
    /// ML-DSA secret key used for signing.
    pub dsa_secret_key: sign::SecretKey,
    /// ML-KEM secret key (reserved for future encapsulation).
    pub kem_secret_key: kem::SecretKey,
}

impl SigningKey {
    /// Return a reference to the public key information.
    pub fn info(&self) -> &KeyInfo {
        &self.info
    }
}

/// Location of the default key file (`<data_dir>/hs/keys/default.hskey`).
pub fn default_key_path() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("hs").join("keys").join(DEFAULT_KEY_FILE)
}

/// Generate a new key pair and store it passphrase-encrypted on disk.
///
/// Returns the public [`KeyInfo`] of the newly generated key.
pub fn generate_key(
    output: &Path,
    kem_variant: KemVariant,
    dsa_variant: DsaVariant,
    passphrase: &str,
    params: &KdfParams,
) -> Result<KeyInfo, KeyError> {
    let pair = keygen::generate(kem_variant, dsa_variant)?;

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let kem_seed = pair.kem_secret.to_bytes();
    let dsa_seed = pair.sign_secret.to_bytes();
    let kem_public = pair.kem_public.to_bytes();
    let dsa_public = pair.sign_public.to_bytes();
    let material = keyfile::SecretMaterial {
        kem_variant,
        dsa_variant,
        kem_seed: &kem_seed,
        dsa_seed: &dsa_seed,
        kem_public_key: &kem_public,
        dsa_public_key: &dsa_public,
    };
    keyfile::write(output, &material, passphrase, params)?;

    Ok(KeyInfo {
        kem_variant,
        dsa_variant,
        kem_public_key: pair.kem_public.to_bytes(),
        dsa_public_key: pair.sign_public.to_bytes(),
        fingerprint: keyfile::fingerprint(pair.kem_public.as_bytes(), pair.sign_public.as_bytes()),
    })
}

/// Unlock a secret key file with the given passphrase.
pub fn unlock_key(path: &Path, passphrase: &str) -> Result<SigningKey, KeyError> {
    let mut unlocked: UnlockedKey = keyfile::read(path, passphrase)?;
    let result = SigningKey {
        info: KeyInfo {
            kem_variant: unlocked.kem_variant,
            dsa_variant: unlocked.dsa_variant,
            kem_public_key: unlocked.kem_public_key.clone(),
            dsa_public_key: unlocked.dsa_public_key.clone(),
            fingerprint: keyfile::fingerprint(&unlocked.kem_public_key, &unlocked.dsa_public_key),
        },
        dsa_secret_key: unlocked.sign_secret_key()?,
        kem_secret_key: unlocked.kem_secret_key()?,
    };
    unlocked.kem_seed.zeroize();
    unlocked.dsa_seed.zeroize();
    Ok(result)
}

/// Armor a public key for distribution.
///
/// The body is `BASE64(kem_pk || dsa_pk)` with the algorithm variants on
/// the first content line.
pub fn armor_public_key(info: &KeyInfo) -> String {
    let mut payload = Vec::with_capacity(info.kem_public_key.len() + info.dsa_public_key.len());
    payload.extend_from_slice(&info.kem_public_key);
    payload.extend_from_slice(&info.dsa_public_key);
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);

    let mut out = String::new();
    out.push_str(ARMOR_BEGIN);
    out.push('\n');
    out.push_str(&format!(
        "{} {}\n",
        info.kem_variant.as_str(),
        info.dsa_variant.as_str()
    ));
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(ARMOR_END);
    out.push('\n');
    out
}

/// Parse an armored public key into its components.
pub fn unarmor_public_key(data: &str) -> Result<KeyInfo, KeyError> {
    let mut lines = data.lines();
    let begin = lines
        .next()
        .ok_or_else(|| KeyError::InvalidArmor("empty input".into()))?;
    if begin.trim() != ARMOR_BEGIN {
        return Err(KeyError::InvalidArmor("missing BEGIN marker".into()));
    }
    let algs = lines
        .next()
        .ok_or_else(|| KeyError::InvalidArmor("missing algorithm line".into()))?;
    let mut parts = algs.split_whitespace();
    let kem_name = parts
        .next()
        .ok_or_else(|| KeyError::InvalidArmor("missing KEM algorithm on header line".into()))?;
    let dsa_name = parts
        .next()
        .ok_or_else(|| KeyError::InvalidArmor("missing DSA algorithm on header line".into()))?;
    let kem_variant = KemVariant::parse(kem_name)
        .ok_or_else(|| KeyError::InvalidArmor(format!("unknown KEM variant {}", kem_name)))?;
    let dsa_variant = DsaVariant::parse(dsa_name)
        .ok_or_else(|| KeyError::InvalidArmor(format!("unknown DSA variant {}", dsa_name)))?;

    let mut b64 = String::new();
    for line in lines {
        if line.trim() == ARMOR_END {
            let payload = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .map_err(|e| KeyError::InvalidArmor(format!("invalid base64 body: {}", e)))?;
            let kem_len = kem_variant.public_key_len();
            let dsa_len = dsa_variant.public_key_len();
            if payload.len() != kem_len + dsa_len {
                return Err(KeyError::InvalidArmor("payload length mismatch".into()));
            }
            let kem_public_key = payload[..kem_len].to_vec();
            let dsa_public_key = payload[kem_len..].to_vec();
            let fingerprint = keyfile::fingerprint(&kem_public_key, &dsa_public_key);
            return Ok(KeyInfo {
                kem_variant,
                dsa_variant,
                kem_public_key,
                dsa_public_key,
                fingerprint,
            });
        }
        b64.push_str(line.trim());
    }
    Err(KeyError::InvalidArmor("missing END marker".into()))
}
