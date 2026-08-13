//! Key generation, storage, and public key formatting for `hs`.
//!
//! Secret keys are stored in passphrase-encrypted `.hskey` files (see
//! [`crate::crypto::keyfile`]). Public keys can be exported as an armored
//! `-----BEGIN HS PUBLIC KEY-----` block for out-of-band distribution.

use crate::ascii85;
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
/// Marker prefix of the ASCII85 DNS TXT public-key format.
pub const TXT_KEY_PREFIX: &str = "HS85";
/// Default file name for the default signing key.
pub const DEFAULT_KEY_FILE: &str = "default.hskey";

/// Errors produced by the keys module.
#[derive(Error, Debug)]
pub enum KeyError {
    /// The armored public key is malformed.
    #[error("invalid armored public key: {0}")]
    InvalidArmor(String),
    /// The ASCII85 DNS public-key payload is malformed.
    #[error("invalid ASCII85 public key: {0}")]
    InvalidAscii85(String),
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
    let bytes = std::fs::read(path)?;
    let mut unlocked: UnlockedKey = keyfile::from_bytes(&bytes, passphrase)?;
    let result = SigningKey {
        info: info_from_unlocked(&unlocked),
        dsa_secret_key: unlocked.sign_secret_key()?,
        kem_secret_key: unlocked.kem_secret_key()?,
    };
    unlocked.kem_seed.zeroize();
    unlocked.dsa_seed.zeroize();
    Ok(result)
}

/// Build the public [`KeyInfo`] from an unlocked key file.
fn info_from_unlocked(unlocked: &UnlockedKey) -> KeyInfo {
    KeyInfo {
        kem_variant: unlocked.kem_variant,
        dsa_variant: unlocked.dsa_variant,
        kem_public_key: unlocked.kem_public_key.clone(),
        dsa_public_key: unlocked.dsa_public_key.clone(),
        fingerprint: keyfile::fingerprint(&unlocked.kem_public_key, &unlocked.dsa_public_key),
    }
}

/// Extract the public key information from raw key file bytes.
///
/// Accepts an armored public key (`-----BEGIN HS PUBLIC KEY-----`), an
/// ASCII85 DNS TXT public key (see [`ascii85_public_key`]), or a
/// passphrase-encrypted `.hskey` secret key file, detecting the format
/// from the contents. The secret key file is decrypted with `passphrase`
/// before its public half is returned.
pub fn public_key_from_bytes(bytes: &[u8], passphrase: &str) -> Result<KeyInfo, KeyError> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if is_public_key_text(text) {
            return parse_public_key(text);
        }
    }
    let mut unlocked = keyfile::from_bytes(bytes, passphrase)?;
    let info = info_from_unlocked(&unlocked);
    unlocked.kem_seed.zeroize();
    unlocked.dsa_seed.zeroize();
    Ok(info)
}

/// Load public key information from a file path.
///
/// Accepts both armored public key files and `.hskey` secret key files
/// (see [`public_key_from_bytes`]), so `verify -k` works with either.
pub fn load_public_key(path: &Path, passphrase: &str) -> Result<KeyInfo, KeyError> {
    let bytes = std::fs::read(path)?;
    public_key_from_bytes(&bytes, passphrase)
}

/// Return true if `text` is a textual public key payload.
///
/// That is, either an armored public key (carrying the BEGIN marker) or an
/// ASCII85 DNS TXT public key (starting with [`TXT_KEY_PREFIX`]).
fn is_public_key_text(text: &str) -> bool {
    text.contains(ARMOR_BEGIN) || text.trim_start().starts_with(TXT_KEY_PREFIX)
}

/// Return true if the file at `path` is a textual public key.
///
/// Both the armored `-----BEGIN HS PUBLIC KEY-----` form and the ASCII85
/// DNS TXT form (see [`ascii85_public_key`]) are detected. Used to decide
/// whether a passphrase is needed: textual public keys carry no secret
/// material and are unlocked without one, while `.hskey` secret key files
/// require the passphrase.
pub fn is_armored_key(path: &Path) -> Result<bool, KeyError> {
    let bytes = std::fs::read(path)?;
    Ok(std::str::from_utf8(&bytes).is_ok_and(is_public_key_text))
}

/// Parse a textual public key payload into its components.
///
/// Accepts either the ASCII85 DNS TXT format
/// (`HS85:<KEM>:<DSA>:<ascii85(kem_pk || dsa_pk)>`, used by DNS records)
/// or the legacy armored `-----BEGIN HS PUBLIC KEY-----` format. The
/// ASCII85 form carries no PEM markers.
pub fn parse_public_key(data: &str) -> Result<KeyInfo, KeyError> {
    if data.trim_start().starts_with(TXT_KEY_PREFIX) {
        unascii85_public_key(data)
    } else {
        unarmor_public_key(data)
    }
}

/// Encode a public key in the ASCII85 DNS TXT format.
///
/// The output is a single line of the form
/// `HS85:ML-KEM-768:ML-DSA-65:<ascii85(kem_pk || dsa_pk)>` with no PEM
/// markers. Because the key material is incompressible, ASCII85 (20%
/// overhead) is used instead of compression, keeping the record under the
/// practical 4096-byte DNS TXT limit for the default key variants
/// (3136 bytes → 3945 characters including the header).
pub fn ascii85_public_key(info: &KeyInfo) -> String {
    let mut payload = Vec::with_capacity(info.kem_public_key.len() + info.dsa_public_key.len());
    payload.extend_from_slice(&info.kem_public_key);
    payload.extend_from_slice(&info.dsa_public_key);
    format!(
        "{}:{}:{}:{}",
        TXT_KEY_PREFIX,
        info.kem_variant.as_str(),
        info.dsa_variant.as_str(),
        ascii85::encode(&payload)
    )
}

/// Parse an ASCII85 DNS TXT public key.
///
/// The payload must start with [`TXT_KEY_PREFIX`] followed by
/// `:<KEM>:<DSA>:<ascii85 body>`. Leading/trailing whitespace and any
/// whitespace inside the body (inserted when TXT character-strings are
/// pasted and re-joined) are tolerated. The body may contain the `:`
/// character, so only the first three `:` separators are consumed.
pub fn unascii85_public_key(data: &str) -> Result<KeyInfo, KeyError> {
    let rest = data
        .trim()
        .strip_prefix(TXT_KEY_PREFIX)
        .ok_or_else(|| KeyError::InvalidAscii85("missing HS85 prefix".into()))?
        .strip_prefix(':')
        .ok_or_else(|| KeyError::InvalidAscii85("missing KEM algorithm".into()))?;
    let mut parts = rest.splitn(3, ':');
    let kem_name = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KeyError::InvalidAscii85("missing KEM algorithm".into()))?;
    let dsa_name = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KeyError::InvalidAscii85("missing DSA algorithm".into()))?;
    let encoded = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KeyError::InvalidAscii85("missing key body".into()))?;

    let kem_variant = KemVariant::parse(kem_name)
        .ok_or_else(|| KeyError::InvalidAscii85(format!("unknown KEM variant {}", kem_name)))?;
    let dsa_variant = DsaVariant::parse(dsa_name)
        .ok_or_else(|| KeyError::InvalidAscii85(format!("unknown DSA variant {}", dsa_name)))?;

    let payload = ascii85::decode(encoded).map_err(|e| KeyError::InvalidAscii85(e.to_string()))?;
    let kem_len = kem_variant.public_key_len();
    let dsa_len = dsa_variant.public_key_len();
    if payload.len() != kem_len + dsa_len {
        return Err(KeyError::InvalidAscii85("payload length mismatch".into()));
    }
    let kem_public_key = payload[..kem_len].to_vec();
    let dsa_public_key = payload[kem_len..].to_vec();
    let fingerprint = keyfile::fingerprint(&kem_public_key, &dsa_public_key);
    Ok(KeyInfo {
        kem_variant,
        dsa_variant,
        kem_public_key,
        dsa_public_key,
        fingerprint,
    })
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
///
/// The BEGIN and END markers may be surrounded by arbitrary surrounding
/// text, and the body may be split across any amount of whitespace (for
/// instance when published in a DNS TXT record): after the BEGIN marker
/// the first two whitespace-separated tokens are the algorithm names and
/// the remaining tokens are the concatenated base64 body.
pub fn unarmor_public_key(data: &str) -> Result<KeyInfo, KeyError> {
    let begin = data
        .find(ARMOR_BEGIN)
        .ok_or_else(|| KeyError::InvalidArmor("missing BEGIN marker".into()))?;
    let rest = &data[begin + ARMOR_BEGIN.len()..];
    let end = rest
        .find(ARMOR_END)
        .ok_or_else(|| KeyError::InvalidArmor("missing END marker".into()))?;
    let body = &rest[..end];

    let mut parts = body.split_whitespace();
    let kem_name = parts
        .next()
        .ok_or_else(|| KeyError::InvalidArmor("missing KEM algorithm".into()))?;
    let dsa_name = parts
        .next()
        .ok_or_else(|| KeyError::InvalidArmor("missing DSA algorithm".into()))?;
    let kem_variant = KemVariant::parse(kem_name)
        .ok_or_else(|| KeyError::InvalidArmor(format!("unknown KEM variant {}", kem_name)))?;
    let dsa_variant = DsaVariant::parse(dsa_name)
        .ok_or_else(|| KeyError::InvalidArmor(format!("unknown DSA variant {}", dsa_name)))?;

    let b64: String = parts.collect();
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
    Ok(KeyInfo {
        kem_variant,
        dsa_variant,
        kem_public_key,
        dsa_public_key,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen;
    use crate::crypto::{DsaVariant, KemVariant};

    /// Fast Argon2id parameters for tests (8 KiB, 1 iteration).
    const TEST_PARAMS: KdfParams = KdfParams {
        mem_cost: 8,
        time_cost: 1,
        par_cost: 1,
    };

    /// Generate one key pair and serialize it both as a passphrase-
    /// encrypted `.hskey` blob and as an armored public key string.
    fn sample_key() -> (Vec<u8>, String) {
        let pair = keygen::generate(KemVariant::MlKem768, DsaVariant::MlDsa65).unwrap();
        let kem_seed = pair.kem_secret.to_bytes();
        let dsa_seed = pair.sign_secret.to_bytes();
        let kem_public = pair.kem_public.to_bytes();
        let dsa_public = pair.sign_public.to_bytes();
        let material = keyfile::SecretMaterial {
            kem_variant: KemVariant::MlKem768,
            dsa_variant: DsaVariant::MlDsa65,
            kem_seed: &kem_seed,
            dsa_seed: &dsa_seed,
            kem_public_key: &kem_public,
            dsa_public_key: &dsa_public,
        };
        let secret = keyfile::to_bytes(&material, "hunter2", &TEST_PARAMS).unwrap();
        let info = KeyInfo {
            kem_variant: KemVariant::MlKem768,
            dsa_variant: DsaVariant::MlDsa65,
            kem_public_key: kem_public.clone(),
            dsa_public_key: dsa_public.clone(),
            fingerprint: String::new(),
        };
        (secret, armor_public_key(&info))
    }

    #[test]
    fn public_key_from_bytes_detects_secret_key_file() {
        let (secret, _armor) = sample_key();
        assert!(
            std::str::from_utf8(&secret).is_err(),
            "hskey must be binary"
        );
        let info = public_key_from_bytes(&secret, "hunter2").unwrap();
        assert_eq!(info.fingerprint.len(), 64);
    }

    #[test]
    fn public_key_from_bytes_matches_armor_fingerprint() {
        let (secret, armor) = sample_key();
        let from_secret = public_key_from_bytes(&secret, "hunter2").unwrap();
        let from_armor = public_key_from_bytes(armor.as_bytes(), "").unwrap();
        assert_eq!(from_secret.fingerprint, from_armor.fingerprint);
    }

    #[test]
    fn public_key_from_bytes_wrong_passphrase_fails() {
        let (secret, _armor) = sample_key();
        let err = public_key_from_bytes(&secret, "wrong").unwrap_err();
        assert!(err.to_string().contains("decryption"));
    }

    #[test]
    fn public_key_from_bytes_garbage_fails() {
        let err = public_key_from_bytes(b"garbage", "").unwrap_err();
        assert!(err.to_string().contains("key file"));
    }

    #[test]
    fn ascii85_public_key_round_trips() {
        let (_secret, armor) = sample_key();
        let info = unarmor_public_key(&armor).unwrap();
        let encoded = ascii85_public_key(&info);
        assert!(encoded.starts_with("HS85:ML-KEM-768:ML-DSA-65:"));
        let decoded = unascii85_public_key(&encoded).unwrap();
        assert_eq!(decoded.fingerprint, info.fingerprint);
        assert_eq!(decoded.kem_public_key, info.kem_public_key);
        assert_eq!(decoded.dsa_public_key, info.dsa_public_key);
    }

    #[test]
    fn ascii85_public_key_fits_dns_txt_limit() {
        let (_secret, armor) = sample_key();
        let info = unarmor_public_key(&armor).unwrap();
        let encoded = ascii85_public_key(&info);
        assert!(
            encoded.len() <= 4096,
            "default key TXT record must fit in 4096 bytes, got {}",
            encoded.len()
        );
    }

    #[test]
    fn unascii85_public_key_tolerates_split_strings() {
        let (_secret, armor) = sample_key();
        let info = unarmor_public_key(&armor).unwrap();
        let encoded = ascii85_public_key(&info);
        let split: String = encoded
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 255 == 0 {
                    Vec::from(['\n', c])
                } else {
                    Vec::from([c])
                }
            })
            .collect();
        let decoded = unascii85_public_key(&split).unwrap();
        assert_eq!(decoded.fingerprint, info.fingerprint);
    }

    #[test]
    fn parse_public_key_handles_both_formats() {
        let (_secret, armor) = sample_key();
        let info_armor = parse_public_key(&armor).unwrap();
        let info_ascii = parse_public_key(&ascii85_public_key(&info_armor)).unwrap();
        assert_eq!(info_armor.fingerprint, info_ascii.fingerprint);
    }

    #[test]
    fn public_key_from_bytes_accepts_ascii85_text() {
        let (secret, armor) = sample_key();
        let info = unarmor_public_key(&armor).unwrap();
        let encoded = ascii85_public_key(&info);
        let from_text = public_key_from_bytes(encoded.as_bytes(), "").unwrap();
        let from_secret = public_key_from_bytes(&secret, "hunter2").unwrap();
        assert_eq!(from_text.fingerprint, from_secret.fingerprint);
    }

    #[test]
    fn unascii85_public_key_rejects_garbage() {
        let err = unascii85_public_key("HS85:ML-KEM-768:ML-DSA-65:!!").unwrap_err();
        assert!(err.to_string().contains("ASCII85"));
        let err = unascii85_public_key("nope").unwrap_err();
        assert!(err.to_string().contains("missing HS85 prefix"));
    }
}
