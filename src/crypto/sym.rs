//! XChaCha20-Poly1305 symmetric encryption and Argon2id key derivation.
//!
//! Provides authenticated encryption with 24-byte nonces. Key derivation
//! uses Argon2id to turn passphrases into 32-byte symmetric keys. Used
//! to encrypt `hs` secret key files at rest.

use super::CryptoError;
use argon2::Params;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// Key length in bytes (32 bytes = 256 bits).
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes (24 bytes for XChaCha20).
pub const NONCE_LEN: usize = 24;

/// Default Argon2id memory cost in KiB (64 MiB — OWASP minimum).
pub const DEFAULT_ARGON2_MEM: u32 = 65536;
/// Default Argon2id time cost (iterations).
pub const DEFAULT_ARGON2_TIME: u32 = 3;
/// Default Argon2id parallelism (threads).
pub const DEFAULT_ARGON2_PAR: u32 = 1;

/// Encrypt plaintext with XChaCha20-Poly1305 using the given key.
///
/// Returns (nonce, ciphertext_with_tag). A fresh random nonce is
/// generated for each call.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::Encrypt(format!("invalid key: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::try_from(&nonce_bytes[..])
        .map_err(|_| CryptoError::Encrypt("invalid nonce length".into()))?;

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encrypt(format!("encryption failed: {}", e)))?;

    Ok((nonce_bytes, ciphertext))
}

/// Decrypt an XChaCha20-Poly1305 ciphertext using the given key and nonce.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::Decrypt(format!("invalid key: {}", e)))?;

    let nonce = XNonce::try_from(&nonce[..])
        .map_err(|_| CryptoError::Decrypt("invalid nonce length".into()))?;

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| CryptoError::Decrypt(format!("decryption failed: {}", e)))?;

    Ok(plaintext)
}

/// Derive a 32-byte symmetric key from a passphrase and salt using Argon2id.
///
/// `mem_cost` is in KiB, `time_cost` is the number of iterations,
/// `par_cost` is the degree of parallelism.
pub fn derive_key(
    passphrase: &str,
    salt: &[u8],
    mem_cost: u32,
    time_cost: u32,
    par_cost: u32,
) -> Result<[u8; KEY_LEN], CryptoError> {
    use argon2::Argon2;

    let params = Params::new(mem_cost, time_cost, par_cost, None)
        .map_err(|e| CryptoError::Encrypt(format!("invalid Argon2 params: {}", e)))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::Encrypt(format!("key derivation failed: {}", e)))?;
    Ok(key)
}

/// Generate a random salt of the given length using [`rand::rngs::OsRng`].
pub fn random_salt(len: usize) -> Vec<u8> {
    let mut salt = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}
