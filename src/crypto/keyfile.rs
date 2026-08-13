//! Passphrase-encrypted secret key file format.
//!
//! An `hs` secret key file (`.hskey`) contains both an ML-KEM and an
//! ML-DSA secret key, encrypted at rest with Argon2id + XChaCha20-Poly1305.
//! Secret key material is never stored raw.
//!
//! Binary layout (all multi-byte integers little-endian):
//!
//! ```text
//! +--------+-------+-----+-----+----------+----------+----------+------+-------+-----------+
//! | "HSPK" |  u8   | u8  | u8  |  u32     |  u32     |  u32     | salt | nonce | ciphertext |
//! | magic  | ver   | kem | dsa | argon mem| argon t  | argon p  | 16 B | 24 B  |  + tag     |
//! +--------+-------+-----+-----+----------+----------+----------+------+-------+-----------+
//! ```
//!
//! The ciphertext authenticates and encrypts the concatenation of the
//! 64-byte ML-KEM seed, the 32-byte ML-DSA seed, and the corresponding
//! public keys (whose lengths depend on the variants).

use super::kem;
use super::sign;
use super::sym;
use super::CryptoError;
use super::DsaVariant;
use super::KemVariant;
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};
use zeroize::Zeroize;

/// Magic header bytes for `hs` secret key files.
const MAGIC: &[u8; 4] = b"HSPK";
/// Format version.
const VERSION: u8 = 1;
/// Length of the Argon2id salt.
const SALT_LEN: usize = 16;

/// Salt length in bytes used by the key file format.
pub const SALT_LEN_PUB: usize = SALT_LEN;

/// Argon2id parameters for a key file, stored in the header.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub mem_cost: u32,
    /// Time cost (iterations).
    pub time_cost: u32,
    /// Parallelism (threads).
    pub par_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_cost: sym::DEFAULT_ARGON2_MEM,
            time_cost: sym::DEFAULT_ARGON2_TIME,
            par_cost: sym::DEFAULT_ARGON2_PAR,
        }
    }
}

/// A decrypted `hs` key pair in memory. Seeds are zeroized on drop.
pub struct UnlockedKey {
    /// KEM variant.
    pub kem_variant: KemVariant,
    /// DSA variant.
    pub dsa_variant: DsaVariant,
    /// ML-KEM secret seed (64 bytes).
    pub kem_seed: Vec<u8>,
    /// ML-DSA secret seed (32 bytes).
    pub dsa_seed: Vec<u8>,
    /// ML-KEM public key bytes.
    pub kem_public_key: Vec<u8>,
    /// ML-DSA public key bytes.
    pub dsa_public_key: Vec<u8>,
}

impl Drop for UnlockedKey {
    fn drop(&mut self) {
        self.kem_seed.zeroize();
        self.dsa_seed.zeroize();
    }
}

impl UnlockedKey {
    /// Build a [`kem::SecretKey`] from the stored KEM seed.
    pub fn kem_secret_key(&self) -> Result<kem::SecretKey, CryptoError> {
        kem::SecretKey::from_bytes(&self.kem_seed)
    }

    /// Build a [`sign::SecretKey`] from the stored DSA seed.
    pub fn sign_secret_key(&self) -> Result<sign::SecretKey, CryptoError> {
        sign::SecretKey::from_bytes(&self.dsa_seed)
    }
}

fn kem_from_byte(b: u8) -> Result<KemVariant, CryptoError> {
    match b {
        0 => Ok(KemVariant::MlKem512),
        1 => Ok(KemVariant::MlKem768),
        2 => Ok(KemVariant::MlKem1024),
        _ => Err(CryptoError::InvalidKey(format!(
            "invalid KEM variant marker {}",
            b
        ))),
    }
}

fn kem_to_byte(v: KemVariant) -> u8 {
    match v {
        KemVariant::MlKem512 => 0,
        KemVariant::MlKem768 => 1,
        KemVariant::MlKem1024 => 2,
    }
}

fn dsa_from_byte(b: u8) -> Result<DsaVariant, CryptoError> {
    match b {
        0 => Ok(DsaVariant::MlDsa44),
        1 => Ok(DsaVariant::MlDsa65),
        2 => Ok(DsaVariant::MlDsa87),
        _ => Err(CryptoError::InvalidKey(format!(
            "invalid DSA variant marker {}",
            b
        ))),
    }
}

fn dsa_to_byte(v: DsaVariant) -> u8 {
    match v {
        DsaVariant::MlDsa44 => 0,
        DsaVariant::MlDsa65 => 1,
        DsaVariant::MlDsa87 => 2,
    }
}

/// Secret key material to be serialized into a key file.
///
/// Bundles the algorithm variants, seeds, and public keys so they can be
/// passed to [`to_bytes`] and [`write`] as a single unit.
pub struct SecretMaterial<'a> {
    /// KEM variant.
    pub kem_variant: KemVariant,
    /// DSA variant.
    pub dsa_variant: DsaVariant,
    /// ML-KEM secret seed.
    pub kem_seed: &'a [u8],
    /// ML-DSA secret seed.
    pub dsa_seed: &'a [u8],
    /// ML-KEM public key bytes.
    pub kem_public_key: &'a [u8],
    /// ML-DSA public key bytes.
    pub dsa_public_key: &'a [u8],
}

/// Serialize a secret key file to bytes.
///
/// The `kem_seed` (64 bytes), `dsa_seed` (32 bytes), and their public
/// keys are concatenated and encrypted with XChaCha20-Poly1305 using an
/// Argon2id-derived key.
pub fn to_bytes(
    material: &SecretMaterial<'_>,
    passphrase: &str,
    params: &KdfParams,
) -> Result<Vec<u8>, CryptoError> {
    let kem_seed = material.kem_seed;
    let dsa_seed = material.dsa_seed;
    let kem_public_key = material.kem_public_key;
    let dsa_public_key = material.dsa_public_key;
    if kem_seed.len() != material.kem_variant.secret_key_len() {
        return Err(CryptoError::InvalidKey(format!(
            "KEM seed must be {} bytes for {}",
            material.kem_variant.secret_key_len(),
            material.kem_variant.as_str()
        )));
    }
    if dsa_seed.len() != material.dsa_variant.secret_key_len() {
        return Err(CryptoError::InvalidKey(format!(
            "DSA seed must be {} bytes for {}",
            material.dsa_variant.secret_key_len(),
            material.dsa_variant.as_str()
        )));
    }
    if kem_public_key.len() != material.kem_variant.public_key_len() {
        return Err(CryptoError::InvalidKey(format!(
            "KEM public key must be {} bytes for {}",
            material.kem_variant.public_key_len(),
            material.kem_variant.as_str()
        )));
    }
    if dsa_public_key.len() != material.dsa_variant.public_key_len() {
        return Err(CryptoError::InvalidKey(format!(
            "DSA public key must be {} bytes for {}",
            material.dsa_variant.public_key_len(),
            material.dsa_variant.as_str()
        )));
    }

    let salt = sym::random_salt(SALT_LEN);
    let key = sym::derive_key(
        passphrase,
        &salt,
        params.mem_cost,
        params.time_cost,
        params.par_cost,
    )?;

    let mut plaintext = Vec::with_capacity(
        kem_seed.len() + dsa_seed.len() + kem_public_key.len() + dsa_public_key.len(),
    );
    plaintext.extend_from_slice(kem_seed);
    plaintext.extend_from_slice(dsa_seed);
    plaintext.extend_from_slice(kem_public_key);
    plaintext.extend_from_slice(dsa_public_key);

    let (nonce, ciphertext) = sym::encrypt(&key, &plaintext)?;
    plaintext.zeroize();

    let mut out =
        Vec::with_capacity(MAGIC.len() + 32 + salt.len() + nonce.len() + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(kem_to_byte(material.kem_variant));
    out.push(dsa_to_byte(material.dsa_variant));
    out.extend_from_slice(&params.mem_cost.to_le_bytes());
    out.extend_from_slice(&params.time_cost.to_le_bytes());
    out.extend_from_slice(&params.par_cost.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Write a secret key file to disk with `0o600` permissions.
pub fn write(
    path: &std::path::Path,
    material: &SecretMaterial<'_>,
    passphrase: &str,
    params: &KdfParams,
) -> Result<(), CryptoError> {
    use std::os::unix::fs::OpenOptionsExt;

    let data = to_bytes(material, passphrase, params)?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&data)?;
    file.flush()?;
    Ok(())
}

/// Parse a secret key file from bytes, decrypting with the passphrase.
///
/// The Argon2id parameters are read from the file header, so the caller
/// only needs the passphrase.
pub fn from_bytes(data: &[u8], passphrase: &str) -> Result<UnlockedKey, CryptoError> {
    let header_len = MAGIC.len() + 1 + 1 + 1 + 12 + SALT_LEN + sym::NONCE_LEN;
    if data.len() < header_len {
        return Err(CryptoError::InvalidKey("key file too short".into()));
    }
    if &data[0..4] != MAGIC {
        return Err(CryptoError::InvalidKey(
            "not an hs secret key file (bad magic)".into(),
        ));
    }
    let version = data[4];
    if version != VERSION {
        return Err(CryptoError::InvalidKey(format!(
            "unsupported key file version {}",
            version
        )));
    }
    let kem_variant = kem_from_byte(data[5])?;
    let dsa_variant = dsa_from_byte(data[6])?;

    let mut off = 7;
    let read_u32 = |off: &mut usize| -> Result<u32, CryptoError> {
        let bytes: [u8; 4] = data[*off..*off + 4]
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("key file truncated".into()))?;
        *off += 4;
        Ok(u32::from_le_bytes(bytes))
    };
    let mem_cost = read_u32(&mut off)?;
    let time_cost = read_u32(&mut off)?;
    let par_cost = read_u32(&mut off)?;

    let salt = &data[off..off + SALT_LEN];
    off += SALT_LEN;
    let nonce: [u8; sym::NONCE_LEN] = data[off..off + sym::NONCE_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("key file truncated (nonce)".into()))?;
    off += sym::NONCE_LEN;

    let ciphertext = &data[off..];

    let key = sym::derive_key(passphrase, salt, mem_cost, time_cost, par_cost)?;
    let plaintext = sym::decrypt(&key, &nonce, ciphertext)?;

    let kem_seed_len = kem_variant.secret_key_len();
    let dsa_seed_len = dsa_variant.secret_key_len();
    let kem_pk_len = kem_variant.public_key_len();
    let dsa_pk_len = dsa_variant.public_key_len();
    if plaintext.len() != kem_seed_len + dsa_seed_len + kem_pk_len + dsa_pk_len {
        return Err(CryptoError::InvalidKey(format!(
            "key file plaintext length mismatch: got {}, expected {}",
            plaintext.len(),
            kem_seed_len + dsa_seed_len + kem_pk_len + dsa_pk_len
        )));
    }

    let mut off = 0;
    let kem_seed = plaintext[off..off + kem_seed_len].to_vec();
    off += kem_seed_len;
    let dsa_seed = plaintext[off..off + dsa_seed_len].to_vec();
    off += dsa_seed_len;
    let kem_public_key = plaintext[off..off + kem_pk_len].to_vec();
    off += kem_pk_len;
    let dsa_public_key = plaintext[off..off + dsa_pk_len].to_vec();

    Ok(UnlockedKey {
        kem_variant,
        dsa_variant,
        kem_seed,
        dsa_seed,
        kem_public_key,
        dsa_public_key,
    })
}

/// Read and decrypt a secret key file from disk.
pub fn read(path: &std::path::Path, passphrase: &str) -> Result<UnlockedKey, CryptoError> {
    let mut data = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut data)?;
    let unlocked = from_bytes(&data, passphrase)?;
    data.zeroize();
    Ok(unlocked)
}

/// Compute the key fingerprint: `hex(SHA3-256(kem_pk || dsa_pk))`.
///
/// The fingerprint uniquely identifies a public key pair and is used to
/// name key files and tag signed blocks.
pub fn fingerprint(kem_pk: &[u8], dsa_pk: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(kem_pk);
    hasher.update(dsa_pk);
    hex(&hasher.finalize())
}

/// Hex-encode a byte slice (lowercase).
pub fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
