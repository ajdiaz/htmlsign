//! ML-KEM (CRYSTALS-Kyber) FIPS 203 key encapsulation.
//!
//! Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024 parameter sets.
//! Secret key seeds are 64 bytes, shared secrets are 32 bytes for all
//! variants. Public key and ciphertext sizes vary by variant.
//!
//! In `hs` the KEM keypair is bound into signed blocks so that the same
//! identity can later be used to encrypt content to it; signing itself
//! is performed with ML-DSA.

use super::CryptoError;
use super::KemVariant;
use ml_kem::*;
use zeroize::Zeroize;

/// Length of the shared secret derived from encapsulation (32 bytes).
pub const SHARED_SECRET_LEN: usize = 32;

/// An ML-KEM public key (encapsulation key).
pub struct PublicKey {
    bytes: Vec<u8>,
    variant: KemVariant,
}

impl PublicKey {
    /// Build a [`PublicKey`] from raw bytes, validating the length
    /// matches the expected size for the given variant.
    pub fn from_bytes(bytes: &[u8], variant: KemVariant) -> Result<Self, CryptoError> {
        let expected = variant.public_key_len();
        if bytes.len() != expected {
            return Err(CryptoError::InvalidKey(format!(
                "invalid {} public key length: got {}, expected {}",
                variant.as_str(),
                bytes.len(),
                expected,
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            variant,
        })
    }

    /// View the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Clone the raw public key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// The variant this key was created for.
    pub fn variant(&self) -> KemVariant {
        self.variant
    }
}

/// An ML-KEM secret key (seed), 64 bytes. Zeroized on drop.
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    /// Build a [`SecretKey`] from raw bytes, validating length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKey(
                "ML-KEM secret key must be 64 bytes".into(),
            ));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// View the raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Clone the raw secret key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Generate a new ML-KEM keypair for the given variant.
pub fn keypair(variant: KemVariant) -> Result<(SecretKey, PublicKey), CryptoError> {
    match variant {
        KemVariant::MlKem512 => {
            let (decap, encap) = MlKem512::generate_keypair();
            Ok((
                SecretKey(decap.to_bytes().to_vec()),
                PublicKey {
                    bytes: encap.to_bytes().to_vec(),
                    variant,
                },
            ))
        }
        KemVariant::MlKem768 => {
            let (decap, encap) = MlKem768::generate_keypair();
            Ok((
                SecretKey(decap.to_bytes().to_vec()),
                PublicKey {
                    bytes: encap.to_bytes().to_vec(),
                    variant,
                },
            ))
        }
        KemVariant::MlKem1024 => {
            let (decap, encap) = MlKem1024::generate_keypair();
            Ok((
                SecretKey(decap.to_bytes().to_vec()),
                PublicKey {
                    bytes: encap.to_bytes().to_vec(),
                    variant,
                },
            ))
        }
    }
}

/// Encapsulate a shared secret for a public key.
pub fn encapsulate(pk: &PublicKey) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), CryptoError> {
    match pk.variant {
        KemVariant::MlKem512 => {
            let ek_arr = <Key<EncapsulationKey<MlKem512>>>::try_from(&pk.bytes[..])
                .map_err(|_| CryptoError::Encrypt("invalid encapsulation key length".into()))?;
            let encap = EncapsulationKey::<MlKem512>::new(&ek_arr)
                .map_err(|e| CryptoError::Encrypt(format!("invalid encapsulation key: {}", e)))?;
            let (ct, shared) = encap.encapsulate();
            Ok((ct.to_vec(), shared.into()))
        }
        KemVariant::MlKem768 => {
            let ek_arr = <Key<EncapsulationKey<MlKem768>>>::try_from(&pk.bytes[..])
                .map_err(|_| CryptoError::Encrypt("invalid encapsulation key length".into()))?;
            let encap = EncapsulationKey::<MlKem768>::new(&ek_arr)
                .map_err(|e| CryptoError::Encrypt(format!("invalid encapsulation key: {}", e)))?;
            let (ct, shared) = encap.encapsulate();
            Ok((ct.to_vec(), shared.into()))
        }
        KemVariant::MlKem1024 => {
            let ek_arr = <Key<EncapsulationKey<MlKem1024>>>::try_from(&pk.bytes[..])
                .map_err(|_| CryptoError::Encrypt("invalid encapsulation key length".into()))?;
            let encap = EncapsulationKey::<MlKem1024>::new(&ek_arr)
                .map_err(|e| CryptoError::Encrypt(format!("invalid encapsulation key: {}", e)))?;
            let (ct, shared) = encap.encapsulate();
            Ok((ct.to_vec(), shared.into()))
        }
    }
}

/// Decapsulate a shared secret from a ciphertext using a secret key.
pub fn decapsulate(
    sk: &SecretKey,
    ciphertext: &[u8],
    variant: KemVariant,
) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    let seed_arr = <Seed>::try_from(&sk.0[..64])
        .map_err(|_| CryptoError::Decrypt("invalid secret key seed".into()))?;

    match variant {
        KemVariant::MlKem512 => {
            let decap = DecapsulationKey::<MlKem512>::from_seed(seed_arr);
            let ct_arr = <Ciphertext<MlKem512>>::try_from(ciphertext)
                .map_err(|_| CryptoError::Decrypt("invalid ciphertext length".into()))?;
            let shared = decap.decapsulate(&ct_arr);
            Ok(shared.into())
        }
        KemVariant::MlKem768 => {
            let decap = DecapsulationKey::<MlKem768>::from_seed(seed_arr);
            let ct_arr = <Ciphertext<MlKem768>>::try_from(ciphertext)
                .map_err(|_| CryptoError::Decrypt("invalid ciphertext length".into()))?;
            let shared = decap.decapsulate(&ct_arr);
            Ok(shared.into())
        }
        KemVariant::MlKem1024 => {
            let decap = DecapsulationKey::<MlKem1024>::from_seed(seed_arr);
            let ct_arr = <Ciphertext<MlKem1024>>::try_from(ciphertext)
                .map_err(|_| CryptoError::Decrypt("invalid ciphertext length".into()))?;
            let shared = decap.decapsulate(&ct_arr);
            Ok(shared.into())
        }
    }
}
