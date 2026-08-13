//! ML-DSA (CRYSTALS-Dilithium) FIPS 204 digital signatures.
//!
//! Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets.
//! Public keys and signature sizes vary by variant; secret key
//! seeds are always 32 bytes. Signatures are produced over the raw
//! canonical bytes of a signed block.

use super::CryptoError;
use super::DsaVariant;
use ml_dsa::common::Key;
use ml_dsa::*;
use zeroize::Zeroize;

/// An ML-DSA public key (verifying key).
pub struct PublicKey {
    bytes: Vec<u8>,
    variant: DsaVariant,
}

impl PublicKey {
    /// Build a [`PublicKey`] from raw bytes, validating the length
    /// matches the expected size for the given variant.
    pub fn from_bytes(bytes: &[u8], variant: DsaVariant) -> Result<Self, CryptoError> {
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
    pub fn variant(&self) -> DsaVariant {
        self.variant
    }
}

/// An ML-DSA secret key (seed), 32 bytes. Zeroized on drop.
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    /// Build a [`SecretKey`] from raw bytes, validating length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "ML-DSA secret key must be 32 bytes".into(),
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

/// Generate a new ML-DSA keypair for the given variant.
pub fn keypair(variant: DsaVariant) -> Result<(SecretKey, PublicKey), CryptoError> {
    match variant {
        DsaVariant::MlDsa44 => {
            let signing_key = SigningKey::<MlDsa44>::generate();
            let verifying_key = signing_key.verifying_key();
            let seed: Seed = signing_key.to_bytes();
            let vk_key: Key<VerifyingKey<MlDsa44>> = verifying_key.to_bytes();
            Ok((
                SecretKey(seed.to_vec()),
                PublicKey {
                    bytes: vk_key.to_vec(),
                    variant,
                },
            ))
        }
        DsaVariant::MlDsa65 => {
            let signing_key = SigningKey::<MlDsa65>::generate();
            let verifying_key = signing_key.verifying_key();
            let seed: Seed = signing_key.to_bytes();
            let vk_key: Key<VerifyingKey<MlDsa65>> = verifying_key.to_bytes();
            Ok((
                SecretKey(seed.to_vec()),
                PublicKey {
                    bytes: vk_key.to_vec(),
                    variant,
                },
            ))
        }
        DsaVariant::MlDsa87 => {
            let signing_key = SigningKey::<MlDsa87>::generate();
            let verifying_key = signing_key.verifying_key();
            let seed: Seed = signing_key.to_bytes();
            let vk_key: Key<VerifyingKey<MlDsa87>> = verifying_key.to_bytes();
            Ok((
                SecretKey(seed.to_vec()),
                PublicKey {
                    bytes: vk_key.to_vec(),
                    variant,
                },
            ))
        }
    }
}

/// Sign a message with an ML-DSA secret key.
pub fn sign(sk: &SecretKey, message: &[u8], variant: DsaVariant) -> Result<Vec<u8>, CryptoError> {
    let seed_arr = <Seed>::try_from(&sk.0[..32])
        .map_err(|_| CryptoError::Sign("invalid signing key seed".into()))?;

    match variant {
        DsaVariant::MlDsa44 => {
            let signing_key = SigningKey::<MlDsa44>::new(&seed_arr);
            let signature: Signature<MlDsa44> = signing_key.sign(message);
            let sig_encoded: EncodedSignature<MlDsa44> = signature.encode();
            Ok(sig_encoded.to_vec())
        }
        DsaVariant::MlDsa65 => {
            let signing_key = SigningKey::<MlDsa65>::new(&seed_arr);
            let signature: Signature<MlDsa65> = signing_key.sign(message);
            let sig_encoded: EncodedSignature<MlDsa65> = signature.encode();
            Ok(sig_encoded.to_vec())
        }
        DsaVariant::MlDsa87 => {
            let signing_key = SigningKey::<MlDsa87>::new(&seed_arr);
            let signature: Signature<MlDsa87> = signing_key.sign(message);
            let sig_encoded: EncodedSignature<MlDsa87> = signature.encode();
            Ok(sig_encoded.to_vec())
        }
    }
}

/// Verify a signature against a message using an ML-DSA public key.
pub fn verify(pk: &PublicKey, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    match pk.variant {
        DsaVariant::MlDsa44 => {
            let vk_arr = <Key<VerifyingKey<MlDsa44>>>::try_from(&pk.bytes[..])
                .map_err(|_| CryptoError::Verify("invalid verifying key length".into()))?;
            let verifying_key = VerifyingKey::<MlDsa44>::new(&vk_arr);
            let sig_encoded = <EncodedSignature<MlDsa44>>::try_from(signature)
                .map_err(|_| CryptoError::Verify("invalid signature length".into()))?;
            let sig = Signature::<MlDsa44>::decode(&sig_encoded)
                .ok_or_else(|| CryptoError::Verify("invalid signature encoding".into()))?;
            match verifying_key.verify(message, &sig) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        DsaVariant::MlDsa65 => {
            let vk_arr = <Key<VerifyingKey<MlDsa65>>>::try_from(&pk.bytes[..])
                .map_err(|_| CryptoError::Verify("invalid verifying key length".into()))?;
            let verifying_key = VerifyingKey::<MlDsa65>::new(&vk_arr);
            let sig_encoded = <EncodedSignature<MlDsa65>>::try_from(signature)
                .map_err(|_| CryptoError::Verify("invalid signature length".into()))?;
            let sig = Signature::<MlDsa65>::decode(&sig_encoded)
                .ok_or_else(|| CryptoError::Verify("invalid signature encoding".into()))?;
            match verifying_key.verify(message, &sig) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        DsaVariant::MlDsa87 => {
            let vk_arr = <Key<VerifyingKey<MlDsa87>>>::try_from(&pk.bytes[..])
                .map_err(|_| CryptoError::Verify("invalid verifying key length".into()))?;
            let verifying_key = VerifyingKey::<MlDsa87>::new(&vk_arr);
            let sig_encoded = <EncodedSignature<MlDsa87>>::try_from(signature)
                .map_err(|_| CryptoError::Verify("invalid signature length".into()))?;
            let sig = Signature::<MlDsa87>::decode(&sig_encoded)
                .ok_or_else(|| CryptoError::Verify("invalid signature encoding".into()))?;
            match verifying_key.verify(message, &sig) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }
}
