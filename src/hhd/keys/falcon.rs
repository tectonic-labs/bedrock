//! Falcon-512 keypair wrapper of [`falcon-rust`][falcon-rust] implementation.
//!
//! This module provides a wrapper for Falcon-512, a post-quantum digital signature
//! algorithm based on lattice cryptography.
//!
//! # Features
//!
//! - Derive keypairs from seeds using [SLIP-0010][slip-0010] hierarchical deterministic key derivation
//! - Sign messages and verify signatures
//! - Convert between Falcon keypairs and generic keypair representations
//!
//! # Key Specifications
//!
//! - **Private key**: 1281 bytes
//! - **Public key**: 897 bytes
//! - **Signature**: 666 bytes
//!
//! # Derivation Path
//!
//! Uses BIP-44 hardened derivation path: `m/44'/60'/0'/0'/{address_index}'`
//! - `44'`: BIP-44 standard
//! - `60'`: Ethereum coin type
//! - `0'`: Account index
//! - `0'`: Change (hardened)
//! - `{address_index}'`: Address index (hardened)
//!
//! [falcon-rust]: https://docs.rs/falcon-rust/latest/falcon_rust/
//! [slip-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

use crate::falcon::{FalconScheme, FalconSigningKey, FalconVerificationKey};
use crate::hhd::keys::{GenericKeyPair, KeyError};
use crate::hhd::signatures::{FALCON512_KEY_GENERATION_SEED_SIZE, SignatureScheme};
use crate::hhd::slip10::{Slip10, Slip10XPrvKey};
use bip32::secp256k1::ecdsa::SigningKey;
use zeroize::Zeroize;

#[cfg(feature = "vrfy")]
use crate::falcon::FalconSignature;

/// Falcon-512 keypair containing both signing and verifying keys.
///
/// This keypair can be used to:
/// - Sign messages using the private signing key
/// - Verify signatures using the public verifying key
/// - Derive from seeds using SLIP-0010 HD key derivation
pub struct FalconKeyPair {
    /// The public verifying key used for signature verification.
    pub verifying_key: FalconVerificationKey,
    /// The private signing key used for message signing.
    pub signing_key: FalconSigningKey,
}

impl FalconKeyPair {
    /// Generates a Falcon-512 keypair directly from a 32-byte seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed bytes (must be exactly 32 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(FalconKeyPair)` - The generated keypair
    /// * `Err(KeyError)` - If seed length is invalid or key generation fails
    pub fn generate_keypair_from_seed(seed: &[u8]) -> Result<Self, KeyError> {
        if seed.len() != FALCON512_KEY_GENERATION_SEED_SIZE {
            return Err(KeyError::InvalidSeedLength {
                expected: FALCON512_KEY_GENERATION_SEED_SIZE,
                actual: seed.len(),
            });
        }

        // Convert to fixed-size array
        let mut seed_array = [0u8; FALCON512_KEY_GENERATION_SEED_SIZE];
        seed_array.copy_from_slice(seed);

        // Generate keypair using falcon-rust
        let (verifying_key, signing_key) = FalconScheme::Dsa512
            .keypair_from_seed(&seed_array)
            .map_err(|e| KeyError::KeyGenerationFailed(e.to_string()))?;

        // Zeroize the seed bytes
        seed_array.zeroize();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Derives a Falcon-512 keypair from a seed and address index using SLIP-0010.
    ///
    /// Uses the BIP-44 hardened derivation path: `m/44'/60'/0'/0'/{address_index}'`
    ///
    /// # Arguments
    ///
    /// * `seed` - The master seed bytes (typically 64 bytes)
    /// * `address_index` - The address index for derivation (hardened)
    ///
    /// # Returns
    ///
    /// * `Ok(FalconKeyPair)` - The derived keypair
    /// * `Err(KeyError)` - If derivation fails
    pub fn derive_from_seed(seed: &[u8], address_index: u32) -> Result<Self, KeyError> {
        // Build derivation path following BIP-44 (m/44'/60'/0'/0'/${address_index}')
        // following the full hardened derivation path convention.
        let derivation_path_str = format!(
            "{}/{}'",
            SignatureScheme::Falcon512.bip44_hardened_base_path()?,
            address_index
        );
        let derivation_path = derivation_path_str.parse()?;

        // Derive HD child seed from master child seed (SLIP-10):
        let child_xprv: Slip10XPrvKey<SigningKey> =
            Slip10::derive_from_path(seed, &derivation_path, SignatureScheme::Falcon512)?;
        let mut private_key_bytes = child_xprv.private_key_bytes();

        // Generate Falcon keypair from seed
        let keypair = Self::generate_keypair_from_seed(&private_key_bytes)?;

        // Zeroize the private key bytes
        private_key_bytes.zeroize();

        Ok(keypair)
    }

    /// Converts a Falcon keypair to a generic keypair representation.
    ///
    /// Serializes the keys to byte vectors and wraps them in a `GenericKeyPair`.
    ///
    /// # Returns
    ///
    /// A `GenericKeyPair` containing:
    /// - Public key: 897 bytes (Falcon-512 format)
    /// - Private key: 1281 bytes (Falcon-512 format)
    /// - Signature scheme: `Falcon512`
    pub fn to_generic_key_pair(&self) -> Result<GenericKeyPair, KeyError> {
        // Serialize keys
        let signing_key = self.signing_key.to_raw_bytes();
        let verifying_key = self.verifying_key.to_raw_bytes();

        GenericKeyPair::new(verifying_key, signing_key, SignatureScheme::Falcon512)
    }

    #[cfg(feature = "sign")]
    /// Signs a message using the private signing key and returns the signature as bytes.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign as bytes
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The signature bytes (variable length, typically 666 bytes)
    /// * `Err(KeyError)` - If signing fails
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let signature = FalconScheme::Dsa512
            .sign(message, &self.signing_key)
            .map_err(|e| KeyError::SigningFailed(e.to_string()))?;
        Ok(signature.to_raw_bytes().to_vec())
    }

    #[cfg(feature = "vrfy")]
    /// Verifies a signature against a message using the public verifying key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature bytes
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If the signature is valid
    /// * `Ok(false)` - If the signature is invalid
    /// * `Err(KeyError)` - If signature format is invalid
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, KeyError> {
        // Deserialize signature
        let signature = FalconSignature::from_raw_bytes(FalconScheme::Dsa512, signature)
            .map_err(|_| KeyError::InvalidSignatureFormat)?;
        let verified = FalconScheme::Dsa512
            .verify(message, &signature, &self.verifying_key)
            .is_ok();
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hhd::signatures::SignatureScheme;

    // Test seed
    const TEST_FALCON_SEED_64: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];

    /// Test that Falcon keypair can be derived from a seed
    #[test]
    fn test_falcon_derive_from_seed_basic() {
        let address_index = 0u32;

        let keypair = FalconKeyPair::derive_from_seed(&TEST_FALCON_SEED_64, address_index)
            .expect("should derive Falcon keypair from seed");

        // Falcon-512 signing key should be 1281 bytes
        assert_eq!(
            keypair.signing_key.to_raw_bytes().len(),
            SignatureScheme::Falcon512.signing_key_size(),
            "Falcon-512 signing key should be 1281 bytes"
        );

        // Falcon-512 verifying key should be 897 bytes
        assert_eq!(
            keypair.verifying_key.to_raw_bytes().len(),
            SignatureScheme::Falcon512.verifying_key_size(),
            "Falcon-512 verifying key should be 897 bytes"
        );
    }

    /// Test that Falcon keypair derivation is deterministic
    #[test]
    fn test_falcon_derive_from_seed_deterministic() {
        let address_index = 5u32;

        // Derive same keypair twice
        let keypair1 = FalconKeyPair::derive_from_seed(&TEST_FALCON_SEED_64, address_index)
            .expect("should derive Falcon keypair");
        let keypair2 = FalconKeyPair::derive_from_seed(&TEST_FALCON_SEED_64, address_index)
            .expect("should derive Falcon keypair");

        // Same seed + same address index = same keypair
        assert_eq!(
            keypair1.signing_key.to_raw_bytes(),
            keypair2.signing_key.to_raw_bytes(),
            "Signing keys should be identical for same seed and address index"
        );
        assert_eq!(
            keypair1.verifying_key.to_raw_bytes(),
            keypair2.verifying_key.to_raw_bytes(),
            "Verifying keys should be identical for same seed and address index"
        );
    }

    #[cfg(all(feature = "sign", feature = "vrfy"))]
    /// Tests signing and verification using the keypair methods.
    #[test]
    fn test_falcon_sign_verify() {
        let keypair = FalconKeyPair::derive_from_seed(&TEST_FALCON_SEED_64, 0)
            .expect("should generate Falcon keypair from seed");
        let message = b"Hello, Falcon-512!";
        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).unwrap());
    }
}
