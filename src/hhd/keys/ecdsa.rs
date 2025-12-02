//! ECDSA secp256k1 keypair wrapper of [`Bip32`][Bip32] implementation.
//!
//! This module provides an implementation of ECDSA (Elliptic Curve Digital Signature Algorithm)
//! using the secp256k1 curve, which is commonly used in Bitcoin and Ethereum applications.
//!
//! # Features
//!
//! - Derive keypairs from seeds using BIP-32 hierarchical deterministic (HD) key derivation
//! - Sign messages and verify signatures
//! - Convert between ECDSA keypairs and generic keypair representations
//!
//! # Key Specifications
//!
//! - **Private key**: 32 bytes (256 bits)
//! - **Public key**: 33 bytes (compressed)
//! - **Signature**: 64 bytes (32 bytes for r, 32 bytes for s)
//!
//! # Derivation Path
//!
//! Uses BIP-44 derivation path: `m/44'/60'/0'/0/{address_index}`
//! - `44'`: BIP-44 standard
//! - `60'`: Ethereum coin type
//! - `0'`: Account index
//! - `0`: Change (external addresses)
//! - `{address_index}`: Address index (non-hardened)
//!
//! # Example
//!
//! ```no_run
//! use bedrock::hhd::EcdsaKeyPair;
//!
//! let seed = [0u8; 64]; // 64-byte seed
//! let keypair = EcdsaKeyPair::derive_from_seed(&seed, 0).unwrap();
//!
//! let message = b"Hello, world!";
//! let signature = keypair.sign(message).unwrap();
//! assert!(keypair.verify(message, &signature).unwrap());
//! ```
//!
//! [Bip32]: https://docs.rs/bip32/latest/bip32/

use crate::hhd::keys::{GenericKeyPair, KeyError};
use crate::hhd::signatures::SignatureScheme;
use bip32::XPrv;
use bip32::secp256k1::ecdsa::{SigningKey, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "sign")]
use bip32::secp256k1::ecdsa::signature::Signer;

#[cfg(feature = "vrfy")]
use bip32::secp256k1::ecdsa::signature::Verifier;

#[cfg(any(feature = "sign", feature = "vrfy"))]
use bip32::secp256k1::ecdsa::Signature;

/// ECDSA secp256k1 keypair containing both signing and verifying keys.
///
/// This keypair can be used to:
/// - Sign messages using the private signing key
/// - Verify signatures using the public verifying key
/// - Derive from seeds using BIP-32 HD key derivation
#[derive(ZeroizeOnDrop)]
pub struct EcdsaKeyPair {
    /// The public verifying key used for signature verification.
    #[zeroize(skip)]
    pub verifying_key: VerifyingKey,
    /// The private signing key used for message signing.
    #[zeroize(on_drop)]
    pub signing_key: SigningKey,
}

impl EcdsaKeyPair {
    /// Derives an ECDSA keypair from a seed and an address index using BIP-32 HD key derivation.
    ///
    /// This method follows the BIP-44 derivation path: `m/44'/60'/0'/0/{address_index}`
    /// where the address index is non-hardened.
    ///
    /// # Arguments
    ///
    /// * `seed` - The master seed bytes (typically 64 bytes from BIP-39 or BIP-85)
    /// * `address_index` - The address index for derivation (non-hardened)
    ///
    /// # Returns
    ///
    /// * `Ok(EcdsaKeyPair)` - The derived keypair
    /// * `Err(KeyError)` - If derivation fails (invalid path, seed length, etc.)
    ///
    /// # Errors
    ///
    /// Returns `KeyError` in the following cases:
    /// - Invalid derivation path parsing
    /// - BIP-32 derivation failure
    /// - Invalid signing key creation
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::EcdsaKeyPair;
    ///
    /// let seed = [0u8; 64];
    /// let keypair = EcdsaKeyPair::derive_from_seed(&seed, 0).unwrap();
    /// ```
    pub fn derive_from_seed(seed: &[u8], address_index: u32) -> Result<Self, KeyError> {
        // Build derivation path following BIP-44 (m/44'/60'/0'/0/${address_index})
        let derivation_path_str = format!(
            "{}/{}",
            SignatureScheme::EcdsaSecp256k1.bip44_non_hardened_base_path()?,
            address_index
        );
        let derivation_path = derivation_path_str.parse()?;

        // Derive HD child seed from master child seed (BIP-32):
        let child_xprv = XPrv::derive_from_path(seed, &derivation_path)?;

        // Extract private key bytes from child xprv
        let mut private_key_bytes = child_xprv.to_bytes();
        let signing_key = SigningKey::from_bytes(&private_key_bytes.into())
            .map_err(|e| KeyError::EcdsaError(format!("Failed to create signing key: {:?}", e)))?;
        let verifying_key = *signing_key.verifying_key();

        // Zeroize the private key bytes
        private_key_bytes.zeroize();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Converts an ECDSA keypair to a generic keypair representation.
    ///
    /// This method serializes the keys to byte vectors and wraps them in a `GenericKeyPair`
    /// structure that can be used for scheme-agnostic key handling.
    ///
    /// # Returns
    ///
    /// A `GenericKeyPair` containing:
    /// - Public key: 33 bytes (compressed SEC1 format)
    /// - Private key: 32 bytes (raw scalar bytes)
    /// - Signature scheme: `EcdsaSecp256k1`
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::EcdsaKeyPair;
    ///
    /// let keypair = EcdsaKeyPair::derive_from_seed(&[0u8; 64], 0).unwrap();
    /// let generic = keypair.to_generic_key_pair().unwrap();
    /// assert_eq!(generic.public_key.len(), 33);
    /// assert_eq!(generic.private_key.len(), 32);
    /// ```
    pub fn to_generic_key_pair(&self) -> Result<GenericKeyPair, KeyError> {
        let public_key = self.verifying_key.to_encoded_point(true).as_ref().to_vec();
        let private_key = self.signing_key.to_bytes().to_vec();
        let signature_scheme = SignatureScheme::EcdsaSecp256k1;

        GenericKeyPair::new(public_key, private_key, signature_scheme)
    }

    /// Returns a clone of the verifying key (public key).
    ///
    /// The verifying key can be used to verify signatures without access to the private key.
    ///
    /// # Returns
    ///
    /// A `VerifyingKey` instance that can be used for signature verification.
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::EcdsaKeyPair;
    ///
    /// let keypair = EcdsaKeyPair::derive_from_seed(&[0u8; 64], 0).unwrap();
    /// let verifying_key = keypair.verifying_key();
    /// ```
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    #[cfg(feature = "sign")]
    /// Signs a message using the private signing key and returns the signature as bytes.
    ///
    /// The signature is computed using ECDSA over the secp256k1 curve and is deterministic
    /// based on the message content and the private key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign as bytes
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The signature as 64 bytes (32 bytes for r, 32 bytes for s)
    /// * `Err(KeyError)` - If signing fails (e.g., signature generation error)
    ///
    /// # Errors
    ///
    /// Returns `KeyError::SigningFailed` if the signature generation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::EcdsaKeyPair;
    ///
    /// let keypair = EcdsaKeyPair::derive_from_seed(&[0u8; 64], 0).unwrap();
    /// let message = b"Hello, world!";
    /// let signature = keypair.sign(message).unwrap();
    /// assert_eq!(signature.len(), 64);
    /// ```
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        // Sign the message
        let signature: Signature = self
            .signing_key
            .try_sign(message)
            .map_err(|e| KeyError::SigningFailed(e.to_string()))?;

        // Convert signature to bytes (64 bytes: r and s values)
        Ok(signature.to_bytes().to_vec())
    }

    #[cfg(feature = "vrfy")]
    /// Verifies a signature against a message using the public verifying key.
    ///
    /// This method checks if the signature was created by the corresponding private key
    /// for the given message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature bytes (must be exactly 64 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If the signature is valid
    /// * `Ok(false)` - If the signature is invalid
    /// * `Err(KeyError)` - If signature format is invalid
    ///
    /// # Errors
    ///
    /// Returns `KeyError::InvalidSignatureFormat` if:
    /// - The signature is not exactly 64 bytes
    /// - The signature cannot be parsed from bytes
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::EcdsaKeyPair;
    ///
    /// let keypair = EcdsaKeyPair::derive_from_seed(&[0u8; 64], 0).unwrap();
    /// let message = b"Hello, world!";
    /// let signature = keypair.sign(message).unwrap();
    /// assert!(keypair.verify(message, &signature).unwrap());
    ///
    /// // Wrong message should fail
    /// assert!(!keypair.verify(b"Wrong message", &signature).unwrap());
    /// ```
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, KeyError> {
        let signature = Signature::from_bytes(signature.into())
            .map_err(|_| KeyError::InvalidSignatureFormat)?;
        Ok(self.verifying_key.verify(message, &signature).is_ok())
    }
}

#[cfg(all(feature = "sign", feature = "vrfy"))]
#[cfg(test)]
mod tests {
    use super::EcdsaKeyPair;

    /// Test seed for ECDSA keypair derivation tests.
    ///
    /// This is a 64-byte seed used for deterministic testing.
    const TEST_ECDSA_SEED_64: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];

    /// Tests that signing and verification work correctly for ECDSA keypairs.
    ///
    /// This test verifies:
    /// - Keypair can be derived from a seed
    /// - Messages can be signed
    /// - Signatures can be verified
    /// - Correct signatures validate successfully
    #[test]
    fn test_ecdsa_sign_verify() {
        let keypair = EcdsaKeyPair::derive_from_seed(&TEST_ECDSA_SEED_64, 0).unwrap();
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).unwrap());
    }
}
