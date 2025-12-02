//! Key management module for hybrid HD wallet.
//!
//! This module provides a wrapper interface for managing keypairs of different signature schemes.
//!
//! # Signatures supported
//!
//! - [ECDSA secp256k1][ecdsa] : Classic elliptic curve signatures for Bitcoin/Ethereum compatibility
//! - [Falcon-512][falcon]: Post-quantum lattice-based signatures for future security
//!
//! # Modules
//!
//! - [`ecdsa`]: ECDSA secp256k1 keypair implementation
//! - [`falcon`]: Falcon-512 keypair implementation

mod ecdsa;
mod error;
mod falcon;

pub use ecdsa::EcdsaKeyPair;
pub use error::KeyError;
pub use falcon::FalconKeyPair;

use crate::falcon::{FalconScheme, FalconSigningKey, FalconVerificationKey};
use crate::hhd::signatures::SignatureScheme;
use bip32::secp256k1::ecdsa::SigningKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A generic keypair wrapper that supports multiple signature schemes.
///
/// This struct provides a unified representation for keypairs across different
/// cryptographic schemes, allowing scheme-agnostic signing and verification operations.
/// The actual key format depends on the specified `SignatureScheme`.
///
/// # Key Formats by Scheme
///
/// ## ECDSA secp256k1
/// - **Public key**: 33 bytes (compressed SEC1 format)
/// - **Private key**: 32 bytes (raw scalar bytes)
///
/// ## Falcon-512
/// - **Public key**: 897 bytes (Falcon-512 format)
/// - **Private key**: 1281 bytes (Falcon-512 format)
///
/// # Example
///
/// ```
/// use bedrock::hhd::{EcdsaKeyPair, GenericKeyPair};
/// use bedrock::hhd::SignatureScheme;
///
/// let seed = [0u8; 64];
/// let ecdsa_keypair = EcdsaKeyPair::derive_from_seed(&seed, 0).unwrap();
/// let generic = ecdsa_keypair.to_generic_key_pair().unwrap();
///
/// let message = b"Hello, world!";
/// let signature = generic.sign(message).unwrap();
/// assert!(generic.verify(message, &signature).unwrap());
/// ```

#[derive(ZeroizeOnDrop)]
pub struct GenericKeyPair {
    /// The public key bytes
    #[zeroize(on_drop)]
    pub public_key: Vec<u8>,
    /// The private key bytes
    #[zeroize(on_drop)]
    pub private_key: Vec<u8>,
    /// The signature scheme this keypair uses
    #[zeroize(skip)]
    pub signature_scheme: SignatureScheme,
}

impl GenericKeyPair {
    /// Creates a new `GenericKeyPair` from raw key bytes and a signature scheme.
    ///
    /// Note: this constructor validates the key format or lengths.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key bytes (format depends on signature scheme)
    /// * `private_key` - The private key bytes (format depends on signature scheme)
    /// * `signature_scheme` - The signature scheme this keypair uses
    ///
    /// # Returns
    ///
    /// * `Ok(GenericKeyPair)` - The new `GenericKeyPair` instance.
    /// * `Err(KeyError)` - If the key format or lengths are invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::{EcdsaKeyPair, GenericKeyPair};
    /// use bedrock::hhd::SignatureScheme;
    ///
    /// let ecdsa_keypair = EcdsaKeyPair::derive_from_seed(&[0u8; 64], 0).unwrap();
    /// let generic = ecdsa_keypair.to_generic_key_pair();
    /// // Now you can use the generic wrapper
    /// ```
    pub fn new(
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        signature_scheme: SignatureScheme,
    ) -> Result<Self, KeyError> {
        let generic_keypair = Self {
            public_key,
            private_key,
            signature_scheme,
        };

        // Validate key format and lengths
        match signature_scheme {
            SignatureScheme::EcdsaSecp256k1 => {
                generic_keypair.to_ecdsa_key_pair()?;
                Ok(generic_keypair)
            }
            SignatureScheme::Falcon512 => {
                generic_keypair.to_falcon_key_pair()?;
                Ok(generic_keypair)
            }
        }
    }

    /// Converts a `GenericKeyPair` to an `EcdsaKeyPair`.
    ///
    /// This method validates that the keypair uses the ECDSA secp256k1 scheme
    /// and that the key lengths match the expected format before conversion.
    ///
    /// # Returns
    ///
    /// * `Ok(EcdsaKeyPair)` - The converted ECDSA keypair
    /// * `Err(KeyError)` - If the scheme is not ECDSA or key format is invalid
    ///
    /// # Errors
    ///
    /// Returns `KeyError` in the following cases:
    /// - `UnsupportedScheme`: If the keypair is not using ECDSA secp256k1
    /// - `InvalidKeyFormat`: If key lengths don't match ECDSA requirements
    /// - Key deserialization errors
    fn to_ecdsa_key_pair(&self) -> Result<EcdsaKeyPair, KeyError> {
        match self.signature_scheme {
            SignatureScheme::EcdsaSecp256k1 => {
                // Verify key lengths
                if self.private_key.len() != SignatureScheme::EcdsaSecp256k1.signing_key_size() {
                    return Err(KeyError::InvalidKeyFormat);
                }
                if self.public_key.len() != SignatureScheme::EcdsaSecp256k1.verifying_key_size() {
                    return Err(KeyError::InvalidKeyFormat);
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&self.private_key);

                let signing_key = SigningKey::from_bytes(&key_bytes.into())
                    .expect("should deserialize secret key");

                // Zeroize the key bytes
                key_bytes.zeroize();

                let verifying_key = *signing_key.verifying_key();
                Ok(EcdsaKeyPair {
                    signing_key,
                    verifying_key,
                })
            }
            SignatureScheme::Falcon512 => Err(KeyError::UnsupportedScheme),
        }
    }

    /// Converts a `GenericKeyPair` to a `FalconKeyPair`.
    ///
    /// This method validates that the keypair uses the Falcon-512 scheme
    /// and that the key lengths match the expected format before conversion.
    ///
    /// # Returns
    ///
    /// * `Ok(FalconKeyPair)` - The converted Falcon keypair
    /// * `Err(KeyError)` - If the scheme is not Falcon-512 or key format is invalid
    ///
    /// # Errors
    ///
    /// Returns `KeyError` in the following cases:
    /// - `UnsupportedScheme`: If the keypair is not using Falcon-512
    /// - `InvalidKeyFormat`: If key lengths don't match Falcon-512 requirements
    /// - Key deserialization errors
    fn to_falcon_key_pair(&self) -> Result<FalconKeyPair, KeyError> {
        match self.signature_scheme {
            SignatureScheme::EcdsaSecp256k1 => Err(KeyError::UnsupportedScheme),
            SignatureScheme::Falcon512 => {
                // Verify key lengths
                if self.private_key.len() != SignatureScheme::Falcon512.signing_key_size() {
                    return Err(KeyError::InvalidKeyFormat);
                }
                if self.public_key.len() != SignatureScheme::Falcon512.verifying_key_size() {
                    return Err(KeyError::InvalidKeyFormat);
                }

                let signing_key =
                    FalconSigningKey::from_raw_bytes(FalconScheme::Dsa512, &self.private_key)
                        .expect("should deserialize secret key");
                let verifying_key =
                    FalconVerificationKey::from_raw_bytes(FalconScheme::Dsa512, &self.public_key)
                        .expect("should deserialize public key");
                Ok(FalconKeyPair {
                    signing_key,
                    verifying_key,
                })
            }
        }
    }

    #[cfg(feature = "sign")]
    /// Signs a message using the appropriate signature scheme.
    ///
    /// This method automatically selects the correct signing algorithm based on
    /// the keypair's signature scheme and signs the provided message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign as bytes
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The signature bytes (format depends on signature scheme)
    ///   - ECDSA secp256k1: 64 bytes (32 bytes for r, 32 bytes for s)
    ///   - Falcon-512: ~666 bytes (variable length)
    /// * `Err(KeyError)` - If signing fails or scheme is unsupported
    ///
    /// # Errors
    ///
    /// Returns `KeyError` in the following cases:
    /// - `UnsupportedScheme`: If the signature scheme is not supported
    /// - `InvalidKeyFormat`: If key format is invalid
    /// - `SigningFailed`: If the signing operation fails
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::{EcdsaKeyPair, GenericKeyPair};
    ///
    /// let ecdsa_keypair = EcdsaKeyPair::derive_from_seed(&[0u8; 64], 0).unwrap();
    /// let generic = ecdsa_keypair.to_generic_key_pair().unwrap();
    /// let message = b"Hello, world!";
    /// let signature = generic.sign(message).unwrap();
    /// ```
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        match self.signature_scheme {
            SignatureScheme::EcdsaSecp256k1 => self.to_ecdsa_key_pair()?.sign(message),
            SignatureScheme::Falcon512 => self.to_falcon_key_pair()?.sign(message),
        }
    }

    #[cfg(feature = "vrfy")]
    /// Verifies a signature against a message using the appropriate signature scheme.
    ///
    /// This method automatically selects the correct verification algorithm based on
    /// the keypair's signature scheme and verifies the signature against the message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature bytes to verify (format depends on signature scheme)
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If the signature is valid
    /// * `Ok(false)` - If the signature is invalid
    /// * `Err(KeyError)` - If verification fails or scheme is unsupported
    ///
    /// # Errors
    ///
    /// Returns `KeyError` in the following cases:
    /// - `UnsupportedScheme`: If the signature scheme is not supported
    /// - `InvalidKeyFormat`: If key format is invalid
    /// - `InvalidSignatureFormat`: If signature format is invalid
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::{EcdsaKeyPair, GenericKeyPair};
    ///
    /// let ecdsa_keypair = EcdsaKeyPair::derive_from_seed(&[0u8; 64], 0).unwrap();
    /// let generic = ecdsa_keypair.to_generic_key_pair().unwrap();
    /// let message = b"Hello, world!";
    /// let signature = generic.sign(message).unwrap();
    /// assert!(generic.verify(message, &signature).unwrap());
    ///
    /// // Wrong message should fail
    /// assert!(!generic.verify(b"Wrong message", &signature).unwrap());
    /// ```
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, KeyError> {
        match self.signature_scheme {
            SignatureScheme::EcdsaSecp256k1 => self.to_ecdsa_key_pair()?.verify(message, signature),
            SignatureScheme::Falcon512 => self.to_falcon_key_pair()?.verify(message, signature),
        }
    }
}

#[cfg(test)]
mod tests {
    /// Tests that signing and verification work correctly for both ECDSA and Falcon keypairs
    /// when using the generic wrapper.
    ///
    /// This test verifies:
    /// - ECDSA keypairs can be wrapped and used through the generic interface
    /// - Falcon keypairs can be wrapped and used through the generic interface
    /// - Signatures generated through the generic interface can be verified
    #[test]
    #[cfg(all(feature = "sign", feature = "vrfy"))]
    fn test_generic_key_pair_sign_verify() {
        use crate::hhd::keys::{ecdsa::EcdsaKeyPair, falcon::FalconKeyPair};

        // ECDSA and Falcon test seed
        const TEST_SIGNATURE_SEED_64: [u8; 64] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ];

        // Generate ECDSA key pair and test sign/verify using generic wrapper
        let ecdsa_keypair = EcdsaKeyPair::derive_from_seed(&TEST_SIGNATURE_SEED_64, 0).unwrap();
        let generic_ecdsa = ecdsa_keypair.to_generic_key_pair().unwrap();
        let message = b"Hello, world!";
        let signature = generic_ecdsa.sign(message).unwrap();
        assert!(generic_ecdsa.verify(message, &signature).unwrap());

        // Generate Falcon key pair and test sign/verify using generic wrapper
        let falcon_keypair = FalconKeyPair::derive_from_seed(&TEST_SIGNATURE_SEED_64, 0).unwrap();
        let generic_falcon = falcon_keypair.to_generic_key_pair().unwrap();
        let signature_falcon = generic_falcon.sign(message).unwrap();
        assert!(generic_falcon.verify(message, &signature_falcon).unwrap());
    }
}
