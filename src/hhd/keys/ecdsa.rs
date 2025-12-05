//! This module provides a method to derive an ECDSA secp256k1 keypair from a seed and an address index using [BIP-32][bip-32].
//!
//! # Key Specifications
//!
//! - **Private key**: 32 bytes (256 bits)
//! - **Public key**: 33 bytes (compressed)
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
//! [Bip32]: https://docs.rs/bip32/latest/bip32/

use crate::hhd::keys::KeyError;
use crate::hhd::signatures::SignatureScheme;
use bip32::secp256k1::ecdsa::{SigningKey, VerifyingKey};
use bip32::XPrv;
use zeroize::Zeroize;

/// ECDSA secp256k1 keypair
#[derive(Debug, Copy, Clone)]
pub struct EcdsaSecp256k1 {}

impl EcdsaSecp256k1 {
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
    /// * `Ok(SigningKey, VerifyingKey)` - The derived keypair
    /// * `Err(KeyError)` - If derivation fails (invalid path, seed length, etc.)
    ///
    /// # Errors
    ///
    /// Returns `KeyError` in the following cases:
    /// - Invalid derivation path parsing
    /// - BIP-32 derivation failure
    /// - Invalid signing key creation
    pub fn derive_from_seed(
        seed: &[u8],
        address_index: u32,
    ) -> Result<(SigningKey, VerifyingKey), KeyError> {
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

        Ok((signing_key, verifying_key))
    }
}

#[cfg(all(feature = "sign", feature = "vrfy"))]
#[cfg(test)]
mod tests {
    use super::EcdsaSecp256k1;
    use bip32::secp256k1::ecdsa::{
        signature::{Signer, Verifier},
        Signature,
    };

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
        let (sk, vk) = EcdsaSecp256k1::derive_from_seed(&TEST_ECDSA_SEED_64, 0).unwrap();
        let message = b"test message";
        let signature: Signature = sk.sign(message);
        assert!(vk.verify(message, &signature).is_ok());
    }
}
