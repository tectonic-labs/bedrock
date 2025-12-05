//! This module provides a method to derive a Falcon-512 keypair from a seed and an address index using [SLIP-0010][slip-0010].
//!
//! # Key Specifications
//!
//! - **Private key**: 1281 bytes
//! - **Public key**: 897 bytes
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
//! [slip-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

use crate::falcon::{FalconScheme, FalconSigningKey, FalconVerificationKey};
use crate::hhd::keys::KeyError;
use crate::hhd::signatures::{FALCON512_KEY_GENERATION_SEED_SIZE, SignatureScheme};
use crate::hhd::slip10::{Slip10, Slip10XPrvKey};
use bip32::secp256k1::ecdsa::SigningKey;
use zeroize::Zeroize;

/// Falcon-512 keypair
#[derive(Debug, Copy, Clone)]
pub struct FnDsa512 {}

impl FnDsa512 {
    /// Generates a Falcon-512 keypair directly from a 32-byte seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed bytes (must be exactly 32 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok((FalconSigningKey, FalconVerificationKey))` - The generated keypair
    /// * `Err(KeyError)` - If seed length is invalid or key generation fails
    fn generate_keypair_from_seed(
        seed: &[u8],
    ) -> Result<(FalconSigningKey, FalconVerificationKey), KeyError> {
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

        Ok((signing_key, verifying_key))
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
    /// * `Ok((FalconSigningKey, FalconVerificationKey))` - The derived keypair
    /// * `Err(KeyError)` - If derivation fails
    pub fn derive_from_seed(
        seed: &[u8],
        address_index: u32,
    ) -> Result<(FalconSigningKey, FalconVerificationKey), KeyError> {
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
        let (signing_key, verifying_key) = Self::generate_keypair_from_seed(&private_key_bytes)?;

        // Zeroize the private key bytes
        private_key_bytes.zeroize();

        Ok((signing_key, verifying_key))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

        let keypair = FnDsa512::derive_from_seed(&TEST_FALCON_SEED_64, address_index)
            .expect("should derive Falcon keypair from seed");

        // Falcon-512 signing key should be 1281 bytes
        assert_eq!(
            keypair.0.to_raw_bytes().len(),
            SignatureScheme::Falcon512.signing_key_size(),
            "Falcon-512 signing key should be 1281 bytes"
        );

        // Falcon-512 verifying key should be 897 bytes
        assert_eq!(
            keypair.1.to_raw_bytes().len(),
            SignatureScheme::Falcon512.verifying_key_size(),
            "Falcon-512 verifying key should be 897 bytes"
        );
    }

    /// Test that Falcon keypair derivation is deterministic
    #[test]
    fn test_falcon_derive_from_seed_deterministic() {
        let address_index = 5u32;

        // Derive same keypair twice
        let keypair1 = FnDsa512::derive_from_seed(&TEST_FALCON_SEED_64, address_index)
            .expect("should derive Falcon keypair");
        let keypair2 = FnDsa512::derive_from_seed(&TEST_FALCON_SEED_64, address_index)
            .expect("should derive Falcon keypair");

        // Same seed + same address index = same keypair
        assert_eq!(
            keypair1.0.to_raw_bytes(),
            keypair2.0.to_raw_bytes(),
            "Signing keys should be identical for same seed and address index"
        );
        assert_eq!(
            keypair1.1.to_raw_bytes(),
            keypair2.1.to_raw_bytes(),
            "Verifying keys should be identical for same seed and address index"
        );
    }

    #[cfg(all(feature = "sign", feature = "vrfy"))]
    /// Tests signing and verification using the keypair methods.
    #[test]
    fn test_falcon_sign_verify() {
        let keypair = FnDsa512::derive_from_seed(&TEST_FALCON_SEED_64, 0)
            .expect("should generate Falcon keypair from seed");
        let message = b"Hello, Falcon-512!";
        let signature = FalconScheme::Dsa512.sign(message, &keypair.0).unwrap();
        assert!(
            FalconScheme::Dsa512
                .verify(message, &signature, &keypair.1)
                .is_ok()
        );
    }
}
