//! This module provides a method to derive a MAYO-2 keypair from a seed and an address index using [SLIP-0010][slip-0010].
//!
//! # Key Specifications
//!
//! - **Private key**: 24 bytes (the compact MAYO-2 secret-key seed)
//! - **Public key**: 4368 bytes
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
//! # Seed Truncation
//!
//! A SLIP-0010 child key is 32 bytes, while MAYO keygen seed sizes are 24 bytes
//! (MAYO-1/2), 32 bytes (MAYO-3), and 40 bytes (MAYO-5). The derivation rule for
//! the MAYO family is:
//!
//! - **MAYO-1/2**: truncate the 32-byte SLIP-0010 child key to its first 24 bytes.
//!   SLIP-0010 output is computationally indistinguishable from uniform, so any
//!   24-byte prefix is itself uniform and truncation preserves the full 192-bit
//!   seed security targeted by MAYO-1/2.
//! - **MAYO-3**: use all 32 bytes directly.
//! - **MAYO-5**: not supported in HHD (its 40-byte seed cannot be sourced from a
//!   32-byte SLIP-0010 child key).
//!
//! Only MAYO-2 is currently implemented.
//!
//! [slip-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

use crate::hhd::keys::KeyError;
use crate::hhd::signatures::{SignatureScheme, MAYO_2_KEY_GENERATION_SEED_SIZE};
use crate::hhd::slip10::{Slip10, Slip10XPrvKey};
use crate::mayo::{MayoScheme, MayoSigningKey, MayoVerificationKey};
use bip32::secp256k1::ecdsa::SigningKey;
use zeroize::Zeroize;

/// MAYO-2 keypair derivation.
#[derive(Debug, Copy, Clone)]
pub struct Mayo2;

impl Mayo2 {
    /// Generates a MAYO-2 keypair directly from a 24-byte seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed bytes (must be exactly 24 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok((MayoSigningKey, MayoVerificationKey))` - The generated keypair
    /// * `Err(KeyError)` - If seed length is invalid or key generation fails
    fn generate_keypair_from_seed(
        seed: &[u8],
    ) -> Result<(MayoSigningKey, MayoVerificationKey), KeyError> {
        if seed.len() != MAYO_2_KEY_GENERATION_SEED_SIZE {
            return Err(KeyError::InvalidSeedLength {
                expected: MAYO_2_KEY_GENERATION_SEED_SIZE,
                actual: seed.len(),
            });
        }

        // Convert to fixed-size array
        let mut seed_array = [0u8; MAYO_2_KEY_GENERATION_SEED_SIZE];
        seed_array.copy_from_slice(seed);

        // Generate keypair using pq-mayo
        let (verifying_key, signing_key) = MayoScheme::Mayo2
            .keypair_from_seed(&seed_array)
            .map_err(|e| KeyError::KeyGenerationFailed(e.to_string()))?;

        // Zeroize the seed bytes
        seed_array.zeroize();

        Ok((signing_key, verifying_key))
    }

    /// Derives a MAYO-2 keypair from a seed and address index using SLIP-0010.
    ///
    /// Uses the BIP-44 hardened derivation path: `m/44'/60'/0'/0'/{address_index}'`
    ///
    /// The 32-byte SLIP-0010 child key is truncated to its first 24 bytes to match
    /// the MAYO-2 keygen seed size. SLIP-0010 output is uniform, so truncation
    /// preserves the 192-bit seed security targeted by MAYO-2.
    ///
    /// # Arguments
    ///
    /// * `seed` - The master seed bytes (typically 64 bytes)
    /// * `address_index` - The address index for derivation (hardened)
    ///
    /// # Returns
    ///
    /// * `Ok((MayoSigningKey, MayoVerificationKey))` - The derived keypair
    /// * `Err(KeyError)` - If derivation fails
    pub fn derive_from_seed(
        seed: &[u8],
        address_index: u32,
    ) -> Result<(MayoSigningKey, MayoVerificationKey), KeyError> {
        // Build derivation path following BIP-44 (m/44'/60'/0'/0'/${address_index}')
        // following the full hardened derivation path convention.
        let derivation_path_str = format!(
            "{}/{}'",
            SignatureScheme::Mayo2.bip44_hardened_base_path()?,
            address_index
        );
        let derivation_path = derivation_path_str.parse()?;

        // Derive HD child seed from master child seed (SLIP-10):
        let child_xprv: Slip10XPrvKey<SigningKey> =
            Slip10::derive_from_path(seed, &derivation_path, SignatureScheme::Mayo2)?;
        let mut private_key_bytes = child_xprv.private_key_bytes();

        // Generate MAYO-2 keypair from the truncated 24-byte seed
        let (signing_key, verifying_key) = Self::generate_keypair_from_seed(
            &private_key_bytes[..MAYO_2_KEY_GENERATION_SEED_SIZE],
        )?;

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
    use bip32::DerivationPath;

    // Test seed
    const TEST_MAYO_SEED_64: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];

    /// Test that a MAYO-2 keypair can be derived from a seed
    #[test]
    fn test_mayo2_derive_from_seed_basic() {
        let (sk, vk) = Mayo2::derive_from_seed(&TEST_MAYO_SEED_64, 0)
            .expect("should derive MAYO-2 keypair from seed");

        assert_eq!(
            sk.to_raw_bytes().len(),
            SignatureScheme::Mayo2.signing_key_size()
        );
        assert_eq!(
            vk.to_raw_bytes().len(),
            SignatureScheme::Mayo2.verifying_key_size()
        );
    }

    /// Test that MAYO-2 keypair derivation is deterministic
    #[test]
    fn test_mayo2_derive_from_seed_deterministic() {
        let address_index = 5u32;

        let (sk1, vk1) = Mayo2::derive_from_seed(&TEST_MAYO_SEED_64, address_index)
            .expect("should derive MAYO-2 keypair");
        let (sk2, vk2) = Mayo2::derive_from_seed(&TEST_MAYO_SEED_64, address_index)
            .expect("should derive MAYO-2 keypair");

        // Same seed + same address index = same keypair
        assert_eq!(
            sk1.to_raw_bytes(),
            sk2.to_raw_bytes(),
            "Signing keys should be identical for same seed and address index"
        );
        assert_eq!(
            vk1.to_raw_bytes(),
            vk2.to_raw_bytes(),
            "Verifying keys should be identical for same seed and address index"
        );
    }

    /// Test that the derived keypair equals a direct keygen from the truncated
    /// 24-byte prefix of the SLIP-0010 child key.
    #[test]
    fn test_mayo2_truncation_rule() {
        let address_index = 3u32;

        // Derive via the HHD path
        let (sk, vk) = Mayo2::derive_from_seed(&TEST_MAYO_SEED_64, address_index)
            .expect("should derive MAYO-2 keypair");

        // Derive the SLIP-0010 child key directly and truncate manually
        let derivation_path: DerivationPath = format!(
            "{}/{}'",
            SignatureScheme::Mayo2.bip44_hardened_base_path().unwrap(),
            address_index
        )
        .parse()
        .unwrap();
        let child_xprv: Slip10XPrvKey<SigningKey> =
            Slip10::derive_from_path(&TEST_MAYO_SEED_64, &derivation_path, SignatureScheme::Mayo2)
                .unwrap();
        let child_key = child_xprv.private_key_bytes();
        assert_eq!(
            child_key.len(),
            32,
            "SLIP-0010 child key should be 32 bytes"
        );

        let (expected_vk, expected_sk) = MayoScheme::Mayo2
            .keypair_from_seed(&child_key[..MAYO_2_KEY_GENERATION_SEED_SIZE])
            .unwrap();

        assert_eq!(sk.to_raw_bytes(), expected_sk.to_raw_bytes());
        assert_eq!(vk.to_raw_bytes(), expected_vk.to_raw_bytes());
    }

    #[cfg(all(feature = "sign", feature = "vrfy"))]
    /// Tests signing and verification using the derived keypair.
    #[test]
    fn test_mayo2_sign_verify() {
        let (sk, vk) = Mayo2::derive_from_seed(&TEST_MAYO_SEED_64, 0)
            .expect("should derive MAYO-2 keypair from seed");
        let message = b"Hello, MAYO!";
        let signature = MayoScheme::Mayo2.sign(message, &sk).unwrap();
        assert!(MayoScheme::Mayo2.verify(message, &signature, &vk).is_ok());
    }
}
