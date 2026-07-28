//! This module provides methods to derive MAYO keypairs from a seed and an address index using [SLIP-0010][slip-0010].
//!
//! # Key Specifications
//!
//! - **Private key** (compact secret-key seed): 24 bytes (MAYO-1/2), 32 bytes (MAYO-3)
//! - **Public key**: 1420 bytes (MAYO-1), 4368 bytes (MAYO-2), 2986 bytes (MAYO-3)
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
//! # Seed Truncation (strip-only)
//!
//! A SLIP-0010 child key is always 32 bytes, while MAYO keygen seed sizes are 24 bytes
//! (MAYO-1/2), 32 bytes (MAYO-3), and 40 bytes (MAYO-5). The derivation rule for the MAYO
//! family only strips bits, never expands them:
//!
//! - **MAYO-1/2**: truncate the 32-byte SLIP-0010 child key to its first 24 bytes.
//!   SLIP-0010 output is computationally indistinguishable from uniform, so any 24-byte
//!   prefix is itself uniform and truncation preserves the full 192-bit seed security
//!   targeted by MAYO-1/2.
//! - **MAYO-3**: use all 32 bytes directly.
//! - **MAYO-5**: deliberately not supported in HHD (its 40-byte seed cannot be sourced
//!   from a 32-byte SLIP-0010 child key without expansion).
//!
//! [slip-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

use crate::hhd::keys::KeyError;
use crate::hhd::signatures::{
    SignatureScheme, MAYO_1_KEY_GENERATION_SEED_SIZE, MAYO_2_KEY_GENERATION_SEED_SIZE,
    MAYO_3_KEY_GENERATION_SEED_SIZE,
};
use crate::hhd::slip10::{Slip10, Slip10XPrvKey};
use crate::mayo::{MayoScheme, MayoSigningKey, MayoVerificationKey};
use bip32::secp256k1::ecdsa::SigningKey;
use zeroize::Zeroize;

macro_rules! impl_mayo_struct {
    (
        $name:ident,
        $scheme:ident, // SignatureScheme variant: Mayo1, Mayo2, Mayo3
        $version:ident, // MayoScheme variant: Mayo1, Mayo2, Mayo3
        $seed_size_const:ident,
    ) => {
        #[derive(Clone, Debug)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for mayo")]
        #[repr(transparent)]
        pub struct $name;

        impl $name {
            /// Generates a MAYO keypair directly from a seed of exactly the scheme's
            /// keygen seed size (24 bytes for MAYO-1/2, 32 bytes for MAYO-3).
            ///
            /// # Arguments
            ///
            /// * `seed` - The seed bytes (must be exactly the scheme's keygen seed size)
            ///
            /// # Returns
            ///
            /// * `Ok((MayoSigningKey, MayoVerificationKey))` - The generated keypair
            /// * `Err(KeyError)` - If seed length is invalid or key generation fails
            fn generate_keypair_from_seed(
                seed: &[u8],
            ) -> Result<(MayoSigningKey, MayoVerificationKey), KeyError> {
                if seed.len() != $seed_size_const {
                    return Err(KeyError::InvalidSeedLength {
                        expected: $seed_size_const,
                        actual: seed.len(),
                    });
                }

                // Convert to fixed-size array
                let mut seed_array = [0u8; $seed_size_const];
                seed_array.copy_from_slice(seed);

                // Generate keypair using pq-mayo
                let (verifying_key, signing_key) = MayoScheme::$version
                    .keypair_from_seed(&seed_array)
                    .map_err(|e| KeyError::KeyGenerationFailed(e.to_string()))?;

                // Zeroize the seed bytes
                seed_array.zeroize();

                Ok((signing_key, verifying_key))
            }

            /// Derives a MAYO keypair from a seed and address index using SLIP-0010.
            ///
            /// Uses the BIP-44 hardened derivation path: `m/44'/60'/0'/0'/{address_index}'`
            ///
            /// The 32-byte SLIP-0010 child key is truncated to the scheme's keygen seed
            /// size (its first 24 bytes for MAYO-1/2, all 32 bytes for MAYO-3). SLIP-0010
            /// output is uniform, so truncation preserves the seed security targeted by
            /// the parameter set. HHD derivation only strips bits and never expands them.
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
                    SignatureScheme::$scheme.bip44_hardened_base_path()?,
                    address_index
                );
                let derivation_path = derivation_path_str.parse()?;

                // Derive HD child seed from master child seed (SLIP-10):
                let child_xprv: Slip10XPrvKey<SigningKey> =
                    Slip10::derive_from_path(seed, &derivation_path, SignatureScheme::$scheme)?;
                let mut private_key_bytes = child_xprv.private_key_bytes();

                // Generate MAYO keypair from the (possibly truncated) seed
                let (signing_key, verifying_key) =
                    Self::generate_keypair_from_seed(&private_key_bytes[..$seed_size_const])?;

                // Zeroize the private key bytes
                private_key_bytes.zeroize();

                Ok((signing_key, verifying_key))
            }
        }
    };
}

impl_mayo_struct!(Mayo1, Mayo1, Mayo1, MAYO_1_KEY_GENERATION_SEED_SIZE,);

impl_mayo_struct!(Mayo2, Mayo2, Mayo2, MAYO_2_KEY_GENERATION_SEED_SIZE,);

impl_mayo_struct!(Mayo3, Mayo3, Mayo3, MAYO_3_KEY_GENERATION_SEED_SIZE,);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hhd::signatures::SignatureScheme;
    use bip32::DerivationPath;
    use rstest::rstest;

    // Test seed
    const TEST_MAYO_SEED_64: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];

    fn derive(scheme: SignatureScheme, index: u32) -> (MayoSigningKey, MayoVerificationKey) {
        match scheme {
            SignatureScheme::Mayo1 => Mayo1::derive_from_seed(&TEST_MAYO_SEED_64, index),
            SignatureScheme::Mayo2 => Mayo2::derive_from_seed(&TEST_MAYO_SEED_64, index),
            SignatureScheme::Mayo3 => Mayo3::derive_from_seed(&TEST_MAYO_SEED_64, index),
            _ => panic!("Invalid scheme"),
        }
        .expect("should derive MAYO keypair from seed")
    }

    /// Test that a MAYO keypair can be derived from a seed
    #[rstest]
    #[case::mayo1(SignatureScheme::Mayo1)]
    #[case::mayo2(SignatureScheme::Mayo2)]
    #[case::mayo3(SignatureScheme::Mayo3)]
    fn test_mayo_derive_from_seed_basic(#[case] scheme: SignatureScheme) {
        let (sk, vk) = derive(scheme, 0);
        assert_eq!(sk.to_raw_bytes().len(), scheme.signing_key_size());
        assert_eq!(vk.to_raw_bytes().len(), scheme.verifying_key_size());
    }

    /// Test that MAYO keypair derivation is deterministic
    #[rstest]
    #[case::mayo1(SignatureScheme::Mayo1)]
    #[case::mayo2(SignatureScheme::Mayo2)]
    #[case::mayo3(SignatureScheme::Mayo3)]
    fn test_mayo_derive_from_seed_deterministic(#[case] scheme: SignatureScheme) {
        let (sk1, vk1) = derive(scheme, 5);
        let (sk2, vk2) = derive(scheme, 5);
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

    /// Test that the derived keypair equals a direct keygen from the (possibly truncated)
    /// prefix of the SLIP-0010 child key.
    #[rstest]
    #[case::mayo1(
        SignatureScheme::Mayo1,
        MayoScheme::Mayo1,
        MAYO_1_KEY_GENERATION_SEED_SIZE
    )]
    #[case::mayo2(
        SignatureScheme::Mayo2,
        MayoScheme::Mayo2,
        MAYO_2_KEY_GENERATION_SEED_SIZE
    )]
    #[case::mayo3(
        SignatureScheme::Mayo3,
        MayoScheme::Mayo3,
        MAYO_3_KEY_GENERATION_SEED_SIZE
    )]
    fn test_mayo_truncation_rule(
        #[case] scheme: SignatureScheme,
        #[case] mayo_scheme: MayoScheme,
        #[case] seed_size: usize,
    ) {
        let address_index = 3u32;
        let (sk, vk) = derive(scheme, address_index);

        // Derive the SLIP-0010 child key directly and truncate manually
        let derivation_path: DerivationPath = format!(
            "{}/{}'",
            scheme.bip44_hardened_base_path().unwrap(),
            address_index
        )
        .parse()
        .unwrap();
        let child_xprv: Slip10XPrvKey<SigningKey> =
            Slip10::derive_from_path(TEST_MAYO_SEED_64, &derivation_path, scheme).unwrap();
        let child_key = child_xprv.private_key_bytes();
        assert_eq!(
            child_key.len(),
            32,
            "SLIP-0010 child key should be 32 bytes"
        );

        let (expected_vk, expected_sk) = mayo_scheme
            .keypair_from_seed(&child_key[..seed_size])
            .unwrap();

        assert_eq!(sk.to_raw_bytes(), expected_sk.to_raw_bytes());
        assert_eq!(vk.to_raw_bytes(), expected_vk.to_raw_bytes());
    }

    #[cfg(all(feature = "sign", feature = "vrfy"))]
    /// Tests signing and verification using the derived keypair.
    #[rstest]
    #[case::mayo1(SignatureScheme::Mayo1, MayoScheme::Mayo1)]
    #[case::mayo2(SignatureScheme::Mayo2, MayoScheme::Mayo2)]
    #[case::mayo3(SignatureScheme::Mayo3, MayoScheme::Mayo3)]
    fn test_mayo_sign_verify(#[case] key_scheme: SignatureScheme, #[case] mayo_scheme: MayoScheme) {
        let (sk, vk) = derive(key_scheme, 0);
        let message = b"Hello, MAYO!";
        let signature = mayo_scheme.sign(message, &sk).unwrap();
        assert!(mayo_scheme.verify(message, &signature, &vk).is_ok());
    }
}
