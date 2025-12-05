//! This module provides a method to derive a ML-DSA keypair from a seed and an address index using [SLIP-0010][slip-0010].
//!
//! # Key Specifications
//!
//! - **Private key**: 2560 bytes (ML-DSA 44), 4032 bytes (ML-DSA 65), 4896 bytes (ML-DSA 87)
//! - **Public key**: 1312 bytes (ML-DSA 44), 1952 bytes (ML-DSA 65), 2592 bytes (ML-DSA 87)
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

use crate::hhd::keys::KeyError;
use crate::hhd::signatures::{
    SignatureScheme, ML_DSA_44_KEY_GENERATION_SEED_SIZE, ML_DSA_65_KEY_GENERATION_SEED_SIZE,
    ML_DSA_87_KEY_GENERATION_SEED_SIZE,
};
use crate::hhd::slip10::{Slip10, Slip10XPrvKey};
use crate::ml_dsa::{MlDsaScheme, MlDsaSigningKey, MlDsaVerificationKey};
use bip32::secp256k1::ecdsa::SigningKey;
use zeroize::Zeroize;

macro_rules! impl_ml_dsa_struct {
    (
        $name:ident,
        $version:ident, // ML-DSA version: Dsa44, Dsa65, Dsa87
        $seed_size_const:ident,
    ) => {
        #[derive(Clone, Debug)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for ml-dsa")]
        #[repr(transparent)]
        pub struct $name;

        impl $name {
            /// Generates a ML-DSA keypair directly from a 32-byte seed.
            ///
            /// # Arguments
            ///
            /// * `seed` - The seed bytes (must be exactly 32 bytes)
            ///
            /// # Returns
            ///
            /// * `Ok((MlDsaSigningKey, MlDsaVerificationKey))` - The generated keypair
            /// * `Err(KeyError)` - If seed length is invalid or key generation fails
            fn generate_keypair_from_seed(
                seed: &[u8],
            ) -> Result<(MlDsaSigningKey, MlDsaVerificationKey), KeyError> {
                if seed.len() != $seed_size_const {
                    return Err(KeyError::InvalidSeedLength {
                        expected: $seed_size_const,
                        actual: seed.len(),
                    });
                }

                // Convert to fixed-size array
                let mut seed_array = [0u8; $seed_size_const];
                seed_array.copy_from_slice(seed);

                // Generate keypair using ml-dsa-rust
                let (verifying_key, signing_key) = MlDsaScheme::$version
                    .keypair_from_seed(&seed_array)
                    .map_err(|e| KeyError::KeyGenerationFailed(e.to_string()))?;

                // Zeroize the seed bytes
                seed_array.zeroize();

                Ok((signing_key, verifying_key))
            }

            /// Derives a ML-DSA keypair from a seed and address index using SLIP-0010.
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
            /// * `Ok((MlDsaSigningKey, MlDsaVerificationKey))` - The derived keypair
            /// * `Err(KeyError)` - If derivation fails
            pub fn derive_from_seed(
                seed: &[u8],
                address_index: u32,
            ) -> Result<(MlDsaSigningKey, MlDsaVerificationKey), KeyError> {
                // Build derivation path following BIP-44 (m/44'/60'/0'/0'/${address_index}')
                // following the full hardened derivation path convention.
                let derivation_path_str = format!(
                    "{}/{}'",
                    SignatureScheme::$name.bip44_hardened_base_path()?,
                    address_index
                );
                let derivation_path = derivation_path_str.parse()?;

                // Derive HD child seed from master child seed (SLIP-10):
                let child_xprv: Slip10XPrvKey<SigningKey> =
                    Slip10::derive_from_path(seed, &derivation_path, SignatureScheme::$name)?;
                let mut private_key_bytes = child_xprv.private_key_bytes();

                // Generate MlDsa keypair from seed
                let (signing_key, verifying_key) =
                    Self::generate_keypair_from_seed(&private_key_bytes)?;

                // Zeroize the private key bytes
                private_key_bytes.zeroize();

                Ok((signing_key, verifying_key))
            }
        }
    };
}

impl_ml_dsa_struct!(MlDsa44, Dsa44, ML_DSA_44_KEY_GENERATION_SEED_SIZE,);

impl_ml_dsa_struct!(MlDsa65, Dsa65, ML_DSA_65_KEY_GENERATION_SEED_SIZE,);

impl_ml_dsa_struct!(MlDsa87, Dsa87, ML_DSA_87_KEY_GENERATION_SEED_SIZE,);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hhd::signatures::SignatureScheme;
    use rstest::rstest;

    // Test seed
    const TEST_ML_DSA_SEED_64: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];

    /// Test that MlDsa keypair can be derived from a seed
    #[rstest]
    #[case::mldsa44(SignatureScheme::MlDsa44)]
    #[case::mldsa65(SignatureScheme::MlDsa65)]
    #[case::mldsa87(SignatureScheme::MlDsa87)]
    fn test_mldsa_derive_from_seed_basic(#[case] scheme: SignatureScheme) {
        let address_index = 0u32;

        let keypair = match scheme {
            SignatureScheme::MlDsa44 => {
                MlDsa44::derive_from_seed(&TEST_ML_DSA_SEED_64, address_index)
            }
            SignatureScheme::MlDsa65 => {
                MlDsa65::derive_from_seed(&TEST_ML_DSA_SEED_64, address_index)
            }
            SignatureScheme::MlDsa87 => {
                MlDsa87::derive_from_seed(&TEST_ML_DSA_SEED_64, address_index)
            }
            _ => panic!("Invalid scheme"),
        }
        .expect("should derive MlDsa keypair from seed");

        assert_eq!(keypair.0.to_raw_bytes().len(), scheme.signing_key_size(),);

        assert_eq!(keypair.1.to_raw_bytes().len(), scheme.verifying_key_size(),);
    }

    /// Test that MlDsa keypair derivation is deterministic
    #[rstest]
    #[case::mldsa44(SignatureScheme::MlDsa44)]
    #[case::mldsa65(SignatureScheme::MlDsa65)]
    #[case::mldsa87(SignatureScheme::MlDsa87)]
    fn test_mldsa_derive_from_seed_deterministic(#[case] scheme: SignatureScheme) {
        let address_index = 5u32;

        // Derive same keypair twice
        let (keypair1, keypair2) = match scheme {
            SignatureScheme::MlDsa44 => {
                let keypair1 = MlDsa44::derive_from_seed(&TEST_ML_DSA_SEED_64, address_index);
                let keypair2 = MlDsa44::derive_from_seed(&TEST_ML_DSA_SEED_64, address_index);
                (keypair1, keypair2)
            }
            SignatureScheme::MlDsa65 => {
                let keypair1 = MlDsa65::derive_from_seed(&TEST_ML_DSA_SEED_64, address_index);
                let keypair2 = MlDsa65::derive_from_seed(&TEST_ML_DSA_SEED_64, address_index);
                (keypair1, keypair2)
            }
            SignatureScheme::MlDsa87 => {
                let keypair1 = MlDsa87::derive_from_seed(&TEST_ML_DSA_SEED_64, address_index);
                let keypair2 = MlDsa87::derive_from_seed(&TEST_ML_DSA_SEED_64, address_index);
                (keypair1, keypair2)
            }
            _ => panic!("Invalid scheme"),
        };
        let keypair1 = keypair1.expect("should derive MlDsa keypair");
        let keypair2 = keypair2.expect("should derive MlDsa keypair");

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
    #[rstest]
    #[case::mldsa44(SignatureScheme::MlDsa44, MlDsaScheme::Dsa44)]
    #[case::mldsa65(SignatureScheme::MlDsa65, MlDsaScheme::Dsa65)]
    #[case::mldsa87(SignatureScheme::MlDsa87, MlDsaScheme::Dsa87)]
    fn test_mldsa_sign_verify(
        #[case] key_scheme: SignatureScheme,
        #[case] mldsa_scheme: MlDsaScheme,
    ) {
        let keypair = match key_scheme {
            SignatureScheme::MlDsa44 => MlDsa44::derive_from_seed(&TEST_ML_DSA_SEED_64, 0),
            SignatureScheme::MlDsa65 => MlDsa65::derive_from_seed(&TEST_ML_DSA_SEED_64, 0),
            SignatureScheme::MlDsa87 => MlDsa87::derive_from_seed(&TEST_ML_DSA_SEED_64, 0),
            _ => panic!("Invalid scheme"),
        }
        .expect("should generate MlDsa keypair from seed");
        let message = b"Hello, MlDsa!";
        let signature = mldsa_scheme.sign(message, &keypair.0).unwrap();
        assert!(mldsa_scheme.verify(message, &signature, &keypair.1).is_ok());
    }
}
