//! This module provides a method to derive a SLH-DSA keypair from a seed and an address index using [SLIP-0010][slip-0010].
//!
//! # Key Specifications
//!
//! - **128-bit (Level 1)**: 48-byte keygen seed; signing key 64 bytes, verifying key 32 bytes
//! - **192-bit (Level 3)**: 72-byte keygen seed; signing key 96 bytes, verifying key 48 bytes
//! - **256-bit (Level 5)**: 96-byte keygen seed; signing key 128 bytes, verifying key 64 bytes
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
    SignatureScheme, SLH_DSA_128_KEY_GENERATION_SEED_SIZE, SLH_DSA_192_KEY_GENERATION_SEED_SIZE,
    SLH_DSA_256_KEY_GENERATION_SEED_SIZE,
};
use crate::hhd::slip10::{Slip10, Slip10XPrvKey};
use crate::slh_dsa::{SlhDsaSigningKey, SlhDsaVerificationKey};
use bip32::secp256k1::ecdsa::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

/// Expands 32-byte SLIP-10 output to the required seed size (48, 72, or 96) using HMAC-SHA512.
/// HMAC-SHA512 yields 64 bytes; for 72 and 96 we chain a second block (HKDF-expand style).
fn expand_seed_for_slh_dsa(
    private_key_bytes: &[u8],
    domain_separator: &[u8],
    seed_size: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(seed_size);
    let mut mac =
        Hmac::<Sha512>::new_from_slice(domain_separator).expect("HMAC accepts any key size");
    mac.update(private_key_bytes);
    let mut block = mac.finalize().into_bytes();
    let take = core::cmp::min(64, seed_size);
    out.extend_from_slice(&block[..take]);
    let mut filled = take;
    let mut counter = 1u8;
    while filled < seed_size {
        let mut mac =
            Hmac::<Sha512>::new_from_slice(domain_separator).expect("HMAC accepts any key size");
        mac.update(private_key_bytes);
        mac.update(&[counter]);
        block = mac.finalize().into_bytes();
        let take = core::cmp::min(64, seed_size - filled);
        out.extend_from_slice(&block[..take]);
        filled += take;
        counter += 1;
    }
    out
}

macro_rules! impl_slh_dsa_struct {
    (
        $name:ident,
        $scheme_variant:ident,
        $seed_size_const:ident,
        $slh_dsa_scheme:expr,
    ) => {
        #[derive(Clone, Debug)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for slh-dsa")]
        #[repr(transparent)]
        pub struct $name;

        impl $name {
            /// Generates a SLH-DSA keypair directly from a seed of the scheme's keygen seed size.
            ///
            /// # Arguments
            ///
            /// * `seed` - The seed bytes (length must match scheme: 48, 72, or 96 bytes)
            ///
            /// # Returns
            ///
            /// * `Ok((SlhDsaSigningKey, SlhDsaVerificationKey))` - The generated keypair
            /// * `Err(KeyError)` - If seed length is invalid or key generation fails
            fn generate_keypair_from_seed(
                seed: &[u8],
            ) -> Result<(SlhDsaSigningKey, SlhDsaVerificationKey), KeyError> {
                if seed.len() != $seed_size_const {
                    return Err(KeyError::InvalidSeedLength {
                        expected: $seed_size_const,
                        actual: seed.len(),
                    });
                }

                let (verifying_key, signing_key) = $slh_dsa_scheme
                    .keypair_from_seed(seed)
                    .map_err(|e: crate::error::Error| {
                        KeyError::KeyGenerationFailed(e.to_string())
                    })?;

                Ok((signing_key, verifying_key))
            }

            /// Derives a SLH-DSA keypair from a seed and address index using SLIP-0010.
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
            /// * `Ok((SlhDsaSigningKey, SlhDsaVerificationKey))` - The derived keypair
            /// * `Err(KeyError)` - If derivation fails
            pub fn derive_from_seed(
                seed: &[u8],
                address_index: u32,
            ) -> Result<(SlhDsaSigningKey, SlhDsaVerificationKey), KeyError> {
                let scheme = SignatureScheme::$scheme_variant;
                let derivation_path_str =
                    format!("{}/{}'", scheme.bip44_hardened_base_path()?, address_index);
                let derivation_path = derivation_path_str.parse()?;

                let child_xprv: Slip10XPrvKey<SigningKey> =
                    Slip10::derive_from_path(seed, &derivation_path, scheme)?;
                let mut private_key_bytes = child_xprv.private_key_bytes();

                let seed_bytes: Vec<u8> = if $seed_size_const == 32 {
                    private_key_bytes.clone()
                } else {
                    expand_seed_for_slh_dsa(
                        &private_key_bytes,
                        scheme.domain_separator(),
                        $seed_size_const,
                    )
                };

                let (signing_key, verifying_key) = Self::generate_keypair_from_seed(&seed_bytes)?;

                private_key_bytes.zeroize();

                Ok((signing_key, verifying_key))
            }
        }
    };
}

impl_slh_dsa_struct!(
    SlhDsaSha2128s,
    SlhDsaSha2128s,
    SLH_DSA_128_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaSha2128s,
);
impl_slh_dsa_struct!(
    SlhDsaSha2128f,
    SlhDsaSha2128f,
    SLH_DSA_128_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaSha2128f,
);
impl_slh_dsa_struct!(
    SlhDsaShake128s,
    SlhDsaShake128s,
    SLH_DSA_128_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaShake128s,
);
impl_slh_dsa_struct!(
    SlhDsaShake128f,
    SlhDsaShake128f,
    SLH_DSA_128_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaShake128f,
);

impl_slh_dsa_struct!(
    SlhDsaSha2192s,
    SlhDsaSha2192s,
    SLH_DSA_192_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaSha2192s,
);
impl_slh_dsa_struct!(
    SlhDsaSha2192f,
    SlhDsaSha2192f,
    SLH_DSA_192_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaSha2192f,
);
impl_slh_dsa_struct!(
    SlhDsaShake192s,
    SlhDsaShake192s,
    SLH_DSA_192_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaShake192s,
);
impl_slh_dsa_struct!(
    SlhDsaShake192f,
    SlhDsaShake192f,
    SLH_DSA_192_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaShake192f,
);

impl_slh_dsa_struct!(
    SlhDsaSha2256s,
    SlhDsaSha2256s,
    SLH_DSA_256_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaSha2256s,
);
impl_slh_dsa_struct!(
    SlhDsaSha2256f,
    SlhDsaSha2256f,
    SLH_DSA_256_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaSha2256f,
);
impl_slh_dsa_struct!(
    SlhDsaShake256s,
    SlhDsaShake256s,
    SLH_DSA_256_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaShake256s,
);
impl_slh_dsa_struct!(
    SlhDsaShake256f,
    SlhDsaShake256f,
    SLH_DSA_256_KEY_GENERATION_SEED_SIZE,
    crate::slh_dsa::SlhDsaScheme::SlhDsaShake256f,
);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hhd::signatures::SignatureScheme;

    const TEST_SLH_DSA_SEED_64: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];

    #[test]
    fn test_slh_dsa_derive_from_seed_basic() {
        let cases: &[(
            SignatureScheme,
            Result<(SlhDsaSigningKey, SlhDsaVerificationKey), KeyError>,
        )] = &[
            (
                SignatureScheme::SlhDsaSha2128s,
                SlhDsaSha2128s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaSha2128f,
                SlhDsaSha2128f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaShake128s,
                SlhDsaShake128s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaShake128f,
                SlhDsaShake128f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaSha2192s,
                SlhDsaSha2192s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaSha2192f,
                SlhDsaSha2192f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaShake192s,
                SlhDsaShake192s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaShake192f,
                SlhDsaShake192f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaSha2256s,
                SlhDsaSha2256s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaSha2256f,
                SlhDsaSha2256f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaShake256s,
                SlhDsaShake256s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
            (
                SignatureScheme::SlhDsaShake256f,
                SlhDsaShake256f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            ),
        ];
        for (scheme, result) in cases {
            let keypair = result
                .as_ref()
                .expect("should derive SLH-DSA keypair from seed");
            assert_eq!(keypair.0.to_raw_bytes().len(), scheme.signing_key_size());
            assert_eq!(keypair.1.to_raw_bytes().len(), scheme.verifying_key_size());
        }
    }

    #[test]
    fn test_slh_dsa_derive_from_seed_deterministic() {
        let keypair1 =
            SlhDsaSha2128s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 5).expect("first derivation");
        let keypair2 =
            SlhDsaSha2128s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 5).expect("second derivation");
        assert_eq!(keypair1.0.to_raw_bytes(), keypair2.0.to_raw_bytes());
        assert_eq!(keypair1.1.to_raw_bytes(), keypair2.1.to_raw_bytes());

        let keypair1 =
            SlhDsaSha2256f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 3).expect("first derivation");
        let keypair2 =
            SlhDsaSha2256f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 3).expect("second derivation");
        assert_eq!(keypair1.0.to_raw_bytes(), keypair2.0.to_raw_bytes());
        assert_eq!(keypair1.1.to_raw_bytes(), keypair2.1.to_raw_bytes());
    }

    #[cfg(all(feature = "sign", feature = "vrfy"))]
    #[test]
    fn test_slh_dsa_sign_verify() {
        for keypair_result in [
            SlhDsaSha2128s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
            SlhDsaSha2256f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0),
        ] {
            let keypair = keypair_result.expect("should derive keypair");
            let message = b"Hello, SLH-DSA!";
            let scheme = keypair.0.scheme();
            let signature = scheme.sign(message, &keypair.0).unwrap();
            assert!(scheme.verify(message, &signature, &keypair.1).is_ok());
        }
    }
}
