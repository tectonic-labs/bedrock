//! This module provides a method to derive SLH-DSA keypairs from a seed and an address index using [SLIP-0010][slip-0010].
//!
//! SLH-DSA-SHAKE-128f/128s require a 48-byte seed for key generation, while SLIP-0010
//! produces 32-byte derived keys. To bridge this, the 32-byte SLIP-0010 key is expanded
//! to 48 bytes using HMAC-SHA512 with a scheme-specific domain separator, then truncated.
//!
//! # Key Specifications
//!
//! - **Private key**: 64 bytes (both 128f and 128s)
//! - **Public key**: 32 bytes (both 128f and 128s)
//! - **Signature**: 17,088 bytes (128f), 7,856 bytes (128s)
//!
//! # Derivation Path
//!
//! Uses BIP-44 hardened derivation path: `m/44'/60'/0'/0'/{address_index}'`
//!
//! [slip-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

use crate::hhd::keys::KeyError;
use crate::hhd::signatures::{SignatureScheme, SLH_DSA_SHAKE_128_KEY_GENERATION_SEED_SIZE};
use crate::hhd::slip10::{Slip10, Slip10XPrvKey};
use crate::slh_dsa::{SlhDsaScheme, SlhDsaSigningKey, SlhDsaVerificationKey};
use bip32::secp256k1::ecdsa::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

macro_rules! impl_slh_dsa_key_struct {
    (
        $name:ident,
        $scheme_variant:ident,
        $sig_scheme:expr,
        $expansion_domain:expr,
    ) => {
        #[derive(Clone, Debug)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("Key derivation for [`", stringify!($name), "`]")]
        #[repr(transparent)]
        pub struct $name;

        impl $name {
            /// Generates an SLH-DSA keypair from a 32-byte SLIP-10 derived key.
            ///
            /// Expands the 32-byte key to 48 bytes using HMAC-SHA512 with a
            /// scheme-specific domain separator, then uses the first 48 bytes
            /// as the SLH-DSA key generation seed.
            fn generate_keypair_from_seed(
                seed: &[u8],
            ) -> Result<(SlhDsaSigningKey, SlhDsaVerificationKey), KeyError> {
                // Expand 32-byte SLIP-10 key to 48 bytes for SLH-DSA
                let mut hmac = HmacSha512::new_from_slice($expansion_domain)
                    .map_err(|e| KeyError::KeyGenerationFailed(e.to_string()))?;
                hmac.update(seed);
                let expanded = hmac.finalize().into_bytes();

                let mut seed_array = [0u8; SLH_DSA_SHAKE_128_KEY_GENERATION_SEED_SIZE];
                seed_array.copy_from_slice(&expanded[..SLH_DSA_SHAKE_128_KEY_GENERATION_SEED_SIZE]);

                let (verifying_key, signing_key) = SlhDsaScheme::$scheme_variant
                    .keypair_from_seed(&seed_array)
                    .map_err(|e| KeyError::KeyGenerationFailed(e.to_string()))?;

                seed_array.zeroize();

                Ok((signing_key, verifying_key))
            }

            /// Derives an SLH-DSA keypair from a seed and address index using SLIP-0010.
            ///
            /// Uses the BIP-44 hardened derivation path: `m/44'/60'/0'/0'/{address_index}'`
            pub fn derive_from_seed(
                seed: &[u8],
                address_index: u32,
            ) -> Result<(SlhDsaSigningKey, SlhDsaVerificationKey), KeyError> {
                let derivation_path_str = format!(
                    "{}/{}'",
                    $sig_scheme.bip44_hardened_base_path()?,
                    address_index
                );
                let derivation_path = derivation_path_str.parse()?;

                let child_xprv: Slip10XPrvKey<SigningKey> =
                    Slip10::derive_from_path(seed, &derivation_path, $sig_scheme)?;
                let mut private_key_bytes = child_xprv.private_key_bytes();

                let (signing_key, verifying_key) =
                    Self::generate_keypair_from_seed(&private_key_bytes)?;

                private_key_bytes.zeroize();

                Ok((signing_key, verifying_key))
            }
        }
    };
}

impl_slh_dsa_key_struct!(
    SlhDsaShake128f,
    SlhDsaShake128f,
    SignatureScheme::SlhDsaShake128f,
    b"SLH-DSA-SHAKE-128f key expansion",
);

impl_slh_dsa_key_struct!(
    SlhDsaShake128s,
    SlhDsaShake128s,
    SignatureScheme::SlhDsaShake128s,
    b"SLH-DSA-SHAKE-128s key expansion",
);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hhd::signatures::SignatureScheme;
    use rstest::rstest;

    const TEST_SLH_DSA_SEED_64: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];

    #[rstest]
    #[case::shake128f(SignatureScheme::SlhDsaShake128f)]
    #[case::shake128s(SignatureScheme::SlhDsaShake128s)]
    fn test_slhdsa_derive_from_seed_basic(#[case] scheme: SignatureScheme) {
        let address_index = 0u32;

        let keypair = match scheme {
            SignatureScheme::SlhDsaShake128f => {
                SlhDsaShake128f::derive_from_seed(&TEST_SLH_DSA_SEED_64, address_index)
            }
            SignatureScheme::SlhDsaShake128s => {
                SlhDsaShake128s::derive_from_seed(&TEST_SLH_DSA_SEED_64, address_index)
            }
            _ => panic!("Invalid scheme"),
        }
        .expect("should derive SLH-DSA keypair from seed");

        assert_eq!(keypair.0.to_raw_bytes().len(), scheme.signing_key_size());
        assert_eq!(keypair.1.to_raw_bytes().len(), scheme.verifying_key_size());
    }

    #[rstest]
    #[case::shake128f(SignatureScheme::SlhDsaShake128f)]
    #[case::shake128s(SignatureScheme::SlhDsaShake128s)]
    fn test_slhdsa_derive_from_seed_deterministic(#[case] scheme: SignatureScheme) {
        let address_index = 5u32;

        let (keypair1, keypair2) = match scheme {
            SignatureScheme::SlhDsaShake128f => {
                let kp1 = SlhDsaShake128f::derive_from_seed(&TEST_SLH_DSA_SEED_64, address_index);
                let kp2 = SlhDsaShake128f::derive_from_seed(&TEST_SLH_DSA_SEED_64, address_index);
                (kp1, kp2)
            }
            SignatureScheme::SlhDsaShake128s => {
                let kp1 = SlhDsaShake128s::derive_from_seed(&TEST_SLH_DSA_SEED_64, address_index);
                let kp2 = SlhDsaShake128s::derive_from_seed(&TEST_SLH_DSA_SEED_64, address_index);
                (kp1, kp2)
            }
            _ => panic!("Invalid scheme"),
        };
        let keypair1 = keypair1.expect("should derive SLH-DSA keypair");
        let keypair2 = keypair2.expect("should derive SLH-DSA keypair");

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
    #[rstest]
    #[case::shake128f(SignatureScheme::SlhDsaShake128f, SlhDsaScheme::SlhDsaShake128f)]
    #[case::shake128s(SignatureScheme::SlhDsaShake128s, SlhDsaScheme::SlhDsaShake128s)]
    fn test_slhdsa_sign_verify(
        #[case] key_scheme: SignatureScheme,
        #[case] slhdsa_scheme: SlhDsaScheme,
    ) {
        let keypair = match key_scheme {
            SignatureScheme::SlhDsaShake128f => {
                SlhDsaShake128f::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0)
            }
            SignatureScheme::SlhDsaShake128s => {
                SlhDsaShake128s::derive_from_seed(&TEST_SLH_DSA_SEED_64, 0)
            }
            _ => panic!("Invalid scheme"),
        }
        .expect("should generate SLH-DSA keypair from seed");
        let message = b"Hello, SLH-DSA!";
        let signature = slhdsa_scheme.sign(message, &keypair.0).unwrap();
        assert!(slhdsa_scheme
            .verify(message, &signature, &keypair.1)
            .is_ok());
    }
}
