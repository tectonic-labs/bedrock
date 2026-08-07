//! BIP-85 implementation for deriving child seeds from a mnemonic.
//!
//! This module derives scheme-specific seeds from one BIP-39 mnemonic using the
//! [BIP-85][bip-85] standard. BIP-85 deterministically derives multiple entropy sources
//! from one master seed, allowing signature schemes and HHD-enabled KEMs to use separate
//! seeds in the same wallet.
//!
//! # Features
//!
//! - Derives scheme-specific seeds from one mnemonic.
//! - Supports ECDSA secp256k1, Falcon-512, ML-DSA, MAYO, and HQC.
//!
//! # Derivation Process
//!
//! The BIP-85 derivation process follows these steps:
//!
//! 1. **Master seed**: Convert the BIP-39 mnemonic to a master seed using PBKDF2.
//! 2. **Derivation path**: Derive an extended private key (XPrv) using a scheme-specific
//!    path.
//!    - Base path: `m/83696968'/83286642'`
//!    - Scheme-specific suffix: `1'` for ECDSA, `2'` for Falcon-512, `4'`–`9'` for
//!      ML-DSA and MAYO, and `10'`–`12'` for HQC.
//! 3. **Entropy extraction**: Extract entropy using HMAC-SHA-512 with the key-info string.
//!    - Key info: `"bip-entropy-from-k"`
//! 4. **Child seed**: Return a 64-byte scheme-specific seed.
//!
//! # Example
//!
//! ```no_run
//! use tectonic_bedrock::hhd::Bip85;
//! use tectonic_bedrock::hhd::Mnemonic;
//! use tectonic_bedrock::hhd::SignatureScheme;
//!
//! let mnemonic = Mnemonic::from_phrase("abandon abandon abandon...").unwrap();
//! let ecdsa_seed = Bip85::derive_seed_from_mnemonic(
//!     mnemonic.clone(),
//!     SignatureScheme::EcdsaSecp256k1,
//!     None,
//! ).unwrap();
//! ```
//!
//! [bip-85]: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki

use crate::hhd::mnemonic::{Mnemonic, MnemonicError};
use crate::hhd::signatures::{SignatureScheme, SignatureSchemeError, SignatureSeed};
#[cfg(feature = "hqc")]
use crate::{
    hhd::kems::{self, HhdKemSchemeError, KemSeed},
    kem::KemScheme,
};
use bip32::{DerivationPath, Seed, XPrv};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

/// HMAC-SHA-512 type alias for BIP-85 entropy extraction.
type HmacSha512 = Hmac<Sha512>;

/// Base derivation path for BIP-85 child seed derivation.
///
/// This path (`m/83696968'/83286642'`) is the standard BIP-85 base path used
/// for deriving child seeds from a master mnemonic.
const BIP85_BASE_PATH: &str = "m/83696968'/83286642'";

/// Key-info string used for HMAC-SHA-512 in BIP-85 entropy extraction.
///
/// This constant string `"bip-entropy-from-k"` is used as the HMAC key when
/// extracting entropy from a derived private key according to BIP-85.
const BIP85_KEY_INFO: &str = "bip-entropy-from-k";

/// BIP-85 implementation for deriving child seeds from a mnemonic.
///
/// This struct provides static methods for BIP-85 seed derivation.
/// It derives scheme-specific seeds from a single BIP-39 mnemonic, allowing multiple
/// schemes to share a master seed while maintaining cryptographic separation.
///
/// # Derivation Paths
///
/// Each supported scheme gets a unique derivation path:
///
/// - **ECDSA secp256k1**: `m/83696968'/83286642'/1'`.
/// - **Falcon-512**: `m/83696968'/83286642'/2'`.
/// - **ML-DSA-44/65/87**: Suffixes `4'`, `5'`, and `6'`.
/// - **MAYO-1/2/3**: Suffixes `7'`, `8'`, and `9'`.
/// - **HQC-128/192/256**: Suffixes `10'`, `11'`, and `12'`.
///
/// This ensures that different schemes produce different seeds from the same
/// mnemonic, providing cryptographic seed separation between schemes.
#[derive(Clone, Copy, Debug)]
pub struct Bip85;

impl Bip85 {
    /// Converts a signature scheme to its BIP-85 child index number.
    ///
    /// Each signature scheme is assigned a unique index for BIP-85 derivation:
    ///
    /// - ECDSA secp256k1: `1`
    /// - Falcon-512: `2`
    /// - ML-DSA 44: `4`
    /// - ML-DSA 65: `5`
    /// - ML-DSA 87: `6`
    /// - MAYO-1: `7`
    /// - MAYO-2: `8`
    /// - MAYO-3: `9`
    ///
    /// Index 3 is reserved for future analysis.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The signature scheme to get the index for
    ///
    /// # Returns
    ///
    /// The child index as a `u32` value.
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::Bip85;
    /// use tectonic_bedrock::hhd::SignatureScheme;
    ///
    /// assert_eq!(Bip85::child_index_from_scheme(SignatureScheme::EcdsaSecp256k1), 1);
    /// assert_eq!(Bip85::child_index_from_scheme(SignatureScheme::Falcon512), 2);
    /// assert_eq!(Bip85::child_index_from_scheme(SignatureScheme::MlDsa65), 5);
    /// assert_eq!(Bip85::child_index_from_scheme(SignatureScheme::MlDsa87), 6);
    /// ```
    pub fn child_index_from_scheme(scheme: SignatureScheme) -> u32 {
        match scheme {
            SignatureScheme::EcdsaSecp256k1 => 1,
            SignatureScheme::Falcon512 => 2,
            SignatureScheme::MlDsa44 => 4,
            SignatureScheme::MlDsa65 => 5,
            SignatureScheme::MlDsa87 => 6,
            SignatureScheme::Mayo1 => 7,
            SignatureScheme::Mayo2 => 8,
            SignatureScheme::Mayo3 => 9,
        }
    }

    /// Converts an HHD-enabled KEM to its BIP-85 child index.
    ///
    /// HQC-128, HQC-192, and HQC-256 use indices `10`, `11`, and `12`
    /// respectively. These indices do not overlap any signature branch.
    #[cfg(feature = "hqc")]
    pub(crate) fn child_index_from_kem_scheme(scheme: KemScheme) -> Result<u32, HhdKemSchemeError> {
        if scheme == KemScheme::Hqc128 {
            Ok(10)
        } else if scheme == KemScheme::Hqc192 {
            Ok(11)
        } else if scheme == KemScheme::Hqc256 {
            Ok(12)
        } else {
            Err(HhdKemSchemeError::UnsupportedScheme(scheme))
        }
    }

    /// Gets the BIP-85 child path suffix for the given signature scheme.
    ///
    /// Returns a hardened path suffix (for example, `"1'"`) that is appended
    /// to the base BIP-85 path to create the scheme-specific derivation path.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The signature scheme to get the path suffix for
    ///
    /// # Returns
    ///
    /// A hardened path suffix as a `String` (for example, `"1'"` for ECDSA or `"2'"`
    /// for Falcon-512).
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::Bip85;
    /// use tectonic_bedrock::hhd::SignatureScheme;
    ///
    /// assert_eq!(Bip85::child_path_from_scheme(SignatureScheme::EcdsaSecp256k1), "1'");
    /// assert_eq!(Bip85::child_path_from_scheme(SignatureScheme::Falcon512), "2'");
    /// assert_eq!(Bip85::child_path_from_scheme(SignatureScheme::MlDsa65), "5'");
    /// assert_eq!(Bip85::child_path_from_scheme(SignatureScheme::MlDsa87), "6'");
    /// ```
    pub fn child_path_from_scheme(scheme: SignatureScheme) -> String {
        format!("{}'", Bip85::child_index_from_scheme(scheme))
    }

    /// Gets the hardened BIP-85 child path suffix for an HHD-enabled KEM.
    #[cfg(feature = "hqc")]
    pub(crate) fn child_path_from_kem_scheme(
        scheme: KemScheme,
    ) -> Result<String, HhdKemSchemeError> {
        Ok(format!("{}'", Bip85::child_index_from_kem_scheme(scheme)?))
    }

    /// Builds the full BIP-85 derivation path for the given signature scheme.
    ///
    /// Combines the base BIP-85 path (`m/83696968'/83286642'`) with the
    /// scheme-specific child index to form the complete derivation path.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The signature scheme to get the derivation path for
    ///
    /// # Returns
    ///
    /// The full BIP-85 derivation path as a `String`.
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::Bip85;
    /// use tectonic_bedrock::hhd::SignatureScheme;
    ///
    /// assert_eq!(
    ///     Bip85::derivation_path_from_scheme(SignatureScheme::EcdsaSecp256k1),
    ///     "m/83696968'/83286642'/1'"
    /// );
    /// assert_eq!(
    ///     Bip85::derivation_path_from_scheme(SignatureScheme::Falcon512),
    ///     "m/83696968'/83286642'/2'"
    /// );
    /// assert_eq!(
    ///     Bip85::derivation_path_from_scheme(SignatureScheme::MlDsa65),
    ///     "m/83696968'/83286642'/5'"
    /// );
    /// assert_eq!(
    ///     Bip85::derivation_path_from_scheme(SignatureScheme::MlDsa87),
    ///     "m/83696968'/83286642'/6'"
    /// );
    /// ```
    pub fn derivation_path_from_scheme(scheme: SignatureScheme) -> String {
        format!(
            "{}/{}",
            BIP85_BASE_PATH,
            Bip85::child_path_from_scheme(scheme)
        )
    }

    /// Builds the full BIP-85 derivation path for an HHD-enabled KEM.
    #[cfg(feature = "hqc")]
    pub(crate) fn derivation_path_from_kem_scheme(
        scheme: KemScheme,
    ) -> Result<String, HhdKemSchemeError> {
        Ok(format!(
            "{}/{}",
            BIP85_BASE_PATH,
            Bip85::child_path_from_kem_scheme(scheme)?
        ))
    }

    /// Parses the full BIP-85 derivation path into a `DerivationPath`.
    ///
    /// This method converts the string representation of the derivation path
    /// into a `DerivationPath` type that can be used for BIP-32 key derivation.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The signature scheme to get the parsed derivation path for
    ///
    /// # Returns
    ///
    /// * `Ok(DerivationPath)` - The parsed derivation path
    /// * `Err(SignatureSchemeError)` - If the path cannot be parsed
    ///
    /// # Errors
    ///
    /// Returns `SignatureSchemeError::InvalidDerivationPath` if the path
    /// string cannot be parsed into a valid derivation path.
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::Bip85;
    /// use tectonic_bedrock::hhd::SignatureScheme;
    ///
    /// let path = Bip85::derivation_path_from_scheme_parsed(
    ///     SignatureScheme::EcdsaSecp256k1
    /// ).unwrap();
    /// assert_eq!(path.to_string(), "m/83696968'/83286642'/1'");
    /// ```
    pub fn derivation_path_from_scheme_parsed(
        scheme: SignatureScheme,
    ) -> Result<DerivationPath, SignatureSchemeError> {
        Bip85::derivation_path_from_scheme(scheme)
            .parse()
            .map_err(SignatureSchemeError::InvalidDerivationPath)
    }

    /// Parses the full BIP-85 derivation path for an HHD-enabled KEM.
    #[cfg(feature = "hqc")]
    pub(crate) fn derivation_path_from_kem_scheme_parsed(
        scheme: KemScheme,
    ) -> Result<DerivationPath, HhdKemSchemeError> {
        Bip85::derivation_path_from_kem_scheme(scheme)?
            .parse()
            .map_err(|error: bip32::Error| {
                HhdKemSchemeError::InvalidDerivationPath(error.to_string())
            })
    }

    /// Derives a child seed from a mnemonic using BIP-85.
    ///
    /// This method implements the BIP-85 standard to derive a scheme-specific
    /// seed from a BIP-39 mnemonic. The derivation process ensures that different
    /// signature schemes produce different seeds from the same mnemonic.
    ///
    /// # Derivation Steps
    ///
    /// 1. Convert the mnemonic to a master seed using BIP-39 (PBKDF2).
    /// 2. Derive an extended private key (`XPrv`) using BIP-32 with the scheme-specific path.
    /// 3. Extract the private-key bytes from the derived `XPrv`.
    /// 4. Apply HMAC-SHA-512 with the key-info string to extract entropy.
    /// 5. Return a 64-byte, scheme-specific seed.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - The BIP-39 mnemonic to derive from
    /// * `scheme` - The signature scheme to derive a seed for
    /// * `password` - Optional password for the mnemonic (BIP-39 passphrase)
    ///
    /// # Returns
    ///
    /// * `Ok(SignatureSeed)` - The derived scheme-specific seed
    /// * `Err(Bip85Error)` - If derivation fails
    ///
    /// # Errors
    ///
    /// Returns `Bip85Error` in the following cases:
    /// - `Mnemonic`: If mnemonic to seed conversion fails
    /// - `InvalidDerivationPath`: If the derivation path cannot be parsed
    /// - `Bip32`: If BIP-32 key derivation fails
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::Bip85;
    /// use tectonic_bedrock::hhd::{Mnemonic, SignatureScheme};
    ///
    /// let mnemonic = Mnemonic::from_phrase(
    ///     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    /// ).unwrap();
    ///
    /// let ecdsa_seed = Bip85::derive_seed_from_mnemonic(
    ///     mnemonic.clone(),
    ///     SignatureScheme::EcdsaSecp256k1,
    ///     None,
    /// ).unwrap();
    ///
    /// let falcon_seed = Bip85::derive_seed_from_mnemonic(
    ///     mnemonic,
    ///     SignatureScheme::Falcon512,
    ///     None,
    /// ).unwrap();
    ///
    /// // The seeds are different despite using the same mnemonic
    /// assert_ne!(ecdsa_seed.as_seed().as_bytes(), falcon_seed.as_seed().as_bytes());
    /// ```
    pub fn derive_seed_from_mnemonic(
        mnemonic: Mnemonic,
        scheme: SignatureScheme,
        password: Option<&str>,
    ) -> Result<SignatureSeed, Bip85Error> {
        // 1. Derive master seed from mnemonic (BIP-39)
        let master_seed = mnemonic.to_seed(password)?;

        // 2. Derive HD child seed from master seed (BIP-32):
        //      - master_root_key = HMAC-SHA-512("Bitcoin seed", master_seed)
        //      - child_xprv = CKD(master_root_key, info = scheme_derivation_path)
        let scheme_derivation_path = Bip85::derivation_path_from_scheme_parsed(scheme)?;
        let child_xprv = XPrv::derive_from_path(&master_seed, &scheme_derivation_path)?;

        // 3. Extract private key (sk) from child xprv
        let mut private_key_bytes = child_xprv.to_bytes();

        // 4. BIP-85 extraction step
        //      - I = HMAC-SHA-512("bip-entropy-from-k", sk)
        let seed = Bip85::extract_entropy(private_key_bytes.as_ref(), scheme)?;

        // Zeroize the private key bytes
        private_key_bytes.zeroize();

        Ok(seed)
    }

    /// Derives a KEM-specific 64-byte root seed from a mnemonic using BIP-85.
    ///
    /// # Errors
    ///
    /// Returns [`Bip85Error`] if the KEM is not HHD-enabled or mnemonic, path,
    /// BIP-32, or entropy extraction fails.
    #[cfg(feature = "hqc")]
    pub(crate) fn derive_kem_seed_from_mnemonic(
        mnemonic: &Mnemonic,
        scheme: KemScheme,
        password: Option<&str>,
    ) -> Result<KemSeed, Bip85Error> {
        kems::ensure_hhd_supported(scheme)?;
        let master_seed = mnemonic.to_seed(password)?;
        let scheme_derivation_path = Bip85::derivation_path_from_kem_scheme_parsed(scheme)?;
        let child_xprv = XPrv::derive_from_path(&master_seed, &scheme_derivation_path)?;
        let mut private_key_bytes = child_xprv.to_bytes();
        let seed = Bip85::extract_kem_entropy(private_key_bytes.as_ref(), scheme);
        private_key_bytes.zeroize();
        seed
    }

    /// Extracts entropy from a private key using BIP-85 HMAC-SHA-512 extraction.
    ///
    /// This method implements the BIP-85 entropy extraction step, which uses
    /// HMAC-SHA-512 with the key-info string `"bip-entropy-from-k"` to derive
    /// a 64-byte seed from the provided private key bytes.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key bytes to extract entropy from (typically 32 bytes)
    /// * `scheme` - The signature scheme to wrap the resulting seed in
    ///
    /// # Returns
    ///
    /// * `Ok(SignatureSeed)` - The extracted seed wrapped in a scheme-specific type
    /// * `Err(Bip85Error)` - If HMAC key creation fails
    ///
    /// # Errors
    ///
    /// Returns `Bip85Error::InvalidHmacKeyLength` if the HMAC key cannot be created
    /// (this should not happen in practice as the key info string is fixed).
    ///
    /// # Note
    ///
    /// This is an internal method used by `derive_seed_from_mnemonic`. It is exposed
    /// for advanced use cases, but most users should use `derive_seed_from_mnemonic`.
    pub fn extract_entropy(
        private_key: &[u8],
        scheme: SignatureScheme,
    ) -> Result<SignatureSeed, Bip85Error> {
        let mut child_seed = Bip85::extract_entropy_bytes(private_key)?;

        // Return the child seed for the given scheme.
        let signature_seed = match scheme {
            SignatureScheme::EcdsaSecp256k1 => SignatureSeed::ECDSAsecp256k1(Seed::new(child_seed)),
            SignatureScheme::Falcon512 => SignatureSeed::Falcon512(Seed::new(child_seed)),
            SignatureScheme::MlDsa44 => SignatureSeed::MlDsa44(Seed::new(child_seed)),
            SignatureScheme::MlDsa65 => SignatureSeed::MlDsa65(Seed::new(child_seed)),
            SignatureScheme::MlDsa87 => SignatureSeed::MlDsa87(Seed::new(child_seed)),
            SignatureScheme::Mayo1 => SignatureSeed::Mayo1(Seed::new(child_seed)),
            SignatureScheme::Mayo2 => SignatureSeed::Mayo2(Seed::new(child_seed)),
            SignatureScheme::Mayo3 => SignatureSeed::Mayo3(Seed::new(child_seed)),
        };

        child_seed.zeroize();

        Ok(signature_seed)
    }

    /// Extracts BIP-85 entropy and associates it with an HHD-enabled KEM.
    ///
    /// # Errors
    ///
    /// Returns [`Bip85Error`] when the KEM is unsupported or HMAC initialization fails.
    #[cfg(feature = "hqc")]
    pub(crate) fn extract_kem_entropy(
        private_key: &[u8],
        scheme: KemScheme,
    ) -> Result<KemSeed, Bip85Error> {
        kems::ensure_hhd_supported(scheme)?;
        let mut child_seed = Bip85::extract_entropy_bytes(private_key)?;
        let kem_seed = KemSeed::new(scheme, Seed::new(child_seed));
        child_seed.zeroize();
        Ok(kem_seed)
    }

    fn extract_entropy_bytes(private_key: &[u8]) -> Result<[u8; 64], Bip85Error> {
        let mut hmac = HmacSha512::new_from_slice(BIP85_KEY_INFO.as_bytes()).map_err(|_| {
            Bip85Error::InvalidHmacKeyLength {
                expected: 64,
                actual: BIP85_KEY_INFO.len(),
            }
        })?;
        hmac.update(private_key);
        Ok(hmac.finalize().into_bytes().into())
    }
}

/// Errors that can occur during BIP-85 seed derivation.
#[derive(Debug, thiserror::Error)]
pub enum Bip85Error {
    /// An error occurred during mnemonic-to-seed conversion (BIP-39).
    #[error("Mnemonic error: {0}")]
    Mnemonic(#[from] MnemonicError),
    /// An error occurred while parsing or validating the derivation path.
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(#[from] SignatureSchemeError),
    /// HMAC key length validation failed during entropy extraction.
    #[error("Invalid HMAC key length: expected {expected}, got {actual}")]
    InvalidHmacKeyLength {
        /// Expected HMAC key length in bytes.
        expected: usize,
        /// Actual HMAC key length in bytes.
        actual: usize,
    },
    /// An error occurred during BIP-32 key derivation.
    #[error("BIP-32 error: {0}")]
    Bip32(#[from] bip32::Error),
    /// The requested KEM has no HHD derivation definition.
    #[cfg(feature = "hqc")]
    #[error("KEM scheme error: {0}")]
    HhdKemScheme(#[from] HhdKemSchemeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip32::XPrv;
    use rstest::rstest;

    #[rstest]
    #[case(SignatureScheme::EcdsaSecp256k1, "m/83696968'/83286642'/1'")]
    #[case(SignatureScheme::Falcon512, "m/83696968'/83286642'/2'")]
    #[case(SignatureScheme::MlDsa65, "m/83696968'/83286642'/5'")]
    #[case(SignatureScheme::MlDsa87, "m/83696968'/83286642'/6'")]
    #[case(SignatureScheme::Mayo1, "m/83696968'/83286642'/7'")]
    #[case(SignatureScheme::Mayo2, "m/83696968'/83286642'/8'")]
    #[case(SignatureScheme::Mayo3, "m/83696968'/83286642'/9'")]
    fn test_bip85_paths(#[case] scheme: SignatureScheme, #[case] expected: &str) {
        assert_eq!(Bip85::derivation_path_from_scheme(scheme), expected);
    }

    #[rstest]
    #[case(SignatureScheme::EcdsaSecp256k1, "m/83696968'/83286642'/1'")]
    #[case(SignatureScheme::Falcon512, "m/83696968'/83286642'/2'")]
    #[case(SignatureScheme::MlDsa65, "m/83696968'/83286642'/5'")]
    #[case(SignatureScheme::MlDsa87, "m/83696968'/83286642'/6'")]
    #[case(SignatureScheme::Mayo1, "m/83696968'/83286642'/7'")]
    #[case(SignatureScheme::Mayo2, "m/83696968'/83286642'/8'")]
    #[case(SignatureScheme::Mayo3, "m/83696968'/83286642'/9'")]
    fn test_bip85_paths_parsed(#[case] scheme: SignatureScheme, #[case] expected: &str) {
        let path =
            Bip85::derivation_path_from_scheme_parsed(scheme).expect("should parse valid path");
        assert_eq!(path.to_string(), expected);
    }

    #[cfg(feature = "hqc")]
    #[rstest]
    #[case::hqc128(KemScheme::Hqc128, "m/83696968'/83286642'/10'")]
    #[case::hqc192(KemScheme::Hqc192, "m/83696968'/83286642'/11'")]
    #[case::hqc256(KemScheme::Hqc256, "m/83696968'/83286642'/12'")]
    fn test_hqc_bip85_paths(#[case] scheme: KemScheme, #[case] expected: &str) {
        assert_eq!(
            Bip85::derivation_path_from_kem_scheme(scheme).unwrap(),
            expected
        );
        assert_eq!(
            Bip85::derivation_path_from_kem_scheme_parsed(scheme)
                .unwrap()
                .to_string(),
            expected
        );
    }

    #[cfg(feature = "hqc")]
    #[test]
    fn hqc_parameter_sets_receive_distinct_bip85_seeds() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();

        let hqc128 =
            Bip85::derive_kem_seed_from_mnemonic(&mnemonic, KemScheme::Hqc128, None).unwrap();
        let hqc192 =
            Bip85::derive_kem_seed_from_mnemonic(&mnemonic, KemScheme::Hqc192, None).unwrap();
        let hqc256 =
            Bip85::derive_kem_seed_from_mnemonic(&mnemonic, KemScheme::Hqc256, None).unwrap();

        assert_ne!(hqc128.as_seed().as_bytes(), hqc192.as_seed().as_bytes());
        assert_ne!(hqc128.as_seed().as_bytes(), hqc256.as_seed().as_bytes());
        assert_ne!(hqc192.as_seed().as_bytes(), hqc256.as_seed().as_bytes());
    }

    fn test_bip_85(
        master_xprv_str: &str,
        derivation_path_str: &str,
        expected_derived_key_hex: &str,
        expected_derived_entropy_hex: &str,
    ) {
        // 1. Parse the master XPrv
        let root_key: XPrv = master_xprv_str.parse().expect("should parse valid xprv");

        // 2. Parse and derive from the path
        let derivation_path: DerivationPath = derivation_path_str
            .parse()
            .expect("should parse valid path");
        // Derive from the root key (not from seed)
        let derived_xprv = derivation_path
            .iter()
            .try_fold(root_key, |key, child_num| key.derive_child(child_num))
            .expect("should derive valid key");

        // 3. Extract the private key bytes (DERIVED KEY)
        let derived_key_bytes = derived_xprv.to_bytes();
        let derived_key_hex: String = derived_key_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        assert_eq!(derived_key_hex, expected_derived_key_hex);

        // 4. Apply BIP-85 extraction step to get DERIVED ENTROPY
        let mut hmac =
            HmacSha512::new_from_slice(BIP85_KEY_INFO.as_bytes()).expect("should create HMAC");
        hmac.update(derived_key_bytes.as_ref());
        let derived_entropy = hmac.finalize().into_bytes();

        // Convert to hex string
        let derived_entropy_hex: String = derived_entropy
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        assert_eq!(derived_entropy_hex, expected_derived_entropy_hex);
    }

    /// Tests BIP-85 derivation using test case 1 from the BIP-85 specification.
    ///
    /// This test verifies that the BIP-85 implementation produces the expected
    /// derived key and entropy values according to the official test vectors.
    ///
    /// Test vectors from: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#user-content-Test_vectors
    #[test]
    fn test_bip85_derivation_test_case_1() {
        test_bip_85(
            "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
            "m/83696968'/0'/0'",
            "cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
            "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7",
        );
    }

    /// Tests BIP-85 derivation using test case 2 from the BIP-85 specification.
    ///
    /// This test verifies that the BIP-85 implementation produces the expected
    /// derived key and entropy values according to the official test vectors.
    ///
    /// Test vectors from: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#user-content-Test_vectors
    #[test]
    fn test_bip85_derivation_test_case_2() {
        test_bip_85(
            "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
            "m/83696968'/0'/1'",
            "503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba",
            "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e",
        );
    }

    /// Tests that ECDSA and Falcon derive different seeds from the same mnemonic.
    ///
    /// # What it verifies
    ///
    /// - ECDSA and Falcon produce different seeds from the same mnemonic
    /// - The derivation paths are different (ending in `1'` vs `2'`)
    /// - The seeds are properly formatted as 64-byte values
    #[test]
    fn test_ecdsa_and_falcon_different_seeds_from_same_mnemonic() {
        // Use a fixed mnemonic for both ecdsa and falcon
        let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase).expect("should parse valid mnemonic");
        let password = None;

        // Derive seed for ECDSA scheme
        let ecdsa_seed = Bip85::derive_seed_from_mnemonic(
            mnemonic.clone(),
            SignatureScheme::EcdsaSecp256k1,
            password,
        )
        .expect("should derive ECDSA seed");

        // Derive seed for Falcon scheme using the same mnemonic
        let falcon_seed = Bip85::derive_seed_from_mnemonic(
            mnemonic.clone(),
            SignatureScheme::Falcon512,
            password,
        )
        .expect("should derive Falcon seed");

        // Derive seed for MlDsa65 scheme using the same mnemonic
        let mldsa65_seed =
            Bip85::derive_seed_from_mnemonic(mnemonic.clone(), SignatureScheme::MlDsa65, password)
                .expect("should derive MlDsa65 seed");

        // Extract seed bytes for comparison
        let ecdsa_seed_bytes = ecdsa_seed.as_seed().as_bytes();
        let falcon_seed_bytes = falcon_seed.as_seed().as_bytes();
        let mldsa65_seed_bytes = mldsa65_seed.as_seed().as_bytes();

        // Verify that the seeds are different
        assert_ne!(
            ecdsa_seed_bytes, falcon_seed_bytes,
            "ECDSA and Falcon seeds should be different from the same mnemonic"
        );

        assert_ne!(
            ecdsa_seed_bytes, mldsa65_seed_bytes,
            "ECDSA and MlDsa65 seeds should be different from the same mnemonic"
        );

        assert_ne!(
            falcon_seed_bytes, mldsa65_seed_bytes,
            "Falcon and MlDsa65 seeds should be different from the same mnemonic"
        );

        // Verify that the derivation paths are different (1' vs 2')
        assert_eq!(
            Bip85::derivation_path_from_scheme(SignatureScheme::EcdsaSecp256k1),
            "m/83696968'/83286642'/1'",
            "ECDSA should use derivation path ending in 1'"
        );
        assert_eq!(
            Bip85::derivation_path_from_scheme(SignatureScheme::Falcon512),
            "m/83696968'/83286642'/2'",
            "Falcon should use derivation path ending in 2'"
        );
    }
}
