//! SLIP10 derivation
//!
//! [SLIP10][slip10-spec] specifies a derivation method for hierarchical deterministic wallets.
//! that includes more curves than [BIP32][bip32-spec].
//!
//! Refer to [SLIP10][slip10-spec] to learn more about the derivation method.
//!
//! This implementation only considers hardened derivation paths.
//!
//! [slip10-spec]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
//! [bip32-spec]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

use crate::hhd::signatures::SignatureScheme;
use bip32::DerivationPath;
use bip32::{ChildNumber, ExtendedKeyAttrs, KeyFingerprint, PrivateKey, PublicKey};
use hmac::{digest::crypto_common::InvalidLength, Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;
type HmacSha512 = Hmac<Sha512>;

/// SLIP10 extended private key
pub(crate) struct Slip10XPrvKey<K: PrivateKey> {
    private_key: K,
    attrs: ExtendedKeyAttrs,
}

impl<K: PrivateKey> Slip10XPrvKey<K> {
    /// Derive a child key for a particular [`ChildNumber`].
    /// Function based on the BIP-32 implementation.
    pub(crate) fn derive_child(
        &self,
        child_number: ChildNumber,
    ) -> Result<Slip10XPrvKey<K>, Slip10Error> {
        let depth = self
            .attrs
            .depth
            .checked_add(1)
            .ok_or(Slip10Error::MaximumDerivationDepthExceeded)?;
        let (tweak, chain_code) = self
            .private_key
            .derive_tweak(&self.attrs.chain_code, child_number)?;

        // We should technically loop here if the tweak is zero or overflows
        // the order of the underlying elliptic curve group, incrementing the
        // index, however per "Child key derivation (CKD) functions":
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
        //
        // > "Note: this has probability lower than 1 in 2^127."
        //
        // ...so instead, we simply return an error if this were ever to happen,
        // as the chances of it happening are vanishingly small.
        let private_key = self.private_key.derive_child(tweak)?;

        let attrs = ExtendedKeyAttrs {
            parent_fingerprint: self.private_key.public_key().fingerprint(),
            child_number,
            chain_code,
            depth,
        };

        Ok(Slip10XPrvKey { private_key, attrs })
    }

    /// Get the private key bytes of the Slip10XPrvKey.
    pub(crate) fn private_key_bytes(&self) -> Vec<u8> {
        self.private_key.to_bytes().into()
    }
}

/// SLIP10 implementation that only supports hardened derivation paths from seed.
///
/// ## Supported curves:
/// - Falcon-512
/// - ML-DSA 44
/// - ML-DSA 65
/// - ML-DSA 87
///
/// ## Supported derivation paths:
/// - Hardened derivation paths
#[derive(Debug, Copy, Clone)]
pub(crate) struct Slip10;

impl Slip10 {
    /// Derive a child key from the given [`DerivationPath`] for a specific signature scheme.
    pub(crate) fn derive_from_path<S, K>(
        seed: S,
        path: &DerivationPath,
        scheme: SignatureScheme,
    ) -> Result<Slip10XPrvKey<K>, Slip10Error>
    where
        S: AsRef<[u8]>,
        K: PrivateKey,
    {
        // Validate that all components in the derivation path are hardened
        validate_all_hardened(path)?;

        path.iter().fold(
            Self::derive_root_xprv_from_seed::<S, K>(seed, scheme),
            |maybe_key, child_num| maybe_key.and_then(|key| key.derive_child(child_num)),
        )
    }

    /// Create the root extended key for the given seed value.
    pub(crate) fn derive_root_xprv_from_seed<S, K>(
        seed: S,
        scheme: SignatureScheme,
    ) -> Result<Slip10XPrvKey<K>, Slip10Error>
    where
        S: AsRef<[u8]>,
        K: PrivateKey,
    {
        if seed.as_ref().len() != scheme.root_seed_size() {
            return Err(Slip10Error::InvalidSeedLength {
                expected: scheme.root_seed_size(),
                actual: seed.as_ref().len(),
            });
        }

        let mut hmac = HmacSha512::new_from_slice(scheme.domain_separator())?;
        hmac.update(seed.as_ref());

        let mut result = hmac.finalize().into_bytes();
        let (secret_key, chain_code) = result.split_at(scheme.key_generation_seed_size());
        let private_key = PrivateKey::from_bytes(secret_key.try_into()?)?;
        let attrs = ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: KeyFingerprint::default(),
            child_number: ChildNumber::default(),
            chain_code: chain_code.try_into()?,
        };
        // Zeroize the result from hmac bytes
        result.zeroize();

        Ok(Slip10XPrvKey { private_key, attrs })
    }
}

/// Validate that all components in a derivation path are hardened
///
/// # Arguments
/// * `path` - The derivation path to validate
///
/// # Returns
/// * `Ok(())` if all components are hardened
/// * `Err(Slip10Error::InvalidDerivationPath)` if any component is not hardened
pub(crate) fn validate_all_hardened(path: &DerivationPath) -> Result<(), Slip10Error> {
    for child_num in path.iter() {
        if !child_num.is_hardened() {
            return Err(Slip10Error::InvalidDerivationPath(format!(
                "Path component {} is not hardened. All path components must be hardened. Path: {}",
                child_num, path
            )));
        }
    }
    Ok(())
}

/// Errors for the SLIP10 implementation.
#[derive(Debug, thiserror::Error)]
pub enum Slip10Error {
    /// Invalid derivation path
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),
    /// Invalid seed length
    #[error("Invalid seed length: expected {expected}, got {actual}")]
    InvalidSeedLength {
        /// Expected seed length in bytes
        expected: usize,
        /// Actual seed length in bytes
        actual: usize,
    },
    /// Invalid HMAC key length
    #[error("Invalid HMAC key length")]
    InvalidHmacKeyLength(#[from] InvalidLength),
    /// Array conversion failed
    #[error("Array conversion failed: {0}")]
    ConversionError(#[from] std::array::TryFromSliceError),
    /// BIP32 error
    #[error("BIP32 error: {0}")]
    Bip32(#[from] bip32::Error),
    /// Maximum derivation depth exceeded
    #[error("Maximum derivation depth exceeded")]
    MaximumDerivationDepthExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hhd::signatures::SignatureScheme;
    use bip32::{secp256k1::ecdsa::SigningKey, DerivationPath, Prefix, Seed as Bip32Seed, XPrv};

    const TEST_SEED_64: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ];

    // ============================================================================
    // Tests for validate_all_hardened
    // ============================================================================

    #[test]
    fn test_validate_all_hardened_valid_path() {
        let path: DerivationPath = "m/44'/60'/0'/0'".parse().unwrap();
        assert!(validate_all_hardened(&path).is_ok());
    }

    #[test]
    fn test_validate_all_hardened_mixed_path() {
        let path: DerivationPath = "m/44'/60'/0/0'".parse().unwrap(); // Middle component not hardened
        assert!(validate_all_hardened(&path).is_err());
    }

    // ============================================================================
    // Test for derive_root_xprv_from_seed
    // ============================================================================

    #[test]
    fn test_derive_root_xprv_from_seed_valid_seed() {
        let scheme = SignatureScheme::Falcon512;
        let result = Slip10::derive_root_xprv_from_seed(TEST_SEED_64, scheme);
        assert!(result.is_ok());

        let key: Slip10XPrvKey<SigningKey> = result.unwrap();
        // Verify root key has depth 0
        assert_eq!(key.attrs.depth, 0);
        assert_eq!(key.attrs.child_number, ChildNumber::default());
    }

    // ============================================================================
    // Test for bip32 test vector 3 with hardened paths
    // ============================================================================

    // Test vector 3 from BIP-32
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-3
    // This test compares SLIP0010 implementation with BIP-32 library to check consistency.

    // Seed (hex): 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
    const TEST_VECTOR_3_SEED_HEX: &str = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";

    // Expected results from test vector 3
    const EXPECTED_ROOT_XPRV: &str = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";
    const EXPECTED_M_0H_XPRV: &str = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";

    /// Test BIP-32 test vector 3 with hardened paths.
    /// Verifies that BIP-32 and SLIP-0010 produce identical results.
    #[test]
    fn test_bip32_vector_3_hardened_paths() {
        let scheme = SignatureScheme::EcdsaSecp256k1;

        // Parse seed from hex
        let seed_bytes = hex::decode(TEST_VECTOR_3_SEED_HEX).expect("should decode hex seed");

        // Test root key (m)
        test_root_key_equivalence(&seed_bytes, scheme, EXPECTED_ROOT_XPRV);

        // // Test m/0'
        test_path_equivalence(&seed_bytes, scheme, "m/0'", EXPECTED_M_0H_XPRV);
    }

    fn test_root_key_equivalence(seed: &[u8], scheme: SignatureScheme, expected_xprv_str: &str) {
        // For this test vector, we'll use the 64-byte seed directly
        let seed_64_array: [u8; 64] = seed.try_into().unwrap();

        // 1. Generate root using BIP-32
        let bip32_seed = Bip32Seed::new(seed_64_array);
        let bip32_root = XPrv::new(&bip32_seed).expect("should create BIP32 root");

        // Verify BIP-32 root matches expected
        let bip32_root_str = bip32_root.to_string(Prefix::XPRV);
        assert_eq!(
            bip32_root_str.as_str(),
            expected_xprv_str,
            "BIP-32 root should match test vector"
        );

        // 2. Generate root using SLIP-0010
        // Note: SLIP-0010 uses 64-byte seed for secp256k1
        let slip10_root: Slip10XPrvKey<SigningKey> =
            Slip10::derive_root_xprv_from_seed(seed_64_array, scheme)
                .expect("should create SLIP10 root");

        // 3. Compare private keys
        let bip32_private_bytes = bip32_root.to_bytes();
        let slip10_private_bytes = slip10_root.private_key_bytes();

        assert_eq!(
            bip32_private_bytes.as_ref(),
            slip10_private_bytes.as_slice(),
            "Root private keys should match between BIP-32 and SLIP-0010"
        );

        // 4. Compare chain codes
        assert_eq!(
            bip32_root.attrs().chain_code,
            slip10_root.attrs.chain_code.as_ref(),
            "Root chain codes should match"
        );

        // 5. Compare public keys
        let bip32_public = bip32_root.public_key();
        let slip10_public = slip10_root.private_key.public_key();

        assert_eq!(
            bip32_public.to_bytes().as_ref(),
            slip10_public.to_bytes().as_slice(),
            "Root public keys should match"
        );

        // 6. Compare depth (should be 0 for root)
        assert_eq!(bip32_root.attrs().depth, 0);
        assert_eq!(slip10_root.attrs.depth, 0);
    }

    /// Test path equivalence between BIP-32 and SLIP-0010
    /// Verifies that BIP-32 and SLIP-0010 produce identical results
    fn test_path_equivalence(
        seed: &[u8],
        scheme: SignatureScheme,
        path_str: &str,
        expected_xprv_str: &str,
    ) {
        // Convert seed to 64 bytes array
        let seed_64_array: [u8; 64] = seed.try_into().unwrap();

        // Parse derivation path
        let path: DerivationPath = path_str.parse().expect("should parse derivation path");

        // 1. Derive using BIP-32
        let bip32_seed = Bip32Seed::new(seed_64_array);
        let bip32_root = XPrv::new(&bip32_seed).expect("should create BIP32 root");

        let bip32_key = path
            .iter()
            .fold(Ok(bip32_root), |maybe_key, child_num| {
                maybe_key.and_then(|key| key.derive_child(child_num))
            })
            .expect("should derive BIP32 key");

        // Verify BIP-32 result matches expected
        let bip32_key_str = bip32_key.to_string(Prefix::XPRV);
        assert_eq!(
            bip32_key_str.as_str(),
            expected_xprv_str,
            "BIP-32 derived key should match test vector for path: {}",
            path_str
        );

        // 2. Derive using SLIP-0010
        let slip10_key: Slip10XPrvKey<SigningKey> =
            Slip10::derive_from_path(seed_64_array, &path, scheme)
                .expect("should derive SLIP10 key");

        // 3. Compare private keys
        let bip32_private_bytes = bip32_key.to_bytes();
        let slip10_private_bytes = slip10_key.private_key_bytes();

        assert_eq!(
            bip32_private_bytes.as_ref(),
            slip10_private_bytes.as_slice(),
            "Private keys should match between BIP-32 and SLIP-0010 for path: {}",
            path_str
        );

        // 4. Compare chain codes
        assert_eq!(
            bip32_key.attrs().chain_code,
            slip10_key.attrs.chain_code.as_ref(),
            "Chain codes should match for path: {}",
            path_str
        );

        // 5. Compare public keys
        let bip32_public = bip32_key.public_key();
        let slip10_public = slip10_key.private_key.public_key();

        assert_eq!(
            bip32_public.to_bytes().as_ref(),
            slip10_public.to_bytes().as_slice(),
            "Public keys should match for path: {}",
            path_str
        );

        // 6. Compare depth
        assert_eq!(
            bip32_key.attrs().depth,
            slip10_key.attrs.depth,
            "Depth should match for path: {}",
            path_str
        );

        // 7. Compare child numbers (should match last component of path)
        let last_child = path.iter().last();
        if let Some(expected_child) = last_child {
            assert_eq!(
                bip32_key.attrs().child_number,
                expected_child,
                "Child number should match last path component"
            );
            assert_eq!(
                slip10_key.attrs.child_number, expected_child,
                "SLIP-0010 child number should match"
            );
        }
    }
}
