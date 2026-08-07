//! Signature scheme definitions and constants for the hybrid HD wallet.
//!
//! This module provides type definitions, constants, and utilities for working with
//! different signature schemes in the hybrid wallet. It supports ECDSA secp256k1 and the
//! Falcon-512, ML-DSA, and MAYO post-quantum signature schemes.
//!
//! # Supported Schemes
//!
//! - **ECDSA secp256k1**: Classical elliptic-curve signatures for Bitcoin and Ethereum
//!   compatibility.
//! - **Falcon-512**: Post-quantum lattice-based signatures.
//! - **ML-DSA**: NIST-standardized post-quantum lattice-based signatures.
//! - **MAYO**: Post-quantum multivariate signatures.
//!
//! # Key Concepts
//!
//! - **SignatureScheme**: Enum identifying a specific signature algorithm.
//! - **SignatureSeed**: Scheme-specific seed wrapper for HD key derivation.
//! - **Constants**: Scheme-specific sizes, paths, and domain separators.
//!
//! # Derivation Paths
//!
//! Each scheme uses a BIP-44-compatible path:
//!
//! - **ECDSA**: Supports both hardened and non-hardened paths.
//! - **Falcon-512, ML-DSA, and MAYO**: Use hardened paths through SLIP-0010.
//!
//! [BIP-44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
//! [SLIP-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

use bip32::Seed;
use std::fmt;

/// Size in bytes of the seed required for ECDSA secp256k1 key generation (32 bytes = 256 bits).
pub const ECDSA_SECP256K1_KEY_GENERATION_SEED_SIZE: usize = 32;
/// Size in bytes of the root seed for ECDSA secp256k1 HD key derivation (64 bytes = 512 bits).
pub const ECDSA_SECP256K1_ROOT_SEED_SIZE: usize = 64;
/// Domain separator string used for ECDSA secp256k1 in BIP-32 key derivation.
pub const ECDSA_SECP256K1_DOMAIN_SEPARATOR: &[u8] = b"Bitcoin seed";
/// Size in bytes of an ECDSA secp256k1 signing key (private key): 32 bytes (256 bits).
pub const ECDSA_SECP256K1_SIGNING_KEY_SIZE: usize = 32;
/// Size in bytes of an ECDSA secp256k1 verifying key (public key): 33 bytes (compressed format).
pub const ECDSA_SECP256K1_VERIFYING_KEY_SIZE: usize = 33;
/// Size in bytes of an ECDSA secp256k1 signature: 64 bytes (32 bytes for r, 32 bytes for s).
pub const ECDSA_SECP256K1_SIGNATURE_SIZE: usize = 64;

/// Size in bytes of the seed required for Falcon-512 key generation (32 bytes = 256 bits).
pub const FALCON512_KEY_GENERATION_SEED_SIZE: usize = 32;
/// Size in bytes of the root seed for Falcon-512 HD key derivation (64 bytes = 512 bits).
pub const FALCON512_ROOT_SEED_SIZE: usize = 64;
/// Domain separator string used for Falcon-512 in SLIP-0010 key derivation.
pub const FALCON512_DOMAIN_SEPARATOR: &[u8] = b"Falcon-512 seed";
/// Size in bytes of a Falcon-512 signing key (private key): 1281 bytes.
pub const FALCON512_SIGNING_KEY_SIZE: usize = 1281;
/// Size in bytes of a Falcon-512 verifying key (public key): 897 bytes.
pub const FALCON512_VERIFYING_KEY_SIZE: usize = 897;
/// Size in bytes of a Falcon-512 signature: approximately 666 bytes (variable length).
pub const FALCON512_SIGNATURE_SIZE: usize = 666;

/// Size in bytes of the seed required for ML-DSA-44 key generation (32 bytes = 256 bits).
/// FIPS 204 (page 33): 𝜉 ∈ 𝔹^32 for `KeyGen_internal(𝜉)`.
#[deprecated(since = "0.3.0", note = "use ML_DSA_65_KEY_GENERATION_SEED_SIZE")]
pub const ML_DSA_44_KEY_GENERATION_SEED_SIZE: usize = 32;
/// Size in bytes of the seed required for ML-DSA-65 key generation (32 bytes = 256 bits).
pub const ML_DSA_65_KEY_GENERATION_SEED_SIZE: usize = 32;
/// Size in bytes of the seed required for ML-DSA-87 key generation (32 bytes = 256 bits).
pub const ML_DSA_87_KEY_GENERATION_SEED_SIZE: usize = 32;
/// Size in bytes of the root seed for ML-DSA-44 HD key derivation (64 bytes = 512 bits).
#[deprecated(since = "0.3.0", note = "use ML_DSA_65_ROOT_SEED_SIZE")]
pub const ML_DSA_44_ROOT_SEED_SIZE: usize = 64;
/// Size in bytes of the root seed for ML-DSA-65 HD key derivation (64 bytes = 512 bits).
pub const ML_DSA_65_ROOT_SEED_SIZE: usize = 64;
/// Size in bytes of the root seed for ML-DSA-87 HD key derivation (64 bytes = 512 bits).
pub const ML_DSA_87_ROOT_SEED_SIZE: usize = 64;
/// Domain separator string used for ML-DSA-44 in SLIP-0010 key derivation.
#[deprecated(since = "0.3.0", note = "use ML_DSA_65_DOMAIN_SEPARATOR")]
pub const ML_DSA_44_DOMAIN_SEPARATOR: &[u8] = b"ML-DSA-44 seed";
/// Domain separator string used for ML-DSA-65 in SLIP-0010 key derivation.
pub const ML_DSA_65_DOMAIN_SEPARATOR: &[u8] = b"ML-DSA-65 seed";
/// Domain separator string used for ML-DSA-87 in SLIP-0010 key derivation.
pub const ML_DSA_87_DOMAIN_SEPARATOR: &[u8] = b"ML-DSA-87 seed";
/// Sizes from the ML-DSA standard: <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf>.
/// Size in bytes of an ML-DSA-44 signing key (private key).
#[deprecated(since = "0.3.0", note = "use ML_DSA_65_SIGNING_KEY_SIZE")]
pub const ML_DSA_44_SIGNING_KEY_SIZE: usize = 2560;
/// Size in bytes of an ML-DSA-65 signing key (private key).
pub const ML_DSA_65_SIGNING_KEY_SIZE: usize = 4032;
/// Size in bytes of an ML-DSA-87 signing key (private key).
pub const ML_DSA_87_SIGNING_KEY_SIZE: usize = 4896;
/// Size in bytes of an ML-DSA-44 verifying key (public key).
#[deprecated(since = "0.3.0", note = "use ML_DSA_65_VERIFYING_KEY_SIZE")]
pub const ML_DSA_44_VERIFYING_KEY_SIZE: usize = 1312;
/// Size in bytes of an ML-DSA-65 verifying key (public key).
pub const ML_DSA_65_VERIFYING_KEY_SIZE: usize = 1952;
/// Size in bytes of an ML-DSA-87 verifying key (public key).
pub const ML_DSA_87_VERIFYING_KEY_SIZE: usize = 2592;
/// Size in bytes of an ML-DSA-44 signature.
#[deprecated(since = "0.3.0", note = "use ML_DSA_65_SIGNATURE_SIZE")]
pub const ML_DSA_44_SIGNATURE_SIZE: usize = 2420;
/// Size in bytes of an ML-DSA-65 signature.
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;
/// Size in bytes of an ML-DSA-87 signature.
pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4627;

/// Size in bytes of the seed required for MAYO-1 key generation.
///
/// A SLIP-0010 child key is always 32 bytes, while MAYO key-generation seeds are 24 bytes
/// (MAYO-1/2), 32 bytes (MAYO-3), and 40 bytes (MAYO-5). The HHD derivation rule for the
/// MAYO family only truncates bits; it never expands them. MAYO-1/2 truncate the 32-byte
/// SLIP-0010 child key to its first 24 bytes, MAYO-3 uses all 32 bytes directly, and
/// MAYO-5 is deliberately not supported in HHD (its 40-byte seed cannot be sourced from a
/// 32-byte SLIP-0010 child key without expansion). SLIP-0010 output is computationally
/// indistinguishable from uniform, so any prefix is itself uniform and truncation
/// preserves the full seed security targeted by the parameter set.
pub const MAYO_1_KEY_GENERATION_SEED_SIZE: usize = 24;
/// Size in bytes of the seed required for MAYO-2 key generation.
pub const MAYO_2_KEY_GENERATION_SEED_SIZE: usize = 24;
/// Size in bytes of the seed required for MAYO-3 key generation.
pub const MAYO_3_KEY_GENERATION_SEED_SIZE: usize = 32;
/// Size in bytes of the root seed for MAYO-1 HD key derivation (64 bytes = 512 bits).
pub const MAYO_1_ROOT_SEED_SIZE: usize = 64;
/// Size in bytes of the root seed for MAYO-2 HD key derivation (64 bytes = 512 bits).
pub const MAYO_2_ROOT_SEED_SIZE: usize = 64;
/// Size in bytes of the root seed for MAYO-3 HD key derivation (64 bytes = 512 bits).
pub const MAYO_3_ROOT_SEED_SIZE: usize = 64;
/// Domain separator string used for MAYO-1 in SLIP-0010 key derivation.
pub const MAYO_1_DOMAIN_SEPARATOR: &[u8] = b"MAYO-1 seed";
/// Domain separator string used for MAYO-2 in SLIP-0010 key derivation.
pub const MAYO_2_DOMAIN_SEPARATOR: &[u8] = b"MAYO-2 seed";
/// Domain separator string used for MAYO-3 in SLIP-0010 key derivation.
pub const MAYO_3_DOMAIN_SEPARATOR: &[u8] = b"MAYO-3 seed";
/// Size in bytes of a MAYO-1 signing key (private key): the compact secret-key seed.
pub const MAYO_1_SIGNING_KEY_SIZE: usize = 24;
/// Size in bytes of a MAYO-2 signing key (private key): the compact secret-key seed.
pub const MAYO_2_SIGNING_KEY_SIZE: usize = 24;
/// Size in bytes of a MAYO-3 signing key (private key): the compact secret-key seed.
pub const MAYO_3_SIGNING_KEY_SIZE: usize = 32;
/// Size in bytes of a MAYO-1 verifying key (public key).
pub const MAYO_1_VERIFYING_KEY_SIZE: usize = 1420;
/// Size in bytes of a MAYO-2 verifying key (public key).
pub const MAYO_2_VERIFYING_KEY_SIZE: usize = 4368;
/// Size in bytes of a MAYO-3 verifying key (public key).
pub const MAYO_3_VERIFYING_KEY_SIZE: usize = 2986;
/// Size in bytes of a MAYO-1 signature.
pub const MAYO_1_SIGNATURE_SIZE: usize = 454;
/// Size in bytes of a MAYO-2 signature.
pub const MAYO_2_SIGNATURE_SIZE: usize = 216;
/// Size in bytes of a MAYO-3 signature.
pub const MAYO_3_SIGNATURE_SIZE: usize = 681;

/// BIP-44 non-hardened base derivation path.
pub const BIP44_NON_HARDENED_BASE_PATH: &str = "m/44'/60'/0'/0";

/// BIP-44 hardened base derivation path.
pub const BIP44_HARDENED_BASE_PATH: &str = "m/44'/60'/0'/0'";

/// A scheme-specific seed wrapper for hierarchical deterministic key derivation.
///
/// This enum wraps a `Seed` with its associated signature scheme type, allowing
/// the wallet to maintain cryptographic separation between different schemes while
/// using a unified interface. Each variant contains a 64-byte seed that serves as
/// the root for HD key derivation in its respective scheme.
///
/// # Example
///
/// ```
/// use tectonic_bedrock::hhd::{SignatureSeed, SignatureScheme};
/// use bip32::Seed;
///
/// // Create a seed (typically from BIP-85 derivation)
/// let seed_bytes = [0u8; 64];
/// let seed = Seed::new(seed_bytes);
///
/// // Wrap it in a scheme-specific type
/// let ecdsa_seed = SignatureSeed::ECDSAsecp256k1(seed);
///
/// // Access the underlying seed
/// let inner_seed = ecdsa_seed.as_seed();
/// ```
pub enum SignatureSeed {
    /// ECDSA secp256k1 signature scheme seed.
    ECDSAsecp256k1(Seed),
    /// Falcon-512 signature scheme seed.
    Falcon512(Seed),
    /// ML-DSA-44 signature scheme seed.
    #[deprecated(since = "0.3.0", note = "use MlDsa65")]
    MlDsa44(Seed),
    /// ML-DSA-65 signature scheme seed.
    MlDsa65(Seed),
    /// ML-DSA-87 signature scheme seed.
    MlDsa87(Seed),
    /// MAYO-1 signature scheme seed.
    Mayo1(Seed),
    /// MAYO-2 signature scheme seed.
    Mayo2(Seed),
    /// MAYO-3 signature scheme seed.
    Mayo3(Seed),
}

impl fmt::Debug for SignatureSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            SignatureSeed::ECDSAsecp256k1(_) => "ECDSAsecp256k1",
            SignatureSeed::Falcon512(_) => "Falcon512",
            SignatureSeed::MlDsa44(_) => "MlDsa44",
            SignatureSeed::MlDsa65(_) => "MlDsa65",
            SignatureSeed::MlDsa87(_) => "MlDsa87",
            SignatureSeed::Mayo1(_) => "Mayo1",
            SignatureSeed::Mayo2(_) => "Mayo2",
            SignatureSeed::Mayo3(_) => "Mayo3",
        };

        let seed_bytes = self.as_seed().as_bytes().to_vec();
        let masked_seed = format!("<{} bytes hidden>", seed_bytes.len());

        f.debug_struct("SignatureSeed")
            .field("scheme", &variant)
            .field("seed", &masked_seed)
            .finish()
    }
}

impl SignatureSeed {
    /// Gets a reference to the underlying seed for this signature scheme.
    ///
    /// This method extracts the `Seed` from the scheme-specific wrapper, allowing
    /// access to the raw seed bytes for key derivation operations.
    ///
    /// # Returns
    ///
    /// A reference to the `Seed` instance (64 bytes).
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::SignatureSeed;
    /// use bip32::Seed;
    ///
    /// let seed = Seed::new([0u8; 64]);
    /// let signature_seed = SignatureSeed::ECDSAsecp256k1(seed);
    ///
    /// // Get the underlying seed
    /// let inner_seed = signature_seed.as_seed();
    /// assert_eq!(inner_seed.as_bytes().len(), 64);
    /// ```
    pub fn as_seed(&self) -> &Seed {
        match self {
            SignatureSeed::ECDSAsecp256k1(seed) => seed,
            SignatureSeed::Falcon512(seed) => seed,
            SignatureSeed::MlDsa44(seed) => seed,
            SignatureSeed::MlDsa65(seed) => seed,
            SignatureSeed::MlDsa87(seed) => seed,
            SignatureSeed::Mayo1(seed) => seed,
            SignatureSeed::Mayo2(seed) => seed,
            SignatureSeed::Mayo3(seed) => seed,
        }
    }
}

/// Enumeration of signature schemes supported by the hybrid wallet.
///
/// This enum identifies which cryptographic signature algorithm to use for key
/// generation, signing, and verification. Each scheme has different characteristics:
///
/// - **Key sizes**: Different schemes have different key and signature sizes
/// - **Derivation paths**: Each scheme uses specific HD derivation paths
/// - **Standards**: Different schemes follow different standards (BIP-32 vs SLIP-0010)
///
/// # Example
///
/// ```
/// use tectonic_bedrock::hhd::SignatureScheme;
///
/// let ecdsa = SignatureScheme::EcdsaSecp256k1;
/// let falcon = SignatureScheme::Falcon512;
///
/// // Get scheme-specific properties
/// assert_eq!(ecdsa.signing_key_size(), 32);
/// assert_eq!(falcon.signing_key_size(), 1281);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// ECDSA over the secp256k1 curve.
    EcdsaSecp256k1,
    /// Falcon-512 post-quantum signature scheme.
    Falcon512,
    /// ML-DSA-44 post-quantum signature scheme.
    #[deprecated(since = "0.3.0", note = "use MlDsa65")]
    MlDsa44,
    /// ML-DSA-65 post-quantum signature scheme.
    MlDsa65,
    /// ML-DSA-87 post-quantum signature scheme.
    MlDsa87,
    /// MAYO-1 post-quantum signature scheme.
    ///
    /// HHD derivation only truncates bits; it never expands them. MAYO-1 truncates the 32-byte
    /// SLIP-0010 child key to its first 24 bytes.
    Mayo1,
    /// MAYO-2 post-quantum signature scheme.
    ///
    /// HHD derivation only truncates bits; it never expands them. MAYO-2 truncates the 32-byte
    /// SLIP-0010 child key to its first 24 bytes.
    Mayo2,
    /// MAYO-3 post-quantum signature scheme.
    ///
    /// HHD derivation uses all 32 bytes of the SLIP-0010 child key directly. MAYO-5 is not
    /// offered in HHD because its 40-byte seed would require expansion.
    Mayo3,
}

impl SignatureScheme {
    /// Gets the BIP-44 non-hardened base derivation path for this signature scheme.
    ///
    /// # Returns
    ///
    /// * `Ok(&'static str)` - The base derivation path string
    /// * `Err(SignatureSchemeError::InvalidScheme)` - If the scheme does not support non-hardened paths
    ///
    /// # Errors
    ///
    /// Returns `SignatureSchemeError::InvalidScheme` for schemes that do not support
    /// non-hardened paths (currently only ECDSA secp256k1 supports this).
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::SignatureScheme;
    ///
    /// let ecdsa = SignatureScheme::EcdsaSecp256k1;
    /// let path = ecdsa.bip44_non_hardened_base_path().unwrap();
    /// assert_eq!(path, "m/44'/60'/0'/0");
    ///
    /// // Falcon does not support non-hardened paths.
    /// let falcon = SignatureScheme::Falcon512;
    /// assert!(falcon.bip44_non_hardened_base_path().is_err());
    /// ```
    pub fn bip44_non_hardened_base_path(&self) -> Result<&'static str, SignatureSchemeError> {
        match self {
            SignatureScheme::EcdsaSecp256k1 => Ok(BIP44_NON_HARDENED_BASE_PATH),
            _ => Err(SignatureSchemeError::InvalidScheme),
        }
    }

    /// Gets the BIP-44 hardened base derivation path for this signature scheme.
    ///
    /// # Returns
    ///
    /// * `Ok(&'static str)` - The base derivation path string
    /// * `Err(SignatureSchemeError::InvalidScheme)` - If the scheme does not support hardened paths
    ///
    /// # Errors
    ///
    /// Returns `SignatureSchemeError::InvalidScheme` for schemes that do not support
    /// hardened paths (should not occur for currently supported schemes).
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::SignatureScheme;
    ///
    /// let ecdsa = SignatureScheme::EcdsaSecp256k1;
    /// let path = ecdsa.bip44_hardened_base_path().unwrap();
    /// assert_eq!(path, "m/44'/60'/0'/0'");
    ///
    /// let falcon = SignatureScheme::Falcon512;
    /// let path = falcon.bip44_hardened_base_path().unwrap();
    /// assert_eq!(path, "m/44'/60'/0'/0'");
    /// ```
    pub fn bip44_hardened_base_path(&self) -> Result<&'static str, SignatureSchemeError> {
        match self {
            SignatureScheme::EcdsaSecp256k1
            | SignatureScheme::Falcon512
            | SignatureScheme::MlDsa44
            | SignatureScheme::MlDsa65
            | SignatureScheme::MlDsa87
            | SignatureScheme::Mayo1
            | SignatureScheme::Mayo2
            | SignatureScheme::Mayo3 => Ok(BIP44_HARDENED_BASE_PATH),
        }
    }

    /// Gets the seed size in bytes required for deterministic key generation.
    ///
    /// This returns the size of the seed needed when generating a keypair directly
    /// from a seed. Every supported scheme uses a 32-byte seed except MAYO-1 and
    /// MAYO-2, which use 24-byte seeds.
    pub fn key_generation_seed_size(&self) -> usize {
        match self {
            SignatureScheme::EcdsaSecp256k1 => ECDSA_SECP256K1_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::Falcon512 => FALCON512_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::MlDsa44 => ML_DSA_44_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::MlDsa65 => ML_DSA_65_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::MlDsa87 => ML_DSA_87_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::Mayo1 => MAYO_1_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::Mayo2 => MAYO_2_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::Mayo3 => MAYO_3_KEY_GENERATION_SEED_SIZE,
        }
    }

    /// Gets the root seed size in bytes for hierarchical deterministic key derivation.
    ///
    /// This returns the size of the master seed used for HD key derivation. Every
    /// supported scheme uses 64 bytes (512 bits), matching the BIP-39 seed size.
    pub fn root_seed_size(&self) -> usize {
        match self {
            SignatureScheme::EcdsaSecp256k1 => ECDSA_SECP256K1_ROOT_SEED_SIZE,
            SignatureScheme::Falcon512 => FALCON512_ROOT_SEED_SIZE,
            SignatureScheme::MlDsa44 => ML_DSA_44_ROOT_SEED_SIZE,
            SignatureScheme::MlDsa65 => ML_DSA_65_ROOT_SEED_SIZE,
            SignatureScheme::MlDsa87 => ML_DSA_87_ROOT_SEED_SIZE,
            SignatureScheme::Mayo1 => MAYO_1_ROOT_SEED_SIZE,
            SignatureScheme::Mayo2 => MAYO_2_ROOT_SEED_SIZE,
            SignatureScheme::Mayo3 => MAYO_3_ROOT_SEED_SIZE,
        }
    }

    /// Gets the domain separator bytes used for HD key derivation in this scheme.
    ///
    /// The domain separator is used in the HMAC-SHA-512 step when deriving the master
    /// extended private key from a seed. Each scheme uses a distinct separator; for example:
    ///
    /// - **ECDSA secp256k1**: `b"Bitcoin seed"` (BIP-32 standard)
    /// - **Falcon-512**: `b"Falcon-512 seed"` (SLIP-0010 compatible)
    ///
    /// # Returns
    ///
    /// A byte slice containing the domain separator string.
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::SignatureScheme;
    ///
    /// let ecdsa = SignatureScheme::EcdsaSecp256k1;
    /// assert_eq!(ecdsa.domain_separator(), b"Bitcoin seed");
    ///
    /// let falcon = SignatureScheme::Falcon512;
    /// assert_eq!(falcon.domain_separator(), b"Falcon-512 seed");
    /// ```
    pub fn domain_separator(&self) -> &[u8] {
        match self {
            SignatureScheme::EcdsaSecp256k1 => ECDSA_SECP256K1_DOMAIN_SEPARATOR,
            SignatureScheme::Falcon512 => FALCON512_DOMAIN_SEPARATOR,
            SignatureScheme::MlDsa44 => ML_DSA_44_DOMAIN_SEPARATOR,
            SignatureScheme::MlDsa65 => ML_DSA_65_DOMAIN_SEPARATOR,
            SignatureScheme::MlDsa87 => ML_DSA_87_DOMAIN_SEPARATOR,
            SignatureScheme::Mayo1 => MAYO_1_DOMAIN_SEPARATOR,
            SignatureScheme::Mayo2 => MAYO_2_DOMAIN_SEPARATOR,
            SignatureScheme::Mayo3 => MAYO_3_DOMAIN_SEPARATOR,
        }
    }

    /// Gets the signing key (private key) size in bytes for this signature scheme.
    ///
    /// - **ECDSA secp256k1**: 32 bytes
    /// - **Falcon-512**: 1281 bytes
    pub fn signing_key_size(&self) -> usize {
        match self {
            SignatureScheme::EcdsaSecp256k1 => ECDSA_SECP256K1_SIGNING_KEY_SIZE,
            SignatureScheme::Falcon512 => FALCON512_SIGNING_KEY_SIZE,
            SignatureScheme::MlDsa44 => ML_DSA_44_SIGNING_KEY_SIZE,
            SignatureScheme::MlDsa65 => ML_DSA_65_SIGNING_KEY_SIZE,
            SignatureScheme::MlDsa87 => ML_DSA_87_SIGNING_KEY_SIZE,
            SignatureScheme::Mayo1 => MAYO_1_SIGNING_KEY_SIZE,
            SignatureScheme::Mayo2 => MAYO_2_SIGNING_KEY_SIZE,
            SignatureScheme::Mayo3 => MAYO_3_SIGNING_KEY_SIZE,
        }
    }

    /// Gets the verifying key (public key) size in bytes for this signature scheme.
    ///
    /// - **ECDSA secp256k1**: 33 bytes (compressed SEC1 format)
    /// - **Falcon-512**: 897 bytes
    pub fn verifying_key_size(&self) -> usize {
        match self {
            SignatureScheme::EcdsaSecp256k1 => ECDSA_SECP256K1_VERIFYING_KEY_SIZE,
            SignatureScheme::Falcon512 => FALCON512_VERIFYING_KEY_SIZE,
            SignatureScheme::MlDsa44 => ML_DSA_44_VERIFYING_KEY_SIZE,
            SignatureScheme::MlDsa65 => ML_DSA_65_VERIFYING_KEY_SIZE,
            SignatureScheme::MlDsa87 => ML_DSA_87_VERIFYING_KEY_SIZE,
            SignatureScheme::Mayo1 => MAYO_1_VERIFYING_KEY_SIZE,
            SignatureScheme::Mayo2 => MAYO_2_VERIFYING_KEY_SIZE,
            SignatureScheme::Mayo3 => MAYO_3_VERIFYING_KEY_SIZE,
        }
    }

    /// Gets the signature size in bytes for this signature scheme.
    ///
    /// - **ECDSA secp256k1**: 64 bytes (32 bytes for r, 32 bytes for s)
    /// - **Falcon-512**: ~666 bytes (variable length)
    pub fn signature_size(&self) -> usize {
        match self {
            SignatureScheme::EcdsaSecp256k1 => ECDSA_SECP256K1_SIGNATURE_SIZE,
            SignatureScheme::Falcon512 => FALCON512_SIGNATURE_SIZE,
            SignatureScheme::MlDsa44 => ML_DSA_44_SIGNATURE_SIZE,
            SignatureScheme::MlDsa65 => ML_DSA_65_SIGNATURE_SIZE,
            SignatureScheme::MlDsa87 => ML_DSA_87_SIGNATURE_SIZE,
            SignatureScheme::Mayo1 => MAYO_1_SIGNATURE_SIZE,
            SignatureScheme::Mayo2 => MAYO_2_SIGNATURE_SIZE,
            SignatureScheme::Mayo3 => MAYO_3_SIGNATURE_SIZE,
        }
    }
}

/// Errors that can occur during signature scheme operations.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum SignatureSchemeError {
    /// Invalid derivation path encountered during path parsing or validation.
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(#[from] bip32::Error),
    /// The requested signature scheme operation is not supported or invalid.
    #[error("Invalid scheme")]
    InvalidScheme,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_scheme_debug_display() {
        let seed = Seed::new([0u8; 64]);
        let signature_seed = SignatureSeed::ECDSAsecp256k1(seed);
        assert_eq!(
            format!("{:?}", signature_seed),
            "SignatureSeed { scheme: \"ECDSAsecp256k1\", seed: \"<64 bytes hidden>\" }"
        );
    }
}
