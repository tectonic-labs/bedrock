//! Signature scheme definitions and constants for the hybrid HD wallet.
//!
//! This module provides type definitions, constants, and utilities for working with
//! different signature schemes in the hybrid wallet. It supports both classical
//! (ECDSA secp256k1) and post-quantum (Falcon-512) signature schemes.
//!
//! # Supported Schemes
//!
//! - **ECDSA secp256k1**: Classical elliptic curve signatures for Bitcoin/Ethereum compatibility
//! - **Falcon-512**: Post-quantum lattice-based signatures for future security
//!
//! # Key Concepts
//!
//! - **SignatureScheme**: Enum identifying a specific signature algorithm
//! - **SignatureSeed**: Scheme-specific seed wrapper for HD key derivation
//! - **Constants**: Scheme-specific sizes, paths, and domain separators
//!
//! # Derivation Paths
//!
//! Each scheme uses BIP-44 compatible paths:
//! - **ECDSA**: Supports both hardened and non-hardened paths
//! - **Falcon-512**: Uses hardened paths only (via SLIP-0010)
//!
//! [BIP-44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
//! [SLIP-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

use bip32::Seed;

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
pub const FALCON512_DOMAIN_SEPARATOR: &[u8] = b"Falcon-512-v1 seed";
/// Size in bytes of a Falcon-512 signing key (private key): 1281 bytes.
pub const FALCON512_SIGNING_KEY_SIZE: usize = 1281;
/// Size in bytes of a Falcon-512 verifying key (public key): 897 bytes.
pub const FALCON512_VERIFYING_KEY_SIZE: usize = 897;
/// Size in bytes of a Falcon-512 signature: approximately 666 bytes (variable length).
pub const FALCON512_SIGNATURE_SIZE: usize = 666;

/// BIP-44 non-hardened base derivation path
pub const BIP44_NON_HARDENED_BASE_PATH: &str = "m/44'/60'/0'/0";

/// BIP-44 hardened base derivation path
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
/// use bedrock::hhd::{SignatureSeed, SignatureScheme};
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
    /// use bedrock::hhd::SignatureSeed;
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
/// use bedrock::hhd::SignatureScheme;
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
}

impl SignatureScheme {
    /// Gets the BIP-44 non-hardened base derivation path for this signature scheme.
    ///
    /// # Returns
    ///
    /// * `Ok(&'static str)` - The base derivation path string
    /// * `Err(SignatureSchemeError::InvalidScheme)` - If the scheme doesn't support non-hardened paths
    ///
    /// # Errors
    ///
    /// Returns `SignatureSchemeError::InvalidScheme` for schemes that don't support
    /// non-hardened paths (currently only ECDSA secp256k1 supports this).
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::SignatureScheme;
    ///
    /// let ecdsa = SignatureScheme::EcdsaSecp256k1;
    /// let path = ecdsa.bip44_non_hardened_base_path().unwrap();
    /// assert_eq!(path, "m/44'/60'/0'/0");
    ///
    /// // Falcon doesn't support non-hardened paths
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
    /// * `Err(SignatureSchemeError::InvalidScheme)` - If the scheme doesn't support hardened paths
    ///
    /// # Errors
    ///
    /// Returns `SignatureSchemeError::InvalidScheme` for schemes that don't support
    /// hardened paths (should not occur for currently supported schemes).
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::SignatureScheme;
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
            SignatureScheme::EcdsaSecp256k1 | SignatureScheme::Falcon512 => {
                Ok(BIP44_HARDENED_BASE_PATH)
            }
        }
    }

    /// Gets the seed size in bytes required for deterministic key generation.
    ///
    /// This returns the size of the seed needed when generating a keypair directly
    /// from a seed (e.g., for Falcon-512 key generation). This is 32 bytes
    /// (256 bits) for both schemes.
    pub fn key_generation_seed_size(&self) -> usize {
        match self {
            SignatureScheme::EcdsaSecp256k1 => ECDSA_SECP256K1_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::Falcon512 => FALCON512_KEY_GENERATION_SEED_SIZE,
        }
    }

    /// Gets the root seed size in bytes for hierarchical deterministic key derivation.
    ///
    /// This returns the size of the master seed used for HD key derivation. This is
    /// 64 bytes (512 bits) for both schemes, matching the BIP-39 seed size.
    pub fn root_seed_size(&self) -> usize {
        match self {
            SignatureScheme::EcdsaSecp256k1 => ECDSA_SECP256K1_ROOT_SEED_SIZE,
            SignatureScheme::Falcon512 => FALCON512_ROOT_SEED_SIZE,
        }
    }

    /// Gets the domain separator bytes used for HD key derivation in this scheme.
    ///
    /// The domain separator is used in the HMAC-SHA512 step when deriving the master
    /// extended private key from a seed. Different schemes use different separators:
    ///
    /// - **ECDSA secp256k1**: `b"Bitcoin seed"` (BIP-32 standard)
    /// - **Falcon-512**: `b"Falcon-512-v1 seed"` (SLIP-0010 compatible)
    ///
    /// # Returns
    ///
    /// A byte slice containing the domain separator string.
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::SignatureScheme;
    ///
    /// let ecdsa = SignatureScheme::EcdsaSecp256k1;
    /// assert_eq!(ecdsa.domain_separator(), b"Bitcoin seed");
    ///
    /// let falcon = SignatureScheme::Falcon512;
    /// assert_eq!(falcon.domain_separator(), b"Falcon-512-v1 seed");
    /// ```
    pub fn domain_separator(&self) -> &[u8] {
        match self {
            SignatureScheme::EcdsaSecp256k1 => ECDSA_SECP256K1_DOMAIN_SEPARATOR,
            SignatureScheme::Falcon512 => FALCON512_DOMAIN_SEPARATOR,
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
        }
    }
}

/// Errors that can occur during signature scheme operations.
#[derive(Debug, thiserror::Error)]
pub enum SignatureSchemeError {
    /// Invalid derivation path encountered during path parsing or validation.
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(#[from] bip32::Error),
    /// The requested signature scheme operation is not supported or invalid.
    #[error("Invalid scheme")]
    InvalidScheme,
}
