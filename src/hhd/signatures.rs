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

/// Size in bytes of the seed required for ML-DSA key generation (32 bytes = 256 bits).
/// Original standard (pag. 33): 𝜉 ∈ 𝔹^32 for KeyGen_internal(𝜉).
pub const ML_DSA_44_KEY_GENERATION_SEED_SIZE: usize = 32;
pub const ML_DSA_65_KEY_GENERATION_SEED_SIZE: usize = 32;
pub const ML_DSA_87_KEY_GENERATION_SEED_SIZE: usize = 32;
/// Size in bytes of the seed required for SLH-DSA key generation.
/// Liboqs SLH-DSA keypair_from_seed expects seed = (SK.seed || SK.prf || PK.seed), each n bytes;
/// n=16 for 128-bit, n=24 for 192-bit, n=32 for 256-bit, so 3*n = 48, 72, 96.
pub const SLH_DSA_128_KEY_GENERATION_SEED_SIZE: usize = 48; // 3 * 16
pub const SLH_DSA_192_KEY_GENERATION_SEED_SIZE: usize = 72; // 3 * 24
pub const SLH_DSA_256_KEY_GENERATION_SEED_SIZE: usize = 96; // 3 * 32
/// Size in bytes of the root seed for ML-DSA HD key derivation (64 bytes = 512 bits).
pub const ML_DSA_44_ROOT_SEED_SIZE: usize = 64;
pub const ML_DSA_65_ROOT_SEED_SIZE: usize = 64;
pub const ML_DSA_87_ROOT_SEED_SIZE: usize = 64;
/// Size in bytes of the root seed for SLH-DSA HD key derivation (64 bytes = 512 bits).
pub const SLH_DSA_128_ROOT_SEED_SIZE: usize = 64;
pub const SLH_DSA_192_ROOT_SEED_SIZE: usize = 64;
pub const SLH_DSA_256_ROOT_SEED_SIZE: usize = 64;
/// Domain separator string used for ML-DSA 44 in BIP-32 key derivation.
pub const ML_DSA_44_DOMAIN_SEPARATOR: &[u8] = b"ML-DSA-44 seed";
pub const ML_DSA_65_DOMAIN_SEPARATOR: &[u8] = b"ML-DSA-65 seed";
pub const ML_DSA_87_DOMAIN_SEPARATOR: &[u8] = b"ML-DSA-87 seed";
/// Domain separator string used for SLH-DSA 128 in BIP-32 key derivation.
pub const SLH_DSA_SHA2_128S_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Sha2-128s seed";
pub const SLH_DSA_SHA2_128F_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Sha2-128f seed";
pub const SLH_DSA_SHAKE_128S_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Shake-128s seed";
pub const SLH_DSA_SHAKE_128F_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Shake-128f seed";
/// Domain separator string used for SLH-DSA 192 in BIP-32 key derivation.
pub const SLH_DSA_SHA2_192S_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Sha2-192s seed";
pub const SLH_DSA_SHA2_192F_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Sha2-192f seed";
pub const SLH_DSA_SHAKE_192S_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Shake-192s seed";
pub const SLH_DSA_SHAKE_192F_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Shake-192f seed";
/// Domain separator string used for SLH-DSA 256 in BIP-32 key derivation.
pub const SLH_DSA_SHA2_256S_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Sha2-256s seed";
pub const SLH_DSA_SHA2_256F_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Sha2-256f seed";
pub const SLH_DSA_SHAKE_256S_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Shake-256s seed";
pub const SLH_DSA_SHAKE_256F_DOMAIN_SEPARATOR: &[u8] = b"SLH-DSA-Shake-256f seed";
/// Numbers taken from the original slh-dsa standard: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf
/// Size in bytes of a SLH-DSA 128 signing key (private key).
pub const SLH_DSA_128_SIGNING_KEY_SIZE: usize = 64;
pub const SLH_DSA_192_SIGNING_KEY_SIZE: usize = 96;
pub const SLH_DSA_256_SIGNING_KEY_SIZE: usize = 128;
/// Size in bytes of a SLH-DSA 128 verifying key (public key).
pub const SLH_DSA_128_VERIFYING_KEY_SIZE: usize = 32;
pub const SLH_DSA_192_VERIFYING_KEY_SIZE: usize = 48;
pub const SLH_DSA_256_VERIFYING_KEY_SIZE: usize = 64;
/// Size in bytes of a SLH-DSA 128 signature.
pub const SLH_DSA_128_S_SIGNATURE_SIZE: usize = 7856;
pub const SLH_DSA_128_F_SIGNATURE_SIZE: usize = 17088;
pub const SLH_DSA_192_S_SIGNATURE_SIZE: usize = 16224;
pub const SLH_DSA_192_F_SIGNATURE_SIZE: usize = 35664;
pub const SLH_DSA_256_S_SIGNATURE_SIZE: usize = 29792;
pub const SLH_DSA_256_F_SIGNATURE_SIZE: usize = 49856;
/// Numbers taken from the original ml-dsa standard: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
/// Size in bytes of a ML-DSA 44/65/87 signing key (private key)
pub const ML_DSA_44_SIGNING_KEY_SIZE: usize = 2560;
pub const ML_DSA_65_SIGNING_KEY_SIZE: usize = 4032;
pub const ML_DSA_87_SIGNING_KEY_SIZE: usize = 4896;
/// Size in bytes of a ML-DSA 44/65/87 verifying key (public key)
pub const ML_DSA_44_VERIFYING_KEY_SIZE: usize = 1312;
pub const ML_DSA_65_VERIFYING_KEY_SIZE: usize = 1952;
pub const ML_DSA_87_VERIFYING_KEY_SIZE: usize = 2592;
/// Size in bytes of a ML-DSA 44 signature.
pub const ML_DSA_44_SIGNATURE_SIZE: usize = 2420;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;
pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4627;

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
    /// ML-DSA 44 signature scheme seed.
    MlDsa44(Seed),
    /// ML-DSA 65 signature scheme seed.
    MlDsa65(Seed),
    /// ML-DSA 87 signature scheme seed.
    MlDsa87(Seed),
    /// SLH-DSA 128 (SHA2-128, small) signature scheme seed.
    SlhDsaSha2128s(Seed),
    /// SLH-DSA 128 (SHA2-128, fast) signature scheme seed.
    SlhDsaSha2128f(Seed),
    /// SLH-DSA 128 (SHAKE-128, small) signature scheme seed.
    SlhDsaShake128s(Seed),
    /// SLH-DSA 128 (SHAKE-128, fast) signature scheme seed.
    SlhDsaShake128f(Seed),
    /// SLH-DSA 192 (SHA2-192, small) signature scheme seed.
    SlhDsaSha2192s(Seed),
    /// SLH-DSA 192 (SHA2-192, fast) signature scheme seed.
    SlhDsaSha2192f(Seed),
    /// SLH-DSA 192 (SHAKE-192, small) signature scheme seed.
    SlhDsaShake192s(Seed),
    /// SLH-DSA 192 (SHAKE-192, fast) signature scheme seed.
    SlhDsaShake192f(Seed),
    /// SLH-DSA 256 (SHA2-256, small) signature scheme seed.
    SlhDsaSha2256s(Seed),
    /// SLH-DSA 256 (SHA2-256, fast) signature scheme seed.
    SlhDsaSha2256f(Seed),
    /// SLH-DSA 256 (SHAKE-256, small) signature scheme seed.
    SlhDsaShake256s(Seed),
    /// SLH-DSA 256 (SHAKE-256, fast) signature scheme seed.
    SlhDsaShake256f(Seed),
}

impl fmt::Debug for SignatureSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            SignatureSeed::ECDSAsecp256k1(_) => "ECDSAsecp256k1",
            SignatureSeed::Falcon512(_) => "Falcon512",
            SignatureSeed::MlDsa44(_) => "MlDsa44",
            SignatureSeed::MlDsa65(_) => "MlDsa65",
            SignatureSeed::MlDsa87(_) => "MlDsa87",
            SignatureSeed::SlhDsaSha2128s(_) => "SlhDsaSha2128s",
            SignatureSeed::SlhDsaSha2128f(_) => "SlhDsaSha2128f",
            SignatureSeed::SlhDsaShake128s(_) => "SlhDsaShake128s",
            SignatureSeed::SlhDsaShake128f(_) => "SlhDsaShake128f",
            SignatureSeed::SlhDsaSha2192s(_) => "SlhDsaSha2192s",
            SignatureSeed::SlhDsaSha2192f(_) => "SlhDsaSha2192f",
            SignatureSeed::SlhDsaShake192s(_) => "SlhDsaShake192s",
            SignatureSeed::SlhDsaShake192f(_) => "SlhDsaShake192f",
            SignatureSeed::SlhDsaSha2256s(_) => "SlhDsaSha2256s",
            SignatureSeed::SlhDsaSha2256f(_) => "SlhDsaSha2256f",
            SignatureSeed::SlhDsaShake256s(_) => "SlhDsaShake256s",
            SignatureSeed::SlhDsaShake256f(_) => "SlhDsaShake256f",
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
            SignatureSeed::SlhDsaSha2128s(seed) => seed,
            SignatureSeed::SlhDsaSha2128f(seed) => seed,
            SignatureSeed::SlhDsaShake128s(seed) => seed,
            SignatureSeed::SlhDsaShake128f(seed) => seed,
            SignatureSeed::SlhDsaSha2192s(seed) => seed,
            SignatureSeed::SlhDsaSha2192f(seed) => seed,
            SignatureSeed::SlhDsaShake192s(seed) => seed,
            SignatureSeed::SlhDsaShake192f(seed) => seed,
            SignatureSeed::SlhDsaSha2256s(seed) => seed,
            SignatureSeed::SlhDsaSha2256f(seed) => seed,
            SignatureSeed::SlhDsaShake256s(seed) => seed,
            SignatureSeed::SlhDsaShake256f(seed) => seed,
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
    /// ML-DSA 44 post-quantum signature scheme.
    MlDsa44,
    /// ML-DSA 65 post-quantum signature scheme.
    MlDsa65,
    /// ML-DSA 87 post-quantum signature scheme.
    MlDsa87,
    /// SLH-DSA 128 (SHA2-128, small) post-quantum signature scheme.
    SlhDsaSha2128s,
    /// SLH-DSA 128 (SHA2-128, fast) post-quantum signature scheme.
    SlhDsaSha2128f,
    /// SLH-DSA 128 (SHAKE-128, small) post-quantum signature scheme.
    SlhDsaShake128s,
    /// SLH-DSA 128 (SHAKE-128, fast) post-quantum signature scheme.
    SlhDsaShake128f,
    /// SLH-DSA 192 (SHA2-192, small) post-quantum signature scheme.
    SlhDsaSha2192s,
    /// SLH-DSA 192 (SHA2-192, fast) post-quantum signature scheme.
    SlhDsaSha2192f,
    /// SLH-DSA 192 (SHAKE-192, small) post-quantum signature scheme.
    SlhDsaShake192s,
    /// SLH-DSA 192 (SHAKE-192, fast) post-quantum signature scheme.
    SlhDsaShake192f,
    /// SLH-DSA 256 (SHA2-256, small) post-quantum signature scheme.
    SlhDsaSha2256s,
    /// SLH-DSA 256 (SHA2-256, fast) post-quantum signature scheme.
    SlhDsaSha2256f,
    /// SLH-DSA 256 (SHAKE-256, small) post-quantum signature scheme.
    SlhDsaShake256s,
    /// SLH-DSA 256 (SHAKE-256, fast) post-quantum signature scheme.
    SlhDsaShake256f,
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
    /// use tectonic_bedrock::hhd::SignatureScheme;
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
            | SignatureScheme::SlhDsaSha2128s
            | SignatureScheme::SlhDsaSha2128f
            | SignatureScheme::SlhDsaShake128s
            | SignatureScheme::SlhDsaShake128f
            | SignatureScheme::SlhDsaSha2192s
            | SignatureScheme::SlhDsaSha2192f
            | SignatureScheme::SlhDsaShake192s
            | SignatureScheme::SlhDsaShake192f
            | SignatureScheme::SlhDsaSha2256s
            | SignatureScheme::SlhDsaSha2256f
            | SignatureScheme::SlhDsaShake256s
            | SignatureScheme::SlhDsaShake256f => Ok(BIP44_HARDENED_BASE_PATH),
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
            SignatureScheme::MlDsa44 => ML_DSA_44_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::MlDsa65 => ML_DSA_65_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::MlDsa87 => ML_DSA_87_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::SlhDsaSha2128s
            | SignatureScheme::SlhDsaSha2128f
            | SignatureScheme::SlhDsaShake128s
            | SignatureScheme::SlhDsaShake128f => SLH_DSA_128_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::SlhDsaSha2192s
            | SignatureScheme::SlhDsaSha2192f
            | SignatureScheme::SlhDsaShake192s
            | SignatureScheme::SlhDsaShake192f => SLH_DSA_192_KEY_GENERATION_SEED_SIZE,
            SignatureScheme::SlhDsaSha2256s
            | SignatureScheme::SlhDsaSha2256f
            | SignatureScheme::SlhDsaShake256s
            | SignatureScheme::SlhDsaShake256f => SLH_DSA_256_KEY_GENERATION_SEED_SIZE,
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
            SignatureScheme::MlDsa44 => ML_DSA_44_ROOT_SEED_SIZE,
            SignatureScheme::MlDsa65 => ML_DSA_65_ROOT_SEED_SIZE,
            SignatureScheme::MlDsa87 => ML_DSA_87_ROOT_SEED_SIZE,
            SignatureScheme::SlhDsaSha2128s
            | SignatureScheme::SlhDsaSha2128f
            | SignatureScheme::SlhDsaShake128s
            | SignatureScheme::SlhDsaShake128f => SLH_DSA_128_ROOT_SEED_SIZE,
            SignatureScheme::SlhDsaSha2192s
            | SignatureScheme::SlhDsaSha2192f
            | SignatureScheme::SlhDsaShake192s
            | SignatureScheme::SlhDsaShake192f => SLH_DSA_192_ROOT_SEED_SIZE,
            SignatureScheme::SlhDsaSha2256s
            | SignatureScheme::SlhDsaSha2256f
            | SignatureScheme::SlhDsaShake256s
            | SignatureScheme::SlhDsaShake256f => SLH_DSA_256_ROOT_SEED_SIZE,
        }
    }

    /// Gets the domain separator bytes used for HD key derivation in this scheme.
    ///
    /// The domain separator is used in the HMAC-SHA512 step when deriving the master
    /// extended private key from a seed. Different schemes use different separators:
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
            SignatureScheme::SlhDsaSha2128s => SLH_DSA_SHA2_128S_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaSha2128f => SLH_DSA_SHA2_128F_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaShake128s => SLH_DSA_SHAKE_128S_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaShake128f => SLH_DSA_SHAKE_128F_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaSha2192s => SLH_DSA_SHA2_192S_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaSha2192f => SLH_DSA_SHA2_192F_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaShake192s => SLH_DSA_SHAKE_192S_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaShake192f => SLH_DSA_SHAKE_192F_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaSha2256s => SLH_DSA_SHA2_256S_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaSha2256f => SLH_DSA_SHA2_256F_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaShake256s => SLH_DSA_SHAKE_256S_DOMAIN_SEPARATOR,
            SignatureScheme::SlhDsaShake256f => SLH_DSA_SHAKE_256F_DOMAIN_SEPARATOR,
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
            SignatureScheme::SlhDsaSha2128s => SLH_DSA_128_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2128f => SLH_DSA_128_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaShake128s => SLH_DSA_128_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaShake128f => SLH_DSA_128_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2192s => SLH_DSA_192_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2192f => SLH_DSA_192_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaShake192s => SLH_DSA_192_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaShake192f => SLH_DSA_192_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2256s => SLH_DSA_256_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2256f => SLH_DSA_256_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaShake256s => SLH_DSA_256_SIGNING_KEY_SIZE,
            SignatureScheme::SlhDsaShake256f => SLH_DSA_256_SIGNING_KEY_SIZE,
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
            SignatureScheme::SlhDsaSha2128s => SLH_DSA_128_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2128f => SLH_DSA_128_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaShake128s => SLH_DSA_128_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaShake128f => SLH_DSA_128_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2192s => SLH_DSA_192_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2192f => SLH_DSA_192_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaShake192s => SLH_DSA_192_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaShake192f => SLH_DSA_192_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2256s => SLH_DSA_256_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaSha2256f => SLH_DSA_256_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaShake256s => SLH_DSA_256_VERIFYING_KEY_SIZE,
            SignatureScheme::SlhDsaShake256f => SLH_DSA_256_VERIFYING_KEY_SIZE,
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
            SignatureScheme::SlhDsaSha2128s | SignatureScheme::SlhDsaShake128s => {
                SLH_DSA_128_S_SIGNATURE_SIZE
            }
            SignatureScheme::SlhDsaSha2128f | SignatureScheme::SlhDsaShake128f => {
                SLH_DSA_128_F_SIGNATURE_SIZE
            }
            SignatureScheme::SlhDsaSha2192s | SignatureScheme::SlhDsaShake192s => {
                SLH_DSA_192_S_SIGNATURE_SIZE
            }
            SignatureScheme::SlhDsaSha2192f | SignatureScheme::SlhDsaShake192f => {
                SLH_DSA_192_F_SIGNATURE_SIZE
            }
            SignatureScheme::SlhDsaSha2256s | SignatureScheme::SlhDsaShake256s => {
                SLH_DSA_256_S_SIGNATURE_SIZE
            }
            SignatureScheme::SlhDsaSha2256f | SignatureScheme::SlhDsaShake256f => {
                SLH_DSA_256_F_SIGNATURE_SIZE
            }
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
