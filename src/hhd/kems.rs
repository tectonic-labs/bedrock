//! Key-encapsulation scheme metadata for the hybrid HD wallet.
//!
//! HQC is the first KEM family exposed through HHD. All three parameter sets use a
//! 32-byte deterministic key-generation seed, exactly matching one SLIP-0010 child
//! key. The parameter sets use distinct BIP-85 branches and SLIP-0010 domain
//! separators so their key hierarchies remain independent.

use crate::kem::KemScheme;
use bip32::Seed;
use std::fmt;

/// Size of an HQC deterministic key-generation seed.
pub(crate) const HQC_KEY_GENERATION_SEED_SIZE: usize = 32;

/// Size of the scheme-specific root seed used by HQC HHD derivation.
pub(crate) const HQC_ROOT_SEED_SIZE: usize = 64;

/// Hardened BIP-44 base path used for HQC child key derivation.
pub(crate) const HQC_HARDENED_BASE_PATH: &str = "m/44'/60'/0'/0'";

/// Domain separator used for HQC-128 SLIP-0010 derivation.
pub(crate) const HQC_128_DOMAIN_SEPARATOR: &[u8] = b"HQC-128 seed";

/// Domain separator used for HQC-192 SLIP-0010 derivation.
pub(crate) const HQC_192_DOMAIN_SEPARATOR: &[u8] = b"HQC-192 seed";

/// Domain separator used for HQC-256 SLIP-0010 derivation.
pub(crate) const HQC_256_DOMAIN_SEPARATOR: &[u8] = b"HQC-256 seed";

/// A scheme-specific KEM seed derived from the wallet mnemonic through BIP-85.
pub struct KemSeed {
    scheme: KemScheme,
    seed: Seed,
}

impl KemSeed {
    pub(crate) fn new(scheme: KemScheme, seed: Seed) -> Self {
        Self { scheme, seed }
    }

    /// Returns the KEM scheme associated with this seed.
    pub fn scheme(&self) -> KemScheme {
        self.scheme
    }

    /// Returns the underlying 64-byte scheme root seed.
    pub fn as_seed(&self) -> &Seed {
        &self.seed
    }
}

impl fmt::Debug for KemSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemSeed")
            .field("scheme", &self.scheme)
            .field("seed", &"<64 bytes hidden>")
            .finish()
    }
}

/// Errors returned when a KEM is not defined for HHD derivation.
#[derive(Debug, thiserror::Error)]
pub enum HhdKemSchemeError {
    /// The KEM does not have an HHD derivation definition.
    #[error("KEM scheme '{0}' does not support HHD key derivation")]
    UnsupportedScheme(KemScheme),

    /// The scheme's HHD derivation path could not be parsed.
    #[error("invalid KEM derivation path: {0}")]
    InvalidDerivationPath(String),
}

pub(crate) fn ensure_hhd_supported(scheme: KemScheme) -> Result<(), HhdKemSchemeError> {
    if matches!(
        scheme,
        KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256
    ) {
        Ok(())
    } else {
        Err(HhdKemSchemeError::UnsupportedScheme(scheme))
    }
}

pub(crate) fn domain_separator(scheme: KemScheme) -> Result<&'static [u8], HhdKemSchemeError> {
    if scheme == KemScheme::Hqc128 {
        Ok(HQC_128_DOMAIN_SEPARATOR)
    } else if scheme == KemScheme::Hqc192 {
        Ok(HQC_192_DOMAIN_SEPARATOR)
    } else if scheme == KemScheme::Hqc256 {
        Ok(HQC_256_DOMAIN_SEPARATOR)
    } else {
        Err(HhdKemSchemeError::UnsupportedScheme(scheme))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_seed_debug_redacts_seed_material() {
        let seed = KemSeed::new(KemScheme::Hqc128, Seed::new([0x42; HQC_ROOT_SEED_SIZE]));
        let debug = format!("{seed:?}");

        assert!(debug.contains("Hqc128"));
        assert!(debug.contains("<64 bytes hidden>"));
        assert!(!debug.contains("42, 42"));
        assert_eq!(seed.scheme(), KemScheme::Hqc128);
        assert_eq!(seed.as_seed().as_bytes(), &[0x42; HQC_ROOT_SEED_SIZE]);
    }
}
