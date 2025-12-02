//! Key-related error types.

use crate::hhd::signatures::SignatureSchemeError;
use crate::hhd::slip10::Slip10Error;

/// Error type for key operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Invalid or unsupported signature scheme.
    #[error("Invalid scheme")]
    InvalidScheme(#[from] SignatureSchemeError),

    /// Signature generation failed.
    #[error("Signature generation failed: {0}")]
    SigningFailed(String),

    /// Signature verification process failed.
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    /// Signature format is invalid or cannot be parsed.
    #[error("Invalid signature format")]
    InvalidSignatureFormat,

    /// Key format is invalid or cannot be parsed.
    #[error("Invalid key format")]
    InvalidKeyFormat,

    /// Invalid derivation path string.
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    /// BIP-32 derivation error.
    #[error("BIP32 error: {0}")]
    Bip32(#[from] bip32::Error),

    /// SLIP-0010 derivation error.
    #[error("SLIP10 error: {0}")]
    Slip10(#[from] Slip10Error),

    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Key serialization failed.
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// Key deserialization failed.
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    /// ECDSA-specific error.
    #[error("ECDSA error: {0}")]
    EcdsaError(String),

    /// Falcon-specific error.
    #[error("Falcon error: {0}")]
    FalconError(String),

    /// Seed length doesn't match expected size.
    #[error("Invalid seed length: expected {expected}, got {actual}")]
    InvalidSeedLength {
        /// Expected seed length in bytes.
        expected: usize,
        /// Actual seed length in bytes.
        actual: usize,
    },

    /// Signature scheme not supported for this operation.
    #[error("Unsupported signature scheme")]
    UnsupportedScheme,
}
