//! Error types for the library

#[cfg(feature = "oqs")]
use oqs::Error as OqsError;
use thiserror::Error as ThisError;

/// Error type for the library
#[derive(ThisError, Debug)]
pub enum Error {
    /// OQS error
    #[error("OQS error: {0}")]
    OqsError(String),
    /// Invalid scheme
    #[error("Invalid scheme: {0}")]
    InvalidScheme(u8),
    /// Invalid scheme
    #[error("Invalid scheme: {0}")]
    InvalidSchemeStr(String),
    /// Invalid seed length
    #[error("Invalid seed length: expected at least 32 bytes, got {0}")]
    InvalidSeedLength(usize),
    /// Invalid length
    #[error("Invalid length: {0}")]
    InvalidLength(usize),
    /// Errors related to ETH-FALCON DSA
    #[error("An error occurred with eth-falcon: {0}")]
    FnDsaError(String),
    /// SLIP-10 derivation errors
    #[cfg(feature = "hhd")]
    #[error("SLIP-10 error: {0}")]
    Slip10Error(#[from] crate::hhd::Slip10Error),
    /// Signature scheme errors
    #[cfg(feature = "hhd")]
    #[error("Signature scheme error: {0}")]
    SignatureSchemeError(#[from] crate::hhd::SignatureSchemeError),
    /// Key errors
    #[cfg(feature = "hhd")]
    #[error("Key error: {0}")]
    KeyError(#[from] crate::hhd::KeyError),
    /// Mnemonic errors
    #[cfg(feature = "hhd")]
    #[error("Mnemonic error: {0}")]
    MnemonicError(#[from] crate::hhd::MnemonicError),
    /// BIP-85 errors
    #[cfg(feature = "hhd")]
    #[error("BIP-82 error: {0}")]
    Bip85Error(#[from] crate::hhd::Bip85Error),
    /// HD wallet errors
    #[cfg(feature = "hhd")]
    #[error("HD wallet error: {0}")]
    WalletError(#[from] crate::hhd::WalletError),
}

#[cfg(feature = "oqs")]
impl From<OqsError> for Error {
    fn from(error: OqsError) -> Self {
        Error::OqsError(error.to_string())
    }
}

/// Result type for the library
pub type Result<T> = std::result::Result<T, Error>;
