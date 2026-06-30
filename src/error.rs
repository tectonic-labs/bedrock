//! Error types for the library

use thiserror::Error as ThisError;

/// Error type for the library
#[derive(ThisError, Debug)]
pub enum Error {
    /// Classic McEliece error
    #[error("Classic McEliece error: {0}")]
    McElieceError(String),
    /// ML-DSA error
    #[error("ML-DSA error: {0}")]
    MlDsaError(String),
    /// ML-KEM error
    #[error("ML-KEM error: {0}")]
    MlKemError(String),
    /// MAYO error
    #[error("MAYO error: {0}")]
    MayoError(String),
    /// SLH-DSA error
    #[error("SLH-DSA error: {0}")]
    SlhDsaError(String),
    /// Invalid scheme
    #[error("Invalid scheme: {0}")]
    InvalidScheme(u8),
    /// Invalid scheme
    #[error("Invalid scheme: {0}")]
    InvalidSchemeStr(String),
    /// Invalid seed length
    #[error("Invalid seed length: got {0}")]
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

/// Result type for the library
pub type Result<T> = std::result::Result<T, Error>;
