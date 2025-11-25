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
}

#[cfg(feature = "oqs")]
impl From<OqsError> for Error {
    fn from(error: OqsError) -> Self {
        Error::OqsError(error.to_string())
    }
}

/// Result type for the library
pub type Result<T> = std::result::Result<T, Error>;
