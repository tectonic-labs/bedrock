//! Error types for the library

use thiserror::Error as ThisError;

/// Number of one-time-signature leaves in an XMSS key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeavesCount(pub u64);

impl core::fmt::Display for LeavesCount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

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
    /// HQC error
    #[error("HQC error: {0}")]
    HqcError(String),
    /// FrodoKEM error
    #[error("FrodoKEM error: {0}")]
    FrodoError(String),
    /// Streamlined NTRU Prime error
    #[error("sntrup761 error: {0}")]
    SntrupError(String),
    /// XMSS error
    #[error("XMSS error: {0}")]
    XmssError(String),
    /// The XMSS one-time-signature leaves for this key are exhausted; no further
    /// signatures may be produced without revealing the secret key.
    #[error("XMSS key exhausted: all {0} one-time-signature leaves have been consumed")]
    XmssKeyExhausted(LeavesCount),
    /// Bird-of-Prey hybrid signature error
    #[error("Bird-of-Prey error: {0}")]
    BirdOfPreyError(String),
    /// Deterministic RNG error
    #[error("deterministic RNG error: {0}")]
    DetRngError(String),
    /// A key or signature belonging to one scheme was passed to a different scheme.
    ///
    /// Byte length is never a reliable discriminator between parameter sets — MAYO-1
    /// and MAYO-2 share a 24-byte compact secret key, and FrodoKEM's AES and SHAKE
    /// variants are byte-identical in every dimension — so every dispatch method binds
    /// to the stored scheme and reports this error on mismatch.
    #[error("scheme mismatch: expected '{expected}', got '{actual}'")]
    SchemeMismatch {
        /// The scheme the operation was invoked on.
        expected: String,
        /// The scheme the supplied key or signature actually carries.
        actual: String,
    },
    /// Invalid scheme
    #[error("Invalid scheme: {0}")]
    InvalidScheme(u8),
    /// Invalid scheme
    #[error("Invalid scheme: {0}")]
    InvalidSchemeStr(String),
    /// A deprecated scheme, removed for being too weak, was requested (e.g. when
    /// deserializing data produced by an older version of the library).
    #[error(
        "scheme '{scheme}' is deprecated and no longer supported (too weak); use '{replacement}' or a stronger parameter set"
    )]
    DeprecatedScheme {
        /// The deprecated scheme identifier that was requested.
        scheme: &'static str,
        /// The recommended replacement scheme.
        replacement: &'static str,
    },
    /// A scheme reached a dispatcher that does not handle its family.
    ///
    /// The KEM families are dispatched by separate arms, so this indicates the scheme
    /// enum and the dispatch tables have drifted apart — a library invariant violation
    /// rather than bad caller input. It is an error rather than a panic so that a
    /// mis-wiring in a rarely-exercised feature combination degrades to a failed call
    /// instead of taking the process down.
    #[error("internal dispatch error: {0}")]
    SchemeDispatch(&'static str),
    /// Seed-derived key generation is not offered for this scheme.
    ///
    /// Seed-derived (and therefore HD-wallet) key generation is only offered where the
    /// scheme's deterministic seed is 32 bytes or fewer, so that a single SLIP-0010
    /// child key can supply it without expansion. Schemes needing a larger seed —
    /// FrodoKEM among them — refuse rather than invent the extra material.
    #[error("deterministic key generation is not supported: {0}")]
    DeterministicKeygenUnsupported(&'static str),
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
