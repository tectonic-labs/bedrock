//! Multikey, Multisig and Multihash encodings.
//!
//! With the `multiformats` feature (on by default) every key serializes as a
//! [`Multikey`] and every signature as a [`Multisig`], in both binary
//! and human-readable serde formats. Each type also converts with `TryFrom` in both
//! directions, and hash digests convert to and from a [`Multihash`].
//!
//! Only the traits-only builds of the multi-* crates are used: bedrock does all the
//! cryptography, and the multi-* crates only frame the bytes.
//!
//! A scheme with a standard multicodec uses it, with the raw bytes in the `key-data` or
//! `sig-data` attribute. A scheme without one, or whose standard codec defines a
//! different byte format than bedrock's, uses the [`Codec::Identity`] codec: a key adds
//! the `algorithm-name` attribute (the scheme's display name, e.g. `ML-DSA-44`) and the
//! `key-type` attribute (0 public, 1 secret), and a signature adds the `scheme`
//! attribute (the scheme's `u8` value).
//!
//! Decoding is strict. The codec must name the type being decoded, the attribute set
//! must be exactly the one above, comments and multisig messages must be empty, binary
//! input must have no trailing bytes, and the bytes go through the same validation as
//! `from_raw_bytes`.
//!
//! The raw bytes stay available through `to_raw_bytes`, `AsRef<[u8]>` and
//! [`crate::plain`]. Both encodings work side by side: a field can name either one with
//! `#[serde(with = ...)]`, whatever the type's default is.
//!
//! ```
//! # #[cfg(all(feature = "ml-dsa", feature = "kgen"))] {
//! use tectonic_bedrock::ml_dsa::{MlDsaScheme, MlDsaVerificationKey};
//!
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct Keys {
//!     // a Multikey, the same as the type's default
//!     #[serde(with = "tectonic_bedrock::multiformats")]
//!     current: MlDsaVerificationKey,
//!     // the raw `{scheme, value}` shape, with no multiformat framing
//!     #[serde(with = "tectonic_bedrock::plain")]
//!     legacy: MlDsaVerificationKey,
//! }
//!
//! let (current, _) = MlDsaScheme::Dsa65.keypair().unwrap();
//! let (legacy, _) = MlDsaScheme::Dsa87.keypair().unwrap();
//! let json = serde_json::to_string(&Keys { current, legacy }).unwrap();
//! let keys: Keys = serde_json::from_str(&json).unwrap();
//! assert_eq!(keys.legacy.scheme(), MlDsaScheme::Dsa87);
//! # }
//! ```
//!
//! Binary decoding accepts only the canonical encoding. Human-readable decoding goes
//! through the upstream struct form, which also accepts other multibase prefixes for the
//! attribute values.

use serde::{Deserializer, Serialize, Serializer, de::DeserializeOwned};

pub use multi_codec::Codec;
pub use multi_hash::Multihash;
pub use multi_key::Multikey;
pub use multi_sig::Multisig;

#[cfg(any(
    feature = "bird-of-prey",
    feature = "falcon",
    feature = "frodo",
    feature = "hqc",
    feature = "mayo",
    feature = "mceliece",
    feature = "ml-dsa",
    feature = "ml-kem",
    feature = "slh-dsa",
    feature = "sntrup",
    feature = "xmss"
))]
mod envelope;
#[cfg(any(
    feature = "bird-of-prey",
    feature = "falcon",
    feature = "frodo",
    feature = "hqc",
    feature = "mayo",
    feature = "mceliece",
    feature = "ml-dsa",
    feature = "ml-kem",
    feature = "slh-dsa",
    feature = "sntrup",
    feature = "xmss"
))]
pub(crate) use envelope::*;

/// A key or signature whose serde encoding is a Multikey or Multisig.
///
/// Every bedrock key and signature implements it. KEM ciphertexts and shared secrets and
/// the X-Wing types do not, since no multiformat type describes them. It is sealed through
/// [`crate::plain::RawBytes`].
pub trait Multiformat: crate::plain::RawBytes + Serialize + DeserializeOwned {}

/// Serializes `value` as its Multikey or Multisig; use with
/// `#[serde(with = "tectonic_bedrock::multiformats")]`.
pub fn serialize<T: Multiformat, S: Serializer>(
    value: &T,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    value.serialize(s)
}

/// Deserializes a value from its Multikey or Multisig; use with
/// `#[serde(with = "tectonic_bedrock::multiformats")]`.
pub fn deserialize<'de, T: Multiformat, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<T, D::Error> {
    T::deserialize(d)
}

/// Errors from reading a bedrock value out of a multiformat value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MultiformatError {
    /// The codec does not describe the type being decoded.
    #[error("codec {codec} does not encode a {expected}")]
    UnexpectedCodec {
        /// The codec found.
        codec: Codec,
        /// What was being decoded.
        expected: &'static str,
    },
    /// A scheme with a standard codec was encoded with the identity codec.
    #[error("{0} has a standard codec and must not use the identity codec")]
    NonCanonicalIdentity(String),
    /// The attributes are not exactly the set this encoding uses.
    #[error("expected exactly the attributes [{expected}], got [{actual}]")]
    UnexpectedAttributes {
        /// The attribute names this encoding uses.
        expected: String,
        /// The attribute names found.
        actual: String,
    },
    /// A Multikey carried a comment.
    #[error("multikey comments are not supported")]
    Comment,
    /// A Multisig carried a message.
    #[error("multisig messages are not supported")]
    Message,
    /// The `key-type` attribute does not match the type being decoded.
    #[error("key-type attribute does not mark a {0}")]
    KeyType(&'static str),
    /// The `algorithm-name` attribute is not UTF-8.
    #[error("algorithm-name attribute is not UTF-8")]
    AlgorithmName,
    /// The `scheme` attribute is not one minimally encoded varint.
    #[error("scheme attribute is not a minimal varint")]
    SchemeAttribute,
    /// Binary input continued past the end of the value.
    #[error("{0} trailing bytes after the multiformat value")]
    TrailingBytes(usize),
    /// Binary input decoded, but is not the value's one canonical encoding.
    #[error("binary multiformat value is not canonically encoded")]
    NonCanonical,
    /// A multi-key error.
    #[error(transparent)]
    Multikey(#[from] multi_key::Error),
    /// A multi-sig error.
    #[error(transparent)]
    Multisig(#[from] multi_sig::Error),
    /// A multi-hash error.
    #[error(transparent)]
    Multihash(#[from] multi_hash::Error),
}
