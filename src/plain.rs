//! Raw bytes, and the `{scheme, value}` serde shape used before multiformats.
//!
//! Every byte-backed key, signature, ciphertext and shared secret implements [`RawBytes`].
//! Its bytes are exactly what the algorithm defines, with no multiformat framing, and the
//! inherent `to_raw_bytes` / `from_raw_bytes` methods on each type give the same bytes.
//!
//! With the `multiformats` feature, keys serialize as a Multikey and signatures as a
//! Multisig. [`Plain`] and the [`serialize`] / [`deserialize`] functions keep the older
//! `{scheme, value}` shape instead, for reading data written by earlier releases or for
//! storing values without multiformat framing:
//!
//! ```
//! # #[cfg(feature = "ml-dsa")] {
//! use tectonic_bedrock::{ml_dsa::MlDsaVerificationKey, plain::Plain};
//!
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct Stored {
//!     #[serde(with = "tectonic_bedrock::plain")]
//!     key: MlDsaVerificationKey,
//!     // the same shape as a field type
//!     backup: Plain<MlDsaVerificationKey>,
//! }
//! # }
//! ```

use crate::error::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use std::{fmt::Display, str::FromStr};

pub(crate) mod sealed {
    /// Restricts [`super::RawBytes`] to bedrock's own types.
    pub trait Sealed {}
}

/// A byte-backed key, signature, ciphertext or shared secret, read through its raw bytes.
pub trait RawBytes: AsRef<[u8]> + Sized + sealed::Sealed {
    /// The scheme that says how to read the bytes.
    type Scheme: Copy
        + Display
        + FromStr<Err = Error>
        + Into<u8>
        + TryFrom<u8, Error = Error>
        + Serialize
        + DeserializeOwned;

    /// Returns the scheme of this value.
    fn scheme(&self) -> Self::Scheme;

    /// Builds a value from raw bytes, checking them against `scheme`.
    fn from_raw_bytes(scheme: Self::Scheme, bytes: &[u8]) -> Result<Self>;
}

/// Serializes the wrapped value in the `{scheme, value}` shape, without multiformat framing.
///
/// `value` is hex in human-readable formats and raw bytes in binary formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plain<T>(pub T);

impl<T> From<T> for Plain<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: RawBytes> Serialize for Plain<T> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        serialize(&self.0, s)
    }
}

impl<'de, T: RawBytes> Deserialize<'de> for Plain<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        deserialize(d).map(Self)
    }
}

#[derive(Serialize)]
struct ShapeRef<'a, S> {
    scheme: S,
    #[serde(serialize_with = "serdect::slice::serialize_hex_lower_or_bin")]
    value: &'a [u8],
}

#[derive(Deserialize)]
struct Shape<S> {
    scheme: S,
    #[serde(deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec")]
    value: Vec<u8>,
}

/// Serializes `value` in the `{scheme, value}` shape; use with `#[serde(with = "plain")]`.
pub fn serialize<T: RawBytes, S: Serializer>(
    value: &T,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    ShapeRef {
        scheme: value.scheme(),
        value: value.as_ref(),
    }
    .serialize(s)
}

/// Deserializes a value from the `{scheme, value}` shape, checking the bytes against the
/// scheme; use with `#[serde(with = "plain")]`.
pub fn deserialize<'de, T: RawBytes, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<T, D::Error> {
    let shape = Shape::<T::Scheme>::deserialize(d)?;
    let value = T::from_raw_bytes(shape.scheme, &shape.value).map_err(serde::de::Error::custom);
    #[cfg(feature = "zeroize")]
    {
        let mut bytes = shape.value;
        zeroize::Zeroize::zeroize(&mut bytes);
    }
    value
}
