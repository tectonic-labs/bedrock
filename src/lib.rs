//! Tectonic's common cryptography library
//!

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(feature = "falcon", feature = "ml-dsa"))]
#[macro_use]
mod macros;

pub mod error;
#[cfg(feature = "falcon")]
pub mod falcon;
#[cfg(feature = "hhd")]
pub mod hhd;
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;

pub(crate) fn serialize_hex_or_bin<S>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serdect::slice::serialize_hex_lower_or_bin(&bytes, s)
}

pub(crate) fn deserialize_hex_or_bin<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serdect::slice::deserialize_hex_or_bin_vec(d)
}
