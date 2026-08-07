//! Tectonic's common cryptography library.
//!

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(
    feature = "bird-of-prey",
    feature = "falcon",
    feature = "frodo",
    feature = "hqc",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "mceliece",
    feature = "ml-kem",
    feature = "mayo",
    feature = "sntrup",
    feature = "xmss"
))]
#[macro_use]
mod macros;

#[cfg(feature = "bird-of-prey")]
pub mod bird_of_prey;
#[cfg(feature = "bird-of-prey")]
pub mod det_rng;
pub mod error;
#[cfg(feature = "falcon")]
pub mod falcon;
#[cfg(feature = "hhd")]
// The module implements deprecated compatibility APIs; downstream uses still warn.
#[allow(deprecated)]
pub mod hhd;
#[cfg(any(
    feature = "frodo",
    feature = "hqc",
    feature = "mceliece",
    feature = "ml-kem",
    feature = "sntrup"
))]
pub mod kem;
#[cfg(feature = "mayo")]
pub mod mayo;
#[cfg(feature = "ml-dsa")]
// The module implements deprecated compatibility APIs; downstream uses still warn.
#[allow(deprecated)]
pub mod ml_dsa;
#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;
#[cfg(feature = "xmss")]
pub mod xmss;
#[cfg(feature = "xwing")]
pub mod xwing;

#[cfg(all(feature = "xwing", not(any(feature = "ml-kem", feature = "mceliece"))))]
compiler_error!(
    "cannot enable `xwing` without selecting an underlying KEM; enable `ml-kem` or `mceliece`"
);

#[cfg(any(
    feature = "bird-of-prey",
    feature = "frodo",
    feature = "hqc",
    feature = "ml-dsa",
    feature = "mceliece",
    feature = "mayo",
    feature = "slh-dsa",
    feature = "sntrup",
    feature = "xmss"
))]
pub(crate) fn os_rng() -> rand_core_010::UnwrapErr<getrandom_v04::SysRng> {
    rand_core_010::UnwrapErr(getrandom_v04::SysRng)
}

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
