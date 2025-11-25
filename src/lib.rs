//! Tectonic's common cryptography library
//!

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(feature = "falcon", feature = "ml-dsa"))]
#[macro_use]
mod macros;

pub mod error;
#[cfg(feature = "falcon")]
pub mod falcon;
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;
