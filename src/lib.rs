//! Tectonic's common cryptography library
//!

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod error;
pub mod falcon;

#[cfg(feature = "eth_falcon")]
pub mod eth_falcon;
