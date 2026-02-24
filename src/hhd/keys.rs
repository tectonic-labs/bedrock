//! This module provides methods to derive keypairs from a seed and an address index using [BIP-32][bip-32] and [SLIP-0010][slip-0010].
//!
//! # Signatures supported
//!
//! - [ECDSA secp256k1][ecdsa] : Classic elliptic curve signatures for Bitcoin/Ethereum compatibility
//! - [Falcon-512][falcon]: Post-quantum lattice-based signatures for future security
//!
//! # Modules
//!
//! - [`ecdsa`]: ECDSA secp256k1 keypair implementation
//! - [`falcon`]: Falcon-512 keypair implementation

mod ecdsa;
mod error;
#[cfg(feature = "falcon")]
mod falcon;
#[cfg(feature = "ml-dsa")]
mod mldsa;
#[cfg(feature = "slh-dsa")]
mod slhdsa;

pub use ecdsa::EcdsaSecp256k1;
pub use error::KeyError;
#[cfg(feature = "falcon")]
pub use falcon::FnDsa512;
#[cfg(feature = "ml-dsa")]
pub(crate) use mldsa::{MlDsa44, MlDsa65, MlDsa87};
#[cfg(feature = "slh-dsa")]
pub(crate) use slhdsa::{
    SlhDsaSha2128f, SlhDsaSha2128s, SlhDsaSha2192f, SlhDsaSha2192s, SlhDsaSha2256f, SlhDsaSha2256s,
    SlhDsaShake128f, SlhDsaShake128s, SlhDsaShake192f, SlhDsaShake192s, SlhDsaShake256f,
    SlhDsaShake256s,
};
