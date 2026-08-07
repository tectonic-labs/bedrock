//! Methods for deriving keypairs from a seed and an address index with
//! [BIP-32][bip-32] or [SLIP-0010][slip-0010].
//!
//! # Supported algorithms
//!
//! - [ECDSA secp256k1][ecdsa]: Classical elliptic-curve signatures for Bitcoin and
//!   Ethereum compatibility.
//! - [Falcon-512][falcon]: Post-quantum lattice-based signatures.
//! - ML-DSA-44/65/87: Post-quantum lattice-based signatures.
//! - MAYO-1/2/3: Post-quantum multivariate signatures.
//! - HQC-128/192/256: Post-quantum key encapsulation with 32-byte deterministic seeds.
//!
//! # Modules
//!
//! - [`ecdsa`]: ECDSA secp256k1 keypair implementation.
//! - [`falcon`]: Falcon-512 keypair implementation.
//! - `mldsa`: ML-DSA keypair implementation.
//! - `mayo`: MAYO keypair implementation.
//! - `hqc`: HQC encapsulation and decapsulation keypair derivation.

mod ecdsa;
mod error;
#[cfg(feature = "falcon")]
mod falcon;
#[cfg(feature = "hqc")]
mod hqc;
#[cfg(feature = "mayo")]
mod mayo;
#[cfg(feature = "ml-dsa")]
mod mldsa;
pub use ecdsa::EcdsaSecp256k1;
pub use error::KeyError;
#[cfg(feature = "falcon")]
pub use falcon::FnDsa512;
#[cfg(feature = "hqc")]
pub(crate) use hqc::derive_hqc_keypair;
#[cfg(feature = "mayo")]
pub(crate) use mayo::{Mayo1, Mayo2, Mayo3};
#[cfg(feature = "ml-dsa")]
pub(crate) use mldsa::{MlDsa44, MlDsa65, MlDsa87};
