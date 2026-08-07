#![warn(missing_docs)]

//! # Hybrid Hierarchical Deterministic (HD) Wallet Library
//!
//! This library provides a framework for managing hybrid
//! [hierarchical deterministic (HD) wallets](https://en.bitcoin.it/wiki/Deterministic_wallet).
//! A single
//! [BIP-39 mnemonic](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
//! can supply independent hierarchies for conventional
//! [ECDSA secp256k1](https://en.bitcoin.it/wiki/Secp256k1) keys, post-quantum signature
//! keys, and HHD-enabled KEM keys. Bedrock implements Falcon/FN-DSA in pure Rust through
//! the [`fn-dsa`](https://crates.io/crates/fn-dsa) crates.
//!
//! ## Features
//!
//! - **Multi-scheme support**: Derives signature and HQC KEM keys from one wallet.
//! - **Single mnemonic**: Uses one BIP-39 mnemonic to derive all scheme-specific seeds.
//! - **BIP-85 derivation**: Derives scheme-specific seeds according to BIP-85.
//! - **BIP-32 and SLIP-0010**: Supports BIP-32 for ECDSA and SLIP-0010 for post-quantum
//!   schemes.
//! - **Deterministic derivation**: Derives every key from the master seed.
//! - **Cryptographic separation**: Uses independent derivation paths for each scheme.
//!
//! ## Quick Start
//!
//! ### Creating and Using a Hybrid HD Wallet with ECDSA and Falcon
//! ```ignore
//! // This example requires the sign, vrfy, and falcon features.
//! use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
//!
//! // Create a new wallet with ECDSA and Falcon support.
//! let wallet = HHDWallet::new(
//!     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
//!     None, // Optional BIP-39 passphrase.
//! ).unwrap();
//!
//! // Derive an ECDSA keypair at address index 0.
//! let (ecdsa_sk, ecdsa_vk) = wallet.derive_ecdsa_secp256k1_keypair(
//!     0,
//! ).unwrap();
//!
//! // Sign and verify with ECDSA.
//! use tectonic_bedrock::hhd::ecdsa::{
//!     signature::{Signer, Verifier},
//!     Signature,
//! };
//!
//! let message = b"Hello, world!";
//! let ecdsa_signature: Signature = ecdsa_sk.sign(message);
//! let verified = ecdsa_vk.verify(message, &ecdsa_signature);
//! assert!(verified.is_ok());
//!
//! // Derive a Falcon keypair at address index 0.
//! let (falcon_sk, falcon_vk) = wallet.derive_fn_dsa512_keypair(
//!     0,
//! ).unwrap();
//!
//! // Sign and verify with Falcon.
//! use tectonic_bedrock::falcon::FalconScheme;
//! let falcon_signature = FalconScheme::Dsa512.sign(message, &falcon_sk).unwrap();
//! let falcon_verified = FalconScheme::Dsa512.verify(message, &falcon_signature, &falcon_vk);
//! assert!(falcon_verified.is_ok());
//! ```
//!
//! ### Importing a Wallet from an Existing Mnemonic Phrase
//! ```no_run
//! use tectonic_bedrock::hhd::{HHDWallet, Mnemonic, SignatureScheme};
//!
//! // Your BIP-39 phrase (for example, a 24-word phrase)
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
//!
//! // You can optionally provide a BIP-39 passphrase.
//! let password = Some("my secret password");
//!
//! // Import the wallet with ECDSA and Falcon enabled.
//! let wallet = HHDWallet::new_from_mnemonic(
//!     mnemonic,
//!     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
//!     password,
//! ).unwrap();
//!
//! // The wallet can now derive ECDSA and Falcon keypairs.
//! ```
//!
//! ## Architecture
//!
//! The hybrid HD wallet architecture supports multiple schemes in one wallet while
//! maintaining cryptographic separation.
//!
//! ## Overview
//!
//! The wallet follows a hierarchical derivation model:
//!
//! 1. **Master mnemonic** (BIP-39): A 24-word mnemonic is the wallet's root entropy.
//! 2. **Scheme-specific seeds** (BIP-85): Each configured signature scheme or KEM receives
//!    its own 64-byte seed.
//! 3. **Keypairs** (BIP-32/SLIP-0010): Address indices derive individual keypairs from the
//!    scheme-specific seeds.
//!
//! This design ensures that:
//!
//! - Every key can be restored from the mnemonic alone.
//! - Different schemes use cryptographically independent seeds.
//!
//! ## Derivation Paths
//!
//! ### BIP-85 Scheme Seed Derivation
//!
//! Each scheme receives a unique seed through BIP-85 derivation from the master mnemonic:
//!
//! - **ECDSA secp256k1**: `m/83696968'/83286642'/1'`
//! - **Falcon-512**: `m/83696968'/83286642'/2'`
//! - **ML-DSA-44/65/87**: `m/83696968'/83286642'/4'`, `/5'`, and `/6'`
//! - **MAYO-1/2/3**: `m/83696968'/83286642'/7'`, `/8'`, and `/9'`
//! - **HQC-128/192/256**: `m/83696968'/83286642'/10'`, `/11'`, and `/12'`
//!
//! The base path `m/83696968'` is the standard BIP-85 path, `/83286642'` spells
//! "Tectonic" on a T9 keypad, and the final component identifies the scheme. Although the
//! schemes share a mnemonic, they operate on cryptographically independent seeds.
//!
//! ### Key Derivation Paths
//!
//! After obtaining a scheme-specific seed, address indices derive individual keypairs.
//!
//! **ECDSA secp256k1** (BIP-32, BIP-44):
//!
//! - Domain separator: `Bitcoin seed`
//! - Base path: `m/44'/60'/0'/0`
//! - Full path: `m/44'/60'/0'/0/{address_index}`
//! - Standard: BIP-32 (non-hardened address index)
//! - Example for address index 0: `m/44'/60'/0'/0/0`
//!
//! **Falcon-512** (SLIP-0010, hardened):
//!
//! - Domain separator: `Falcon-512 seed`
//! - Base path: `m/44'/60'/0'/0'`
//! - Full path: `m/44'/60'/0'/0'/{address_index}'`
//! - Standard: SLIP-0010 (all components hardened)
//! - Example for address index 0: `m/44'/60'/0'/0'/0'`
//!
//! ### Key Differences
//!
//! | Scheme family | BIP-85 index | HD standard | Address index |
//! |---------------|--------------|-------------|---------------|
//! | ECDSA secp256k1 | `1'` | BIP-32 | Non-hardened |
//! | Falcon-512 | `2'` | SLIP-0010 | Hardened |
//! | ML-DSA-44/65/87 | `4'`/`5'`/`6'` | SLIP-0010 | Hardened |
//! | MAYO-1/2/3 | `7'`/`8'`/`9'` | SLIP-0010 | Hardened |
//! | HQC-128/192/256 | `10'`/`11'`/`12'` | SLIP-0010 | Hardened |
//!
//! For detailed implementation information, see [ARCHITECTURE.md].
//!
//! ## Standards
//!
//! This library implements the following standards:
//!
//! - [BIP-39]: Mnemonic code for generating deterministic keys.
//! - [BIP-32]: Hierarchical deterministic wallets.
//! - [BIP-44]: Multi-account hierarchy for deterministic wallets.
//! - [BIP-85]: Deterministic entropy from BIP-32 keychains.
//! - [SLIP-0010]: Universal private-key derivation from a master private key.
//!
//! [ARCHITECTURE.md]: https://github.com/tectonic-labs/bedrock/blob/main/src/hhd/ARCHITECTURE.md
//! [BIP-39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
//! [BIP-32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//! [BIP-44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
//! [BIP-85]: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
//! [SLIP-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

mod bip85;
#[cfg(feature = "hqc")]
mod kems;
mod keys;
mod mnemonic;
mod signatures;
mod slip10;

pub use bip32::secp256k1::ecdsa;
pub use bip85::{Bip85, Bip85Error};
#[cfg(feature = "hqc")]
pub use kems::{HhdKemSchemeError, KemSeed};
pub use keys::KeyError;
pub use mnemonic::{Mnemonic, MnemonicError};
pub use signatures::{SignatureScheme, SignatureSchemeError, SignatureSeed};
pub use slip10::Slip10Error;

#[cfg(feature = "falcon")]
use crate::falcon::{FalconSigningKey, FalconVerificationKey};
#[cfg(feature = "hqc")]
use crate::kem::{KemDecapsulationKey, KemEncapsulationKey, KemScheme};
#[cfg(feature = "mayo")]
use crate::mayo::{MayoSigningKey, MayoVerificationKey};
#[cfg(feature = "ml-dsa")]
use crate::ml_dsa::{MlDsaSigningKey, MlDsaVerificationKey};
use bip32::secp256k1::ecdsa::{SigningKey, VerifyingKey};
#[cfg(feature = "hqc")]
use keys::derive_hqc_keypair as derive_hqc_keypair_from_seed;
use keys::EcdsaSecp256k1;
#[cfg(feature = "falcon")]
use keys::FnDsa512;
#[cfg(feature = "mayo")]
use keys::{Mayo1, Mayo2, Mayo3};
#[cfg(feature = "ml-dsa")]
use keys::{MlDsa44, MlDsa65, MlDsa87};
use std::{collections::HashMap, fmt};

/// A hybrid hierarchical deterministic (HD) wallet derived from one BIP-39 mnemonic.
///
/// This wallet structure enables managing multiple signature schemes and HHD-enabled KEMs
/// from a single BIP-39 mnemonic phrase. Each configured scheme gets its own
/// scheme-specific seed derived using BIP-85, ensuring cryptographic seed separation while
/// maintaining a unified wallet structure.
///
/// # Key Concepts
///
/// - **Master mnemonic**: A BIP-39 mnemonic phrase that serves as the root entropy.
/// - **Scheme-specific seeds**: Each configured signature or KEM has its own BIP-85 seed.
/// - **Address indexing**: Hierarchical paths derive keys from scheme-specific seeds.
/// - **Cryptographic isolation**: Different schemes use different derived seeds.
///
/// # Derivation Flow
///
/// 1. **Master mnemonic** → BIP-39 seed conversion.
/// 2. **BIP-85 derivation** → Scheme-specific seed for each configured algorithm.
/// 3. **HD key derivation** → Keypairs at specific address indices.
///    - ECDSA uses BIP-32 with BIP-44 paths.
///    - Falcon, ML-DSA, MAYO, and HQC use SLIP-0010 with hardened paths.
///
/// # Example
///
/// ```ignore
/// // This example requires the `falcon` feature.
/// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
///
/// // Create a wallet with both schemes.
/// let wallet = HHDWallet::new(
///     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
///     None,
/// ).unwrap();
///
/// // Get the mnemonic and back it up.
/// let mnemonic_phrase = wallet.mnemonic().to_phrase();
///
/// // Derive keypairs for both schemes at the same address index.
/// let (ecdsa_sk, ecdsa_vk) = wallet.derive_ecdsa_secp256k1_keypair(0).unwrap();
/// let (falcon_sk, falcon_vk) = wallet.derive_fn_dsa512_keypair(0).unwrap();
/// ```
pub struct HHDWallet {
    /// Root mnemonic phrase (BIP-39 compatible) used to derive all scheme-specific seeds.
    pub mnemonic: Mnemonic,
    /// Master seeds indexed by signature scheme, derived from the mnemonic using BIP-85.
    /// All seeds are zeroized on drop according to the `bip32` crate's implementation.
    pub master_seeds: HashMap<SignatureScheme, SignatureSeed>,
    /// Master seeds for HHD-enabled KEMs, derived independently through BIP-85.
    #[cfg(feature = "hqc")]
    pub kem_master_seeds: HashMap<KemScheme, KemSeed>,
}

impl fmt::Debug for HHDWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("HHDWallet");
        debug
            .field("mnemonic", &"<redacted>")
            .field("master_seeds", &self.master_seeds);
        #[cfg(feature = "hqc")]
        debug.field("kem_master_seeds", &self.kem_master_seeds);
        debug.finish()
    }
}

impl HHDWallet {
    /// Creates a new hybrid HD wallet from a given mnemonic phrase.
    ///
    /// This method takes an existing BIP-39 mnemonic and derives scheme-specific seeds
    /// for each provided signature scheme using BIP-85. This allows you to restore a
    /// wallet from a known mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - The BIP-39 mnemonic phrase to derive the wallet from
    /// * `schemes` - A vector of signature schemes to support in this wallet
    /// * `password` - Optional BIP-39 passphrase (adds extra security to the mnemonic)
    ///
    /// # Returns
    ///
    /// * `Ok(HHDWallet)` - The newly created wallet with derived seeds
    /// * `Err(WalletError)` - If seed derivation fails for any scheme
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `Bip85Error`: If BIP-85 seed derivation fails
    /// - `Mnemonic`: If mnemonic processing fails
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, Mnemonic, SignatureScheme};
    ///
    /// let mnemonic = Mnemonic::from_phrase(
    ///     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    /// ).unwrap();
    ///
    /// let wallet = HHDWallet::new_from_mnemonic(
    ///     mnemonic,
    ///     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
    ///     None, // Optional passphrase
    /// ).unwrap();
    /// ```
    pub fn new_from_mnemonic(
        mnemonic: Mnemonic,
        schemes: Vec<SignatureScheme>,
        password: Option<&str>,
    ) -> Result<Self, WalletError> {
        let mut master_seeds = HashMap::new();
        for scheme in schemes {
            let child_seed = Bip85::derive_seed_from_mnemonic(mnemonic.clone(), scheme, password)?;
            master_seeds.insert(scheme, child_seed);
        }

        Ok(HHDWallet {
            mnemonic,
            master_seeds,
            #[cfg(feature = "hqc")]
            kem_master_seeds: HashMap::new(),
        })
    }

    /// Creates a new hybrid HD wallet with a randomly generated mnemonic.
    ///
    /// This method generates a new random BIP-39 mnemonic phrase (24 words) and derives
    /// scheme-specific seeds for each provided signature scheme. This is the recommended
    /// way to create a new wallet.
    ///
    /// # Important
    ///
    /// **Backup the mnemonic phrase!** The wallet can only be restored if you have the
    /// mnemonic phrase. Use `wallet.mnemonic().to_phrase()` to get the phrase.
    ///
    /// # Arguments
    ///
    /// * `schemes` - A vector of signature schemes to support in this wallet
    /// * `password` - Optional BIP-39 passphrase (adds an extra security layer)
    ///
    /// # Returns
    ///
    /// * `Ok(HHDWallet)` - The newly created wallet with a random mnemonic
    /// * `Err(WalletError)` - If wallet creation fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` if seed derivation fails for any scheme.
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// // Create a new wallet supporting both ECDSA and Falcon
    /// let wallet = HHDWallet::new(
    ///     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
    ///     None, // Optional passphrase
    /// ).unwrap();
    ///
    /// // Save the mnemonic phrase for backup
    /// let mnemonic_phrase = wallet.mnemonic().to_phrase();
    /// println!("Your mnemonic phrase: {}", mnemonic_phrase);
    /// ```
    pub fn new(schemes: Vec<SignatureScheme>, password: Option<&str>) -> Result<Self, WalletError> {
        let mnemonic = Mnemonic::new_random();
        Self::new_from_mnemonic(mnemonic, schemes, password)
    }

    /// Creates a wallet from a mnemonic with both signature and HQC KEM branches.
    ///
    /// Existing signature-only constructors remain unchanged. Use this constructor when
    /// one or more HQC parameter sets should be available for hierarchical derivation.
    /// Each KEM receives an independent BIP-85 root seed.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError`] if mnemonic processing, BIP-85 derivation, or KEM
    /// validation fails. Currently HQC-128, HQC-192, and HQC-256 are the HHD-enabled
    /// KEMs.
    #[cfg(feature = "hqc")]
    pub fn new_from_mnemonic_with_kem_schemes(
        mnemonic: Mnemonic,
        signature_schemes: Vec<SignatureScheme>,
        kem_schemes: Vec<KemScheme>,
        password: Option<&str>,
    ) -> Result<Self, WalletError> {
        let mut wallet = Self::new_from_mnemonic(mnemonic, signature_schemes, password)?;
        for scheme in kem_schemes {
            let child_seed =
                Bip85::derive_kem_seed_from_mnemonic(&wallet.mnemonic, scheme, password)?;
            wallet.kem_master_seeds.insert(scheme, child_seed);
        }
        Ok(wallet)
    }

    /// Creates a wallet with a random mnemonic and both signature and HQC KEM branches.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError`] if scheme-specific seed derivation fails.
    #[cfg(feature = "hqc")]
    pub fn new_with_kem_schemes(
        signature_schemes: Vec<SignatureScheme>,
        kem_schemes: Vec<KemScheme>,
        password: Option<&str>,
    ) -> Result<Self, WalletError> {
        Self::new_from_mnemonic_with_kem_schemes(
            Mnemonic::new_random(),
            signature_schemes,
            kem_schemes,
            password,
        )
    }

    /// Gets a reference to the wallet's mnemonic phrase.
    ///
    /// The mnemonic is the root entropy source for the entire wallet. All scheme-specific
    /// seeds are deterministically derived from this mnemonic using BIP-85.
    ///
    /// # Returns
    ///
    /// A reference to the `Mnemonic` instance containing the BIP-39 phrase.
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::EcdsaSecp256k1], None).unwrap();
    /// let mnemonic_phrase = wallet.mnemonic().to_phrase();
    /// println!("Mnemonic: {}", mnemonic_phrase);
    /// ```
    pub fn mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    /// Gets a reference to the master seeds map.
    ///
    /// Returns a map of signature schemes to their corresponding scheme-specific seeds.
    /// These seeds are derived from the master mnemonic using BIP-85 and serve as the
    /// root for hierarchical key derivation in each scheme.
    ///
    /// # Returns
    ///
    /// A reference to the `HashMap` mapping signature schemes to their seeds.
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(
    ///     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
    ///     None,
    /// ).unwrap();
    ///
    /// let master_seeds = wallet.master_seeds();
    /// assert!(master_seeds.contains_key(&SignatureScheme::EcdsaSecp256k1));
    /// assert!(master_seeds.contains_key(&SignatureScheme::Falcon512));
    /// ```
    pub fn master_seeds(&self) -> &HashMap<SignatureScheme, SignatureSeed> {
        &self.master_seeds
    }

    /// Gets the KEM-specific BIP-85 root seeds configured in this wallet.
    #[cfg(feature = "hqc")]
    pub fn kem_master_seeds(&self) -> &HashMap<KemScheme, KemSeed> {
        &self.kem_master_seeds
    }

    /// Derives an ECDSA secp256k1 keypair at the given address index.
    ///
    /// This method derives an ECDSA secp256k1 keypair using the scheme-specific seed and
    /// the provided address index. The derivation path is
    /// `m/44'/60'/0'/0/{address_index}` (BIP-44 path).
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index (non-negative integer)
    ///
    /// # Returns
    ///
    /// * `Ok(SigningKey, VerifyingKey)` - The derived ECDSA secp256k1 keypair
    /// * `Err(WalletError)` - If derivation fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If ECDSA secp256k1 is not supported in this wallet
    /// - `KeyError`: If key derivation fails
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::EcdsaSecp256k1], None).unwrap();
    ///
    /// // Derive an ECDSA keypair at address index 0.
    /// let (ecdsa_sk, ecdsa_vk) = wallet.derive_ecdsa_secp256k1_keypair(0).unwrap();
    ///
    /// // Derive another keypair at address index 1
    /// let (ecdsa_sk2, ecdsa_vk2) = wallet.derive_ecdsa_secp256k1_keypair(1).unwrap();
    /// ```
    pub fn derive_ecdsa_secp256k1_keypair(
        &self,
        address_index: u32,
    ) -> Result<(SigningKey, VerifyingKey), WalletError> {
        // 1. Extract child seed for the corresponding scheme
        let signature_seed = self
            .master_seeds
            .get(&SignatureScheme::EcdsaSecp256k1)
            .ok_or(WalletError::InvalidScheme)?;
        let seed_bytes = signature_seed.as_seed().as_bytes();

        EcdsaSecp256k1::derive_from_seed(seed_bytes, address_index).map_err(WalletError::KeyError)
    }

    #[cfg(feature = "falcon")]
    /// Derives a Falcon-512 keypair at the given address index.
    ///
    /// This method derives a Falcon-512 keypair using the scheme-specific seed and the
    /// provided address index. The derivation path is
    /// `m/44'/60'/0'/0'/{address_index}'` (hardened path).
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index (non-negative integer)
    ///
    /// # Returns
    ///
    /// * `Ok(FalconSigningKey, FalconVerificationKey)` - The derived Falcon-512 keypair
    /// * `Err(WalletError)` - If derivation fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If Falcon-512 is not supported in this wallet
    /// - `KeyError`: If key derivation fails
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::Falcon512], None).unwrap();
    ///
    /// // Derive a Falcon keypair at address index 0.
    /// let (falcon_sk, falcon_vk) = wallet.derive_fn_dsa512_keypair(0).unwrap();
    ///
    /// // Derive another keypair at address index 1
    /// let (falcon_sk2, falcon_vk2) = wallet.derive_fn_dsa512_keypair(1).unwrap();
    /// ```
    pub fn derive_fn_dsa512_keypair(
        &self,
        address_index: u32,
    ) -> Result<(FalconSigningKey, FalconVerificationKey), WalletError> {
        // 1. Extract child seed for the Falcon-512 scheme
        let signature_seed = self
            .master_seeds
            .get(&SignatureScheme::Falcon512)
            .ok_or(WalletError::InvalidScheme)?;
        let seed_bytes = signature_seed.as_seed().as_bytes();

        FnDsa512::derive_from_seed(seed_bytes, address_index).map_err(WalletError::KeyError)
    }

    #[cfg(feature = "ml-dsa")]
    /// Derives an ML-DSA-44 keypair at the given address index.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::InvalidScheme`] if ML-DSA-44 is not configured in this wallet,
    /// or [`WalletError::KeyError`] if key derivation fails.
    #[deprecated(since = "0.3.0", note = "use derive_mldsa65_keypair")]
    pub fn derive_mldsa44_keypair(
        &self,
        address_index: u32,
    ) -> Result<(MlDsaSigningKey, MlDsaVerificationKey), WalletError> {
        let signature_seed = self
            .master_seeds
            .get(&SignatureScheme::MlDsa44)
            .ok_or(WalletError::InvalidScheme)?;
        let seed_bytes = signature_seed.as_seed().as_bytes();

        MlDsa44::derive_from_seed(seed_bytes, address_index).map_err(WalletError::KeyError)
    }

    #[cfg(feature = "ml-dsa")]
    /// Derives an ML-DSA-65 keypair at the given address index.
    ///
    /// This method derives an ML-DSA-65 keypair using the scheme-specific seed and the
    /// provided address index. The derivation path is
    /// `m/44'/60'/0'/0'/{address_index}'` (hardened path).
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index (non-negative integer)
    ///
    /// # Returns
    ///
    /// * `Ok(MlDsaSigningKey, MlDsaVerificationKey)` - The derived ML-DSA-65 keypair
    /// * `Err(WalletError)` - If derivation fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If ML-DSA-65 is not supported in this wallet
    /// - `KeyError`: If key derivation fails
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::MlDsa65], None).unwrap();
    ///
    /// // Derive ML-DSA keypair at address index 0
    /// let (mldsa_sk, mldsa_vk) = wallet.derive_mldsa65_keypair(0).unwrap();
    ///
    /// // Derive another keypair at address index 1
    /// let (mldsa_sk2, mldsa_vk2) = wallet.derive_mldsa65_keypair(1).unwrap();
    /// ```
    pub fn derive_mldsa65_keypair(
        &self,
        address_index: u32,
    ) -> Result<(MlDsaSigningKey, MlDsaVerificationKey), WalletError> {
        // 1. Extract the child seed for the ML-DSA-65 scheme.
        let signature_seed = self
            .master_seeds
            .get(&SignatureScheme::MlDsa65)
            .ok_or(WalletError::InvalidScheme)?;
        let seed_bytes = signature_seed.as_seed().as_bytes();

        MlDsa65::derive_from_seed(seed_bytes, address_index).map_err(WalletError::KeyError)
    }

    #[cfg(feature = "ml-dsa")]
    /// Derives an ML-DSA-87 keypair at the given address index.
    ///
    /// This method derives an ML-DSA-87 keypair using the scheme-specific seed and the
    /// provided address index. The derivation path is
    /// `m/44'/60'/0'/0'/{address_index}'` (hardened path).
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index (non-negative integer)
    ///
    /// # Returns
    ///
    /// * `Ok(MlDsaSigningKey, MlDsaVerificationKey)` - The derived ML-DSA-87 keypair
    /// * `Err(WalletError)` - If derivation fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If ML-DSA-87 is not supported in this wallet
    /// - `KeyError`: If key derivation fails
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::MlDsa87], None).unwrap();
    ///
    /// // Derive ML-DSA keypair at address index 0
    /// let (mldsa_sk, mldsa_vk) = wallet.derive_mldsa87_keypair(0).unwrap();
    ///
    /// // Derive another keypair at address index 1
    /// let (mldsa_sk2, mldsa_vk2) = wallet.derive_mldsa87_keypair(1).unwrap();
    /// ```
    pub fn derive_mldsa87_keypair(
        &self,
        address_index: u32,
    ) -> Result<(MlDsaSigningKey, MlDsaVerificationKey), WalletError> {
        // 1. Extract the child seed for the ML-DSA-87 scheme.
        let signature_seed = self
            .master_seeds
            .get(&SignatureScheme::MlDsa87)
            .ok_or(WalletError::InvalidScheme)?;
        let seed_bytes = signature_seed.as_seed().as_bytes();

        MlDsa87::derive_from_seed(seed_bytes, address_index).map_err(WalletError::KeyError)
    }

    #[cfg(feature = "mayo")]
    /// Derives a MAYO-1 keypair at the given address index.
    ///
    /// The derivation path is `m/44'/60'/0'/0'/{address_index}'` (hardened path). The
    /// 32-byte SLIP-0010 child key is truncated to its first 24 bytes to match the MAYO-1
    /// key-generation seed size (SLIP-0010 output is uniform, so truncation preserves the 192-bit
    /// seed security targeted by MAYO-1).
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index (non-negative integer)
    ///
    /// # Returns
    ///
    /// * `Ok(MayoSigningKey, MayoVerificationKey)` - The derived MAYO-1 keypair
    /// * `Err(WalletError)` - If derivation fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If MAYO-1 is not supported in this wallet
    /// - `KeyError`: If key derivation fails
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::Mayo1], None).unwrap();
    ///
    /// // Derive MAYO-1 keypair at address index 0
    /// let (mayo_sk, mayo_vk) = wallet.derive_mayo1_keypair(0).unwrap();
    /// ```
    pub fn derive_mayo1_keypair(
        &self,
        address_index: u32,
    ) -> Result<(MayoSigningKey, MayoVerificationKey), WalletError> {
        // 1. Extract child seed for the MAYO-1 scheme
        let signature_seed = self
            .master_seeds
            .get(&SignatureScheme::Mayo1)
            .ok_or(WalletError::InvalidScheme)?;
        let seed_bytes = signature_seed.as_seed().as_bytes();

        Mayo1::derive_from_seed(seed_bytes, address_index).map_err(WalletError::KeyError)
    }

    #[cfg(feature = "mayo")]
    /// Derives a MAYO-2 keypair at the given address index.
    ///
    /// The derivation path is `m/44'/60'/0'/0'/{address_index}'` (hardened path). The
    /// 32-byte SLIP-0010 child key is truncated to its first 24 bytes to match the MAYO-2
    /// key-generation seed size (SLIP-0010 output is uniform, so truncation preserves the 192-bit
    /// seed security targeted by MAYO-2).
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index (non-negative integer)
    ///
    /// # Returns
    ///
    /// * `Ok(MayoSigningKey, MayoVerificationKey)` - The derived MAYO-2 keypair
    /// * `Err(WalletError)` - If derivation fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If MAYO-2 is not supported in this wallet
    /// - `KeyError`: If key derivation fails
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::Mayo2], None).unwrap();
    ///
    /// // Derive MAYO-2 keypair at address index 0
    /// let (mayo_sk, mayo_vk) = wallet.derive_mayo2_keypair(0).unwrap();
    /// ```
    pub fn derive_mayo2_keypair(
        &self,
        address_index: u32,
    ) -> Result<(MayoSigningKey, MayoVerificationKey), WalletError> {
        // 1. Extract child seed for the MAYO-2 scheme
        let signature_seed = self
            .master_seeds
            .get(&SignatureScheme::Mayo2)
            .ok_or(WalletError::InvalidScheme)?;
        let seed_bytes = signature_seed.as_seed().as_bytes();

        Mayo2::derive_from_seed(seed_bytes, address_index).map_err(WalletError::KeyError)
    }

    #[cfg(feature = "mayo")]
    /// Derives a MAYO-3 keypair at the given address index.
    ///
    /// The derivation path is `m/44'/60'/0'/0'/{address_index}'` (hardened path). MAYO-3
    /// uses all 32 bytes of the SLIP-0010 child key directly. MAYO-5 is not offered in HHD
    /// because its 40-byte seed would require expansion.
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index (non-negative integer)
    ///
    /// # Returns
    ///
    /// * `Ok(MayoSigningKey, MayoVerificationKey)` - The derived MAYO-3 keypair
    /// * `Err(WalletError)` - If derivation fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If MAYO-3 is not supported in this wallet
    /// - `KeyError`: If key derivation fails
    ///
    /// # Example
    ///
    /// ```
    /// use tectonic_bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::Mayo3], None).unwrap();
    ///
    /// // Derive MAYO-3 keypair at address index 0
    /// let (mayo_sk, mayo_vk) = wallet.derive_mayo3_keypair(0).unwrap();
    /// ```
    pub fn derive_mayo3_keypair(
        &self,
        address_index: u32,
    ) -> Result<(MayoSigningKey, MayoVerificationKey), WalletError> {
        // 1. Extract child seed for the MAYO-3 scheme
        let signature_seed = self
            .master_seeds
            .get(&SignatureScheme::Mayo3)
            .ok_or(WalletError::InvalidScheme)?;
        let seed_bytes = signature_seed.as_seed().as_bytes();

        Mayo3::derive_from_seed(seed_bytes, address_index).map_err(WalletError::KeyError)
    }

    #[cfg(feature = "hqc")]
    fn derive_hqc_keypair(
        &self,
        scheme: KemScheme,
        address_index: u32,
    ) -> Result<(KemEncapsulationKey, KemDecapsulationKey), WalletError> {
        let kem_seed = self
            .kem_master_seeds
            .get(&scheme)
            .ok_or(WalletError::KemSchemeNotConfigured(scheme))?;

        derive_hqc_keypair_from_seed(scheme, kem_seed.as_seed().as_bytes(), address_index)
            .map_err(WalletError::KeyError)
    }

    /// Derives an HQC-128 encapsulation/decapsulation keypair.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError`] if HQC-128 is not configured or derivation fails.
    #[cfg(feature = "hqc")]
    pub fn derive_hqc128_keypair(
        &self,
        address_index: u32,
    ) -> Result<(KemEncapsulationKey, KemDecapsulationKey), WalletError> {
        self.derive_hqc_keypair(KemScheme::Hqc128, address_index)
    }

    /// Derives an HQC-192 encapsulation/decapsulation keypair.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError`] if HQC-192 is not configured or derivation fails.
    #[cfg(feature = "hqc")]
    pub fn derive_hqc192_keypair(
        &self,
        address_index: u32,
    ) -> Result<(KemEncapsulationKey, KemDecapsulationKey), WalletError> {
        self.derive_hqc_keypair(KemScheme::Hqc192, address_index)
    }

    /// Derives an HQC-256 encapsulation/decapsulation keypair.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError`] if HQC-256 is not configured or derivation fails.
    #[cfg(feature = "hqc")]
    pub fn derive_hqc256_keypair(
        &self,
        address_index: u32,
    ) -> Result<(KemEncapsulationKey, KemDecapsulationKey), WalletError> {
        self.derive_hqc_keypair(KemScheme::Hqc256, address_index)
    }
}

/// Errors that can occur during wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// Invalid seed length encountered during operation.
    #[error("Invalid seed length: expected {expected}, got {actual}")]
    InvalidSeedLength {
        /// Expected seed length in bytes
        expected: usize,
        /// Actual seed length in bytes
        actual: usize,
    },
    /// The requested signature scheme is not supported in this wallet.
    #[error("Invalid scheme")]
    InvalidScheme,
    /// The requested KEM was not configured in this wallet.
    #[cfg(feature = "hqc")]
    #[error("KEM scheme '{0}' is not configured in this wallet")]
    KemSchemeNotConfigured(KemScheme),
    /// Invalid derivation path encountered during key derivation.
    #[error("Invalid derivation path")]
    InvalidDerivationPath,
    /// Invalid HMAC key length during entropy extraction.
    #[error("Invalid HMAC key length: expected {expected}, got {actual}")]
    InvalidHmacKeyLength {
        /// Expected HMAC key length in bytes
        expected: usize,
        /// Actual HMAC key length in bytes
        actual: usize,
    },
    /// An error occurred during mnemonic processing (BIP-39).
    #[error("Mnemonic error: {0}")]
    Bip39(#[from] MnemonicError),
    /// An error occurred during BIP-32 key derivation.
    #[error("BIP-32 error: {0}")]
    Bip32(#[from] bip32::Error),
    /// An error occurred in signature-scheme configuration or derivation.
    #[error("Signature scheme error: {0}")]
    SignatureSchemeError(#[from] SignatureSchemeError),
    /// An error occurred during a key operation (derivation, signing, or verification).
    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),
    /// An error occurred during BIP-85 seed derivation.
    #[error("BIP85 error: {0}")]
    Bip85Error(#[from] Bip85Error),
}

#[cfg(feature = "falcon")]
#[test]
fn mnemonic_determinism() {
    let mnemonic = Mnemonic::new_random();
    let schemes = vec![SignatureScheme::Falcon512];

    let wallet1 = HHDWallet::new_from_mnemonic(mnemonic.clone(), schemes.clone(), None).unwrap();
    let wallet2 = HHDWallet::new_from_mnemonic(mnemonic.clone(), schemes.clone(), None).unwrap();

    let keypair1 = wallet1.derive_fn_dsa512_keypair(0).unwrap();
    let keypair2 = wallet2.derive_fn_dsa512_keypair(0).unwrap();

    assert_eq!(keypair1.0, keypair2.0);
    assert_eq!(keypair1.1, keypair2.1);
}

#[cfg(all(test, feature = "hqc"))]
#[allow(clippy::unwrap_used)]
mod hqc_tests {
    use super::*;
    use rstest::rstest;

    fn fixed_mnemonic() -> Mnemonic {
        Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap()
    }

    fn derive(
        wallet: &HHDWallet,
        scheme: KemScheme,
        address_index: u32,
    ) -> Result<(KemEncapsulationKey, KemDecapsulationKey), WalletError> {
        if scheme == KemScheme::Hqc128 {
            wallet.derive_hqc128_keypair(address_index)
        } else if scheme == KemScheme::Hqc192 {
            wallet.derive_hqc192_keypair(address_index)
        } else {
            wallet.derive_hqc256_keypair(address_index)
        }
    }

    #[rstest]
    #[case::hqc128(KemScheme::Hqc128)]
    #[case::hqc192(KemScheme::Hqc192)]
    #[case::hqc256(KemScheme::Hqc256)]
    fn hqc_wallet_restoration_is_deterministic(#[case] scheme: KemScheme) {
        let first = HHDWallet::new_from_mnemonic_with_kem_schemes(
            fixed_mnemonic(),
            Vec::new(),
            vec![scheme],
            None,
        )
        .unwrap();
        let second = HHDWallet::new_from_mnemonic_with_kem_schemes(
            fixed_mnemonic(),
            Vec::new(),
            vec![scheme],
            None,
        )
        .unwrap();

        let first_keys = derive(&first, scheme, 4).unwrap();
        let second_keys = derive(&second, scheme, 4).unwrap();
        assert_eq!(first_keys.0.to_raw_bytes(), second_keys.0.to_raw_bytes());
        assert_eq!(first_keys.1.to_raw_bytes(), second_keys.1.to_raw_bytes());
    }

    #[test]
    fn random_wallet_constructor_configures_requested_kem_seeds() {
        let schemes = [KemScheme::Hqc128, KemScheme::Hqc192, KemScheme::Hqc256];
        let wallet = HHDWallet::new_with_kem_schemes(Vec::new(), schemes.to_vec(), None).unwrap();

        assert_eq!(wallet.kem_master_seeds().len(), schemes.len());
        for scheme in schemes {
            let seed = wallet
                .kem_master_seeds()
                .get(&scheme)
                .expect("requested KEM seed should be configured");
            assert_eq!(seed.scheme(), scheme);
        }
    }

    #[test]
    fn signature_only_constructor_does_not_implicitly_enable_hqc() {
        let wallet = HHDWallet::new_from_mnemonic(fixed_mnemonic(), Vec::new(), None).unwrap();
        assert!(matches!(
            wallet.derive_hqc128_keypair(0),
            Err(WalletError::KemSchemeNotConfigured(KemScheme::Hqc128))
        ));
    }

    #[cfg(all(feature = "encp", feature = "decp"))]
    #[rstest]
    #[case::hqc128(KemScheme::Hqc128)]
    #[case::hqc192(KemScheme::Hqc192)]
    #[case::hqc256(KemScheme::Hqc256)]
    fn hhd_hqc_round_trip(#[case] scheme: KemScheme) {
        let wallet = HHDWallet::new_from_mnemonic_with_kem_schemes(
            fixed_mnemonic(),
            Vec::new(),
            vec![scheme],
            None,
        )
        .unwrap();
        let (encapsulation_key, decapsulation_key) = derive(&wallet, scheme, 0).unwrap();
        let (ciphertext, sender_secret) = scheme.encapsulate(&encapsulation_key).unwrap();
        let receiver_secret = scheme.decapsulate(&ciphertext, &decapsulation_key).unwrap();

        assert_eq!(sender_secret.to_raw_bytes(), receiver_secret.to_raw_bytes());
    }
}

#[cfg(all(feature = "sign", feature = "vrfy"))]
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[cfg(feature = "falcon")]
    use crate::falcon::FalconScheme;
    #[cfg(feature = "mayo")]
    use crate::mayo::MayoScheme;
    #[cfg(feature = "ml-dsa")]
    use crate::ml_dsa::MlDsaScheme;
    use bip32::secp256k1::ecdsa::{
        signature::{Signer, Verifier},
        Signature,
    };
    use rstest::rstest;

    #[rstest]
    #[cfg_attr(
        all(feature = "ml-dsa", feature = "sign", feature = "vrfy"),
        case::mldsa44(SignatureScheme::MlDsa44)
    )]
    #[cfg_attr(
        all(feature = "ml-dsa", feature = "sign", feature = "vrfy"),
        case::mldsa65(SignatureScheme::MlDsa65)
    )]
    #[cfg_attr(
        all(feature = "ml-dsa", feature = "sign", feature = "vrfy"),
        case::mldsa87(SignatureScheme::MlDsa87)
    )]
    #[cfg_attr(feature = "ml-dsa", case::mldsa87(SignatureScheme::MlDsa87))]
    #[case::mldsa87(SignatureScheme::MlDsa87)]
    fn test_hhd_wallet_sign_verify_with_schemes(#[case] scheme: SignatureScheme) {
        let wallet = HHDWallet::new(vec![scheme], None).unwrap();
        let message = b"Hello, world!";

        let (sk, vk) = match scheme {
            SignatureScheme::MlDsa44 => wallet.derive_mldsa44_keypair(0).unwrap(),
            SignatureScheme::MlDsa65 => wallet.derive_mldsa65_keypair(0).unwrap(),
            SignatureScheme::MlDsa87 => wallet.derive_mldsa87_keypair(0).unwrap(),
            _ => panic!("Invalid scheme"),
        };
        let signature = match scheme {
            SignatureScheme::MlDsa44 => MlDsaScheme::Dsa44.sign(message, &sk).unwrap(),
            SignatureScheme::MlDsa65 => MlDsaScheme::Dsa65.sign(message, &sk).unwrap(),
            SignatureScheme::MlDsa87 => MlDsaScheme::Dsa87.sign(message, &sk).unwrap(),
            _ => panic!("Invalid scheme"),
        };
        let res = match scheme {
            SignatureScheme::MlDsa44 => MlDsaScheme::Dsa44.verify(message, &signature, &vk),
            SignatureScheme::MlDsa65 => MlDsaScheme::Dsa65.verify(message, &signature, &vk),
            SignatureScheme::MlDsa87 => MlDsaScheme::Dsa87.verify(message, &signature, &vk),
            _ => panic!("Invalid scheme"),
        };
        assert!(res.is_ok());
    }

    #[cfg(all(feature = "falcon", feature = "sign", feature = "vrfy"))]
    #[test]
    fn test_hhd_wallet_sign_verify_with_falcon() {
        let wallet = HHDWallet::new(vec![SignatureScheme::Falcon512], None).unwrap();
        let message = b"Hello, world!";
        let (sk, vk) = wallet.derive_fn_dsa512_keypair(0).unwrap();
        let signature = FalconScheme::Dsa512.sign(message, &sk).unwrap();
        let res = FalconScheme::Dsa512.verify(message, &signature, &vk);
        assert!(res.is_ok());
    }

    #[cfg(all(feature = "mayo", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mayo1(SignatureScheme::Mayo1, MayoScheme::Mayo1)]
    #[case::mayo2(SignatureScheme::Mayo2, MayoScheme::Mayo2)]
    #[case::mayo3(SignatureScheme::Mayo3, MayoScheme::Mayo3)]
    fn test_hhd_wallet_sign_verify_with_mayo(
        #[case] scheme: SignatureScheme,
        #[case] mayo_scheme: MayoScheme,
    ) {
        let wallet = HHDWallet::new(vec![scheme], None).unwrap();
        let message = b"Hello, world!";
        let (sk, vk) = match scheme {
            SignatureScheme::Mayo1 => wallet.derive_mayo1_keypair(0).unwrap(),
            SignatureScheme::Mayo2 => wallet.derive_mayo2_keypair(0).unwrap(),
            SignatureScheme::Mayo3 => wallet.derive_mayo3_keypair(0).unwrap(),
            _ => panic!("Invalid scheme"),
        };
        let signature = mayo_scheme.sign(message, &sk).unwrap();
        let res = mayo_scheme.verify(message, &signature, &vk);
        assert!(res.is_ok());
    }

    #[test]
    fn test_hhd_wallet_sign_verify_with_ecdsa() {
        let wallet = HHDWallet::new(vec![SignatureScheme::EcdsaSecp256k1], None).unwrap();
        let message = b"Hello, world!";
        let (sk, vk) = wallet.derive_ecdsa_secp256k1_keypair(0).unwrap();
        let signature: Signature = sk.sign(message);
        let res = vk.verify(message, &signature);
        assert!(res.is_ok());
    }

    #[test]
    fn test_hhd_wallet_debug_display() {
        let wallet = HHDWallet::new(
            vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
            None,
        )
        .unwrap();
        let debug_display = format!("{:?}", wallet);
        println!("{}", debug_display);
        assert!(debug_display.contains("mnemonic"));
        assert!(debug_display.contains("master_seeds"));
        assert!(debug_display.contains("ECDSAsecp256k1"));
        assert!(debug_display.contains("Falcon512"));
    }
}
