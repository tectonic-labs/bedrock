#![warn(missing_docs)]

//! # Hybrid Hierarchical Deterministic (HD) Wallet Library
//!
//! This library provides a framework for managing hybrid hierarchical deterministic ([HD wallets](https://en.bitcoin.it/wiki/Deterministic_wallet))
//! that support multiple signature schemes from a single [BIP-39 mnemonic seed phrase](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
//! It enables seamless coexistence of both classical ([ECDSA secp256k1](https://en.bitcoin.it/wiki/Secp256k1)) and
//! post-quantum ([Falcon-512](https://falcon-sign.info/)) signature schemes within a unified wallet structure.
//! The post-quantum Falcon-512 primitive leverages [Tectonic's Bedrock repository](https://github.com/tectonic-labs/bedrock),
//! which is based on the [OQS C implementation](https://github.com/open-quantum-safe/liboqs).
//!
//! ## Features
//!
//! - **Multi-Scheme Support**: Derive keys for multiple signature schemes (ECDSA secp256k1, Falcon-512)
//! - **Single Mnemonic**: Use one BIP-39 mnemonic to derive all scheme-specific seeds
//! - **BIP-85 Derivation**: Scheme-specific seed derivation using BIP-85 standard
//! - **BIP-32 & SLIP-0010**: Support for both BIP-32 (ECDSA) and SLIP-0010 (Falcon) HD key derivation
//! - **Deterministic**: All keys are deterministically derived from the master seed
//! - **Cryptographic Separation**: Each signature scheme uses independent derivation paths
//!
//! ## Quick Start
//!
//! ### Creating and Using a Hybrid HD Wallet with ECDSA and Falcon
//! ```no_run
//! use bedrock::hhd::{HHDWallet, SignatureScheme};
//!
//! // Create a new wallet with both ECDSA and Falcon support
//! let wallet = HHDWallet::new(
//!     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
//!     None, // Optional BIP-39 passphrase
//! ).unwrap();
//!
//! // Derive a keypair for ECDSA at address index 0
//! let ecdsa_keypair = wallet.derive_keypair_for_scheme(
//!     SignatureScheme::EcdsaSecp256k1,
//!     0,
//! ).unwrap();
//!
//! // Sign and verify with ECDSA
//! let message = b"Hello, world!";
//! let ecdsa_signature = wallet.sign_with_scheme(
//!     SignatureScheme::EcdsaSecp256k1,
//!     0,
//!     message,
//! ).unwrap();
//! let verified = wallet.verify_with_scheme(
//!     SignatureScheme::EcdsaSecp256k1,
//!     0,
//!     message,
//!     &ecdsa_signature,
//! ).unwrap();
//! assert!(verified);
//!
//! // Derive a keypair for Falcon at address index 0
//! let falcon_keypair = wallet.derive_keypair_for_scheme(
//!     SignatureScheme::Falcon512,
//!     0,
//! ).unwrap();
//!
//! // Sign and verify with Falcon
//! let falcon_signature = wallet.sign_with_scheme(
//!     SignatureScheme::Falcon512,
//!     0,
//!     message,
//! ).unwrap();
//! let falcon_verified = wallet.verify_with_scheme(
//!     SignatureScheme::Falcon512,
//!     0,
//!     message,
//!     &falcon_signature,
//! ).unwrap();
//! assert!(falcon_verified);
//! ```
//!
//! ### Importing a Wallet from an Existing Mnemonic Phrase
//! ```no_run
//! use bedrock::hhd::{HHDWallet, SignatureScheme, Mnemonic};
//!
//! // Your BIP-39 phrase (for example, a 24-word phrase)
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
//!
//! // You can optionally provide a BIP-39 passphrase
//! let password = Some("my secret password");
//!
//! // Import the wallet with both ECDSA and Falcon enabled
//! let wallet = HHDWallet::new_from_mnemonic(
//!     mnemonic,
//!     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
//!     password,
//! ).unwrap();
//!
//! // Now, use wallet.derive_keypair_for_scheme, sign_with_scheme, etc. as above.
//! ```
//!
//! ### Signing and Verifying with All Schemes
//! ```no_run
//! use bedrock::hhd::{HHDWallet, SignatureScheme};
//!
//! // Create a wallet with both ECDSA and Falcon support
//! let wallet = HHDWallet::new(
//!     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
//!     None,
//! ).unwrap();
//!
//! let message = b"Hello, world!";
//!
//! // Sign with all schemes at the same address index
//! let signatures = wallet.sign_with_all_schemes(0, message).unwrap();
//!
//! // Verify all signatures
//! let verified = wallet.verify_with_all_schemes(0, message, &signatures).unwrap();
//! assert!(verified);
//! ```
//!
//! ## Architecture
//!
//!
//! The hybrid HD wallet architecture enables multiple signature schemes to coexist within a single wallet structure while maintaining cryptographic separation.
//!
//! ## Overview
//!
//! The wallet follows a hierarchical derivation model:
//!
//! 1. **Master Mnemonic** (BIP-39): A single 24-word mnemonic phrase serves as the root entropy source for the entire wallet
//! 2. **Scheme-Specific Seeds** (BIP-85): Each signature scheme receives its own 64-byte seed derived from the master mnemonic
//! 3. **Keypairs** (BIP-32/SLIP-0010): Individual keypairs are derived from scheme seeds using address indices
//!
//! This design ensures that:
//! - All keys are deterministically derived from a single mnemonic, allowing them to be restored from the mnemonic alone
//! - Different signature schemes use cryptographically independent seeds
//!
//! ## Derivation Paths
//!
//! ### BIP-85 Scheme Seed Derivation
//!
//! Each signature scheme gets its own unique seed through BIP-85 derivation from the master mnemonic. Two different paths are used for each signature type::
//!
//! - **ECDSA secp256k1**: `m/83696968'/83286642'/1'`
//! - **Falcon-512**: `m/83696968'/83286642'/2'`
//!
//! The base path `m/83696968'` is the standard BIP-85 path, `/83286642'` stands for Tectonic in a T9 keypad, and the final component (`1'` or `2'`) identifies the signature scheme. This ensures that even though both schemes share the same mnemonic, they operate on cryptographically independent seeds.
//!
//! ### Key Derivation Paths
//!
//! Once a scheme-specific seed is obtained, individual keypairs are derived using address indices:
//!
//! **ECDSA secp256k1** (BIP-32, BIP-44):
//! - Domain separator: `Bitcoin seed`
//! - Base path: `m/44'/60'/0'/0`
//! - Full path: `m/44'/60'/0'/0/{address_index}`
//! - Standard: BIP-32 (non-hardened address index)
//! - Example for address index 0: `m/44'/60'/0'/0/0`
//!
//! **Falcon-512** (SLIP-0010, hardened):
//! - Domain separator: `Falcon-512-v1 seed`
//! - Base path: `m/44'/60'/0'/0'`
//! - Full path: `m/44'/60'/0'/0'/{address_index}'`
//! - Standard: SLIP-0010 (all components hardened)
//! - Example for address index 0: `m/44'/60'/0'/0'/0'`
//!
//! ### Key Differences
//!
//! |      Signature       |   ECDSA secp256k1    |  Falcon-512          |
//! |----------------------|----------------------|----------------------|
//! | **BIP-85 Index**     | `1'`                 | `2'`                 |
//! | **HD Standard**      | BIP-32               | SLIP-0010            |
//! | **Domain Separator** | `Bitcoin seed`       | `Falcon-512-v1 seed` |
//! | **Address Index**    | Non-hardened         | Hardened             |
//!
//! For more detailed implementation information, see the [ARCHITECTURE.md](https://github.com/tectonic-labs/bedrock/blob/main/src/hhd/ARCHITECTURE.md) document.
//!
//! ## Standards
//!
//! This library implements the following standards:
//!
//! - [BIP-39]: Mnemonic code for generating deterministic keys
//! - [BIP-32]: Hierarchical Deterministic Wallets
//! - [BIP-44]: Multi-Account Hierarchy for Deterministic Wallets
//! - [BIP-85]: Deterministic Entropy From BIP32 Keychains
//! - [SLIP-0010]: Universal private key derivation from master private key
//!
//! [ARCHITECTURE.md]: https://github.com/tectonic-labs/bedrock/blob/main/src/hhd/ARCHITECTURE.md
//! [BIP-39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
//! [BIP-32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//! [BIP-44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
//! [BIP-85]: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
//! [SLIP-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

mod bip85;
mod keys;
mod mnemonic;
mod signatures;
mod slip10;

pub use bip85::{Bip85, Bip85Error};
pub use keys::{EcdsaKeyPair, FalconKeyPair, GenericKeyPair, KeyError};
pub use mnemonic::{Mnemonic, MnemonicError};
pub use signatures::{SignatureScheme, SignatureSchemeError, SignatureSeed};
pub use slip10::Slip10;

use std::collections::HashMap;

/// A Hybrid Hierarchical Deterministic (HD) Wallet derived from a single BIP-39 mnemonic.
///
/// This wallet structure enables managing multiple signature schemes (e.g., ECDSA secp256k1
/// and Falcon-512) from a single BIP-39 mnemonic phrase. Each signature scheme gets its own
/// scheme-specific seed derived using BIP-85, ensuring cryptographic seed separation while
/// maintaining a unified wallet structure.
///
/// # Key Concepts
///
/// - **Master Mnemonic**: A single BIP-39 mnemonic phrase that serves as the root entropy
/// - **Scheme-Specific Seeds**: Each signature scheme has its own derived seed (via BIP-85)
/// - **Address Indexing**: Keys are derived from scheme seeds using hierarchical derivation paths
/// - **Cryptographic Isolation**: Different schemes use different derived seeds
///
/// # Derivation Flow
///
/// 1. **Master Mnemonic** → BIP-39 seed conversion
/// 2. **BIP-85 Derivation** → Scheme-specific seed for each signature scheme
/// 3. **HD Key Derivation** → Keypairs at specific address indices
///    - ECDSA: Uses BIP-32 with BIP-44 paths
///    - Falcon: Uses SLIP-0010 with hardened paths
///
/// # Example
///
/// ```
/// use bedrock::hhd::{HHDWallet, SignatureScheme};
///
/// // Create wallet with both schemes
/// let wallet = HHDWallet::new(
///     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
///     None,
/// ).unwrap();
///
/// // Get the mnemonic (backup this!)
/// let mnemonic_phrase = wallet.mnemonic().to_phrase();
///
/// // Derive keypairs for both schemes at the same address index
/// let all_keypairs = wallet.derive_all_keypairs(0).unwrap();
/// ```
pub struct HHDWallet {
    /// Root mnemonic phrase (BIP-39 compatible) used to derive all scheme-specific seeds.
    pub mnemonic: Mnemonic,
    /// Master seeds indexed by signature scheme, derived from the mnemonic using BIP-85.
    /// All seeds are zeroized on drop according to bip32 crate implementation.
    pub master_seeds: HashMap<SignatureScheme, SignatureSeed>,
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
    /// use bedrock::hhd::{HHDWallet, Mnemonic, SignatureScheme};
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
    /// * `password` - Optional BIP-39 passphrase (adds extra security layer)
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
    /// use bedrock::hhd::{HHDWallet, SignatureScheme};
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
    /// use bedrock::hhd::{HHDWallet, SignatureScheme};
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
    /// use bedrock::hhd::{HHDWallet, SignatureScheme};
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

    /// Derives a keypair for a specific signature scheme at the given address index.
    ///
    /// This method derives a keypair using the scheme-specific seed and the provided
    /// address index. The derivation path depends on the signature scheme:
    ///
    /// - **ECDSA secp256k1**: Uses BIP-44 path `m/44'/60'/0'/0/{address_index}`
    /// - **Falcon-512**: Uses hardened path `m/44'/60'/0'/0'/{address_index}'`
    ///
    /// # Arguments
    ///
    /// * `scheme` - The signature scheme to derive a keypair for
    /// * `address_index` - The address index (non-negative integer)
    ///
    /// # Returns
    ///
    /// * `Ok(GenericKeyPair)` - The derived keypair for the specified scheme and index
    /// * `Err(WalletError)` - If derivation fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If the scheme is not supported in this wallet
    /// - `KeyError`: If key derivation fails
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::EcdsaSecp256k1], None).unwrap();
    ///
    /// // Derive ECDSA keypair at address index 0
    /// let keypair = wallet.derive_keypair_for_scheme(
    ///     SignatureScheme::EcdsaSecp256k1,
    ///     0,
    /// ).unwrap();
    ///
    /// // Derive another keypair at address index 1
    /// let keypair2 = wallet.derive_keypair_for_scheme(
    ///     SignatureScheme::EcdsaSecp256k1,
    ///     1,
    /// ).unwrap();
    /// ```
    pub fn derive_keypair_for_scheme(
        &self,
        scheme: SignatureScheme,
        address_index: u32,
    ) -> Result<GenericKeyPair, WalletError> {
        // 1. Extract child seed for the corresponding scheme
        let signature_seed = self
            .master_seeds
            .get(&scheme)
            .ok_or(WalletError::InvalidScheme)?;
        let seed_bytes = signature_seed.as_seed().as_bytes();

        match scheme {
            SignatureScheme::EcdsaSecp256k1 => {
                EcdsaKeyPair::derive_from_seed(seed_bytes, address_index)
                    .and_then(|kp| kp.to_generic_key_pair())
                    .map_err(WalletError::KeyError)
            }
            SignatureScheme::Falcon512 => {
                FalconKeyPair::derive_from_seed(seed_bytes, address_index)
                    .and_then(|kp| kp.to_generic_key_pair())
                    .map_err(WalletError::KeyError)
            }
        }
    }

    /// Derives keypairs for all supported signature schemes at the same address index.
    ///
    /// This method derives a keypair for each signature scheme configured in the wallet
    /// at the specified address index. This is useful when you want to use the same
    /// logical "address" across multiple signature schemes.
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index to derive keypairs for
    ///
    /// # Returns
    ///
    /// * `Ok(HashMap<SignatureScheme, GenericKeyPair>)` - A map of schemes to their keypairs
    /// * `Err(WalletError)` - If derivation fails for any scheme
    ///
    /// # Errors
    ///
    /// Returns `WalletError` if keypair derivation fails for any scheme.
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(
    ///     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
    ///     None,
    /// ).unwrap();
    ///
    /// // Derive keypairs for all schemes at address index 0
    /// let all_keypairs = wallet.derive_all_keypairs(0).unwrap();
    ///
    /// assert!(all_keypairs.contains_key(&SignatureScheme::EcdsaSecp256k1));
    /// assert!(all_keypairs.contains_key(&SignatureScheme::Falcon512));
    /// ```
    pub fn derive_all_keypairs(
        &self,
        address_index: u32,
    ) -> Result<HashMap<SignatureScheme, GenericKeyPair>, WalletError> {
        let mut keypairs = HashMap::new();
        for scheme in self.master_seeds.keys() {
            let keypair = self.derive_keypair_for_scheme(*scheme, address_index)?;
            keypairs.insert(*scheme, keypair);
        }
        Ok(keypairs)
    }

    #[cfg(feature = "sign")]
    /// Signs a message using a specific signature scheme at the given address index.
    ///
    /// This method derives the keypair for the specified scheme and address index,
    /// then signs the message using the appropriate signing algorithm.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The signature scheme to use for signing
    /// * `address_index` - The address index to derive the signing key from
    /// * `message` - The message bytes to sign
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The signature bytes (format depends on signature scheme)
    ///   - ECDSA secp256k1: 64 bytes (r and s values)
    ///   - Falcon-512: ~666 bytes (variable length)
    /// * `Err(WalletError)` - If signing fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If the scheme is not supported
    /// - `KeyError`: If key derivation or signing fails
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::EcdsaSecp256k1], None).unwrap();
    /// let message = b"Hello, world!";
    ///
    /// let signature = wallet.sign_with_scheme(
    ///     SignatureScheme::EcdsaSecp256k1,
    ///     0,
    ///     message,
    /// ).unwrap();
    ///
    /// assert_eq!(signature.len(), 64); // ECDSA signature is 64 bytes
    /// ```
    pub fn sign_with_scheme(
        &self,
        scheme: SignatureScheme,
        address_index: u32,
        message: &[u8],
    ) -> Result<Vec<u8>, WalletError> {
        let keypair = self.derive_keypair_for_scheme(scheme, address_index)?;
        keypair.sign(message).map_err(WalletError::KeyError)
    }

    #[cfg(feature = "vrfy")]
    /// Verifies a signature against a message using a specific signature scheme.
    ///
    /// This method derives the keypair for the specified scheme and address index,
    /// then verifies the signature against the message.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The signature scheme to use for verification
    /// * `address_index` - The address index to derive the verifying key from
    /// * `message` - The message that was signed
    /// * `signature` - The signature bytes to verify
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If the signature is valid
    /// * `Ok(false)` - If the signature is invalid
    /// * `Err(WalletError)` - If verification fails
    ///
    /// # Errors
    ///
    /// Returns `WalletError` in the following cases:
    /// - `InvalidScheme`: If the scheme is not supported
    /// - `KeyError`: If key derivation or verification fails
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(vec![SignatureScheme::EcdsaSecp256k1], None).unwrap();
    /// let message = b"Hello, world!";
    ///
    /// // Sign the message
    /// let signature = wallet.sign_with_scheme(
    ///     SignatureScheme::EcdsaSecp256k1,
    ///     0,
    ///     message,
    /// ).unwrap();
    ///
    /// // Verify the signature
    /// let verified = wallet.verify_with_scheme(
    ///     SignatureScheme::EcdsaSecp256k1,
    ///     0,
    ///     message,
    ///     &signature,
    /// ).unwrap();
    /// assert!(verified);
    ///
    /// // Wrong message should fail
    /// let wrong_message = b"Wrong message";
    /// let verified_wrong = wallet.verify_with_scheme(
    ///     SignatureScheme::EcdsaSecp256k1,
    ///     0,
    ///     wrong_message,
    ///     &signature,
    /// ).unwrap();
    /// assert!(!verified_wrong);
    /// ```
    pub fn verify_with_scheme(
        &self,
        scheme: SignatureScheme,
        address_index: u32,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, WalletError> {
        let keypair = self.derive_keypair_for_scheme(scheme, address_index)?;
        keypair
            .verify(message, signature)
            .map_err(WalletError::KeyError)
    }

    #[cfg(feature = "sign")]
    /// Signs a message using all supported signature schemes at the same address index.
    ///
    /// This method produces signatures for the message using each signature scheme
    /// configured in the wallet, all at the same address index. This is useful for
    /// hybrid signature schemes where you want multiple signatures on the same message.
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index to derive signing keys from
    /// * `message` - The message bytes to sign
    ///
    /// # Returns
    ///
    /// * `Ok(HashMap<SignatureScheme, Vec<u8>>)` - A map of schemes to their signatures
    /// * `Err(WalletError)` - If signing fails for any scheme
    ///
    /// # Errors
    ///
    /// Returns `WalletError` if signing fails for any scheme.
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(
    ///     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
    ///     None,
    /// ).unwrap();
    ///
    /// let message = b"Hello, world!";
    ///
    /// // Sign with all schemes
    /// let signatures = wallet.sign_with_all_schemes(0, message).unwrap();
    ///
    /// // Verify we got signatures from both schemes
    /// assert!(signatures.contains_key(&SignatureScheme::EcdsaSecp256k1));
    /// assert!(signatures.contains_key(&SignatureScheme::Falcon512));
    ///
    /// // ECDSA signature is 64 bytes, Falcon is ~666 bytes
    /// assert_eq!(signatures[&SignatureScheme::EcdsaSecp256k1].len(), 64);
    /// ```
    pub fn sign_with_all_schemes(
        &self,
        address_index: u32,
        message: &[u8],
    ) -> Result<HashMap<SignatureScheme, Vec<u8>>, WalletError> {
        let mut signatures = HashMap::new();
        for scheme in self.master_seeds.keys() {
            let signature = self.sign_with_scheme(*scheme, address_index, message)?;
            signatures.insert(*scheme, signature);
        }
        Ok(signatures)
    }

    #[cfg(feature = "vrfy")]
    /// Verifies signatures for all supported schemes against the same message.
    ///
    /// This method verifies a signature for each signature scheme in the provided
    /// signatures map. All signatures must be valid for this method to return `Ok(true)`.
    /// This is useful for hybrid signature verification where you have multiple
    /// signatures on the same message.
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index to derive verifying keys from
    /// * `message` - The message that was signed
    /// * `signatures` - A map of signature schemes to their signature bytes
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If all signatures are valid
    /// * `Ok(false)` - If any signature is invalid (should not happen, returns error instead)
    /// * `Err(WalletError)` - If verification fails for any scheme
    ///
    /// # Errors
    ///
    /// Returns `WalletError::KeyError(VerificationFailed)` if any signature fails verification.
    /// Other errors may occur if key derivation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::{HHDWallet, SignatureScheme};
    ///
    /// let wallet = HHDWallet::new(
    ///     vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
    ///     None,
    /// ).unwrap();
    ///
    /// let message = b"Hello, world!";
    ///
    /// // Sign with all schemes
    /// let signatures = wallet.sign_with_all_schemes(0, message).unwrap();
    ///
    /// // Verify all signatures
    /// let all_verified = wallet.verify_with_all_schemes(0, message, &signatures).unwrap();
    /// assert!(all_verified);
    /// ```
    pub fn verify_with_all_schemes(
        &self,
        address_index: u32,
        message: &[u8],
        signatures: &HashMap<SignatureScheme, Vec<u8>>,
    ) -> Result<bool, WalletError> {
        for (scheme, signature) in signatures {
            let verified = self.verify_with_scheme(*scheme, address_index, message, signature)?;
            if !verified {
                return Err(WalletError::KeyError(KeyError::VerificationFailed(
                    String::from(format!("Verification failed for scheme: {:?}", scheme)),
                )));
            }
        }
        Ok(true)
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
    /// Error occurred during mnemonic processing (BIP-39).
    #[error("Mnemonic error: {0}")]
    Bip39(#[from] MnemonicError),
    /// Error occurred during BIP-32 key derivation.
    #[error("BIP32 error: {0}")]
    Bip32(#[from] bip32::Error),
    /// Error occurred in signature scheme configuration or derivation.
    #[error("Signature scheme error: {0}")]
    SignatureSchemeError(#[from] SignatureSchemeError),
    /// Error occurred during key operations (derivation, signing, verification).
    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),
    /// Error occurred during BIP-85 seed derivation.
    #[error("BIP85 error: {0}")]
    Bip85Error(#[from] Bip85Error),
}

#[cfg(all(feature = "sign", feature = "vrfy"))]
#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that signing and verification work correctly for both ECDSA and Falcon schemes.
    ///
    /// This test verifies:
    /// - Wallet can be created with multiple signature schemes
    /// - Messages can be signed with all schemes
    /// - Signatures can be verified correctly
    /// - All signatures validate successfully for the same message
    #[test]
    fn test_hhd_wallet_sign_verify() {
        let wallet = HHDWallet::new(
            vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
            None,
        )
        .unwrap();
        let message = b"Hello, world!";
        let signatures = wallet.sign_with_all_schemes(0, message).unwrap();
        let verified = wallet
            .verify_with_all_schemes(0, message, &signatures)
            .unwrap();
        assert!(verified);
    }
}
