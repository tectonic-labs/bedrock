//! BIP-39 mnemonic phrase handling for HD wallet seed generation.
//!
//! This module provides a wrapper around the BIP-39 standard for generating and handling
//! mnemonic phrases. Mnemonic phrases are human-readable representations of entropy that
//! can be used to generate deterministic seeds for hierarchical deterministic wallets.
//!
//! # Features
//!
//! - Generate random 24-word mnemonic phrases (English)
//! - Parse and validate existing mnemonic phrases
//! - Convert mnemonics to BIP-32 seeds with optional passphrase support
//! - Full BIP-39 compliance
//!
//! # BIP-39 Standard
//!
//! This module implements the [BIP-39][bip-39] standard for mnemonic code generation.
//! All mnemonics are 24 words in length using the English wordlist, providing 256 bits
//! of entropy for maximum security.
//!
//! # Seed Generation
//!
//! Mnemonics are converted to seeds using PBKDF2 with:
//! - **Password-based derivation**: Optional passphrase adds extra security
//! - **Iterations**: 2048 iterations (BIP-39 standard)
//! - **Output**: 64-byte (512-bit) seed for BIP-32 HD key derivation
//!
//! # Example
//!
//! ```no_run
//! use bedrock::hhd::Mnemonic;
//!
//! // Generate a new random mnemonic
//! let mnemonic = Mnemonic::new_random();
//! let phrase = mnemonic.to_phrase();
//! println!("Your mnemonic: {}", phrase);
//!
//! // Convert to seed (without passphrase)
//! let seed = mnemonic.to_seed(None).unwrap();
//!
//! // Convert to seed (with passphrase)
//! let seed_with_passphrase = mnemonic.to_seed(Some("my secret passphrase")).unwrap();
//! ```
//!
//! [bip-39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

use bip32::Seed as Bip32Seed;
use bip39::{
    ErrorKind as Bip39ErrorKind, Language, Mnemonic as Bip39Mnemonic, MnemonicType,
    Seed as Bip39Seed,
};

/// A BIP-39 mnemonic phrase wrapper.
///
/// This struct provides a high-level interface for working with BIP-39 mnemonic phrases.
/// It wraps the underlying BIP-39 implementation and provides methods for generating
/// random mnemonics, parsing existing phrases, and converting them to seeds.
///
/// # Mnemonic Format
///
/// - **Length**: 24 words (English)
/// - **Entropy**: 256 bits (maximum security)
/// - **Checksum**: Included in the word sequence
/// - **Wordlist**: BIP-39 English wordlist (2048 words)
///
/// # Example
///
/// ```
/// use bedrock::hhd::Mnemonic;
///
/// // Generate a new random mnemonic
/// let mnemonic = Mnemonic::new_random();
/// let phrase = mnemonic.to_phrase();
///
/// // Parse an existing mnemonic
/// let restored = Mnemonic::from_phrase(phrase).unwrap();
///
/// // Both produce the same seed
/// let seed1 = mnemonic.to_seed(None).unwrap();
/// let seed2 = restored.to_seed(None).unwrap();
/// assert_eq!(seed1.as_bytes(), seed2.as_bytes());
/// ```
#[derive(Clone)]
pub struct Mnemonic {
    inner: Bip39Mnemonic,
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mnemonic")
            .field("phrase", &"<redacted>")
            .finish()
    }
}

impl Mnemonic {
    /// Generates a new random mnemonic phrase of 24 words using the English wordlist.
    ///
    /// This method creates a cryptographically secure random mnemonic phrase following
    /// the BIP-39 standard. The generated mnemonic provides 256 bits of entropy, which
    /// is the maximum security level for BIP-39.
    ///
    /// # Returns
    ///
    /// A new `Mnemonic` instance with a randomly generated 24-word English BIP-39 mnemonic phrase.
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::Mnemonic;
    ///
    /// let mnemonic = Mnemonic::new_random();
    /// let phrase = mnemonic.to_phrase();
    ///
    /// // Verify it's a 24-word phrase
    /// let word_count = phrase.split_whitespace().count();
    /// assert_eq!(word_count, 24);
    /// ```
    pub fn new_random() -> Self {
        let inner = Bip39Mnemonic::new(MnemonicType::Words24, Language::English);
        Self { inner }
    }

    /// Creates a new `Mnemonic` from an existing BIP-39 phrase string.
    ///
    /// This method parses and validates a mnemonic phrase string. The phrase must be
    /// a valid BIP-39 mnemonic (24 words, English wordlist) with a valid checksum.
    ///
    /// # Arguments
    ///
    /// * `phrase` - The mnemonic phrase string (24 words separated by whitespace)
    ///
    /// # Returns
    ///
    /// * `Ok(Mnemonic)` - The parsed and validated mnemonic
    /// * `Err(Bip39ErrorKind)` - If the phrase is invalid
    ///
    /// # Errors
    ///
    /// Returns `Bip39ErrorKind` in the following cases:
    /// - Invalid word count (must be exactly 24 words)
    /// - Invalid word (word not in BIP-39 English wordlist)
    /// - Invalid checksum (mnemonic phrase checksum validation failed)
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::Mnemonic;
    ///
    /// // Valid BIP-39 test phrase
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
    /// assert_eq!(mnemonic.to_phrase(), phrase);
    ///
    /// // Invalid phrase will fail
    /// assert!(Mnemonic::from_phrase("invalid phrase").is_err());
    /// ```
    pub fn from_phrase(phrase: &str) -> Result<Self, Bip39ErrorKind> {
        let inner = Bip39Mnemonic::from_phrase(phrase, Language::English)?;
        Ok(Self { inner })
    }

    /// Gets a reference to the mnemonic phrase string.
    ///
    /// Returns the 24-word mnemonic phrase as a string. This is useful for displaying
    /// the mnemonic to users or storing it for backup purposes.
    ///
    /// # Returns
    ///
    /// A string slice containing the mnemonic phrase (24 words separated by spaces).
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::Mnemonic;
    ///
    /// let mnemonic = Mnemonic::new_random();
    /// let phrase = mnemonic.to_phrase();
    ///
    /// // Display or store the phrase
    /// println!("Backup this phrase: {}", phrase);
    ///
    /// // Verify it contains 24 words
    /// let words: Vec<&str> = phrase.split_whitespace().collect();
    /// assert_eq!(words.len(), 24);
    /// ```
    pub fn to_phrase(&self) -> &str {
        self.inner.phrase()
    }

    /// Converts the mnemonic to a BIP-32 seed using PBKDF2.
    ///
    /// This method implements the BIP-39 seed generation process, which uses PBKDF2
    /// (Password-Based Key Derivation Function 2) to derive a 64-byte seed from the
    /// mnemonic phrase and an optional passphrase.
    ///
    /// # Arguments
    ///
    /// * `password` - Optional BIP-39 passphrase (adds extra security layer)
    ///   - If `None`, uses an empty string (no passphrase)
    ///   - If `Some(passphrase)`, uses the provided passphrase
    ///
    /// # Returns
    ///
    /// * `Ok(Bip32Seed)` - A 64-byte seed suitable for BIP-32 HD key derivation
    /// * `Err(MnemonicError)` - If seed generation fails
    ///
    /// # Errors
    ///
    /// Returns `MnemonicError::InvalidSeedLength` if the generated seed is not exactly
    /// 64 bytes (this should not happen in practice with valid BIP-39 implementations).
    ///
    /// # Security Note
    ///
    /// Using a passphrase provides an additional layer of security. However, if you
    /// forget the passphrase, you will not be able to recover the seed even with the
    /// mnemonic phrase. Store the passphrase separately if used.
    ///
    /// # Example
    ///
    /// ```
    /// use bedrock::hhd::Mnemonic;
    ///
    /// let mnemonic = Mnemonic::new_random();
    ///
    /// // Generate seed without passphrase
    /// let seed_no_passphrase = mnemonic.to_seed(None).unwrap();
    /// assert_eq!(seed_no_passphrase.as_bytes().len(), 64);
    ///
    /// // Generate seed with passphrase
    /// let seed_with_passphrase = mnemonic.to_seed(Some("my secret passphrase")).unwrap();
    /// assert_eq!(seed_with_passphrase.as_bytes().len(), 64);
    ///
    /// // Different passphrases produce different seeds
    /// let seed_different_passphrase = mnemonic.to_seed(Some("different passphrase")).unwrap();
    /// assert_ne!(seed_with_passphrase.as_bytes(), seed_different_passphrase.as_bytes());
    /// ```
    pub fn to_seed(&self, password: Option<&str>) -> Result<Bip32Seed, MnemonicError> {
        let master_seed = Bip39Seed::new(&self.inner, password.unwrap_or(""));

        let master_seed_bytes: [u8; 64] =
            master_seed
                .as_bytes()
                .try_into()
                .map_err(|_| MnemonicError::InvalidSeedLength {
                    expected: 64,
                    actual: master_seed.as_bytes().len(),
                })?;
        let bip_32_master_seed = Bip32Seed::new(master_seed_bytes);
        Ok(bip_32_master_seed)
    }
}

/// Errors that can occur during mnemonic operations.
#[derive(Debug, thiserror::Error)]
pub enum MnemonicError {
    /// Invalid seed length encountered during seed conversion.
    #[error("Invalid seed length: expected {expected}, got {actual}")]
    InvalidSeedLength {
        /// Expected seed length in bytes (always 64 for BIP-39)
        expected: usize,
        /// Actual seed length in bytes
        actual: usize,
    },
    /// Error occurred during BIP-39 mnemonic processing.
    #[error("BIP39 error: {0}")]
    Bip39(#[from] Bip39ErrorKind),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;

    /// This ensures compatibility with other BIP-39 implementations.
    ///
    /// Test vector from: https://github.com/MetacoSA/NBitcoin/blob/master/NBitcoin.Tests/data/bip39_vectors.en.json
    #[test]
    fn password_is_unicode_normalized() {
        let phrase = "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter all";
        let password = "nullius　à　nym.zone ¹teſts² English";
        let expected_seed_hex = "3028751d811a60dc04039d4b5eebe8539a1beea2cae3e0805a0a775f8623b0f9e2a5d6b7a213c478faa0652e4eb940935ac20742171536275baccc1c46a5d016";

        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed = mnemonic.to_seed(Some(password)).unwrap();
        let seed_hex: String = seed
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        assert_eq!(seed_hex, expected_seed_hex);
    }
}
