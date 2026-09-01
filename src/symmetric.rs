//! Transport-neutral symmetric cryptographic primitives.
//!
//! This module contains mechanism only. TLS record framing, QUIC packet
//! protection, nonce construction, and algorithm negotiation remain the
//! responsibility of protocol adapters.

use core::fmt;

use aes::cipher::{BlockCipherEncrypt, KeyInit as _, consts::U16};
use aes::{Aes128, Aes256, Block};
use aes_gcm::aead::{AeadInOut, consts::U12};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf as RustCryptoHkdf;
use hmac::{Hmac as RustCryptoHmac, Mac};
use sha2::{Digest as _, Sha256, Sha384};
use thiserror::Error as ThisError;

/// Length in bytes of every supported AEAD authentication tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Errors returned by symmetric primitive operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
pub enum SymmetricError {
    /// A key does not have the length required by the selected algorithm.
    #[error("invalid symmetric key length")]
    InvalidKeyLength,
    /// A fixed-width value has an unexpected length.
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Required byte length.
        expected: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// Authentication of a ciphertext or MAC failed.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// An HKDF pseudorandom key or requested output has an invalid length.
    #[error("invalid HKDF input or output length")]
    InvalidHkdfLength,
    /// The requested stream-cipher position is outside the supported range.
    #[error("invalid stream-cipher position")]
    InvalidStreamPosition,
}

macro_rules! fixed_bytes {
    ($(#[$metadata:meta])* $name:ident, $length:expr) => {
        $(#[$metadata])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name([u8; $length]);

        impl $name {
            /// Returns the fixed-width byte representation.
            pub const fn as_array(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<[u8; $length]> for $name {
            fn from(value: [u8; $length]) -> Self {
                Self(value)
            }
        }

        impl From<$name> for [u8; $length] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = SymmetricError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let bytes = <[u8; $length]>::try_from(value).map_err(|_| {
                    SymmetricError::InvalidLength {
                        expected: $length,
                        actual: value.len(),
                    }
                })?;
                Ok(Self(bytes))
            }
        }
    };
}

fixed_bytes!(
    /// A 96-bit nonce for the supported AEAD algorithms.
    AeadNonce,
    12
);
fixed_bytes!(
    /// A detached authentication tag produced by a supported AEAD algorithm.
    AuthenticationTag,
    AEAD_TAG_LEN
);
fixed_bytes!(
    /// The output of SHA-256.
    Sha256Digest,
    32
);
fixed_bytes!(
    /// The output of SHA-384.
    Sha384Digest,
    48
);
fixed_bytes!(
    /// An HMAC-SHA-256 authentication tag.
    HmacSha256Tag,
    32
);
fixed_bytes!(
    /// An HMAC-SHA-384 authentication tag.
    HmacSha384Tag,
    48
);

/// A supported authenticated-encryption algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// Returns the required key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Encrypts `payload` in place and returns its detached authentication tag.
    pub fn encrypt_in_place_detached(
        self,
        key: &[u8],
        nonce: AeadNonce,
        associated_data: &[u8],
        payload: &mut [u8],
    ) -> Result<AuthenticationTag, SymmetricError> {
        match self {
            Self::Aes128Gcm => {
                let cipher =
                    Aes128Gcm::new_from_slice(key).map_err(|_| SymmetricError::InvalidKeyLength)?;
                let nonce = aes_gcm::Nonce::<U12>::from(*nonce.as_array());
                cipher
                    .encrypt_inout_detached(&nonce, associated_data, payload.into())
                    .map(|tag| AuthenticationTag::from(<[u8; AEAD_TAG_LEN]>::from(tag)))
                    .map_err(|_| SymmetricError::AuthenticationFailed)
            }
            Self::Aes256Gcm => {
                let cipher =
                    Aes256Gcm::new_from_slice(key).map_err(|_| SymmetricError::InvalidKeyLength)?;
                let nonce = aes_gcm::Nonce::<U12>::from(*nonce.as_array());
                cipher
                    .encrypt_inout_detached(&nonce, associated_data, payload.into())
                    .map(|tag| AuthenticationTag::from(<[u8; AEAD_TAG_LEN]>::from(tag)))
                    .map_err(|_| SymmetricError::AuthenticationFailed)
            }
            Self::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| SymmetricError::InvalidKeyLength)?;
                let nonce = chacha20poly1305::Nonce::from(*nonce.as_array());
                cipher
                    .encrypt_inout_detached(&nonce, associated_data, payload.into())
                    .map(|tag| AuthenticationTag::from(<[u8; AEAD_TAG_LEN]>::from(tag)))
                    .map_err(|_| SymmetricError::AuthenticationFailed)
            }
        }
    }

    /// Authenticates and decrypts `payload` in place.
    pub fn decrypt_in_place_detached(
        self,
        key: &[u8],
        nonce: AeadNonce,
        associated_data: &[u8],
        payload: &mut [u8],
        tag: AuthenticationTag,
    ) -> Result<(), SymmetricError> {
        match self {
            Self::Aes128Gcm => {
                let cipher =
                    Aes128Gcm::new_from_slice(key).map_err(|_| SymmetricError::InvalidKeyLength)?;
                let nonce = aes_gcm::Nonce::<U12>::from(*nonce.as_array());
                let tag = aes_gcm::Tag::from(*tag.as_array());
                cipher
                    .decrypt_inout_detached(&nonce, associated_data, payload.into(), &tag)
                    .map_err(|_| SymmetricError::AuthenticationFailed)
            }
            Self::Aes256Gcm => {
                let cipher =
                    Aes256Gcm::new_from_slice(key).map_err(|_| SymmetricError::InvalidKeyLength)?;
                let nonce = aes_gcm::Nonce::<U12>::from(*nonce.as_array());
                let tag = aes_gcm::Tag::from(*tag.as_array());
                cipher
                    .decrypt_inout_detached(&nonce, associated_data, payload.into(), &tag)
                    .map_err(|_| SymmetricError::AuthenticationFailed)
            }
            Self::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| SymmetricError::InvalidKeyLength)?;
                let nonce = chacha20poly1305::Nonce::from(*nonce.as_array());
                let tag = chacha20poly1305::Tag::from(*tag.as_array());
                cipher
                    .decrypt_inout_detached(&nonce, associated_data, payload.into(), &tag)
                    .map_err(|_| SymmetricError::AuthenticationFailed)
            }
        }
    }
}

/// Computes SHA-256 over `data`.
pub fn sha256(data: &[u8]) -> Sha256Digest {
    Sha256Digest::from(<[u8; 32]>::from(Sha256::digest(data)))
}

/// Computes SHA-384 over `data`.
pub fn sha384(data: &[u8]) -> Sha384Digest {
    Sha384Digest::from(<[u8; 48]>::from(Sha384::digest(data)))
}

/// Incremental SHA-256 state.
#[derive(Clone, Debug, Default)]
pub struct Sha256Context(Sha256);

impl Sha256Context {
    /// Creates an empty SHA-256 context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes to the digest.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the digest without consuming this context.
    pub fn fork_finish(&self) -> Sha256Digest {
        Sha256Digest::from(<[u8; 32]>::from(self.0.clone().finalize()))
    }

    /// Consumes this context and returns the digest.
    pub fn finish(self) -> Sha256Digest {
        Sha256Digest::from(<[u8; 32]>::from(self.0.finalize()))
    }
}

/// Incremental SHA-384 state.
#[derive(Clone, Debug, Default)]
pub struct Sha384Context(Sha384);

impl Sha384Context {
    /// Creates an empty SHA-384 context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes to the digest.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the digest without consuming this context.
    pub fn fork_finish(&self) -> Sha384Digest {
        Sha384Digest::from(<[u8; 48]>::from(self.0.clone().finalize()))
    }

    /// Consumes this context and returns the digest.
    pub fn finish(self) -> Sha384Digest {
        Sha384Digest::from(<[u8; 48]>::from(self.0.finalize()))
    }
}

/// An HMAC-SHA-256 key.
pub struct HmacSha256Key(RustCryptoHmac<Sha256>);

impl HmacSha256Key {
    /// Constructs a key from arbitrary-length key material.
    pub fn new(key: &[u8]) -> Self {
        Self(
            RustCryptoHmac::<Sha256>::new_from_slice(key).unwrap_or_else(|_| {
                <RustCryptoHmac<Sha256> as hmac::KeyInit>::new(&Default::default())
            }),
        )
    }

    /// Authenticates the supplied byte slices as one contiguous message.
    pub fn sign<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> HmacSha256Tag {
        let mut mac = self.0.clone();
        parts.into_iter().for_each(|part| mac.update(part));
        HmacSha256Tag::from(<[u8; 32]>::from(mac.finalize().into_bytes()))
    }

    /// Verifies a tag for the supplied slices treated as one contiguous message.
    pub fn verify<'a>(
        &self,
        parts: impl IntoIterator<Item = &'a [u8]>,
        tag: &[u8],
    ) -> Result<(), SymmetricError> {
        let mut mac = self.0.clone();
        parts.into_iter().for_each(|part| mac.update(part));
        mac.verify_slice(tag)
            .map_err(|_| SymmetricError::AuthenticationFailed)
    }
}

impl fmt::Debug for HmacSha256Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacSha256Key")
            .finish_non_exhaustive()
    }
}

/// An HMAC-SHA-384 key.
pub struct HmacSha384Key(RustCryptoHmac<Sha384>);

impl HmacSha384Key {
    /// Constructs a key from arbitrary-length key material.
    pub fn new(key: &[u8]) -> Self {
        Self(
            RustCryptoHmac::<Sha384>::new_from_slice(key).unwrap_or_else(|_| {
                <RustCryptoHmac<Sha384> as hmac::KeyInit>::new(&Default::default())
            }),
        )
    }

    /// Authenticates the supplied byte slices as one contiguous message.
    pub fn sign<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> HmacSha384Tag {
        let mut mac = self.0.clone();
        parts.into_iter().for_each(|part| mac.update(part));
        HmacSha384Tag::from(<[u8; 48]>::from(mac.finalize().into_bytes()))
    }

    /// Verifies a tag for the supplied slices treated as one contiguous message.
    pub fn verify<'a>(
        &self,
        parts: impl IntoIterator<Item = &'a [u8]>,
        tag: &[u8],
    ) -> Result<(), SymmetricError> {
        let mut mac = self.0.clone();
        parts.into_iter().for_each(|part| mac.update(part));
        mac.verify_slice(tag)
            .map_err(|_| SymmetricError::AuthenticationFailed)
    }
}

impl fmt::Debug for HmacSha384Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacSha384Key")
            .finish_non_exhaustive()
    }
}

/// An HKDF-SHA-256 expander.
pub struct HkdfSha256(RustCryptoHkdf<Sha256>);

impl HkdfSha256 {
    /// Extracts a pseudorandom key from input key material and an optional salt.
    pub fn extract(salt: Option<&[u8]>, input_key_material: &[u8]) -> Self {
        Self(RustCryptoHkdf::new(salt, input_key_material))
    }

    /// Constructs an expander from an existing pseudorandom key.
    pub fn from_prk(pseudorandom_key: &[u8]) -> Result<Self, SymmetricError> {
        RustCryptoHkdf::from_prk(pseudorandom_key)
            .map(Self)
            .map_err(|_| SymmetricError::InvalidHkdfLength)
    }

    /// Expands this key using the concatenated `info` slices.
    pub fn expand(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), SymmetricError> {
        self.0
            .expand_multi_info(info, output)
            .map_err(|_| SymmetricError::InvalidHkdfLength)
    }
}

impl fmt::Debug for HkdfSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HkdfSha256").finish_non_exhaustive()
    }
}

/// An HKDF-SHA-384 expander.
pub struct HkdfSha384(RustCryptoHkdf<Sha384>);

impl HkdfSha384 {
    /// Extracts a pseudorandom key from input key material and an optional salt.
    pub fn extract(salt: Option<&[u8]>, input_key_material: &[u8]) -> Self {
        Self(RustCryptoHkdf::new(salt, input_key_material))
    }

    /// Constructs an expander from an existing pseudorandom key.
    pub fn from_prk(pseudorandom_key: &[u8]) -> Result<Self, SymmetricError> {
        RustCryptoHkdf::from_prk(pseudorandom_key)
            .map(Self)
            .map_err(|_| SymmetricError::InvalidHkdfLength)
    }

    /// Expands this key using the concatenated `info` slices.
    pub fn expand(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), SymmetricError> {
        self.0
            .expand_multi_info(info, output)
            .map_err(|_| SymmetricError::InvalidHkdfLength)
    }
}

impl fmt::Debug for HkdfSha384 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HkdfSha384").finish_non_exhaustive()
    }
}

/// Encrypts one 16-byte block with AES-128.
pub fn aes128_encrypt_block(key: &[u8], plaintext: &[u8; 16]) -> Result<[u8; 16], SymmetricError> {
    aes_encrypt_block::<Aes128>(key, plaintext)
}

/// Encrypts one 16-byte block with AES-256.
pub fn aes256_encrypt_block(key: &[u8], plaintext: &[u8; 16]) -> Result<[u8; 16], SymmetricError> {
    aes_encrypt_block::<Aes256>(key, plaintext)
}

fn aes_encrypt_block<Aes>(key: &[u8], plaintext: &[u8; 16]) -> Result<[u8; 16], SymmetricError>
where
    Aes: BlockCipherEncrypt<BlockSize = U16> + aes::cipher::KeyInit,
{
    let cipher = Aes::new_from_slice(key).map_err(|_| SymmetricError::InvalidKeyLength)?;
    let mut block = Block::from(*plaintext);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

/// Writes ChaCha20 keystream bytes beginning at `position` into `output`.
pub fn chacha20_keystream(
    key: &[u8],
    nonce: &[u8; 12],
    position: u64,
    output: &mut [u8],
) -> Result<(), SymmetricError> {
    let mut cipher =
        ChaCha20::new_from_slices(key, nonce).map_err(|_| SymmetricError::InvalidKeyLength)?;
    cipher
        .try_seek(position)
        .map_err(|_| SymmetricError::InvalidStreamPosition)?;
    cipher
        .try_apply_keystream(output)
        .map_err(|_| SymmetricError::InvalidStreamPosition)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn all_aead_algorithms_round_trip_and_authenticate() {
        for algorithm in [
            AeadAlgorithm::Aes128Gcm,
            AeadAlgorithm::Aes256Gcm,
            AeadAlgorithm::ChaCha20Poly1305,
        ] {
            let key = vec![0x42; algorithm.key_len()];
            let nonce = AeadNonce::from([0x24; 12]);
            let mut payload = b"bedrock symmetric primitive".to_vec();
            let plaintext = payload.clone();
            let mut tag = algorithm
                .encrypt_in_place_detached(&key, nonce, b"context", &mut payload)
                .unwrap();
            algorithm
                .decrypt_in_place_detached(&key, nonce, b"context", &mut payload, tag)
                .unwrap();
            assert_eq!(payload, plaintext);

            tag.0[0] ^= 1;
            assert!(
                algorithm
                    .decrypt_in_place_detached(&key, nonce, b"context", &mut payload, tag)
                    .is_err()
            );
        }
    }

    #[test]
    fn sha2_known_answers_and_incremental_contexts_match() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut context = Sha384Context::new();
        context.update(b"a");
        context.update(b"bc");
        assert_eq!(context.finish(), sha384(b"abc"));
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        let key = HmacSha256Key::new(&[0x0b; 20]);
        let tag = key.sign([b"Hi There".as_slice()]);
        assert_eq!(
            hex::encode(tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert!(
            key.verify([b"Hi ".as_slice(), b"There".as_slice()], tag.as_ref())
                .is_ok()
        );
    }

    #[test]
    fn hkdf_sha256_matches_rfc_5869() {
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let hkdf = HkdfSha256::extract(Some(&salt), &ikm);
        let mut output = [0u8; 42];
        hkdf.expand(&[&info], &mut output).unwrap();
        assert_eq!(
            hex::encode(output),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn aes_block_and_chacha_stream_match_known_answers() {
        let aes = aes128_encrypt_block(&[0; 16], &[0; 16]).unwrap();
        assert_eq!(hex::encode(aes), "66e94bd4ef8a2c3b884cfa59ca342b2e");

        let mut stream = [0u8; 64];
        chacha20_keystream(&[0; 32], &[0; 12], 0, &mut stream).unwrap();
        assert_eq!(
            hex::encode(stream),
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        );
    }
}
