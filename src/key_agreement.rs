//! Transport-neutral ephemeral elliptic-curve key agreement.

use core::fmt;

use p256::elliptic_curve::sec1::ToSec1Point as _;
use thiserror::Error as ThisError;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekStaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::random::{RandomError, fill};

/// Errors returned by ephemeral key-agreement operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
pub enum KeyAgreementError {
    /// The operating system could not provide key material.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// The peer key has an invalid length, encoding, point, or contribution.
    #[error("invalid peer key")]
    InvalidPeerKey,
    /// A generated public key or shared secret had an unexpected representation.
    #[error("invalid generated key representation")]
    InvalidGeneratedKey,
}

macro_rules! public_key {
    ($(#[$metadata:meta])* $name:ident, $length:expr) => {
        $(#[$metadata])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name([u8; $length]);

        impl $name {
            /// Returns the canonical fixed-width byte representation.
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<[u8; $length]> for $name {
            fn from(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = KeyAgreementError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                <[u8; $length]>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| KeyAgreementError::InvalidPeerKey)
            }
        }
    };
}

macro_rules! shared_secret {
    ($(#[$metadata:meta])* $name:ident, $length:expr) => {
        $(#[$metadata])*
        pub struct $name([u8; $length]);

        impl $name {
            /// Returns the fixed-width shared-secret bytes.
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
    };
}

public_key!(
    /// An X25519 public key.
    X25519PublicKey,
    32
);
public_key!(
    /// An uncompressed SEC1 P-256 public key.
    P256PublicKey,
    65
);
public_key!(
    /// An uncompressed SEC1 P-384 public key.
    P384PublicKey,
    97
);
shared_secret!(
    /// An X25519 shared secret.
    X25519SharedSecret,
    32
);
shared_secret!(
    /// A P-256 ECDH shared secret.
    P256SharedSecret,
    32
);
shared_secret!(
    /// A P-384 ECDH shared secret.
    P384SharedSecret,
    48
);

/// An ephemeral X25519 secret and its corresponding public key.
pub struct X25519Ephemeral {
    secret: DalekStaticSecret,
    public_key: X25519PublicKey,
}

impl X25519Ephemeral {
    /// Generates a fresh ephemeral key with operating-system randomness.
    pub fn generate() -> Result<Self, KeyAgreementError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        fill(bytes.as_mut())?;
        let secret = DalekStaticSecret::from(*bytes);
        let public_key = X25519PublicKey::from(DalekPublicKey::from(&secret).to_bytes());
        Ok(Self { secret, public_key })
    }

    /// Returns this ephemeral key's public key.
    pub const fn public_key(&self) -> X25519PublicKey {
        self.public_key
    }

    /// Consumes this ephemeral key and agrees with `peer`.
    pub fn complete(self, peer: &X25519PublicKey) -> Result<X25519SharedSecret, KeyAgreementError> {
        let shared = self
            .secret
            .diffie_hellman(&DalekPublicKey::from(*peer.as_bytes()));
        if !shared.was_contributory() {
            return Err(KeyAgreementError::InvalidPeerKey);
        }
        Ok(X25519SharedSecret(shared.to_bytes()))
    }
}

impl fmt::Debug for X25519Ephemeral {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X25519Ephemeral")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// An ephemeral P-256 secret and its corresponding uncompressed public key.
pub struct P256Ephemeral {
    secret: p256::SecretKey,
    public_key: P256PublicKey,
}

impl P256Ephemeral {
    /// Generates a fresh ephemeral key with operating-system randomness.
    pub fn generate() -> Result<Self, KeyAgreementError> {
        let secret = loop {
            let mut candidate = Zeroizing::new([0u8; 32]);
            fill(candidate.as_mut())?;
            if let Ok(secret) = p256::SecretKey::from_slice(candidate.as_ref()) {
                break secret;
            }
        };
        let encoded = secret.public_key().to_sec1_point(false);
        let public_key = P256PublicKey::try_from(encoded.as_bytes())
            .map_err(|_| KeyAgreementError::InvalidGeneratedKey)?;
        Ok(Self { secret, public_key })
    }

    /// Returns this ephemeral key's canonical uncompressed public key.
    pub const fn public_key(&self) -> P256PublicKey {
        self.public_key
    }

    /// Consumes this ephemeral key and agrees with `peer`.
    pub fn complete(self, peer: &P256PublicKey) -> Result<P256SharedSecret, KeyAgreementError> {
        if peer.as_bytes().first() != Some(&0x04) {
            return Err(KeyAgreementError::InvalidPeerKey);
        }
        let peer = p256::PublicKey::from_sec1_bytes(peer.as_ref())
            .map_err(|_| KeyAgreementError::InvalidPeerKey)?;
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let raw = shared.raw_secret_bytes();
        let bytes = <[u8; 32]>::try_from(raw.as_slice())
            .map_err(|_| KeyAgreementError::InvalidGeneratedKey)?;
        Ok(P256SharedSecret(bytes))
    }
}

impl fmt::Debug for P256Ephemeral {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("P256Ephemeral")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// An ephemeral P-384 secret and its corresponding uncompressed public key.
pub struct P384Ephemeral {
    secret: p384::SecretKey,
    public_key: P384PublicKey,
}

impl P384Ephemeral {
    /// Generates a fresh ephemeral key with operating-system randomness.
    pub fn generate() -> Result<Self, KeyAgreementError> {
        let secret = loop {
            let mut candidate = Zeroizing::new([0u8; 48]);
            fill(candidate.as_mut())?;
            if let Ok(secret) = p384::SecretKey::from_slice(candidate.as_ref()) {
                break secret;
            }
        };
        let encoded = secret.public_key().to_sec1_point(false);
        let public_key = P384PublicKey::try_from(encoded.as_bytes())
            .map_err(|_| KeyAgreementError::InvalidGeneratedKey)?;
        Ok(Self { secret, public_key })
    }

    /// Returns this ephemeral key's canonical uncompressed public key.
    pub const fn public_key(&self) -> P384PublicKey {
        self.public_key
    }

    /// Consumes this ephemeral key and agrees with `peer`.
    pub fn complete(self, peer: &P384PublicKey) -> Result<P384SharedSecret, KeyAgreementError> {
        if peer.as_bytes().first() != Some(&0x04) {
            return Err(KeyAgreementError::InvalidPeerKey);
        }
        let peer = p384::PublicKey::from_sec1_bytes(peer.as_ref())
            .map_err(|_| KeyAgreementError::InvalidPeerKey)?;
        let shared = p384::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let raw = shared.raw_secret_bytes();
        let bytes = <[u8; 48]>::try_from(raw.as_slice())
            .map_err(|_| KeyAgreementError::InvalidGeneratedKey)?;
        Ok(P384SharedSecret(bytes))
    }
}

impl fmt::Debug for P384Ephemeral {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("P384Ephemeral")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn x25519_round_trip_and_low_order_rejection() {
        let alice = X25519Ephemeral::generate().unwrap();
        let bob = X25519Ephemeral::generate().unwrap();
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();
        let alice_secret = alice.complete(&bob_public).unwrap();
        let bob_secret = bob.complete(&alice_public).unwrap();
        assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());

        let ephemeral = X25519Ephemeral::generate().unwrap();
        assert!(ephemeral.complete(&X25519PublicKey::from([0; 32])).is_err());
    }

    #[test]
    fn p256_round_trip_and_invalid_point_rejection() {
        let alice = P256Ephemeral::generate().unwrap();
        let bob = P256Ephemeral::generate().unwrap();
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();
        assert_eq!(
            alice.complete(&bob_public).unwrap().as_ref(),
            bob.complete(&alice_public).unwrap().as_ref()
        );

        let ephemeral = P256Ephemeral::generate().unwrap();
        assert!(ephemeral.complete(&P256PublicKey::from([0; 65])).is_err());
    }

    #[test]
    fn p384_round_trip_and_invalid_point_rejection() {
        let alice = P384Ephemeral::generate().unwrap();
        let bob = P384Ephemeral::generate().unwrap();
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();
        assert_eq!(
            alice.complete(&bob_public).unwrap().as_ref(),
            bob.complete(&alice_public).unwrap().as_ref()
        );

        let ephemeral = P384Ephemeral::generate().unwrap();
        assert!(ephemeral.complete(&P384PublicKey::from([0; 97])).is_err());
    }

    #[test]
    fn public_key_newtypes_reject_wrong_lengths() {
        assert!(X25519PublicKey::try_from([0u8; 31].as_slice()).is_err());
        assert!(P256PublicKey::try_from([0u8; 64].as_slice()).is_err());
        assert!(P384PublicKey::try_from([0u8; 96].as_slice()).is_err());
    }
}
