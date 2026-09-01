//! Transport-neutral conventional digital signatures and key loading.

use core::fmt;

use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::traits::{PublicKeyParts, SignatureScheme as RsaSignatureScheme};
use rsa::{Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use signature::Signer as _;
use signature::hazmat::PrehashVerifier;
use thiserror::Error as ThisError;

const RSA_MINIMUM_BITS: u32 = 2048;

/// Errors returned by conventional signature operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
pub enum ClassicalSignatureError {
    /// The private key encoding or algorithm is unsupported or malformed.
    #[error("invalid or unsupported conventional private key")]
    InvalidPrivateKey,
    /// The public key encoding is malformed or below the required strength.
    #[error("invalid conventional public key")]
    InvalidPublicKey,
    /// The requested scheme does not match the loaded key.
    #[error("signature scheme does not match the loaded key")]
    UnsupportedScheme,
    /// Signing failed.
    #[error("conventional signature generation failed")]
    SigningFailed,
    /// Signature verification failed.
    #[error("conventional signature verification failed")]
    InvalidSignature,
    /// The public-key encoding could not be produced.
    #[error("conventional public-key encoding failed")]
    PublicKeyEncoding,
}

/// The public-key family of a conventional signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassicalSignatureAlgorithm {
    /// RSA.
    Rsa,
    /// ECDSA over P-256.
    EcdsaP256,
    /// ECDSA over P-384.
    EcdsaP384,
    /// Ed25519.
    Ed25519,
}

/// A conventional signature scheme available to protocol adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassicalSignatureScheme {
    /// ECDSA P-256 with SHA-256 and an ASN.1 DER signature.
    EcdsaP256Sha256,
    /// ECDSA P-384 with SHA-384 and an ASN.1 DER signature.
    EcdsaP384Sha384,
    /// Ed25519.
    Ed25519,
    /// RSA-PSS with SHA-256 and a 32-byte salt.
    RsaPssSha256,
    /// RSA-PSS with SHA-384 and a 48-byte salt.
    RsaPssSha384,
    /// RSA-PSS with SHA-512 and a 64-byte salt.
    RsaPssSha512,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
}

/// A conventional signature-verification algorithm.
///
/// The ECDSA variants name both the public-key curve and message digest. This
/// preserves certificate-signature combinations which do not correspond to a
/// TLS handshake `SignatureScheme` name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassicalVerificationAlgorithm {
    /// P-256 ECDSA with SHA-256.
    EcdsaP256Sha256,
    /// P-256 ECDSA with SHA-384.
    EcdsaP256Sha384,
    /// P-256 ECDSA with SHA-512.
    EcdsaP256Sha512,
    /// P-384 ECDSA with SHA-256.
    EcdsaP384Sha256,
    /// P-384 ECDSA with SHA-384.
    EcdsaP384Sha384,
    /// P-384 ECDSA with SHA-512.
    EcdsaP384Sha512,
    /// Ed25519.
    Ed25519,
    /// RSA-PSS with SHA-256.
    RsaPssSha256,
    /// RSA-PSS with SHA-384.
    RsaPssSha384,
    /// RSA-PSS with SHA-512.
    RsaPssSha512,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
}

enum SigningKeyInner {
    Rsa(RsaPrivateKey),
    EcdsaP256(P256SigningKey),
    EcdsaP384(P384SigningKey),
    Ed25519(Ed25519SigningKey),
}

/// A decoded conventional private signing key.
pub struct ClassicalSigningKey {
    inner: SigningKeyInner,
    public_key: Vec<u8>,
    public_key_spki: Vec<u8>,
}

impl ClassicalSigningKey {
    /// Loads RSA, P-256, P-384, or Ed25519 key material from PKCS#8 DER.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, ClassicalSignatureError> {
        if let Ok(key) = RsaPrivateKey::from_pkcs8_der(der) {
            return Self::from_rsa(key);
        }
        if let Ok(key) = p256::SecretKey::from_pkcs8_der(der) {
            return Self::from_p256(P256SigningKey::from(key));
        }
        if let Ok(key) = p384::SecretKey::from_pkcs8_der(der) {
            return Self::from_p384(P384SigningKey::from(key));
        }
        if let Ok(key) = Ed25519SigningKey::from_pkcs8_der(der) {
            return Self::from_ed25519(key);
        }
        Err(ClassicalSignatureError::InvalidPrivateKey)
    }

    /// Loads an RSA private key from PKCS#1 DER.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, ClassicalSignatureError> {
        RsaPrivateKey::from_pkcs1_der(der)
            .map_err(|_| ClassicalSignatureError::InvalidPrivateKey)
            .and_then(Self::from_rsa)
    }

    /// Loads a P-256 or P-384 private key from SEC1 DER.
    pub fn from_sec1_der(der: &[u8]) -> Result<Self, ClassicalSignatureError> {
        if let Ok(key) = p256::SecretKey::from_sec1_der(der) {
            return Self::from_p256(P256SigningKey::from(key));
        }
        if let Ok(key) = p384::SecretKey::from_sec1_der(der) {
            return Self::from_p384(P384SigningKey::from(key));
        }
        Err(ClassicalSignatureError::InvalidPrivateKey)
    }

    /// Returns the key's public-key family.
    pub const fn algorithm(&self) -> ClassicalSignatureAlgorithm {
        match self.inner {
            SigningKeyInner::Rsa(_) => ClassicalSignatureAlgorithm::Rsa,
            SigningKeyInner::EcdsaP256(_) => ClassicalSignatureAlgorithm::EcdsaP256,
            SigningKeyInner::EcdsaP384(_) => ClassicalSignatureAlgorithm::EcdsaP384,
            SigningKeyInner::Ed25519(_) => ClassicalSignatureAlgorithm::Ed25519,
        }
    }

    /// Returns the public-key bytes expected by [`verify`].
    ///
    /// RSA keys use PKCS#1 DER, ECDSA keys use uncompressed SEC1 points, and
    /// Ed25519 keys use their 32-byte compressed encoding.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the DER-encoded SubjectPublicKeyInfo for this key.
    pub fn public_key_spki_der(&self) -> &[u8] {
        &self.public_key_spki
    }

    /// Returns whether this key can produce `scheme`.
    pub const fn supports(&self, scheme: ClassicalSignatureScheme) -> bool {
        matches!(
            (self.algorithm(), scheme),
            (
                ClassicalSignatureAlgorithm::EcdsaP256,
                ClassicalSignatureScheme::EcdsaP256Sha256
            ) | (
                ClassicalSignatureAlgorithm::EcdsaP384,
                ClassicalSignatureScheme::EcdsaP384Sha384
            ) | (
                ClassicalSignatureAlgorithm::Ed25519,
                ClassicalSignatureScheme::Ed25519
            ) | (
                ClassicalSignatureAlgorithm::Rsa,
                ClassicalSignatureScheme::RsaPssSha256
                    | ClassicalSignatureScheme::RsaPssSha384
                    | ClassicalSignatureScheme::RsaPssSha512
                    | ClassicalSignatureScheme::RsaPkcs1Sha256
                    | ClassicalSignatureScheme::RsaPkcs1Sha384
                    | ClassicalSignatureScheme::RsaPkcs1Sha512
            )
        )
    }

    /// Signs `message` with the selected scheme.
    pub fn sign(
        &self,
        scheme: ClassicalSignatureScheme,
        message: &[u8],
    ) -> Result<Vec<u8>, ClassicalSignatureError> {
        if !self.supports(scheme) {
            return Err(ClassicalSignatureError::UnsupportedScheme);
        }

        match (&self.inner, scheme) {
            (SigningKeyInner::EcdsaP256(key), ClassicalSignatureScheme::EcdsaP256Sha256) => {
                let signature: P256Signature = key
                    .try_sign(message)
                    .map_err(|_| ClassicalSignatureError::SigningFailed)?;
                let signature = signature.normalize_s();
                Ok(signature.to_der().as_bytes().to_vec())
            }
            (SigningKeyInner::EcdsaP384(key), ClassicalSignatureScheme::EcdsaP384Sha384) => {
                let signature: P384Signature = key
                    .try_sign(message)
                    .map_err(|_| ClassicalSignatureError::SigningFailed)?;
                let signature = signature.normalize_s();
                Ok(signature.to_der().as_bytes().to_vec())
            }
            (SigningKeyInner::Ed25519(key), ClassicalSignatureScheme::Ed25519) => {
                Ok(key.sign(message).to_bytes().to_vec())
            }
            (SigningKeyInner::Rsa(key), scheme) => sign_rsa(key, scheme, message),
            _ => Err(ClassicalSignatureError::UnsupportedScheme),
        }
    }

    fn from_rsa(key: RsaPrivateKey) -> Result<Self, ClassicalSignatureError> {
        if key.n().bits() < RSA_MINIMUM_BITS {
            return Err(ClassicalSignatureError::InvalidPrivateKey);
        }
        let public_key = key
            .as_public_key()
            .to_pkcs1_der()
            .map_err(|_| ClassicalSignatureError::PublicKeyEncoding)?
            .as_bytes()
            .to_vec();
        let public_key_spki = key
            .as_public_key()
            .to_public_key_der()
            .map_err(|_| ClassicalSignatureError::PublicKeyEncoding)?
            .as_bytes()
            .to_vec();
        Ok(Self {
            inner: SigningKeyInner::Rsa(key),
            public_key,
            public_key_spki,
        })
    }

    fn from_p256(key: P256SigningKey) -> Result<Self, ClassicalSignatureError> {
        let verifying_key = key.verifying_key();
        let public_key = verifying_key.to_sec1_point(false).as_bytes().to_vec();
        let public_key_spki = verifying_key
            .to_public_key_der()
            .map_err(|_| ClassicalSignatureError::PublicKeyEncoding)?
            .as_bytes()
            .to_vec();
        Ok(Self {
            inner: SigningKeyInner::EcdsaP256(key),
            public_key,
            public_key_spki,
        })
    }

    fn from_p384(key: P384SigningKey) -> Result<Self, ClassicalSignatureError> {
        let verifying_key = key.verifying_key();
        let public_key = verifying_key.to_sec1_point(false).as_bytes().to_vec();
        let public_key_spki = verifying_key
            .to_public_key_der()
            .map_err(|_| ClassicalSignatureError::PublicKeyEncoding)?
            .as_bytes()
            .to_vec();
        Ok(Self {
            inner: SigningKeyInner::EcdsaP384(key),
            public_key,
            public_key_spki,
        })
    }

    fn from_ed25519(key: Ed25519SigningKey) -> Result<Self, ClassicalSignatureError> {
        let verifying_key = key.verifying_key();
        let public_key = verifying_key.to_bytes().to_vec();
        let public_key_spki = verifying_key
            .to_public_key_der()
            .map_err(|_| ClassicalSignatureError::PublicKeyEncoding)?
            .as_bytes()
            .to_vec();
        Ok(Self {
            inner: SigningKeyInner::Ed25519(key),
            public_key,
            public_key_spki,
        })
    }
}

impl fmt::Debug for ClassicalSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalSigningKey")
            .field("algorithm", &self.algorithm())
            .field("public_key_len", &self.public_key.len())
            .finish_non_exhaustive()
    }
}

/// Verifies a conventional signature.
pub fn verify(
    algorithm: ClassicalVerificationAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ClassicalSignatureError> {
    match algorithm {
        ClassicalVerificationAlgorithm::EcdsaP256Sha256 => {
            verify_p256::<Sha256>(public_key, message, signature)
        }
        ClassicalVerificationAlgorithm::EcdsaP256Sha384 => {
            verify_p256::<Sha384>(public_key, message, signature)
        }
        ClassicalVerificationAlgorithm::EcdsaP256Sha512 => {
            verify_p256::<Sha512>(public_key, message, signature)
        }
        ClassicalVerificationAlgorithm::EcdsaP384Sha256 => {
            verify_p384::<Sha256>(public_key, message, signature)
        }
        ClassicalVerificationAlgorithm::EcdsaP384Sha384 => {
            verify_p384::<Sha384>(public_key, message, signature)
        }
        ClassicalVerificationAlgorithm::EcdsaP384Sha512 => {
            verify_p384::<Sha512>(public_key, message, signature)
        }
        ClassicalVerificationAlgorithm::Ed25519 => {
            let key = Ed25519VerifyingKey::try_from(public_key)
                .map_err(|_| ClassicalSignatureError::InvalidPublicKey)?;
            let signature = Ed25519Signature::try_from(signature)
                .map_err(|_| ClassicalSignatureError::InvalidSignature)?;
            key.verify_strict(message, &signature)
                .map_err(|_| ClassicalSignatureError::InvalidSignature)
        }
        ClassicalVerificationAlgorithm::RsaPssSha256 => {
            verify_rsa_pss::<Sha256>(public_key, &Sha256::digest(message), signature)
        }
        ClassicalVerificationAlgorithm::RsaPssSha384 => {
            verify_rsa_pss::<Sha384>(public_key, &Sha384::digest(message), signature)
        }
        ClassicalVerificationAlgorithm::RsaPssSha512 => {
            verify_rsa_pss::<Sha512>(public_key, &Sha512::digest(message), signature)
        }
        ClassicalVerificationAlgorithm::RsaPkcs1Sha256 => verify_rsa(
            public_key,
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(message),
            signature,
        ),
        ClassicalVerificationAlgorithm::RsaPkcs1Sha384 => verify_rsa(
            public_key,
            Pkcs1v15Sign::new::<Sha384>(),
            &Sha384::digest(message),
            signature,
        ),
        ClassicalVerificationAlgorithm::RsaPkcs1Sha512 => verify_rsa(
            public_key,
            Pkcs1v15Sign::new::<Sha512>(),
            &Sha512::digest(message),
            signature,
        ),
    }
}

/// Signs a message with the requested RSA scheme.
fn sign_rsa(
    key: &RsaPrivateKey,
    scheme: ClassicalSignatureScheme,
    message: &[u8],
) -> Result<Vec<u8>, ClassicalSignatureError> {
    let mut rng = getrandom_v04::SysRng;
    let result = match scheme {
        ClassicalSignatureScheme::RsaPssSha256 => {
            Pss::<Sha256>::new().sign(Some(&mut rng), key, &Sha256::digest(message))
        }
        ClassicalSignatureScheme::RsaPssSha384 => {
            Pss::<Sha384>::new().sign(Some(&mut rng), key, &Sha384::digest(message))
        }
        ClassicalSignatureScheme::RsaPssSha512 => {
            Pss::<Sha512>::new().sign(Some(&mut rng), key, &Sha512::digest(message))
        }
        ClassicalSignatureScheme::RsaPkcs1Sha256 => {
            Pkcs1v15Sign::new::<Sha256>().sign(Some(&mut rng), key, &Sha256::digest(message))
        }
        ClassicalSignatureScheme::RsaPkcs1Sha384 => {
            Pkcs1v15Sign::new::<Sha384>().sign(Some(&mut rng), key, &Sha384::digest(message))
        }
        ClassicalSignatureScheme::RsaPkcs1Sha512 => {
            Pkcs1v15Sign::new::<Sha512>().sign(Some(&mut rng), key, &Sha512::digest(message))
        }
        _ => return Err(ClassicalSignatureError::UnsupportedScheme),
    };
    result.map_err(|_| ClassicalSignatureError::SigningFailed)
}

/// Verifies an ECDSA signature with a P-256 public key and caller-selected digest.
fn verify_p256<D>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ClassicalSignatureError>
where
    D: sha2::Digest,
{
    let key = P256VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| ClassicalSignatureError::InvalidPublicKey)?;
    let signature = P256Signature::from_der(signature)
        .map_err(|_| ClassicalSignatureError::InvalidSignature)?;
    key.verify_prehash(&D::digest(message), &signature)
        .map_err(|_| ClassicalSignatureError::InvalidSignature)
}

/// Verifies an ECDSA signature with a P-384 public key and caller-selected digest.
fn verify_p384<D>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ClassicalSignatureError>
where
    D: sha2::Digest,
{
    let key = P384VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| ClassicalSignatureError::InvalidPublicKey)?;
    let signature = P384Signature::from_der(signature)
        .map_err(|_| ClassicalSignatureError::InvalidSignature)?;
    key.verify_prehash(&D::digest(message), &signature)
        .map_err(|_| ClassicalSignatureError::InvalidSignature)
}

/// Verifies an RSA-PSS signature while accepting its encoded salt length.
fn verify_rsa_pss<D>(
    public_key: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), ClassicalSignatureError>
where
    D: sha2::Digest + sha2::digest::FixedOutputReset,
{
    let key = parse_rsa_public_key(public_key)?;
    let signature = RsaPssSignature::try_from(signature)
        .map_err(|_| ClassicalSignatureError::InvalidSignature)?;
    RsaPssVerifyingKey::<D>::new_with_auto_salt_len(key)
        .verify_prehash(digest, &signature)
        .map_err(|_| ClassicalSignatureError::InvalidSignature)
}

/// Verifies an RSA signature using a caller-selected padding scheme.
fn verify_rsa<S>(
    public_key: &[u8],
    scheme: S,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), ClassicalSignatureError>
where
    S: rsa::traits::SignatureScheme,
{
    let key = parse_rsa_public_key(public_key)?;
    key.verify(scheme, digest, signature)
        .map_err(|_| ClassicalSignatureError::InvalidSignature)
}

/// Decodes a PKCS#1 RSA public key and enforces the minimum key size.
fn parse_rsa_public_key(public_key: &[u8]) -> Result<RsaPublicKey, ClassicalSignatureError> {
    let key = RsaPublicKey::from_pkcs1_der(public_key)
        .map_err(|_| ClassicalSignatureError::InvalidPublicKey)?;
    if key.n().bits() < RSA_MINIMUM_BITS {
        return Err(ClassicalSignatureError::InvalidPublicKey);
    }
    Ok(key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use signature::hazmat::PrehashSigner as _;

    use super::*;

    #[test]
    fn p256_pkcs8_and_sec1_round_trip() {
        let secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let pkcs8 = secret.to_pkcs8_der().unwrap();
        let key = ClassicalSigningKey::from_pkcs8_der(pkcs8.as_bytes()).unwrap();
        assert_eq!(key.algorithm(), ClassicalSignatureAlgorithm::EcdsaP256);
        let signature = key
            .sign(ClassicalSignatureScheme::EcdsaP256Sha256, b"message")
            .unwrap();
        verify(
            ClassicalVerificationAlgorithm::EcdsaP256Sha256,
            key.public_key(),
            b"message",
            &signature,
        )
        .unwrap();

        let sec1 = secret.to_sec1_der().unwrap();
        assert_eq!(
            ClassicalSigningKey::from_sec1_der(sec1.as_slice())
                .unwrap()
                .algorithm(),
            ClassicalSignatureAlgorithm::EcdsaP256
        );
    }

    #[test]
    fn p384_cross_hash_verification_works() {
        let secret = p384::SecretKey::from_slice(&[0x22; 48]).unwrap();
        let signing_key = P384SigningKey::from(secret.clone());
        let key = ClassicalSigningKey::from_p384(signing_key.clone()).unwrap();
        let signature: P384Signature = signing_key
            .sign_prehash(&Sha256::digest(b"certificate"))
            .unwrap();
        verify(
            ClassicalVerificationAlgorithm::EcdsaP384Sha256,
            key.public_key(),
            b"certificate",
            signature.to_der().as_bytes(),
        )
        .unwrap();

        let sec1 = secret.to_sec1_der().unwrap();
        assert_eq!(
            ClassicalSigningKey::from_sec1_der(sec1.as_slice())
                .unwrap()
                .algorithm(),
            ClassicalSignatureAlgorithm::EcdsaP384
        );
    }

    #[test]
    fn ed25519_pkcs8_round_trip() {
        let signing_key = Ed25519SigningKey::from_bytes(&[0x33; 32]);
        let pkcs8 = signing_key.to_pkcs8_der().unwrap();
        let key = ClassicalSigningKey::from_pkcs8_der(pkcs8.as_bytes()).unwrap();
        assert_eq!(key.algorithm(), ClassicalSignatureAlgorithm::Ed25519);
        let signature = key
            .sign(ClassicalSignatureScheme::Ed25519, b"message")
            .unwrap();
        verify(
            ClassicalVerificationAlgorithm::Ed25519,
            key.public_key(),
            b"message",
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn rsa_pkcs1_and_pkcs8_support_all_schemes() {
        let mut rng = rand_core_010::UnwrapErr(getrandom_v04::SysRng);
        let rsa = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkcs1 = rsa.to_pkcs1_der().unwrap();
        let key = ClassicalSigningKey::from_pkcs1_der(pkcs1.as_bytes()).unwrap();
        let cases = [
            (
                ClassicalSignatureScheme::RsaPssSha256,
                ClassicalVerificationAlgorithm::RsaPssSha256,
            ),
            (
                ClassicalSignatureScheme::RsaPssSha384,
                ClassicalVerificationAlgorithm::RsaPssSha384,
            ),
            (
                ClassicalSignatureScheme::RsaPssSha512,
                ClassicalVerificationAlgorithm::RsaPssSha512,
            ),
            (
                ClassicalSignatureScheme::RsaPkcs1Sha256,
                ClassicalVerificationAlgorithm::RsaPkcs1Sha256,
            ),
            (
                ClassicalSignatureScheme::RsaPkcs1Sha384,
                ClassicalVerificationAlgorithm::RsaPkcs1Sha384,
            ),
            (
                ClassicalSignatureScheme::RsaPkcs1Sha512,
                ClassicalVerificationAlgorithm::RsaPkcs1Sha512,
            ),
        ];
        for (scheme, verification) in cases {
            let signature = key.sign(scheme, b"message").unwrap();
            verify(verification, key.public_key(), b"message", &signature).unwrap();
        }

        let pkcs8 = rsa.to_pkcs8_der().unwrap();
        assert_eq!(
            ClassicalSigningKey::from_pkcs8_der(pkcs8.as_bytes())
                .unwrap()
                .algorithm(),
            ClassicalSignatureAlgorithm::Rsa
        );
    }

    #[test]
    fn rsa_pss_verification_accepts_non_default_salt_length() {
        let mut rng = rand_core_010::UnwrapErr(getrandom_v04::SysRng);
        let rsa = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa.as_public_key().to_pkcs1_der().unwrap();
        let signature = Pss::<Sha256>::new_with_salt(20)
            .sign(Some(&mut rng), &rsa, &Sha256::digest(b"message"))
            .unwrap();

        verify(
            ClassicalVerificationAlgorithm::RsaPssSha256,
            public_key.as_bytes(),
            b"message",
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn undersized_rsa_keys_are_rejected() {
        let mut rng = rand_core_010::UnwrapErr(getrandom_v04::SysRng);
        let rsa = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let private_pkcs1 = rsa.to_pkcs1_der().unwrap();
        assert_eq!(
            ClassicalSigningKey::from_pkcs1_der(private_pkcs1.as_bytes()).unwrap_err(),
            ClassicalSignatureError::InvalidPrivateKey
        );

        let public_pkcs1 = rsa.as_public_key().to_pkcs1_der().unwrap();
        assert_eq!(
            verify(
                ClassicalVerificationAlgorithm::RsaPkcs1Sha256,
                public_pkcs1.as_bytes(),
                b"message",
                &[0; 128],
            )
            .unwrap_err(),
            ClassicalSignatureError::InvalidPublicKey
        );
    }

    #[test]
    fn malformed_inputs_and_scheme_mismatches_fail_closed() {
        assert!(ClassicalSigningKey::from_pkcs8_der(&[0; 32]).is_err());
        assert!(
            verify(
                ClassicalVerificationAlgorithm::Ed25519,
                &[0; 31],
                b"message",
                &[0; 64],
            )
            .is_err()
        );

        let signing_key = Ed25519SigningKey::from_bytes(&[0x44; 32]);
        let key = ClassicalSigningKey::from_ed25519(signing_key).unwrap();
        assert!(
            key.sign(ClassicalSignatureScheme::EcdsaP256Sha256, b"message")
                .is_err()
        );
    }
}
