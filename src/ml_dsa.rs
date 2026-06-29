//! ML-DSA key and signature methods

use crate::{deserialize_hex_or_bin, error::*, serialize_hex_or_bin};
use serde::{Deserialize, Serialize};

#[cfg(feature = "kgen")]
fn os_rng() -> rand_core_010::UnwrapErr<getrandom_v04::SysRng> {
    rand_core_010::UnwrapErr(getrandom_v04::SysRng)
}

macro_rules! impl_ml_dsa_struct {
    ($name:ident, $validate:ident, $expect:expr) => {

        #[derive(Clone, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for ml-dsa")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerMlDsa);

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("scheme", &self.0.scheme)
                    .field("value", &"<redacted>")
                    .finish()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.value.as_ref()
            }
        }

        impl From<InnerMlDsa> for $name {
            fn from(inner: InnerMlDsa) -> Self {
                Self(inner)
            }
        }

        impl $name {
            /// The [`MlDsaScheme`] represented by this struct
            pub fn scheme(&self) -> MlDsaScheme {
                self.0.scheme
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] to its raw byte representation")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] from its raw byte representation and scheme")]
            pub fn from_raw_bytes(scheme: MlDsaScheme, bytes: &[u8]) -> Result<Self> {
                scheme.$validate(bytes)?;
                Ok(InnerMlDsa {
                    scheme,
                    value: bytes.to_vec(),
                }.into())
            }
        }
    };
}

scheme_impl_pure!(
    /// ML-DSA schemes
    MlDsaScheme,
    #[default]
    /// ML-DSA 44 (NIST Level 2)
    Dsa44 => "ML-DSA-44" ; 1 ; 32,
    /// ML-DSA 65 (NIST Level 3)
    Dsa65 => "ML-DSA-65" ; 2 ; 32,
    /// ML-DSA 87 (NIST Level 5)
    Dsa87 => "ML-DSA-87" ; 3 ; 32,
);

serde_impl!(MlDsaScheme);

/// Dispatch a block generic over the concrete `ml_dsa` parameter type `$P` for each scheme.
macro_rules! with_ml_dsa_params {
    ($scheme:expr, |$P:ident| $body:block) => {
        match $scheme {
            MlDsaScheme::Dsa44 => {
                type $P = ml_dsa::MlDsa44;
                $body
            }
            MlDsaScheme::Dsa65 => {
                type $P = ml_dsa::MlDsa65;
                $body
            }
            MlDsaScheme::Dsa87 => {
                type $P = ml_dsa::MlDsa87;
                $body
            }
        }
    };
}

impl MlDsaScheme {
    /// Validate a verification (public) key encoding for this scheme.
    fn validate_public_key(&self, bytes: &[u8]) -> Result<()> {
        with_ml_dsa_params!(self, |P| {
            use ml_dsa::EncodedVerifyingKey;
            EncodedVerifyingKey::<P>::try_from(bytes)
                .map_err(|_| Error::MlDsaError("an invalid public key".to_string()))?;
            Ok(())
        })
    }

    /// Validate a signing (secret) key encoding for this scheme (expanded FIPS-204 form).
    fn validate_signing_key(&self, bytes: &[u8]) -> Result<()> {
        with_ml_dsa_params!(self, |P| {
            use ml_dsa::ExpandedSigningKeyBytes;
            ExpandedSigningKeyBytes::<P>::try_from(bytes)
                .map_err(|_| Error::MlDsaError("an invalid signing key".to_string()))?;
            Ok(())
        })
    }

    /// Validate a signature encoding for this scheme.
    fn validate_signature(&self, bytes: &[u8]) -> Result<()> {
        with_ml_dsa_params!(self, |P| {
            ml_dsa::Signature::<P>::try_from(bytes)
                .map_err(|_| Error::MlDsaError("an invalid signature".to_string()))?;
            Ok(())
        })
    }

    #[cfg(feature = "kgen")]
    /// Generate a new ML-DSA verification and signing key pair.
    // `to_expanded` is deprecated upstream in favour of the seed form, but the wire format is the
    // expanded key, so we keep using it.
    #[allow(deprecated)]
    pub fn keypair(&self) -> Result<(MlDsaVerificationKey, MlDsaSigningKey)> {
        use ml_dsa::{signature::Keypair, KeyGen};
        with_ml_dsa_params!(self, |P| {
            let mut rng = os_rng();
            let sk = P::key_gen(&mut rng);
            Ok(self.pack_keypair(
                sk.verifying_key().encode().to_vec(),
                sk.signing_key().to_expanded().to_vec(),
            ))
        })
    }

    #[cfg(feature = "kgen")]
    /// Generate a new ML-DSA verification and signing key pair from a 32-byte seed (FIPS-204 ξ).
    #[allow(deprecated)]
    pub fn keypair_from_seed(
        &self,
        seed: &[u8],
    ) -> Result<(MlDsaVerificationKey, MlDsaSigningKey)> {
        if seed.len() != self.seed_size() {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        use ml_dsa::{signature::Keypair, KeyGen, B32};
        with_ml_dsa_params!(self, |P| {
            let xi = B32::try_from(seed).map_err(|_| Error::InvalidSeedLength(seed.len()))?;
            let sk = P::from_seed(&xi);
            Ok(self.pack_keypair(
                sk.verifying_key().encode().to_vec(),
                sk.signing_key().to_expanded().to_vec(),
            ))
        })
    }

    #[cfg(feature = "kgen")]
    /// Pack raw verification/signing key bytes into bedrock's byte-backed key types.
    fn pack_keypair(&self, vk: Vec<u8>, sk: Vec<u8>) -> (MlDsaVerificationKey, MlDsaSigningKey) {
        (
            InnerMlDsa {
                scheme: *self,
                value: vk,
            }
            .into(),
            InnerMlDsa {
                scheme: *self,
                value: sk,
            }
            .into(),
        )
    }

    #[cfg(feature = "sign")]
    /// Sign a message with the specified signing key (deterministic, empty context).
    #[allow(deprecated)]
    pub fn sign(&self, message: &[u8], signing_key: &MlDsaSigningKey) -> Result<MlDsaSignature> {
        use ml_dsa::{ExpandedSigningKey, ExpandedSigningKeyBytes};
        with_ml_dsa_params!(self, |P| {
            let enc = ExpandedSigningKeyBytes::<P>::try_from(signing_key.0.value.as_slice())
                .map_err(|_| Error::MlDsaError("an invalid signing key".to_string()))?;
            let sk = ExpandedSigningKey::<P>::from_expanded(&enc);
            let signature = sk
                .sign_deterministic(message, &[])
                .map_err(|e| Error::MlDsaError(e.to_string()))?;
            Ok(InnerMlDsa {
                scheme: *self,
                value: signature.encode().to_vec(),
            }
            .into())
        })
    }

    #[cfg(feature = "vrfy")]
    /// Verify a signature.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &MlDsaSignature,
        verification_key: &MlDsaVerificationKey,
    ) -> Result<()> {
        use ml_dsa::{EncodedVerifyingKey, Signature, VerifyingKey};
        with_ml_dsa_params!(self, |P| {
            let enc = EncodedVerifyingKey::<P>::try_from(verification_key.0.value.as_slice())
                .map_err(|_| Error::MlDsaError("an invalid public key".to_string()))?;
            let vk = VerifyingKey::<P>::decode(&enc);
            let sig = Signature::<P>::try_from(signature.0.value.as_slice())
                .map_err(|_| Error::MlDsaError("an invalid signature".to_string()))?;
            if vk.verify_with_context(message, &[], &sig) {
                Ok(())
            } else {
                Err(Error::MlDsaError(
                    "signature verification failed".to_string(),
                ))
            }
        })
    }
}

impl_ml_dsa_struct!(MlDsaSigningKey, validate_signing_key, "a valid signing key");

impl_ml_dsa_struct!(
    MlDsaVerificationKey,
    validate_public_key,
    "a valid public key"
);

impl_ml_dsa_struct!(MlDsaSignature, validate_signature, "a valid signature");

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerMlDsa {
    scheme: MlDsaScheme,
    #[serde(
        serialize_with = "serialize_hex_or_bin",
        deserialize_with = "deserialize_hex_or_bin"
    )]
    value: Vec<u8>,
}

impl std::fmt::Debug for InnerMlDsa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerMlDsa")
            .field("scheme", &self.scheme)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for InnerMlDsa {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for MlDsaSigningKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for MlDsaSigningKey {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rstest::*;

    #[cfg(all(feature = "kgen", feature = "sign"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn serdes(#[case] scheme: MlDsaScheme) {
        let (pk, sk) = scheme.keypair().unwrap();

        let bytes = postcard::to_stdvec(&sk).unwrap();
        let sk2 = postcard::from_bytes::<MlDsaSigningKey>(&bytes).unwrap();
        assert_eq!(sk, sk2);

        let string = serde_json::to_string(&sk).unwrap();
        let sk2 = serde_json::from_str::<MlDsaSigningKey>(&string).unwrap();
        assert_eq!(sk, sk2);

        let bytes = postcard::to_stdvec(&pk).unwrap();
        let pk2 = postcard::from_bytes::<MlDsaVerificationKey>(&bytes).unwrap();
        assert_eq!(pk, pk2);

        let string = serde_json::to_string(&pk).unwrap();
        let pk2 = serde_json::from_str::<MlDsaVerificationKey>(&string).unwrap();
        assert_eq!(pk, pk2);

        let msg = [0u8; 8];
        let sig = sk.0.scheme.sign(&msg, &sk).unwrap();

        let bytes = postcard::to_stdvec(&sig).unwrap();
        let sig2 = postcard::from_bytes::<MlDsaSignature>(&bytes).unwrap();
        assert_eq!(sig, sig2);

        let string = serde_json::to_string(&sig).unwrap();
        let sig2 = serde_json::from_str::<MlDsaSignature>(&string).unwrap();
        assert_eq!(sig, sig2);
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn flow(#[case] scheme: MlDsaScheme) {
        const MSG: &[u8] = &[0u8; 8];
        let (pk, sk) = scheme.keypair().unwrap();

        let signature = sk.0.scheme.sign(MSG, &sk).unwrap();
        let res = pk.0.scheme.verify(MSG, &signature, &pk);
        assert!(res.is_ok());

        let res = pk.0.scheme.verify(&[1u8; 8], &signature, &pk);
        assert!(res.is_err());
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44, 1312, 2560, 2420)]
    #[case::mldsa65(MlDsaScheme::Dsa65, 1952, 4032, 3309)]
    #[case::mldsa87(MlDsaScheme::Dsa87, 2592, 4896, 4627)]
    fn fixed_sizes(
        #[case] scheme: MlDsaScheme,
        #[case] pk_len: usize,
        #[case] sk_len: usize,
        #[case] sig_len: usize,
    ) {
        let (pk, sk) = scheme.keypair().unwrap();
        assert_eq!(pk.to_raw_bytes().len(), pk_len);
        assert_eq!(sk.to_raw_bytes().len(), sk_len);
        let sig = scheme.sign(&[0u8; 8], &sk).unwrap();
        assert_eq!(sig.to_raw_bytes().len(), sig_len);
    }

    #[cfg(feature = "kgen")]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn seed_determinism(#[case] scheme: MlDsaScheme) {
        let seed = [7u8; 32];
        let (pk1, sk1) = scheme.keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = scheme.keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1.as_ref(), pk2.as_ref());
        assert_eq!(sk1.as_ref(), sk2.as_ref());
        assert!(scheme.keypair_from_seed(&[0u8; 31]).is_err());
    }
}
