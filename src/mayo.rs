//! MAYO key and signature methods

use crate::{deserialize_hex_or_bin, error::*, serialize_hex_or_bin};
use serde::{Deserialize, Serialize};

#[cfg(feature = "kgen")]
fn os_rng() -> rand_core_010::UnwrapErr<getrandom_v04::SysRng> {
    rand_core_010::UnwrapErr(getrandom_v04::SysRng)
}

macro_rules! impl_mayo_struct {
    ($name:ident, $validate:ident, $expect:expr) => {
        #[derive(Clone, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for mayo")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerMayo);

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

        impl From<InnerMayo> for $name {
            fn from(inner: InnerMayo) -> Self {
                $name(inner)
            }
        }

        impl $name {
            /// The [`MayoScheme`] represented by this struct
            pub fn scheme(&self) -> MayoScheme {
                self.0.scheme
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] to its raw byte representation")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] from its raw byte representation and scheme")]
            pub fn from_raw_bytes(scheme: MayoScheme, bytes: &[u8]) -> Result<Self> {
                scheme.$validate(bytes)?;
                Ok(InnerMayo {
                    scheme,
                    value: bytes.to_vec(),
                }.into())
            }
        }
    };
}

scheme_impl_pure!(
    /// MAYO schemes
    MayoScheme,
    #[default]
    /// MAYO-1 (NIST Level 1)
    Mayo1 => "MAYO-1" ; 1 ; 24,
    /// MAYO-2 (NIST Level 1)
    Mayo2 => "MAYO-2" ; 2 ; 24,
    /// MAYO-3 (NIST Level 3)
    Mayo3 => "MAYO-3" ; 3 ; 32,
    /// MAYO-5 (NIST Level 5)
    Mayo5 => "MAYO-5" ; 4 ; 40,
);

serde_impl!(MayoScheme);

/// Dispatch a block generic over the concrete `pq_mayo` parameter type `$P` for each scheme.
macro_rules! with_mayo_params {
    ($scheme:expr, |$P:ident| $body:block) => {
        match $scheme {
            MayoScheme::Mayo1 => {
                type $P = pq_mayo::Mayo1;
                $body
            }
            MayoScheme::Mayo2 => {
                type $P = pq_mayo::Mayo2;
                $body
            }
            MayoScheme::Mayo3 => {
                type $P = pq_mayo::Mayo3;
                $body
            }
            MayoScheme::Mayo5 => {
                type $P = pq_mayo::Mayo5;
                $body
            }
        }
    };
}

impl MayoScheme {
    /// Validate a verification (public) key encoding for this scheme.
    fn validate_public_key(&self, bytes: &[u8]) -> Result<()> {
        with_mayo_params!(self, |P| {
            pq_mayo::VerifyingKey::<P>::try_from(bytes)
                .map_err(|_| Error::MayoError("an invalid public key".to_string()))?;
            Ok(())
        })
    }

    /// Validate a signing (secret) key encoding for this scheme.
    fn validate_signing_key(&self, bytes: &[u8]) -> Result<()> {
        with_mayo_params!(self, |P| {
            pq_mayo::SigningKey::<P>::try_from(bytes)
                .map_err(|_| Error::MayoError("an invalid signing key".to_string()))?;
            Ok(())
        })
    }

    /// Validate a signature encoding for this scheme.
    fn validate_signature(&self, bytes: &[u8]) -> Result<()> {
        with_mayo_params!(self, |P| {
            pq_mayo::Signature::<P>::try_from(bytes)
                .map_err(|_| Error::MayoError("an invalid signature".to_string()))?;
            Ok(())
        })
    }

    #[cfg(feature = "kgen")]
    /// Generate a new MAYO verification and signing key pair.
    pub fn keypair(&self) -> Result<(MayoVerificationKey, MayoSigningKey)> {
        with_mayo_params!(self, |P| {
            let mut rng = os_rng();
            let keypair = pq_mayo::KeyPair::<P>::generate(&mut rng)
                .map_err(|e| Error::MayoError(e.to_string()))?;
            Ok(self.pack_keypair(
                keypair.verifying_key().as_ref().to_vec(),
                keypair.signing_key().as_ref().to_vec(),
            ))
        })
    }

    #[cfg(feature = "kgen")]
    /// Generate a new MAYO key pair from a seed (the compact secret-key seed).
    ///
    /// The seed must be exactly `seed_size()` bytes (24 for MAYO-1/2, 32 for MAYO-3, 40 for MAYO-5).
    pub fn keypair_from_seed(&self, seed: &[u8]) -> Result<(MayoVerificationKey, MayoSigningKey)> {
        if seed.len() != self.seed_size() {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        with_mayo_params!(self, |P| {
            let keypair = pq_mayo::KeyPair::<P>::from_seed(seed)
                .map_err(|e| Error::MayoError(e.to_string()))?;
            Ok(self.pack_keypair(
                keypair.verifying_key().as_ref().to_vec(),
                keypair.signing_key().as_ref().to_vec(),
            ))
        })
    }

    #[cfg(feature = "kgen")]
    /// Pack raw verification/signing key bytes into bedrock's byte-backed key types.
    fn pack_keypair(&self, vk: Vec<u8>, sk: Vec<u8>) -> (MayoVerificationKey, MayoSigningKey) {
        (
            InnerMayo {
                scheme: *self,
                value: vk,
            }
            .into(),
            InnerMayo {
                scheme: *self,
                value: sk,
            }
            .into(),
        )
    }

    #[cfg(feature = "sign")]
    /// Sign a message with the specified signing key.
    ///
    /// MAYO signing is randomized; the salt is drawn from the thread RNG.
    pub fn sign(&self, message: &[u8], signing_key: &MayoSigningKey) -> Result<MayoSignature> {
        use signature::Signer;
        // MAYO-1 and MAYO-2 share a 24-byte secret key, so the length check inside
        // `try_from` cannot tell them apart; bind the call to the key's own scheme.
        if signing_key.0.scheme != *self {
            return Err(Error::MayoError(
                "signing key scheme does not match".to_string(),
            ));
        }
        with_mayo_params!(self, |P| {
            let sk = pq_mayo::SigningKey::<P>::try_from(signing_key.0.value.as_slice())
                .map_err(|_| Error::MayoError("an invalid signing key".to_string()))?;
            let signature = sk
                .try_sign(message)
                .map_err(|e| Error::MayoError(e.to_string()))?;
            Ok(InnerMayo {
                scheme: *self,
                value: signature.as_ref().to_vec(),
            }
            .into())
        })
    }

    #[cfg(feature = "vrfy")]
    /// Verify a signature.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &MayoSignature,
        verification_key: &MayoVerificationKey,
    ) -> Result<()> {
        use signature::Verifier;
        if verification_key.0.scheme != *self || signature.0.scheme != *self {
            return Err(Error::MayoError("scheme does not match".to_string()));
        }
        with_mayo_params!(self, |P| {
            let vk = pq_mayo::VerifyingKey::<P>::try_from(verification_key.0.value.as_slice())
                .map_err(|_| Error::MayoError("an invalid public key".to_string()))?;
            let sig = pq_mayo::Signature::<P>::try_from(signature.0.value.as_slice())
                .map_err(|_| Error::MayoError("an invalid signature".to_string()))?;
            vk.verify(message, &sig)
                .map_err(|_| Error::MayoError("signature verification failed".to_string()))
        })
    }
}

impl_mayo_struct!(MayoSigningKey, validate_signing_key, "a valid signing key");

impl_mayo_struct!(
    MayoVerificationKey,
    validate_public_key,
    "a valid public key"
);

impl_mayo_struct!(MayoSignature, validate_signature, "a valid signature");

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerMayo {
    scheme: MayoScheme,
    #[serde(
        serialize_with = "serialize_hex_or_bin",
        deserialize_with = "deserialize_hex_or_bin"
    )]
    value: Vec<u8>,
}

impl std::fmt::Debug for InnerMayo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerMayo")
            .field("scheme", &self.scheme)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for InnerMayo {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for MayoSigningKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for MayoSigningKey {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rstest::*;

    #[cfg(all(feature = "kgen", feature = "sign"))]
    #[rstest]
    #[case::mayo1(MayoScheme::Mayo1)]
    #[case::mayo2(MayoScheme::Mayo2)]
    #[case::mayo3(MayoScheme::Mayo3)]
    #[case::mayo5(MayoScheme::Mayo5)]
    fn serdes(#[case] scheme: MayoScheme) {
        let (pk, sk) = scheme.keypair().unwrap();

        let bytes = postcard::to_stdvec(&sk).unwrap();
        let sk2 = postcard::from_bytes::<MayoSigningKey>(&bytes).unwrap();
        assert_eq!(sk, sk2);

        let string = serde_json::to_string(&sk).unwrap();
        let sk2 = serde_json::from_str::<MayoSigningKey>(&string).unwrap();
        assert_eq!(sk, sk2);

        let bytes = postcard::to_stdvec(&pk).unwrap();
        let pk2 = postcard::from_bytes::<MayoVerificationKey>(&bytes).unwrap();
        assert_eq!(pk, pk2);

        let string = serde_json::to_string(&pk).unwrap();
        let pk2 = serde_json::from_str::<MayoVerificationKey>(&string).unwrap();
        assert_eq!(pk, pk2);

        let msg = [0u8; 8];
        let sig = sk.0.scheme.sign(&msg, &sk).unwrap();

        let bytes = postcard::to_stdvec(&sig).unwrap();
        let sig2 = postcard::from_bytes::<MayoSignature>(&bytes).unwrap();
        assert_eq!(sig, sig2);

        let string = serde_json::to_string(&sig).unwrap();
        let sig2 = serde_json::from_str::<MayoSignature>(&string).unwrap();
        assert_eq!(sig, sig2);
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mayo1(MayoScheme::Mayo1)]
    #[case::mayo2(MayoScheme::Mayo2)]
    #[case::mayo3(MayoScheme::Mayo3)]
    #[case::mayo5(MayoScheme::Mayo5)]
    fn flow(#[case] scheme: MayoScheme) {
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
    #[case::mayo1(MayoScheme::Mayo1, 1420, 24, 454)]
    #[case::mayo2(MayoScheme::Mayo2, 4368, 24, 216)]
    #[case::mayo3(MayoScheme::Mayo3, 2986, 32, 681)]
    #[case::mayo5(MayoScheme::Mayo5, 5554, 40, 964)]
    fn fixed_sizes(
        #[case] scheme: MayoScheme,
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

    // MAYO-1 and MAYO-2 share a 24-byte secret key; signing/verifying one scheme's key
    // material under the other's label must be rejected, not silently accepted.
    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[test]
    fn cross_scheme_mayo1_mayo2_rejected() {
        const MSG: &[u8] = &[0u8; 8];
        let (_pk1, sk1) = MayoScheme::Mayo1.keypair().unwrap();
        let (pk2, sk2) = MayoScheme::Mayo2.keypair().unwrap();

        // Signing a MAYO-1 key under the MAYO-2 scheme is rejected despite equal key length.
        assert!(MayoScheme::Mayo2.sign(MSG, &sk1).is_err());

        // A genuine MAYO-2 signature must not verify under the MAYO-1 scheme.
        let sig2 = MayoScheme::Mayo2.sign(MSG, &sk2).unwrap();
        assert!(MayoScheme::Mayo1.verify(MSG, &sig2, &pk2).is_err());
        assert!(MayoScheme::Mayo2.verify(MSG, &sig2, &pk2).is_ok());
    }

    #[cfg(feature = "kgen")]
    #[rstest]
    #[case::mayo1(MayoScheme::Mayo1, 24)]
    #[case::mayo2(MayoScheme::Mayo2, 24)]
    #[case::mayo3(MayoScheme::Mayo3, 32)]
    #[case::mayo5(MayoScheme::Mayo5, 40)]
    fn seed_determinism(#[case] scheme: MayoScheme, #[case] seed_len: usize) {
        let seed = vec![7u8; seed_len];
        let (pk1, sk1) = scheme.keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = scheme.keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1.as_ref(), pk2.as_ref());
        assert_eq!(sk1.as_ref(), sk2.as_ref());
        assert!(scheme.keypair_from_seed(&vec![0u8; seed_len - 1]).is_err());
    }
}
