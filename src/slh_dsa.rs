//! SLH-DSA key and signature methods.

use crate::error::*;
#[cfg(feature = "kgen")]
use crate::os_rng;
use serde::{Deserialize, Serialize};

macro_rules! impl_slh_dsa_struct {
    ($name:ident, $validate:ident, $expect:expr, $($multiformat:tt)+) => {
        #[derive(Clone)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A byte-backed [`", stringify!($name), "`] value for SLH-DSA.")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerSlhDsa);

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

        impl From<InnerSlhDsa> for $name {
            fn from(inner: InnerSlhDsa) -> Self {
                $name(inner)
            }
        }

        impl $name {
            /// Returns the [`SlhDsaScheme`] represented by this value.
            pub fn scheme(&self) -> SlhDsaScheme {
                self.0.scheme
            }

            #[doc = concat!("Converts [`", stringify!($name), "`] to its raw byte representation.")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = concat!("Constructs [`", stringify!($name), "`] from raw bytes and a scheme.")]
            pub fn from_raw_bytes(scheme: SlhDsaScheme, bytes: &[u8]) -> Result<Self> {
                scheme.$validate(bytes)?;
                Ok(InnerSlhDsa {
                    scheme,
                    value: bytes.to_vec(),
                }
                .into())
            }
        }

        raw_bytes_impl!($name, SlhDsaScheme);
        #[cfg(feature = "multiformats")]
        $($multiformat)+;
    };
}

scheme_impl_pure!(
    /// SLH-DSA schemes.
    SlhDsaScheme,
    #[default]
    /// SLH-DSA-SHA2-128s (NIST Level 1).
    SlhDsaSha2128s => "SLH-DSA-SHA2-128s" ; 1 ; 48,
    /// SLH-DSA-SHA2-128f (NIST Level 1).
    SlhDsaSha2128f => "SLH-DSA-SHA2-128f" ; 2 ; 48,
    /// SLH-DSA-SHAKE-128s (NIST Level 1).
    SlhDsaShake128s => "SLH-DSA-SHAKE-128s" ; 3 ; 48,
    /// SLH-DSA-SHAKE-128f (NIST Level 1).
    SlhDsaShake128f => "SLH-DSA-SHAKE-128f" ; 4 ; 48,
    /// SLH-DSA-SHA2-192s (NIST Level 3).
    SlhDsaSha2192s => "SLH-DSA-SHA2-192s" ; 5 ; 72,
    /// SLH-DSA-SHA2-192f (NIST Level 3).
    SlhDsaSha2192f => "SLH-DSA-SHA2-192f" ; 6 ; 72,
    /// SLH-DSA-SHAKE-192s (NIST Level 3).
    SlhDsaShake192s => "SLH-DSA-SHAKE-192s" ; 7 ; 72,
    /// SLH-DSA-SHAKE-192f (NIST Level 3).
    SlhDsaShake192f => "SLH-DSA-SHAKE-192f" ; 8 ; 72,
    /// SLH-DSA-SHA2-256s (NIST Level 5).
    SlhDsaSha2256s => "SLH-DSA-SHA2-256s" ; 9 ; 96,
    /// SLH-DSA-SHA2-256f (NIST Level 5).
    SlhDsaSha2256f => "SLH-DSA-SHA2-256f" ; 10 ; 96,
    /// SLH-DSA-SHAKE-256s (NIST Level 5).
    SlhDsaShake256s => "SLH-DSA-SHAKE-256s" ; 11 ; 96,
    /// SLH-DSA-SHAKE-256f (NIST Level 5).
    SlhDsaShake256f => "SLH-DSA-SHAKE-256f" ; 12 ; 96,
);

serde_impl!(SlhDsaScheme);

#[cfg(feature = "multiformats")]
multicodec_table!(SlhDsaScheme {
    SlhDsaSha2128s, PublicKey => SlhDsaSha2128SPub;
    SlhDsaSha2128s, SecretKey => SlhDsaSha2128SPriv;
    SlhDsaSha2128s, Signature => SlhDsaSha2128SMsig;
    SlhDsaSha2128f, PublicKey => SlhDsaSha2128FPub;
    SlhDsaSha2128f, SecretKey => SlhDsaSha2128FPriv;
    SlhDsaSha2128f, Signature => SlhDsaSha2128FMsig;
    SlhDsaShake128s, PublicKey => SlhDsaShake128SPub;
    SlhDsaShake128s, SecretKey => SlhDsaShake128SPriv;
    SlhDsaShake128s, Signature => SlhDsaShake128SMsig;
    SlhDsaShake128f, PublicKey => SlhDsaShake128FPub;
    SlhDsaShake128f, SecretKey => SlhDsaShake128FPriv;
    SlhDsaShake128f, Signature => SlhDsaShake128FMsig;
    SlhDsaSha2192s, PublicKey => SlhDsaSha2192SPub;
    SlhDsaSha2192s, SecretKey => SlhDsaSha2192SPriv;
    SlhDsaSha2192s, Signature => SlhDsaSha2192SMsig;
    SlhDsaSha2192f, PublicKey => SlhDsaSha2192FPub;
    SlhDsaSha2192f, SecretKey => SlhDsaSha2192FPriv;
    SlhDsaSha2192f, Signature => SlhDsaSha2192FMsig;
    SlhDsaShake192s, PublicKey => SlhDsaShake192SPub;
    SlhDsaShake192s, SecretKey => SlhDsaShake192SPriv;
    SlhDsaShake192s, Signature => SlhDsaShake192SMsig;
    SlhDsaShake192f, PublicKey => SlhDsaShake192FPub;
    SlhDsaShake192f, SecretKey => SlhDsaShake192FPriv;
    SlhDsaShake192f, Signature => SlhDsaShake192FMsig;
    SlhDsaSha2256s, PublicKey => SlhDsaSha2256SPub;
    SlhDsaSha2256s, SecretKey => SlhDsaSha2256SPriv;
    SlhDsaSha2256s, Signature => SlhDsaSha2256SMsig;
    SlhDsaSha2256f, PublicKey => SlhDsaSha2256FPub;
    SlhDsaSha2256f, SecretKey => SlhDsaSha2256FPriv;
    SlhDsaSha2256f, Signature => SlhDsaSha2256FMsig;
    SlhDsaShake256s, PublicKey => SlhDsaShake256SPub;
    SlhDsaShake256s, SecretKey => SlhDsaShake256SPriv;
    SlhDsaShake256s, Signature => SlhDsaShake256SMsig;
    SlhDsaShake256f, PublicKey => SlhDsaShake256FPub;
    SlhDsaShake256f, SecretKey => SlhDsaShake256FPriv;
    SlhDsaShake256f, Signature => SlhDsaShake256FMsig;
});

/// Dispatch a block generic over the concrete `slh_dsa` parameter type `$P` for each scheme.
macro_rules! with_slh_dsa_params {
    ($scheme:expr, |$P:ident| $body:block) => {
        match $scheme {
            SlhDsaScheme::SlhDsaSha2128s => {
                type $P = slh_dsa::Sha2_128s;
                $body
            }
            SlhDsaScheme::SlhDsaSha2128f => {
                type $P = slh_dsa::Sha2_128f;
                $body
            }
            SlhDsaScheme::SlhDsaShake128s => {
                type $P = slh_dsa::Shake128s;
                $body
            }
            SlhDsaScheme::SlhDsaShake128f => {
                type $P = slh_dsa::Shake128f;
                $body
            }
            SlhDsaScheme::SlhDsaSha2192s => {
                type $P = slh_dsa::Sha2_192s;
                $body
            }
            SlhDsaScheme::SlhDsaSha2192f => {
                type $P = slh_dsa::Sha2_192f;
                $body
            }
            SlhDsaScheme::SlhDsaShake192s => {
                type $P = slh_dsa::Shake192s;
                $body
            }
            SlhDsaScheme::SlhDsaShake192f => {
                type $P = slh_dsa::Shake192f;
                $body
            }
            SlhDsaScheme::SlhDsaSha2256s => {
                type $P = slh_dsa::Sha2_256s;
                $body
            }
            SlhDsaScheme::SlhDsaSha2256f => {
                type $P = slh_dsa::Sha2_256f;
                $body
            }
            SlhDsaScheme::SlhDsaShake256s => {
                type $P = slh_dsa::Shake256s;
                $body
            }
            SlhDsaScheme::SlhDsaShake256f => {
                type $P = slh_dsa::Shake256f;
                $body
            }
        }
    };
}

impl SlhDsaScheme {
    fn validate_public_key(&self, bytes: &[u8]) -> Result<()> {
        with_slh_dsa_params!(self, |P| {
            slh_dsa::VerifyingKey::<P>::try_from(bytes)
                .map_err(|_| Error::SlhDsaError("an invalid verification key".to_string()))?;
            Ok(())
        })
    }

    fn validate_signing_key(&self, bytes: &[u8]) -> Result<()> {
        with_slh_dsa_params!(self, |P| {
            slh_dsa::SigningKey::<P>::try_from(bytes)
                .map_err(|_| Error::SlhDsaError("an invalid signing key".to_string()))?;
            Ok(())
        })
    }

    fn validate_signature(&self, bytes: &[u8]) -> Result<()> {
        with_slh_dsa_params!(self, |P| {
            slh_dsa::Signature::<P>::try_from(bytes)
                .map_err(|_| Error::SlhDsaError("an invalid signature".to_string()))?;
            Ok(())
        })
    }

    #[cfg(feature = "kgen")]
    /// Generates a new SLH-DSA verification and signing keypair.
    pub fn keypair(&self) -> Result<(SlhDsaVerificationKey, SlhDsaSigningKey)> {
        use slh_dsa::signature::Keypair;
        with_slh_dsa_params!(self, |P| {
            let mut rng = os_rng();
            let sk = slh_dsa::SigningKey::<P>::new(&mut rng);
            let vk = sk.verifying_key();
            Ok(self.pack_keypair(vk.to_vec(), sk.to_bytes().to_vec()))
        })
    }

    #[cfg(feature = "kgen")]
    /// Generates a new SLH-DSA keypair from a seed.
    ///
    /// The seed is `sk_seed ‖ sk_prf ‖ pk_seed`, each `N` bytes (`N` = 16/24/32 for the
    /// 128/192/256 security levels), per FIPS 205's `slh_keygen_internal`.
    pub fn keypair_from_seed(
        &self,
        seed: &[u8],
    ) -> Result<(SlhDsaVerificationKey, SlhDsaSigningKey)> {
        if seed.len() != self.seed_size() {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        use slh_dsa::signature::Keypair;
        let n = seed.len() / 3;
        let (sk_seed, rest) = seed.split_at(n);
        let (sk_prf, pk_seed) = rest.split_at(n);
        with_slh_dsa_params!(self, |P| {
            let sk = slh_dsa::SigningKey::<P>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
            let vk = sk.verifying_key();
            Ok(self.pack_keypair(vk.to_vec(), sk.to_bytes().to_vec()))
        })
    }

    #[cfg(feature = "kgen")]
    fn pack_keypair(&self, vk: Vec<u8>, sk: Vec<u8>) -> (SlhDsaVerificationKey, SlhDsaSigningKey) {
        (
            InnerSlhDsa {
                scheme: *self,
                value: vk,
            }
            .into(),
            InnerSlhDsa {
                scheme: *self,
                value: sk,
            }
            .into(),
        )
    }

    #[cfg(feature = "sign")]
    /// Signs a message with the specified signing key (deterministic, empty context).
    pub fn sign(&self, message: &[u8], signing_key: &SlhDsaSigningKey) -> Result<SlhDsaSignature> {
        use slh_dsa::signature::Signer;
        with_slh_dsa_params!(self, |P| {
            let sk = slh_dsa::SigningKey::<P>::try_from(signing_key.0.value.as_slice())
                .map_err(|_| Error::SlhDsaError("an invalid signing key".to_string()))?;
            let signature = sk
                .try_sign(message)
                .map_err(|e| Error::SlhDsaError(e.to_string()))?;
            Ok(InnerSlhDsa {
                scheme: *self,
                value: signature.to_vec(),
            }
            .into())
        })
    }

    #[cfg(feature = "vrfy")]
    /// Verifies a signature.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &SlhDsaSignature,
        verification_key: &SlhDsaVerificationKey,
    ) -> Result<()> {
        use slh_dsa::signature::Verifier;
        with_slh_dsa_params!(self, |P| {
            let vk = slh_dsa::VerifyingKey::<P>::try_from(verification_key.0.value.as_slice())
                .map_err(|_| Error::SlhDsaError("an invalid verification key".to_string()))?;
            let sig = slh_dsa::Signature::<P>::try_from(signature.0.value.as_slice())
                .map_err(|_| Error::SlhDsaError("an invalid signature".to_string()))?;
            vk.verify(message, &sig)
                .map_err(|_| Error::SlhDsaError("signature verification failed".to_string()))
        })
    }
}

impl_slh_dsa_struct!(
    SlhDsaSigningKey,
    validate_signing_key,
    "a valid signing key",
    multikey_impl!(SlhDsaSigningKey, SecretKey)
);

impl_slh_dsa_struct!(
    SlhDsaVerificationKey,
    validate_public_key,
    "a valid verification key",
    multikey_impl!(SlhDsaVerificationKey, PublicKey)
);

impl_slh_dsa_struct!(
    SlhDsaSignature,
    validate_signature,
    "a valid signature",
    multisig_impl!(SlhDsaSignature)
);

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerSlhDsa {
    scheme: SlhDsaScheme,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    value: Vec<u8>,
}

impl std::fmt::Debug for InnerSlhDsa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerSlhDsa")
            .field("scheme", &self.scheme)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for InnerSlhDsa {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for InnerSlhDsa {}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for SlhDsaSigningKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SlhDsaSigningKey {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rstest::*;

    /// Run a test body on a thread with a large stack; SLH-DSA signatures overflow libtest's
    /// default 2 MB stack.
    #[allow(clippy::unwrap_used)]
    fn with_large_stack(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(all(
        feature = "multiformats",
        feature = "kgen",
        feature = "sign",
        feature = "vrfy"
    ))]
    #[rstest]
    #[case::slh_dsa_sha2_128s(SlhDsaScheme::SlhDsaSha2128s)]
    #[case::slh_dsa_sha2_128f(SlhDsaScheme::SlhDsaSha2128f)]
    #[case::slh_dsa_shake_128s(SlhDsaScheme::SlhDsaShake128s)]
    #[case::slh_dsa_shake_128f(SlhDsaScheme::SlhDsaShake128f)]
    #[case::slh_dsa_sha2_192s(SlhDsaScheme::SlhDsaSha2192s)]
    #[case::slh_dsa_sha2_192f(SlhDsaScheme::SlhDsaSha2192f)]
    #[case::slh_dsa_shake_192s(SlhDsaScheme::SlhDsaShake192s)]
    #[case::slh_dsa_shake_192f(SlhDsaScheme::SlhDsaShake192f)]
    #[case::slh_dsa_sha2_256s(SlhDsaScheme::SlhDsaSha2256s)]
    #[case::slh_dsa_sha2_256f(SlhDsaScheme::SlhDsaSha2256f)]
    #[case::slh_dsa_shake_256s(SlhDsaScheme::SlhDsaShake256s)]
    #[case::slh_dsa_shake_256f(SlhDsaScheme::SlhDsaShake256f)]
    fn serdes(#[case] scheme: SlhDsaScheme) {
        with_large_stack(move || serdes_inner(scheme));
    }

    #[cfg(all(
        feature = "multiformats",
        feature = "kgen",
        feature = "sign",
        feature = "vrfy"
    ))]
    fn serdes_inner(scheme: SlhDsaScheme) {
        let (pk, sk) = scheme.keypair().unwrap();

        let bytes = postcard::to_stdvec(&sk).unwrap();
        let sk2 = postcard::from_bytes::<SlhDsaSigningKey>(&bytes).unwrap();
        assert_eq!(sk, sk2);

        let string = serde_json::to_string(&sk).unwrap();
        let sk2 = serde_json::from_str::<SlhDsaSigningKey>(&string).unwrap();
        assert_eq!(sk, sk2);

        let bytes = postcard::to_stdvec(&pk).unwrap();
        let pk2 = postcard::from_bytes::<SlhDsaVerificationKey>(&bytes).unwrap();
        assert_eq!(pk, pk2);

        let string = serde_json::to_string(&pk).unwrap();
        let pk2 = serde_json::from_str::<SlhDsaVerificationKey>(&string).unwrap();
        assert_eq!(pk, pk2);

        let msg = [0u8; 8];
        let sig = sk.0.scheme.sign(&msg, &sk).unwrap();

        let bytes = postcard::to_stdvec(&sig).unwrap();
        let sig2 = postcard::from_bytes::<SlhDsaSignature>(&bytes).unwrap();
        assert_eq!(sig, sig2);

        let string = serde_json::to_string(&sig).unwrap();
        let sig2 = serde_json::from_str::<SlhDsaSignature>(&string).unwrap();
        assert_eq!(sig, sig2);
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::slh_dsa_sha2_128s(SlhDsaScheme::SlhDsaSha2128s)]
    #[case::slh_dsa_sha2_128f(SlhDsaScheme::SlhDsaSha2128f)]
    #[case::slh_dsa_shake_128s(SlhDsaScheme::SlhDsaShake128s)]
    #[case::slh_dsa_shake_128f(SlhDsaScheme::SlhDsaShake128f)]
    #[case::slh_dsa_sha2_192s(SlhDsaScheme::SlhDsaSha2192s)]
    #[case::slh_dsa_sha2_192f(SlhDsaScheme::SlhDsaSha2192f)]
    #[case::slh_dsa_shake_192s(SlhDsaScheme::SlhDsaShake192s)]
    #[case::slh_dsa_shake_192f(SlhDsaScheme::SlhDsaShake192f)]
    #[case::slh_dsa_sha2_256s(SlhDsaScheme::SlhDsaSha2256s)]
    #[case::slh_dsa_sha2_256f(SlhDsaScheme::SlhDsaSha2256f)]
    #[case::slh_dsa_shake_256s(SlhDsaScheme::SlhDsaShake256s)]
    #[case::slh_dsa_shake_256f(SlhDsaScheme::SlhDsaShake256f)]
    fn flow(#[case] scheme: SlhDsaScheme) {
        with_large_stack(move || flow_inner(scheme));
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    fn flow_inner(scheme: SlhDsaScheme) {
        const MSG: &[u8] = &[0u8; 8];
        let (pk, sk) = scheme.keypair().unwrap();
        let signature = sk.0.scheme.sign(MSG, &sk).unwrap();
        let res = pk.0.scheme.verify(MSG, &signature, &pk);
        assert!(res.is_ok());

        let res = pk.0.scheme.verify(&[1u8; 8], &signature, &pk);
        assert!(res.is_err());
    }

    #[cfg(feature = "kgen")]
    #[rstest]
    #[case::slh_dsa_sha2_128s(SlhDsaScheme::SlhDsaSha2128s, 48)]
    #[case::slh_dsa_sha2_128f(SlhDsaScheme::SlhDsaSha2128f, 48)]
    #[case::slh_dsa_shake_128s(SlhDsaScheme::SlhDsaShake128s, 48)]
    #[case::slh_dsa_shake_128f(SlhDsaScheme::SlhDsaShake128f, 48)]
    #[case::slh_dsa_sha2_192s(SlhDsaScheme::SlhDsaSha2192s, 72)]
    #[case::slh_dsa_sha2_192f(SlhDsaScheme::SlhDsaSha2192f, 72)]
    #[case::slh_dsa_shake_192s(SlhDsaScheme::SlhDsaShake192s, 72)]
    #[case::slh_dsa_shake_192f(SlhDsaScheme::SlhDsaShake192f, 72)]
    #[case::slh_dsa_sha2_256s(SlhDsaScheme::SlhDsaSha2256s, 96)]
    #[case::slh_dsa_sha2_256f(SlhDsaScheme::SlhDsaSha2256f, 96)]
    #[case::slh_dsa_shake_256s(SlhDsaScheme::SlhDsaShake256s, 96)]
    #[case::slh_dsa_shake_256f(SlhDsaScheme::SlhDsaShake256f, 96)]
    fn keypair_from_seed_valid(#[case] scheme: SlhDsaScheme, #[case] seed_len: usize) {
        let seed = vec![0xABu8; seed_len];
        let result = scheme.keypair_from_seed(&seed);
        assert!(result.is_ok());

        // Determinism: same seed produces same keypair
        let (pk1, sk1) = result.unwrap();
        let (pk2, sk2) = scheme.keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1.as_ref(), pk2.as_ref());
        assert_eq!(sk1.as_ref(), sk2.as_ref());
    }

    #[cfg(feature = "kgen")]
    #[rstest]
    #[case::too_short(SlhDsaScheme::SlhDsaSha2128s, 32)]
    #[case::too_long(SlhDsaScheme::SlhDsaSha2128s, 100)]
    #[case::level_3_seed_for_level_1(SlhDsaScheme::SlhDsaSha2128s, 72)]
    #[case::level_5_seed_for_level_1(SlhDsaScheme::SlhDsaSha2128s, 96)]
    #[case::level_1_seed_for_level_5(SlhDsaScheme::SlhDsaSha2256s, 48)]
    fn keypair_from_seed_invalid(#[case] scheme: SlhDsaScheme, #[case] seed_len: usize) {
        let seed = vec![0xABu8; seed_len];
        let result = scheme.keypair_from_seed(&seed);
        assert!(result.is_err());
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::sha2_128f(SlhDsaScheme::SlhDsaSha2128f)]
    #[case::shake_256f(SlhDsaScheme::SlhDsaShake256f)]
    fn plain_encoding_is_unchanged(#[case] scheme: SlhDsaScheme) {
        with_large_stack(move || {
            let (pk, sk) = scheme.keypair().unwrap();
            crate::test_utils::assert_plain_compatible(&pk, &pk.0);
            crate::test_utils::assert_plain_compatible(&sk, &sk.0);
            let sig = scheme.sign(b"bedrock", &sk).unwrap();
            crate::test_utils::assert_plain_compatible(&sig, &sig.0);
        });
    }

    #[cfg(all(
        feature = "multiformats",
        feature = "kgen",
        feature = "sign",
        feature = "vrfy"
    ))]
    #[rstest]
    #[case::sha2_128f(
        SlhDsaScheme::SlhDsaSha2128f,
        crate::multiformats::Codec::SlhDsaSha2128FPub,
        crate::multiformats::Codec::SlhDsaSha2128FPriv,
        crate::multiformats::Codec::SlhDsaSha2128FMsig
    )]
    #[case::shake_256f(
        SlhDsaScheme::SlhDsaShake256f,
        crate::multiformats::Codec::SlhDsaShake256FPub,
        crate::multiformats::Codec::SlhDsaShake256FPriv,
        crate::multiformats::Codec::SlhDsaShake256FMsig
    )]
    fn multiformat_encoding(
        #[case] scheme: SlhDsaScheme,
        #[case] public: crate::multiformats::Codec,
        #[case] secret: crate::multiformats::Codec,
        #[case] signature: crate::multiformats::Codec,
    ) {
        with_large_stack(move || {
            use crate::{multiformats::Multikey, test_utils::*};
            let (pk, sk) = scheme.keypair().unwrap();
            assert_multikey(&pk, public);
            assert_multikey(&sk, secret);
            // a key never decodes as the other half of its pair
            assert!(SlhDsaSigningKey::try_from(&Multikey::try_from(&pk).unwrap()).is_err());
            assert!(SlhDsaVerificationKey::try_from(&Multikey::try_from(&sk).unwrap()).is_err());
            let sig = scheme.sign(b"bedrock", &sk).unwrap();
            assert_multisig(&sig, signature);
        });
    }

    #[cfg(feature = "multiformats")]
    #[test]
    fn multicodec_table_is_invertible() {
        use crate::multiformats::{Role, SchemeCodec};
        for scheme in [
            SlhDsaScheme::SlhDsaSha2128s,
            SlhDsaScheme::SlhDsaSha2128f,
            SlhDsaScheme::SlhDsaShake128s,
            SlhDsaScheme::SlhDsaShake128f,
            SlhDsaScheme::SlhDsaSha2192s,
            SlhDsaScheme::SlhDsaSha2192f,
            SlhDsaScheme::SlhDsaShake192s,
            SlhDsaScheme::SlhDsaShake192f,
            SlhDsaScheme::SlhDsaSha2256s,
            SlhDsaScheme::SlhDsaSha2256f,
            SlhDsaScheme::SlhDsaShake256s,
            SlhDsaScheme::SlhDsaShake256f,
        ] {
            for role in [Role::PublicKey, Role::SecretKey, Role::Signature] {
                if let Some(codec) = scheme.codec(role) {
                    assert_eq!(SlhDsaScheme::from_codec(codec, role), Some(scheme));
                }
            }
        }
    }
}
