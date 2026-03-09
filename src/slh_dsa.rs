//! SLH-DSA key and signature methods

use crate::{deserialize_hex_or_bin, error::*, serialize_hex_or_bin};
use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};

macro_rules! impl_slh_dsa_struct {
    ($name:ident, $convert:ident, $expect:expr) => {
        #[derive(Clone, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for slh-dsa")]
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
            /// The [`SlhDsaScheme`] represented by this struct
            pub fn scheme(&self) -> SlhDsaScheme {
                self.0.scheme
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] to its raw byte representation")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] from its raw byte representation and scheme")]
            pub fn from_raw_bytes(scheme: SlhDsaScheme, bytes: &[u8]) -> Result<Self> {
                let alg = scheme.into();
                let sig = Sig::new(alg).map_err(|e| Error::OqsError(e.to_string()))?;
                sig.$convert(bytes).ok_or(Error::OqsError($expect.to_string()))?;
                Ok(InnerSlhDsa {
                    scheme,
                    value: bytes.to_vec(),
                }.into())
            }
        }
    };
}

scheme_impl!(
    /// SLH-DSA schemes
    SlhDsaScheme,
    Algorithm,
    #[default]
    /// SLH-DSA-SHA2-128s (NIST Level 1)
    SlhDsaSha2128s => Algorithm::SlhDsaPureSha2128s ; "SLH-DSA-SHA2-128s" ; 1 ; 48,
    /// SLH-DSA-SHA2-128f (NIST Level 1)
    SlhDsaSha2128f => Algorithm::SlhDsaPureSha2128f ; "SLH-DSA-SHA2-128f" ; 2 ; 48,
    /// SLH-DSA-SHAKE-128s (NIST Level 1)
    SlhDsaShake128s => Algorithm::SlhDsaPureShake128s ; "SLH-DSA-SHAKE-128s" ; 3 ; 48,
    /// SLH-DSA-SHAKE-128f (NIST Level 1)
    SlhDsaShake128f => Algorithm::SlhDsaPureShake128f ; "SLH-DSA-SHAKE-128f" ; 4 ; 48,
    /// SLH-DSA-SHA2-192s (NIST Level 3)
    SlhDsaSha2192s => Algorithm::SlhDsaPureSha2192s ; "SLH-DSA-SHA2-192s" ; 5 ; 72,
    /// SLH-DSA-SHA2-192f (NIST Level 3)
    SlhDsaSha2192f => Algorithm::SlhDsaPureSha2192f ; "SLH-DSA-SHA2-192f" ; 6 ; 72,
    /// SLH-DSA-SHAKE-192s (NIST Level 3)
    SlhDsaShake192s => Algorithm::SlhDsaPureShake192s ; "SLH-DSA-SHAKE-192s" ; 7 ; 72,
    /// SLH-DSA-SHAKE-192f (NIST Level 3)
    SlhDsaShake192f => Algorithm::SlhDsaPureShake192f ; "SLH-DSA-SHAKE-192f" ; 8 ; 72,
    /// SLH-DSA-SHA2-256s (NIST Level 5)
    SlhDsaSha2256s => Algorithm::SlhDsaPureSha2256s ; "SLH-DSA-SHA2-256s" ; 9 ; 96,
    /// SLH-DSA-SHA2-256f (NIST Level 5)
    SlhDsaSha2256f => Algorithm::SlhDsaPureSha2256f ; "SLH-DSA-SHA2-256f" ; 10 ; 96,
    /// SLH-DSA-SHAKE-256s (NIST Level 5)
    SlhDsaShake256s => Algorithm::SlhDsaPureShake256s ; "SLH-DSA-SHAKE-256s" ; 11 ; 96,
    /// SLH-DSA-SHAKE-256f (NIST Level 5)
    SlhDsaShake256f => Algorithm::SlhDsaPureShake256f ; "SLH-DSA-SHAKE-256f" ; 12 ; 96,
);

serde_impl!(SlhDsaScheme);

impl_slh_dsa_struct!(
    SlhDsaSigningKey,
    secret_key_from_bytes,
    "a valid signing key"
);

impl_slh_dsa_struct!(
    SlhDsaVerificationKey,
    public_key_from_bytes,
    "a valid verification key"
);

impl_slh_dsa_struct!(SlhDsaSignature, signature_from_bytes, "a valid signature");

base_sign_impl!(
    SlhDsaScheme,
    "SLH-DSA",
    SlhDsaSigningKey,
    SlhDsaVerificationKey,
    SlhDsaSignature,
    InnerSlhDsa,
    Sig,
);

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerSlhDsa {
    scheme: SlhDsaScheme,
    #[serde(
        serialize_with = "serialize_hex_or_bin",
        deserialize_with = "deserialize_hex_or_bin"
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
mod tests {
    use super::*;
    use rstest::*;

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
    fn serdes(#[case] scheme: SlhDsaScheme) {
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
    #[case::slh_dsa_128(SlhDsaScheme::SlhDsaSha2128s, 48)]
    #[case::slh_dsa_192(SlhDsaScheme::SlhDsaSha2192s, 72)]
    #[case::slh_dsa_256(SlhDsaScheme::SlhDsaSha2256s, 96)]
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
}
