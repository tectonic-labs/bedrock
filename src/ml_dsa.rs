//! ML-DSA key and signature methods

use crate::{deserialize_hex_or_bin, error::*, serialize_hex_or_bin};
use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};

macro_rules! impl_ml_dsa_struct {
    ($name:ident, $convert:ident, $expect:expr) => {

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
                let alg = scheme.into();
                let sig = Sig::new(alg).expect("a valid algorithm");
                let _value = sig.$convert(bytes).ok_or(Error::OqsError($expect.to_string()))?.to_owned();
                Ok(InnerMlDsa {
                    scheme,
                    value: bytes.to_vec(),
                }.into())
            }
        }
    };
}

scheme_impl!(
    /// ML-DSA schemes
    MlDsaScheme,
    Algorithm,
    #[default]
    /// ML-DSA 44 (NIST Level 2)
    Dsa44 => Algorithm::MlDsa44 ; "ML-DSA-44" ; 1,
    /// ML-DSA 65 (NIST Level 3)
    Dsa65 => Algorithm::MlDsa65 ; "ML-DSA-65" ; 2,
    /// ML-DSA 87 (NIST Level 5)
    Dsa87 => Algorithm::MlDsa87 ; "ML-DSA-87" ; 3,
);

serde_impl!(MlDsaScheme);

impl_ml_dsa_struct!(
    MlDsaSigningKey,
    secret_key_from_bytes,
    "a valid signing key"
);

impl_ml_dsa_struct!(
    MlDsaVerificationKey,
    public_key_from_bytes,
    "a valid public key"
);

impl_ml_dsa_struct!(MlDsaSignature, signature_from_bytes, "a valid signature");

base_sign_impl!(
    MlDsaScheme,
    "ML-DSA",
    MlDsaSigningKey,
    MlDsaVerificationKey,
    MlDsaSignature,
    InnerMlDsa,
    Sig,
);

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
}
