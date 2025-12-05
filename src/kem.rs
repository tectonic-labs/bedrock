//! KEM methods
//! ClassicMcEliece348864
//! ML-KEM are supported

use crate::{deserialize_hex_or_bin, error::*, serialize_hex_or_bin};
use oqs::kem::{Algorithm, Kem};
use serde::{Deserialize, Serialize};

macro_rules! impl_kem_struct {
    ($name:ident, $convert:ident, $expect:expr) => {

        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for kems")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerKem);

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.value.as_ref()
            }
        }

        impl From<InnerKem> for $name {
            fn from(inner: InnerKem) -> Self {
                Self(inner)
            }
        }

        impl $name {
            /// The [`KemScheme`] represented by this struct
            pub fn scheme(&self) -> KemScheme {
                self.0.scheme
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] to its raw byte representation")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] from its raw byte representation and scheme")]
            pub fn from_raw_bytes(scheme: KemScheme, bytes: &[u8]) -> Result<Self> {
                let alg = scheme.into();
                let sig = Kem::new(alg).expect("a valid algorithm");
                let _value = sig.$convert(bytes).ok_or(Error::OqsError($expect.to_string()))?.to_owned();
                Ok(InnerKem {
                    scheme,
                    value: bytes.to_vec(),
                }.into())
            }
        }
    };
}

scheme_impl!(
    /// KEM schemes
    KemScheme,
    Algorithm,
    @cfg(feature = "ml-kem")
    #[cfg_attr(feature = "ml-kem", default)]
    /// ML-KEM 512 (NIST Level 1)
    MlKem512 => Algorithm::MlKem512 ; "ML-KEM-512" ; 1,
    @cfg(feature = "ml-kem")
    /// ML-KEM 768 (NIST Level 3)
    MlKem768 => Algorithm::MlKem768 ; "ML-KEM-768" ; 2,
    @cfg(feature = "ml-kem")
    /// ML-KEM 1024 (NIST Level 5)
    MlKem1024 => Algorithm::MlKem1024 ; "ML-KEM-1024" ; 3,
    @cfg(feature = "mceliece")
    #[cfg_attr(not(feature = "ml-kem"), default)]
    /// Classic McEliece 348864 (NIST Level 1)
    ClassicMcEliece348864 => Algorithm::ClassicMcEliece348864 ; "ClassicMcEliece-348864" ; 4,
);

serde_impl!(KemScheme);

impl_kem_struct!(
    KemEncapsulationKey,
    public_key_from_bytes,
    "a valid encapsulation key"
);
impl_kem_struct!(
    KemDecapsulationKey,
    secret_key_from_bytes,
    "a valid decapsulation key"
);
impl_kem_struct!(
    KemCiphertext,
    ciphertext_from_bytes,
    "a valid kem ciphertext"
);
impl_kem_struct!(
    KemSharedSecret,
    shared_secret_from_bytes,
    "a valid shared secret"
);

base_kem_impl!(
    KemScheme,
    "Key-Encapsulation",
    KemEncapsulationKey,
    KemDecapsulationKey,
    KemCiphertext,
    KemSharedSecret,
    InnerKem,
    Kem,
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerKem {
    scheme: KemScheme,
    #[serde(
        serialize_with = "serialize_hex_or_bin",
        deserialize_with = "deserialize_hex_or_bin"
    )]
    value: Vec<u8>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rstest::*;

    #[cfg(all(feature = "kgen", feature = "encp"))]
    #[rstest]
    #[cfg_attr(feature = "ml-kem", case::mlkem512(KemScheme::MlKem512))]
    #[cfg_attr(feature = "ml-kem", case::mlkem768(KemScheme::MlKem768))]
    #[cfg_attr(feature = "ml-kem", case::mlkem1024(KemScheme::MlKem1024))]
    #[cfg_attr(feature = "mceliece", case::mceliece(KemScheme::ClassicMcEliece348864))]
    fn serdes(#[case] scheme: KemScheme) {
        let (ek, dk) = scheme.keypair().unwrap();

        let bytes = postcard::to_stdvec(&ek).unwrap();
        let ek2 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ek, ek2);

        let string = serde_json::to_string(&ek).unwrap();
        let ek2 = serde_json::from_str::<KemEncapsulationKey>(&string).unwrap();
        assert_eq!(ek, ek2);

        let bytes = postcard::to_stdvec(&dk).unwrap();
        let dk2 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(dk, dk2);

        let string = serde_json::to_string(&dk).unwrap();
        let dk2 = serde_json::from_str::<KemDecapsulationKey>(&string).unwrap();
        assert_eq!(dk, dk2);

        let (ct, ss) = scheme.encapsulate(&ek).unwrap();

        let bytes = postcard::to_stdvec(&ct).unwrap();
        let ct2 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ct, ct2);

        let string = serde_json::to_string(&ct).unwrap();
        let ct2 = serde_json::from_str::<KemCiphertext>(&string).unwrap();
        assert_eq!(ct, ct2);

        let bytes = postcard::to_stdvec(&ss).unwrap();
        let ss2 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ss, ss2);

        let string = serde_json::to_string(&ss).unwrap();
        let ss2 = serde_json::from_str::<KemSharedSecret>(&string).unwrap();
        assert_eq!(ss, ss2);
    }

    #[cfg(all(feature = "kgen", feature = "encp", feature = "decp"))]
    #[rstest]
    #[cfg_attr(feature = "ml-kem", case::mlkem512(KemScheme::MlKem512))]
    #[cfg_attr(feature = "ml-kem", case::mlkem768(KemScheme::MlKem768))]
    #[cfg_attr(feature = "ml-kem", case::mlkem1024(KemScheme::MlKem1024))]
    #[cfg_attr(feature = "mceliece", case::mceliece(KemScheme::ClassicMcEliece348864))]
    fn flow(#[case] scheme: KemScheme) {
        let (ek, dk) = scheme.keypair().unwrap();

        let (mut ct, ss) = scheme.encapsulate(&ek).unwrap();
        let ss2 = scheme.decapsulate(&ct, &dk).unwrap();
        assert_eq!(ss, ss2);

        ct.0.value.iter_mut().for_each(|v| *v = v.saturating_add(1));
        let ss2 = scheme.decapsulate(&ct, &dk).unwrap();
        assert_ne!(ss, ss2);
    }
}
