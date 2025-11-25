//! ML-DSA key and signature methods

use crate::error::*;
use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

macro_rules! impl_ml_dsa_struct {
    ($name:ident, $convert:ident, $expect:expr) => {

        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for ml-dsa")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerMlDsa);

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
            /// The [`FalconScheme`] represented by this struct
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

/// ML-DSA schemes
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum MlDsaScheme {
    /// ML-DSA-44 (NIST Level 2)
    #[default]
    Dsa44,
    /// ML-DSA-65 (NIST Level 3)
    Dsa65,
    /// ML-DSA-87 (NIST Level 5)
    Dsa87,
}

impl From<MlDsaScheme> for Algorithm {
    fn from(scheme: MlDsaScheme) -> Self {
        match scheme {
            MlDsaScheme::Dsa44 => Algorithm::MlDsa44,
            MlDsaScheme::Dsa65 => Algorithm::MlDsa65,
            MlDsaScheme::Dsa87 => Algorithm::MlDsa87,
        }
    }
}

impl From<&MlDsaScheme> for Algorithm {
    fn from(scheme: &MlDsaScheme) -> Self {
        match *scheme {
            MlDsaScheme::Dsa44 => Algorithm::MlDsa44,
            MlDsaScheme::Dsa65 => Algorithm::MlDsa65,
            MlDsaScheme::Dsa87 => Algorithm::MlDsa87,
        }
    }
}

impl From<MlDsaScheme> for u8 {
    fn from(scheme: MlDsaScheme) -> Self {
        match scheme {
            MlDsaScheme::Dsa44 => 1,
            MlDsaScheme::Dsa65 => 2,
            MlDsaScheme::Dsa87 => 3,
        }
    }
}

impl From<&MlDsaScheme> for u8 {
    fn from(scheme: &MlDsaScheme) -> Self {
        (*scheme).into()
    }
}

impl TryFrom<u8> for MlDsaScheme {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(MlDsaScheme::Dsa44),
            2 => Ok(MlDsaScheme::Dsa65),
            3 => Ok(MlDsaScheme::Dsa87),
            _ => Err(Error::InvalidScheme(value)),
        }
    }
}

impl Display for MlDsaScheme {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Dsa44 => "ML-DSA-44",
                Self::Dsa65 => "ML-DSA-65",
                Self::Dsa87 => "ML-DSA-87",
            }
        )
    }
}

impl FromStr for MlDsaScheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "ML-DSA-44" => Ok(MlDsaScheme::Dsa44),
            "ML-DSA-65" => Ok(MlDsaScheme::Dsa65),
            "ML-DSA-87" => Ok(MlDsaScheme::Dsa87),
            _ => Err(Error::InvalidSchemeStr(s.to_owned())),
        }
    }
}

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

impl MlDsaScheme {
    #[cfg(feature = "kgen")]
    /// Generate a new ML-DSA signing and verification key pair
    pub fn keypair(&self) -> Result<(MlDsaVerificationKey, MlDsaSigningKey)> {
        let alg = self.into();
        let scheme = Sig::new(alg)?;
        let (pk, sk) = scheme.keypair()?;
        Ok((
            InnerMlDsa {
                scheme: *self,
                value: pk.into_vec(),
            }
            .into(),
            InnerMlDsa {
                scheme: *self,
                value: sk.into_vec(),
            }
            .into(),
        ))
    }

    #[cfg(feature = "sign")]
    /// Sign a message with the specified signing key
    pub fn sign(&self, message: &[u8], signing_key: &MlDsaSigningKey) -> Result<MlDsaSignature> {
        let alg = self.into();
        let scheme = Sig::new(alg)?;
        let sk = scheme
            .secret_key_from_bytes(signing_key.0.value.as_slice())
            .ok_or_else(|| Error::OqsError("an invalid signing key".to_string()))?;
        let signature = scheme.sign(message, sk)?;
        Ok(InnerMlDsa {
            scheme: *self,
            value: signature.into_vec(),
        }
        .into())
    }

    #[cfg(feature = "vrfy")]
    /// Verify a signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &MlDsaSignature,
        verification_key: &MlDsaVerificationKey,
    ) -> Result<()> {
        let alg = self.into();
        let scheme = Sig::new(alg)?;
        let sig = scheme
            .signature_from_bytes(signature.0.value.as_slice())
            .ok_or_else(|| Error::OqsError("an invalid signature".to_string()))?;
        let vk = scheme
            .public_key_from_bytes(verification_key.0.value.as_slice())
            .ok_or_else(|| Error::OqsError("an invalid public key".to_string()))?;
        scheme.verify(message, sig, vk)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerMlDsa {
    scheme: MlDsaScheme,
    value: Vec<u8>,
}

#[cfg(test)]
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

        let signature = sk.0.scheme.sign(&MSG, &sk).unwrap();
        let res = pk.0.scheme.verify(MSG, &signature, &pk);
        assert!(res.is_ok());

        let res = pk.0.scheme.verify(&[1u8; 8], &signature, &pk);
        assert!(res.is_err());
    }
}
