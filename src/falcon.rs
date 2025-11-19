//! Falcon key and signature methods

use crate::error::{Error, Result};
use oqs::sig::{Algorithm, PublicKey, SecretKey, Sig, Signature};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DError, MapAccess, Visitor},
    ser::SerializeStruct,
};
use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

macro_rules! derive_cfg_test {
    ($name:ident) => {
        #[cfg(test)]
        impl Eq for $name {}

        #[cfg(test)]
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.scheme == other.scheme && self.value.as_ref() == other.value.as_ref()
            }
        }
    };
}

macro_rules! impl_raw {
    ($name:ident) => {
        impl $name {
            #[doc = concat!("Convert [`", stringify!($name), "`] to its raw byte representation")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.value.as_ref().to_vec()
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] from its raw byte representation and scheme")]
            pub fn from_raw_bytes(bytes: &[u8]) -> Result<Self> {
                let inner = FalconSerde {
                    scheme: FalconScheme::from_any_length(bytes.len())?,
                    value: bytes.to_vec(),
                };
                Self::try_from(inner)
            }
        }
    };
}

/// Falcon schemes
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum FalconScheme {
    /// DSA-512
    #[default]
    Dsa512,
    /// DSA-1024
    Dsa1024,
}

impl From<FalconScheme> for Algorithm {
    fn from(scheme: FalconScheme) -> Self {
        match scheme {
            FalconScheme::Dsa512 => Algorithm::Falcon512,
            FalconScheme::Dsa1024 => Algorithm::Falcon1024,
        }
    }
}

impl From<&FalconScheme> for Algorithm {
    fn from(scheme: &FalconScheme) -> Self {
        match *scheme {
            FalconScheme::Dsa512 => Algorithm::Falcon512,
            FalconScheme::Dsa1024 => Algorithm::Falcon1024,
        }
    }
}

impl From<FalconScheme> for u8 {
    fn from(scheme: FalconScheme) -> Self {
        match scheme {
            FalconScheme::Dsa512 => 1,
            FalconScheme::Dsa1024 => 2,
        }
    }
}

impl From<&FalconScheme> for u8 {
    fn from(scheme: &FalconScheme) -> Self {
        (*scheme).into()
    }
}

impl TryFrom<u8> for FalconScheme {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(FalconScheme::Dsa512),
            2 => Ok(FalconScheme::Dsa1024),
            _ => Err(Error::InvalidScheme(value)),
        }
    }
}

impl Display for FalconScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Dsa512 => "FN-DSA-512",
                Self::Dsa1024 => "FN-DSA-1024",
            }
        )
    }
}

impl FromStr for FalconScheme {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "FN-DSA-512" => Ok(FalconScheme::Dsa512),
            "FN-DSA-1024" => Ok(FalconScheme::Dsa1024),
            _ => Err(Error::InvalidSchemeStr(s.to_string())),
        }
    }
}

impl Serialize for FalconScheme {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_u8(self.into())
        }
    }
}

impl<'de> Deserialize<'de> for FalconScheme {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            Ok(s.parse().map_err(serde::de::Error::custom)?)
        } else {
            let u8 = u8::deserialize(d)?;
            Ok(u8.try_into().map_err(serde::de::Error::custom)?)
        }
    }
}

impl FalconScheme {
    #[cfg(feature = "kgen")]
    /// Generate a new Falcon signing and verification key pair
    pub fn keypair(&self) -> Result<(FalconVerificationKey, FalconSigningKey)> {
        let alg = self.into();
        let scheme = Sig::new(alg)?;
        let (pk, sk) = scheme.keypair()?;
        Ok((
            FalconVerificationKey {
                scheme: *self,
                value: pk,
            },
            FalconSigningKey {
                scheme: *self,
                value: sk,
            },
        ))
    }

    #[cfg(feature = "kgen")]
    /// Generate a new Falcon signing and verification key pair from a seed
    pub fn keypair_from_seed(seed: &[u8]) -> Result<(FalconVerificationKey, FalconSigningKey)> {
        if seed.len() < 32 {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        todo!()
    }

    #[cfg(feature = "sign")]
    /// Sign a message
    pub fn sign(&self, message: &[u8], signing_key: &FalconSigningKey) -> Result<FalconSignature> {
        let alg = self.into();
        let scheme = Sig::new(alg)?;
        let signature = scheme.sign(message, &signing_key.value)?;
        Ok(FalconSignature {
            scheme: *self,
            value: signature,
        })
    }

    #[cfg(feature = "vrfy")]
    /// Verify a signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &FalconSignature,
        verification_key: &FalconVerificationKey,
    ) -> Result<()> {
        let alg = self.into();
        let scheme = Sig::new(alg)?;
        scheme.verify(message, &signature.value, &verification_key.value)?;
        Ok(())
    }

    const fn from_any_length(length: usize) -> Result<Self> {
        match length {
            1281                                 // sign-key
            | 897                                // vrfy-key
            | 666 => Ok(FalconScheme::Dsa512),   // signature 
            2305                                 // sign-key
            | 1793                               // vrfy-key
            | 1280 => Ok(FalconScheme::Dsa1024), // signature
            _ => Err(Error::InvalidLength(length))
        }
    }
}

/// Falcon signing key
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(into = "FalconSerde", try_from = "FalconSerde")]
pub struct FalconSigningKey {
    pub(crate) scheme: FalconScheme,
    pub(crate) value: SecretKey,
}

derive_cfg_test!(FalconSigningKey);

impl_raw!(FalconSigningKey);

/// Falcon verification key
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(into = "FalconSerde", try_from = "FalconSerde")]
pub struct FalconVerificationKey {
    pub(crate) scheme: FalconScheme,
    pub(crate) value: PublicKey,
}

derive_cfg_test!(FalconVerificationKey);

impl_raw!(FalconVerificationKey);

/// Falcon signature
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(into = "FalconSerde", try_from = "FalconSerde")]
pub struct FalconSignature {
    pub(crate) scheme: FalconScheme,
    pub(crate) value: Signature,
}

derive_cfg_test!(FalconSignature);

impl_raw!(FalconSignature);

/// Exists solely for serialization and deserialization purposes
struct FalconSerde {
    scheme: FalconScheme,
    value: Vec<u8>,
}

impl From<FalconSigningKey> for FalconSerde {
    fn from(key: FalconSigningKey) -> Self {
        Self::from(&key)
    }
}

impl From<&FalconSigningKey> for FalconSerde {
    fn from(key: &FalconSigningKey) -> Self {
        FalconSerde {
            scheme: key.scheme,
            value: key.value.as_ref().to_vec(),
        }
    }
}

impl TryFrom<FalconSerde> for FalconSigningKey {
    type Error = Error;

    fn try_from(value: FalconSerde) -> Result<Self> {
        let alg = value.scheme.into();
        let scheme = Sig::new(alg)?;
        let key = scheme
            .secret_key_from_bytes(&value.value)
            .ok_or(Error::OqsError("Invalid signing key".to_string()))?;
        Ok(FalconSigningKey {
            scheme: value.scheme,
            value: key.to_owned(),
        })
    }
}

impl From<FalconVerificationKey> for FalconSerde {
    fn from(value: FalconVerificationKey) -> Self {
        Self::from(&value)
    }
}

impl From<&FalconVerificationKey> for FalconSerde {
    fn from(key: &FalconVerificationKey) -> Self {
        FalconSerde {
            scheme: key.scheme,
            value: key.value.as_ref().to_vec(),
        }
    }
}

impl TryFrom<FalconSerde> for FalconVerificationKey {
    type Error = Error;

    fn try_from(value: FalconSerde) -> Result<Self> {
        let alg = value.scheme.into();
        let scheme = Sig::new(alg)?;
        let key = scheme
            .public_key_from_bytes(&value.value)
            .ok_or(Error::OqsError("Invalid verification key".to_string()))?;
        Ok(Self {
            scheme: value.scheme,
            value: key.to_owned(),
        })
    }
}

impl From<FalconSignature> for FalconSerde {
    fn from(value: FalconSignature) -> Self {
        Self::from(&value)
    }
}

impl From<&FalconSignature> for FalconSerde {
    fn from(value: &FalconSignature) -> Self {
        Self {
            scheme: value.scheme,
            value: value.value.as_ref().to_vec(),
        }
    }
}

impl TryFrom<FalconSerde> for FalconSignature {
    type Error = Error;

    fn try_from(value: FalconSerde) -> Result<Self> {
        let alg = value.scheme.into();
        let scheme = Sig::new(alg)?;
        let signature = scheme
            .signature_from_bytes(&value.value)
            .ok_or(Error::OqsError("Invalid signature".to_string()))?;
        Ok(Self {
            scheme: value.scheme,
            value: signature.to_owned(),
        })
    }
}

impl Serialize for FalconSerde {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            let mut state = s.serialize_struct("FalconSigningKey", 2)?;
            state.serialize_field("scheme", &self.scheme)?;
            state.serialize_field("key", &hex::encode(&self.value))?;
            state.end()
        } else {
            self.value.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for FalconSerde {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            struct SerdeVisitor;

            impl<'de> Visitor<'de> for SerdeVisitor {
                type Value = FalconSerde;

                fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a falcon signing key in human readable format")
                }

                fn visit_map<V>(self, mut map: V) -> std::result::Result<Self::Value, V::Error>
                where
                    V: MapAccess<'de>,
                {
                    let mut scheme: Option<FalconScheme> = None;
                    let mut key: Option<String> = None;

                    while let Some(name) = map.next_key::<String>()? {
                        match name.as_str() {
                            "scheme" => {
                                scheme = Some(map.next_value::<FalconScheme>()?);
                            }
                            "key" => {
                                key = Some(map.next_value::<String>()?);
                            }
                            _ => {}
                        }
                    }

                    let scheme = scheme.ok_or(DError::custom("scheme is required"))?;
                    let key = key.ok_or(DError::custom("key is required"))?;
                    let key = hex::decode(key).map_err(DError::custom)?;
                    Ok(FalconSerde { scheme, value: key })
                }
            }

            const FIELDS: &[&str] = &["scheme", "key"];
            d.deserialize_struct("FalconSerde", FIELDS, SerdeVisitor)
        } else {
            let data = Vec::<u8>::deserialize(d)?;
            let scheme = FalconScheme::from_any_length(data.len())
                .map_err(|_| DError::custom("Invalid deserialization data".to_string()))?;
            let key = data;
            Ok(FalconSerde { scheme, value: key })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "kgen", feature = "sign"))]
    #[test]
    fn serdes() {
        let (pk, sk) = FalconScheme::Dsa512.keypair().unwrap();

        let bytes = postcard::to_stdvec(&sk).unwrap();
        let sk2 = postcard::from_bytes::<FalconSigningKey>(&bytes).unwrap();
        assert_eq!(sk, sk2);

        let string = serde_json::to_string(&sk).unwrap();
        let sk2 = serde_json::from_str::<FalconSigningKey>(&string).unwrap();
        assert_eq!(sk, sk2);

        let bytes = postcard::to_stdvec(&pk).unwrap();
        let pk2 = postcard::from_bytes::<FalconVerificationKey>(&bytes).unwrap();
        assert_eq!(pk, pk2);

        let string = serde_json::to_string(&pk).unwrap();
        let pk2 = serde_json::from_str::<FalconVerificationKey>(&string).unwrap();
        assert_eq!(pk, pk2);

        let msg = [0u8; 8];
        let sig = sk.scheme.sign(&msg, &sk).unwrap();

        let bytes = postcard::to_stdvec(&sig).unwrap();
        let sig2 = postcard::from_bytes::<FalconSignature>(&bytes).unwrap();
        assert_eq!(sig, sig2);

        let string = serde_json::to_string(&sig).unwrap();
        let sig2 = serde_json::from_str::<FalconSignature>(&string).unwrap();
        assert_eq!(sig, sig2);
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[test]
    fn flow() {
        const MSG: &[u8] = &[0u8; 8];
        let (pk, sk) = FalconScheme::Dsa512.keypair().unwrap();

        let signature = sk.scheme.sign(&MSG, &sk).unwrap();
        let res = pk.scheme.verify(MSG, &signature, &pk);
        assert!(res.is_ok());

        let res = pk.scheme.verify(&[1u8; 8], &signature, &pk);
        assert!(res.is_err());
    }
}
