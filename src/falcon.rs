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
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.value.as_ref()
            }
        }

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
    #[cfg(feature = "eth_falcon")]
    /// ETHFALCON
    Ethereum,
}

impl From<FalconScheme> for Algorithm {
    fn from(scheme: FalconScheme) -> Self {
        match scheme {
            FalconScheme::Dsa512 => Algorithm::Falcon512,
            FalconScheme::Dsa1024 => Algorithm::Falcon1024,
            FalconScheme::Ethereum => Algorithm::Falcon512,
        }
    }
}

impl From<&FalconScheme> for Algorithm {
    fn from(scheme: &FalconScheme) -> Self {
        match *scheme {
            FalconScheme::Dsa512 => Algorithm::Falcon512,
            FalconScheme::Dsa1024 => Algorithm::Falcon1024,
            FalconScheme::Ethereum => Algorithm::Falcon512,
        }
    }
}

impl From<FalconScheme> for u8 {
    fn from(scheme: FalconScheme) -> Self {
        match scheme {
            FalconScheme::Dsa512 => 1,
            FalconScheme::Dsa1024 => 2,
            FalconScheme::Ethereum => 3,
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
            3 => Ok(FalconScheme::Ethereum),
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
                Self::Ethereum => "ETHFALCON",
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
            "ETHFALCON" => Ok(FalconScheme::Ethereum),
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
    pub fn keypair_from_seed(
        &self,
        seed: &[u8],
    ) -> Result<(FalconVerificationKey, FalconSigningKey)> {
        if seed.len() < 32 || seed.len() > 64 {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        let alg = self.into();
        let scheme = Sig::new(alg)?;
        let (pk, sk) = scheme.keypair_from_seed(seed)?;
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

    #[cfg(feature = "sign")]
    fn sign_inner(
        &self,
        message: &[u8],
        signing_key: &FalconSigningKey,
    ) -> Result<FalconSignature> {
        let alg = self.into();
        let scheme = Sig::new(alg)?;
        let signature = scheme.sign(message, &signing_key.value)?;
        Ok(FalconSignature {
            scheme: *self,
            value: signature,
        })
    }

    #[cfg(all(feature = "sign", not(feature = "eth_falcon")))]
    pub fn sign(&self, message: &[u8], signing_key: &FalconSigningKey) -> Result<FalconSignature> {
        self.sign_inner(message, signing_key)
    }

    #[cfg(all(feature = "sign", feature = "eth_falcon"))]
    /// Sign a message
    pub fn sign(&self, message: &[u8], signing_key: &FalconSigningKey) -> Result<FalconSignature> {
        match self {
            Self::Ethereum => {
                use fn_dsa_sign::{
                    FN_DSA_LOGN_512, SigningKey, SigningKeyStandard,
                    eth_falcon::{EthFalconSigningKey, generate_salt},
                    signature_size,
                };

                let mut sk = SigningKeyStandard::decode(signing_key.value.as_ref())
                    .ok_or_else(|| Error::FnDsaError("Invalid signing key".to_string()))?;
                let salt = generate_salt();
                let mut sig = [0u8; signature_size(FN_DSA_LOGN_512)];
                sk.sign_eth(message, &salt, &mut sig);
                let alg = self.into();
                let scheme = Sig::new(alg)?;
                let value = scheme
                    .signature_from_bytes(&sig)
                    .map(|s| s.to_owned())
                    .ok_or(Error::FnDsaError("Invalid signature".to_string()))?;
                Ok(FalconSignature {
                    scheme: *self,
                    value,
                })
            }
            _ => self.sign_inner(message, signing_key),
        }
    }

    #[cfg(feature = "vrfy")]
    fn verify_inner(
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

    #[cfg(all(feature = "vrfy", not(feature = "eth_falcon")))]
    /// Verify a signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &FalconSignature,
        verification_key: &FalconVerificationKey,
    ) -> Result<()> {
        self.verify_inner(message, signature, verification_key)
    }

    #[cfg(all(feature = "vrfy", feature = "eth_falcon"))]
    /// Verify a signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &FalconSignature,
        verification_key: &FalconVerificationKey,
    ) -> Result<()> {
        match self {
            Self::Ethereum => {
                use fn_dsa_comm::eth_falcon::{SALT_LEN, decode_signature_to_packed};
                use fn_dsa_vrfy::eth_falcon::EthFalconVerifyingKey as Efvk;

                let pk = crate::eth_falcon::EthFalconVerifyingKey::try_from(verification_key)?;
                let pk = Efvk::decode(&pk);

                let mut salt = [0u8; SALT_LEN];
                salt.copy_from_slice(&signature.value.as_ref()[1..41]);

                let sig = decode_signature_to_packed(signature.value.as_ref())
                    .map_err(|e| Error::FnDsaError(e.to_string()))?;

                if pk.verify(message, &salt, &sig) {
                    Ok(())
                } else {
                    Err(Error::FnDsaError("Invalid signature".to_string()))
                }
            }
            _ => self.verify_inner(message, signature, verification_key),
        }
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

impl FalconSigningKey {
    #[cfg(feature = "eth_falcon")]
    /// Change the scheme if allowed
    ///
    /// NOTE: feels kludgy
    pub fn set_scheme(&mut self, scheme: FalconScheme) -> Result<()> {
        let my_scheme = self.scheme;
        match (my_scheme, scheme) {
            (FalconScheme::Dsa512, FalconScheme::Ethereum)
            | (FalconScheme::Ethereum, FalconScheme::Dsa512) => {
                self.scheme = scheme;
                Ok(())
            }
            _ => Err(Error::InvalidSchemeStr(format!(
                "Unsupported scheme change from {} to {}",
                my_scheme, scheme
            ))),
        }
    }
}

/// Falcon verification key
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(into = "FalconSerde", try_from = "FalconSerde")]
pub struct FalconVerificationKey {
    pub(crate) scheme: FalconScheme,
    pub(crate) value: PublicKey,
}

derive_cfg_test!(FalconVerificationKey);

impl_raw!(FalconVerificationKey);

impl FalconVerificationKey {
    #[cfg(feature = "eth_falcon")]
    /// Change the scheme if allowed
    ///
    /// NOTE: feels kludgy
    pub fn set_scheme(&mut self, scheme: FalconScheme) -> Result<()> {
        let my_scheme = self.scheme;
        match (my_scheme, scheme) {
            (FalconScheme::Dsa512, FalconScheme::Ethereum)
            | (FalconScheme::Ethereum, FalconScheme::Dsa512) => {
                self.scheme = scheme;
                Ok(())
            }
            _ => Err(Error::InvalidSchemeStr(format!(
                "Unsupported scheme change from {} to {}",
                my_scheme, scheme
            ))),
        }
    }
}

#[cfg(feature = "eth_falcon")]
impl TryFrom<FalconVerificationKey> for crate::eth_falcon::EthFalconVerifyingKey {
    type Error = Error;

    fn try_from(public_key: FalconVerificationKey) -> std::result::Result<Self, Self::Error> {
        Self::try_from(&public_key)
    }
}

#[cfg(feature = "eth_falcon")]
impl TryFrom<&FalconVerificationKey> for crate::eth_falcon::EthFalconVerifyingKey {
    type Error = Error;

    /// Convert Falcon public key to ETHFALCON Solidity format (abi.encodePacked, NTT form)
    ///
    /// # Arguments
    /// * `pubkey` - Standard Falcon public key (897 bytes)
    ///
    /// # Returns
    /// * 1024-byte abi.encodePacked(uint256[32]) format
    fn try_from(public_key: &FalconVerificationKey) -> Result<Self> {
        if public_key.scheme == FalconScheme::Ethereum {
            fn_dsa_comm::eth_falcon::decode_pubkey_to_ntt_packed(public_key.value.as_ref())
                .map_err(|e| Error::FnDsaError(e.to_string()))
        } else {
            Err(Error::InvalidSchemeStr(
                "Only ETHFALCON public key is supported".to_string(),
            ))
        }
    }
}

/// Falcon signature
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(into = "FalconSerde", try_from = "FalconSerde")]
pub struct FalconSignature {
    pub(crate) scheme: FalconScheme,
    pub(crate) value: Signature,
}

derive_cfg_test!(FalconSignature);

impl_raw!(FalconSignature);

#[cfg(feature = "eth_falcon")]
impl TryFrom<FalconSignature> for crate::eth_falcon::EthFalconSignature {
    type Error = Error;

    /// Convert Falcon signature to ETHFALCON Solidity format (abi.encodePacked)
    ///
    /// # Arguments
    /// * `signature` - Standard Falcon signature bytes
    ///
    /// # Returns
    /// * 1024-byte abi.encodePacked(uint256[32]) format
    fn try_from(signature: FalconSignature) -> Result<Self> {
        Self::try_from(&signature)
    }
}

#[cfg(feature = "eth_falcon")]
impl TryFrom<&FalconSignature> for crate::eth_falcon::EthFalconSignature {
    type Error = Error;
    fn try_from(signature: &FalconSignature) -> Result<Self> {
        if signature.scheme == FalconScheme::Ethereum {
            fn_dsa_comm::eth_falcon::decode_signature_to_packed(signature.value.as_ref())
                .map_err(|e| Error::FnDsaError(e.to_string()))
        } else {
            Err(Error::InvalidSchemeStr(
                "Only ETHFALCON signature is supported".to_string(),
            ))
        }
    }
}

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

    #[cfg(feature = "kgen")]
    #[test]
    fn expected_seed() {
        const SEED: &[u8] = &[1u8; 48];
        let (pk, sk) = FalconScheme::Dsa512.keypair_from_seed(SEED).unwrap();

        assert_eq!(
            &hex::encode(pk.to_raw_bytes()),
            "0964915645b6542669866b136394dd07741e49d68a2b46114bba76578c07ce8b936c1f693cc929b3d6d4b40f11f9d87d8af93bbecf58864110bd189c23d7eb508e4038f89d6b4f6926d7e7fbd6944465572aa1690e6475ed7715446083f51774315cd36d1147f522ca9a8815710b73d9b4bfa15f4727d00ba1657bb11fd6c04bc1ca3726d6a823fc09b5f0db7f112ee29a80573fa9d989b62c6ce36518eaf44ae8a42374fc772b61fb3330ca818c81ef882c52aa22c347b8580ce11b5355bf8e2103090d9645a102b32c67b2009d3a69306904547170f98f255984205328158593beae15fb8ea948101ab3f7356c8d4789d750191eeb9f8092203354db02ed6ef602943f7afed0c0fa42d669ca149146849d28a63ea41a5ba92c5586e7aec36403cce4c2f0cce788769d14ccc086094523045d5218bd51e195498c5181d619b921c416100aebb35fea4b96296044a945a492420de84f1aea78fa5bf94dde64b94cef5ac68cf668c24f3a3bc5470cad71f14dabab5ab501276a9f0956ddc5058c6a6a00fad361614b0f65f69af1486b4637c56dc9ab0a94bbd9d0f1724a1e2d913e2b3c1c911318740a07e9c5bd542c34924a02aec5b44277d2b182647de499a6b85d74c5e32f9303146625d19d16bc958d3276182df284dcd675e44145aca8e5f5d75944ade28a1641deddaa74c8167018396be5ddaac10dad8d54da5176906caa9245d2d51abf9ece9ed8b1213c7fde7eca968afe19081386c3144148eadbf276ae5d1099062a5f97cd9711ccea6b980c963939b0dc645669595e30a3db4e5ddcd50881ddaa276acc5451dfe98ad40de1ce262ebdf8369960eec4afe64550b2d12d2e6c2f6705a08d74c9f0439445544f2e0ffaae29e11b142f12e0dcfa5c488be9c2dfca66a08266add329187d476574c970b02af311fe184392a1812909cd0b112150d8b813c074b076e6371569104405a29b5c221e1556a8b326e299ddda197fe067090a8d960ed8626a325a81585df70a1c1c54ded3388e2efe98eda0992cd81f4bfc6a90a2a0f1ba2a27af70d911103291fc73badd34f101c338298cb8ef8f9aaf904a38974c54ad661283cd53f602229b939b0e8178542d3b33aaff5389d8683845660572b081609017b6f8e560cf98651450adb0abca6436e9ab3a2be4e84b3d8d07f8420ab3cca956db8f14570582d8aecace81aacbeb3d8206530dfc29b411c2b2faa680c65fca62883ddbc69c2fb65efd072522b02a147dd58d6c69"
        );
        assert_eq!(
            &hex::encode(sk.to_raw_bytes()),
            "59001f01ffffbd0891c2105e3f04204803b0c40c1000ec3ffdec203f0c3ffefc5f810f9f3dffa042f44fbef03ebe1841030bd10223cdc1f01d88040e83f04efef7c145085f3fe3ff02fc204803813ff7f0c11020060be07d07af40f7e03f001042142e8417d1c207a080f02fbb0800c1ec30fe13bf412bd03efc31410c007e07edbb1040c8ec40c0085044038ffeec217e043ffe142f8300013d0c50bf13e0000c3f39100f08044ffef430ff1810f7e850be0baf3de82fc900a13f1bdfbff3cf8107afbf0bff7c143fc2000003f810ba0b807f1bf00213cebcec7f44040f8303d10003c34203d03ef3dfc7fbbec21c00bff3e0840bafff2000faf4517b001fc30fcfba17cffff8803c000e020fcefb082fff0c0002202f41e820000001810fd083204f01002082e7f03e0420c70c4ef907f13ef7bfbee7affb1bcf063be1c507d100ec3f7bfffec1079fbdf3afc0f3ff370bd0c4efffc4fc10c3f85ebaffcf860c40c10060020c20800820810c607c1c107fe7e081f8707d148fc1001004f7f17d043ffe0c1fcaf7cfbe0c0046efce40f42f861032820bd1c5f0217c03a13e1760fd006e4213df42fbaf0308af80fc5104005eba1fd00307a13e0beff807f07dec51450c004513d0fd0480c61fe0b3f3f0bf004f40f3df7a04203b0420c41bf07c082ebc0fd181f02f8407b142fc1ec10fcf830bef3ffc0f7fe40081f7f1010020c2e3c0fef04045002006000080ffc1beeb7038080f41fc1f811bffff13d0070ffe3f03b1010c4149147ffe087ec107ce7c040fc6fc2e82fc4e87f8813d13c2fffc5043048fbff040c1185f811bf180ecaf3cffcec900338103bfbefbb13fefaf46e3d0c507e13cefa0be0fd07df84e42105101f7c0030c2fc20fe13e004fc72bbf7ff3be01fb707f1800f5fc5f4200200104224413e03f041f85ef6f0513dffc0bff40ffcf7c23e004f39e3d0c10bdf83fbb040f79fc903ff7af7cfb80421fefbc17f041f7cffcfbd07608217de0003ef46000fff1c10c0ec6002ffd0fefbedc2f0227cfc203ff0310413af01e3afc0ffd1bedfaec2fc1f3b200f44083ec0e43e014c3fbdcedef02f8ec1f0b0dfb2ffaf8f5da28f4170f030bec0ff207e5f810faff0009ece7dde6150af703de07e8f8f7f309233ffbfbf40bff18ffd8f4de04f12e0ee3fe17050202e2f1c5f5ef11ebe71706f707fbeb0e15ec0ec61f010d05f61ad2eec6f81033e2fd0906ea052c20eff0d71e2ae210e3f4fb091ff003fb0815dfcad919f906e51c06f91ff711f8eced110e200c031702e4c3f0fb1ff6080d1f04ea04fff7f13117ff25011ef50be0edf8effa0f11d61101e9f620f4e3f80b071b35e331b220e0f3f6eb1ffa150317f813c2fbf30903fd11d40ffc17da1bee023a0014f207f4e7d4090cf2f20725ca17f30a190f00ea1105f51e22cdf0faf22dfb151403d803f4ee2dfad10102eb140216edf0fdfa0c03ff300504e6edf93f150feb03fa0a12f0fdf8dbf813ddf9f91bd2fc1505f509f5eee9e80a0ef928f119eddf06e8030709fef8e70d5c1cfc1a15d81d3106e208f70d04f9001209f913ed05d410f42301c8d6fc2df3350fef04eeec0c0fe70e1e06e208fa1cdce815f5280bf7f4f50a0a09c3ebe22710e3eb02faf00beaf31403e424f82dd9f3fe15210707f1fdf50f0107e10018e8f422f0fcfeffdcf505e906f30ae322eccee2c0bf0d1ce5ff27edd227dee7ff111cf008e633090e140ffa02edebffe4faf4f804ee2ff0ece707ed063818fd0ef01a2005e71703ff05d60d03eff61efe04fd120be3"
        );
    }

    #[test]
    fn seed_boundaries() {
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[]).is_err());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 31]).is_err());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 32]).is_ok());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 48]).is_ok());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 64]).is_ok());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 65]).is_err());
    }
}
