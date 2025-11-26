//! Falcon key and signature methods

use crate::{
    deserialize_hex_or_bin,
    error::{Error, Result},
    serialize_hex_or_bin,
};
use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

#[cfg(feature = "eth_falcon")]
mod eth_falcon;

macro_rules! impl_falcon_struct {
    ($name:ident, $convert:ident, $expect:expr) => {

        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for fn-dsa")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerFalcon);

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.value.as_ref()
            }
        }

        impl From<InnerFalcon> for $name {
            fn from(inner: InnerFalcon) -> Self {
                Self(inner)
            }
        }

        impl $name {
            /// The [`FalconScheme`] represented by this struct
            pub fn scheme(&self) -> FalconScheme {
                self.0.scheme
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] to its raw byte representation")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] from its raw byte representation and scheme")]
            pub fn from_raw_bytes(scheme: FalconScheme, bytes: &[u8]) -> Result<Self> {
                let alg = scheme.into();
                let sig = Sig::new(alg).expect("a valid algorithm");
                let _value = sig.$convert(bytes).ok_or(Error::OqsError($expect.to_string()))?.to_owned();
                Ok(InnerFalcon {
                    scheme,
                    value: bytes.to_vec(),
                }.into())
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
            #[cfg(feature = "eth_falcon")]
            // Used solely for testing encodings since OQS doesn't know about ETHFALCON
            FalconScheme::Ethereum => Algorithm::Falcon512,
        }
    }
}

impl From<&FalconScheme> for Algorithm {
    fn from(scheme: &FalconScheme) -> Self {
        match *scheme {
            FalconScheme::Dsa512 => Algorithm::Falcon512,
            FalconScheme::Dsa1024 => Algorithm::Falcon1024,
            #[cfg(feature = "eth_falcon")]
            // Used solely for testing encodings since OQS doesn't know about ETHFALCON
            FalconScheme::Ethereum => Algorithm::Falcon512,
        }
    }
}

impl From<FalconScheme> for u8 {
    fn from(scheme: FalconScheme) -> Self {
        match scheme {
            FalconScheme::Dsa512 => 1,
            FalconScheme::Dsa1024 => 2,
            #[cfg(feature = "eth_falcon")]
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
            #[cfg(feature = "eth_falcon")]
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
                #[cfg(feature = "eth_falcon")]
                Self::Ethereum => "ETHFALCON",
            }
        )
    }
}

impl FromStr for FalconScheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "FN-DSA-512" => Ok(FalconScheme::Dsa512),
            "FN-DSA-1024" => Ok(FalconScheme::Dsa1024),
            #[cfg(feature = "eth_falcon")]
            "ETHFALCON" => Ok(FalconScheme::Ethereum),
            _ => Err(Error::InvalidSchemeStr(s.to_string())),
        }
    }
}

serde_impl!(FalconScheme);

impl FalconScheme {
    #[cfg(feature = "kgen")]
    /// Generate a new Falcon signing and verification key pair
    pub fn keypair(&self) -> Result<(FalconVerificationKey, FalconSigningKey)> {
        let alg = self.into();
        let scheme = Sig::new(alg)?;
        let (pk, sk) = scheme.keypair()?;
        Ok((
            InnerFalcon {
                scheme: *self,
                value: pk.into_vec(),
            }
            .into(),
            InnerFalcon {
                scheme: *self,
                value: sk.into_vec(),
            }
            .into(),
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
            InnerFalcon {
                scheme: *self,
                value: pk.into_vec(),
            }
            .into(),
            InnerFalcon {
                scheme: *self,
                value: sk.into_vec(),
            }
            .into(),
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
        let sk = scheme
            .secret_key_from_bytes(signing_key.0.value.as_slice())
            .ok_or_else(|| Error::OqsError("an invalid signing key".to_string()))?;
        let signature = scheme.sign(message, sk)?;
        Ok(InnerFalcon {
            scheme: *self,
            value: signature.into_vec(),
        }
        .into())
    }

    #[cfg(all(feature = "sign", not(feature = "eth_falcon")))]
    /// Sign a message with the specified signing key
    pub fn sign(&self, message: &[u8], signing_key: &FalconSigningKey) -> Result<FalconSignature> {
        self.sign_inner(message, signing_key)
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
        let sig = scheme
            .signature_from_bytes(signature.0.value.as_slice())
            .ok_or_else(|| Error::OqsError("an invalid signature".to_string()))?;
        let vk = scheme
            .public_key_from_bytes(verification_key.0.value.as_slice())
            .ok_or_else(|| Error::OqsError("an invalid public key".to_string()))?;
        scheme.verify(message, sig, vk)?;
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
}

impl_falcon_struct!(
    FalconSigningKey,
    secret_key_from_bytes,
    "a valid signing key"
);
impl_falcon_struct!(
    FalconVerificationKey,
    public_key_from_bytes,
    "a valid public key"
);
impl_falcon_struct!(FalconSignature, signature_from_bytes, "a valid signature");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerFalcon {
    pub(crate) scheme: FalconScheme,
    #[serde(
        serialize_with = "serialize_hex_or_bin",
        deserialize_with = "deserialize_hex_or_bin"
    )]
    pub(crate) value: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[cfg(all(feature = "kgen", feature = "sign", feature = "eth_falcon"))]
    #[rstest]
    #[case::fn512(FalconScheme::Dsa512)]
    #[case::fn1024(FalconScheme::Dsa1024)]
    #[case::ethereum(FalconScheme::Ethereum)]
    fn serdes(#[case] scheme: FalconScheme) {
        let (pk, sk) = scheme.keypair().unwrap();

        let bytes = postcard::to_stdvec(&sk).unwrap();
        let sk2 = postcard::from_bytes::<FalconSigningKey>(&bytes).unwrap();
        assert_eq!(sk, sk2);

        let string = serde_json::to_string(&sk).unwrap();
        println!("{}", string);
        let sk2 = serde_json::from_str::<FalconSigningKey>(&string).unwrap();
        assert_eq!(sk, sk2);

        let bytes = postcard::to_stdvec(&pk).unwrap();
        let pk2 = postcard::from_bytes::<FalconVerificationKey>(&bytes).unwrap();
        assert_eq!(pk, pk2);

        let string = serde_json::to_string(&pk).unwrap();
        let pk2 = serde_json::from_str::<FalconVerificationKey>(&string).unwrap();
        assert_eq!(pk, pk2);

        let msg = [0u8; 8];
        let sig = sk.0.scheme.sign(&msg, &sk).unwrap();

        let bytes = postcard::to_stdvec(&sig).unwrap();
        let sig2 = postcard::from_bytes::<FalconSignature>(&bytes).unwrap();
        assert_eq!(sig, sig2);

        let string = serde_json::to_string(&sig).unwrap();
        let sig2 = serde_json::from_str::<FalconSignature>(&string).unwrap();
        assert_eq!(sig, sig2);
    }

    #[cfg(all(
        feature = "kgen",
        feature = "sign",
        feature = "vrfy",
        feature = "eth_falcon"
    ))]
    #[rstest]
    #[case::fn512(FalconScheme::Dsa512)]
    #[case::fn1024(FalconScheme::Dsa1024)]
    #[case::ethereum(FalconScheme::Ethereum)]
    fn flow(#[case] scheme: FalconScheme) {
        const MSG: &[u8] = &[0u8; 8];
        let (pk, sk) = scheme.keypair().unwrap();

        let signature = sk.0.scheme.sign(&MSG, &sk).unwrap();
        let res = pk.0.scheme.verify(MSG, &signature, &pk);
        assert!(res.is_ok());

        let res = pk.0.scheme.verify(&[1u8; 8], &signature, &pk);
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
