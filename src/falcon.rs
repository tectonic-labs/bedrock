//! Falcon key and signature methods

use crate::{
    deserialize_hex_or_bin,
    error::{Error, Result},
    serialize_hex_or_bin,
};
use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};

#[cfg(feature = "eth_falcon")]
mod eth_falcon;

macro_rules! impl_falcon_struct {
    ($name:ident, $convert:ident, $expect:expr) => {

        #[derive(Clone, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for fn-dsa")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerFalcon);

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

scheme_impl!(
    /// Falcon schemes
    FalconScheme,
    Algorithm,
    #[default]
    /// DSA-512
    Dsa512 => Algorithm::Falcon512 ; "FN-DSA-512" ; 1 ; 32,
    /// DSA-1024
    Dsa1024 => Algorithm::Falcon1024 ; "FN-DSA-1024" ; 2 ; 32,
    @cfg(feature = "eth_falcon")
    /// ETHFALCON
    Ethereum => Algorithm::Falcon512 ; "ETHFALCON" ; 3 ; 32,
);

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
        if seed.len() != self.seed_size() {
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

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerFalcon {
    pub(crate) scheme: FalconScheme,
    #[serde(
        serialize_with = "serialize_hex_or_bin",
        deserialize_with = "deserialize_hex_or_bin"
    )]
    pub(crate) value: Vec<u8>,
}

impl std::fmt::Debug for InnerFalcon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerFalcon")
            .field("scheme", &self.scheme)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for InnerFalcon {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for FalconSigningKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for FalconSigningKey {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

        let signature = sk.0.scheme.sign(MSG, &sk).unwrap();
        let res = pk.0.scheme.verify(MSG, &signature, &pk);
        assert!(res.is_ok());

        let res = pk.0.scheme.verify(&[1u8; 8], &signature, &pk);
        assert!(res.is_err());
    }

    #[cfg(feature = "kgen")]
    #[test]
    fn expected_seed() {
        const SEED: &[u8] = &[1u8; 32];
        let (pk, sk) = FalconScheme::Dsa512.keypair_from_seed(SEED).unwrap();

        assert_eq!(
            &hex::encode(pk.to_raw_bytes()),
            "099ae4427327d6f80f755e906f6e9e64ed162955016f6b498586ef50d4a441d0d03189f18721c1875e41d4b096a856e716bd274528288d45ae8d896525ba023a0b9139e6dce5308a715359a69c4e6872ccd65640d554ec5f1b528b3a46028612d25fd5140e85403fecd03c019c012da47995a092f43ac93188b6ac598ce845a97018f2441e311595957bcc1f4098b28d79982ced78ceb135802c033106a893b4140a4cb6fe3545c294084149407159fc13b53a31e1c2f1a1fed099d1ada4158e439a91865b3cfec4266feb2871d57522f1e55070ac301b6f6d498d34a75b1e40b50cfc9032fc112bb2c2ae92fa5d4c2b7141c9794696048071fabcddfa3778ca37e2c8a59481032054453d70597ccabba878bbd680573205d541dc075acb288e25b1fce91f6b58a642cadaf7c578602071b41e417308ee31114d05c51cd89eb9868bcf9074994b3868bd9aa8414aeb972e1f40144a9b8b823820494341a288b82044166855ae4196b030612a289e78705413c96fa07a206a11e495a5108d66dc2f9b74592895a667c114005bd8d36aa86abca1f6d9e39219949de618646c55a51f616d111432d5caca29c86e85e23a784283eb8f05d5eae4995a80eeb8e6c39fed53c6425992e3d9007cc78b0a9d5b28c0e245604925b75d0038e404fd87084e633aac2a0364f4ba0b8fe3aa1056577528099416bed68481639a94277a3f4fea3340a95980aa3e818e8201b3ecc5156ecf7b29228bb34d1020b8a674140e5ec0aa269533a8ae918980f4bb2130aa46c409451690d26ee50fbd8501636d589b4f219a145d8ad24e7adcf726024799a134f930e6cda2dd75c4e40322457ad769d543dca44452f89e22bf9d75f9c36b531492194ffb4663a00fad06770a04a5b9094e31e016ed11b475b45fab224078db523f2278bdc681e573efc833198596ac20f89f80d690911cc10a5db5f20cd16175f5fb03d182de01d8cf77b40eeb8551369819c996bf3200d0ce5bf167397298eeefd61eb46f59f62e6b8189f5053cdb68b81e42906750b76ec5736a70a5be2f0d1a1b9f06c84d6e7ba112a872b3e8c0b9f1c5ff9109211740285f7fea4654274bcc97dee5562f9166825ae8d05f58b37dd66885f02bde5cfcc5baf4a5ab3899a4171315457b49f64a756a5a3a2e9177450c867e68c5f8188a2c9d382e67e56ec196d6a2e2cba00b9911468a629709648eb10115dacc0e4c817376e7b5a3e230a40765d604ca3a371f22a340b887691b5c04"
        );
        assert_eq!(
            &hex::encode(sk.to_raw_bytes()),
            "59000fc00bc0c4100f01e00044f44ec9041e82fc2fffd01f06f3debdfbdf84f820c3ffaf4028513dffb0fe08307aefffc21ff004efefc2fbe0fe03dffeeb718003fdc6e820000450b5e02f45f00fc3ec1f07fc50fff820c2045042f7f08013de7c03cf3d0bc0bffc2ebe10003d042fc0fbfffaf83f43e80108001e850fd14527cfc5eb7044f3bf43180fbe03c140200d02041e86f03001f7ffbff7cf8804afbc1410ff17ff3f040fbef8100703ce78f83fbef3cf0403d17a183f3be8103ef84045101f4ae8a1bc1fcec2080e7a0471c8040080fbb086f7cf821bddf80830c70c0ff7f812790be2040c1f4103ff810851030c013c200105fc11010ffef9088f41e00ec7ffed89f7e201180dbe000082e3cffe0fe0001810fe0fb046f8107d0fef7d0010830c907adc2e7c083fc0f820ba33f03ee76140f41004fbe13ee43008f7a0c2f830fcef9181fc3105040fc017e080fbd13b0c4e7cf440c30820c507b081fff0beec40430c51fbf41fbcf7efbe082100ff9f3bec0f48081143e0403cfffe8003d0f308213cff9000fc2f40106f7ce00ec00c107dfff1441021bf14503c0b80400bdf45081ec11c5e7ffff081e02ec4046180101100006f81106d0310003df0207f005001f810f917ff83081fbb13ff3ff3d0820c313f004fbc0b907c0c2ec11fbf44e8303f080fc3f410ff1840000bd17ff7f0801c00bf183183041181f3c10107afff003f43fc3f001c70780bf044fb9184eff1030fe0c10fc043003f87e060c2f8703b10a1bdf05084fc6e4117c1bdf050c707c0bd006003ec10b9d7e07efc00be20703d03d0bff4107e14427d0bc0fd13ce04e84004fbf281fc4f80f81fc0f7e17ed41084ffd041fbe1bee82fbcf8107f088100040141036141f7cf00ef70c31020471bef3d048f7c0021bc042085d7d0bd041fbc07a33d187e840bdfc1ec324303d100e7f0800fe040f3fe3b0fb145e80f7b13cec3f7ee7bf7e13f082001f80ec703efc317dfc2040145f7a1bd0fbfbe239e7afc213f006f7dfc1080efc23c1c1d05f7907c0c904613c0bb03f07f0830c0f8518104423afc2fc0fff000ef1ec7fffeb61915fef2fcee141f26fde611f3ffcd000925fd19fdfc24cd0f21003a3c0d00e607cae70713f403d40ef7fff1e20df8f6e5ef01ffdd1010e4c002e6de11e6021a0523d3e00b09f532e8def94cffffeef8180519e3fc1a1e0c1206eb0af304f9200801f80804d21410e706d1f7fce1ee00fceec9fa40f5f4e13ef3fb14f627ee0c0afa12f91717e4fbfd06ef3c1013fcfde50f21031d0dc6e6f5052313e5f01afd05d515d701dc05f7110609d42bcdf9d10639001216e9e909ce36fa280b25f715fed8d2f4044a1e05e4fd11edf82af5020df8f9251b00ed1af8e8fb2713ff4302d71a0010e107400906edea210b0916e315f92114de294c3f15ca0be9e52107eff5edf00315e4d600ef38df11dedff422dbfdd91700dc0cd43d051fe114ea2aed390e05002236f0ee2526fef415eef8f4f42404f1fc2ce9f6f21dfd18d7f9ebf8f613d90e03d80609e426e402e2dceacfe9fd00f544101dfbf9092a0c2f1ff2d4ebfd27152b2afdee3b080af3f90c121bf6d10505c1100322eafac0e41e0d0f08dcc21416142404f5010d1011f2110fc729db36eb090b0b2132e525daf6eff63351ff10f624ecdaff0d12b815eb08f7190813e41b0a02f6bc1221fb18e402dfe91bfb00fbc109fe18041ceedeee1e0dee0814fdcc240fe0f0f4e5dd0bf4e510cc192416f718c6fbca18fb11fee902ee02e9261be0e9d314f71923"
        );
    }

    #[test]
    fn seed_boundaries() {
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[]).is_err());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 31]).is_err());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 32]).is_ok());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 33]).is_err());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 64]).is_err());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 65]).is_err());
    }
}
