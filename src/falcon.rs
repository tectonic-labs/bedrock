//! Falcon key and signature methods
//!
//! Because FIPS-206 (FN-DSA) has not been published, Falcon is not a stable DSA recommended for
//! production. The signature and key formats here may change once the final standard lands.

use crate::{
    deserialize_hex_or_bin,
    error::{Error, Result},
    serialize_hex_or_bin,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "eth_falcon")]
mod eth_falcon;

/// Map a [`FalconScheme`] to the fn-dsa `logn` degree parameter.
fn logn(scheme: FalconScheme) -> u32 {
    match scheme {
        FalconScheme::Dsa512 => 9,
        FalconScheme::Dsa1024 => 10,
        #[cfg(feature = "eth_falcon")]
        FalconScheme::Ethereum => 9,
    }
}

macro_rules! impl_falcon_struct {
    ($name:ident, $validate:ident, $expect:expr) => {

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
                scheme.$validate(bytes)?;
                Ok(InnerFalcon {
                    scheme,
                    value: bytes.to_vec(),
                }.into())
            }
        }
    };
}

scheme_impl_pure!(
    /// Falcon schemes
    FalconScheme,
    #[default]
    /// DSA-512
    Dsa512 => "FN-DSA-512" ; 1 ; 32,
    /// DSA-1024
    Dsa1024 => "FN-DSA-1024" ; 2 ; 48,
    @cfg(feature = "eth_falcon")
    /// ETHFALCON
    Ethereum => "ETHFALCON" ; 3 ; 32,
);

serde_impl!(FalconScheme);

impl FalconScheme {
    /// Validate a Falcon signing (secret) key encoding for this scheme (by length).
    fn validate_signing_key(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() == fn_dsa_comm::sign_key_size(logn(*self)) {
            Ok(())
        } else {
            Err(Error::FnDsaError("an invalid signing key".to_string()))
        }
    }

    /// Validate a Falcon verification (public) key encoding for this scheme (by length).
    fn validate_public_key(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() == fn_dsa_comm::vrfy_key_size(logn(*self)) {
            Ok(())
        } else {
            Err(Error::FnDsaError("an invalid public key".to_string()))
        }
    }

    /// Validate a Falcon signature length for this scheme.
    fn validate_signature(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() == fn_dsa_comm::signature_size(logn(*self)) {
            Ok(())
        } else {
            Err(Error::FnDsaError("an invalid signature".to_string()))
        }
    }

    #[cfg(feature = "kgen")]
    /// Generate a new Falcon signing and verification key pair
    pub fn keypair(&self) -> Result<(FalconVerificationKey, FalconSigningKey)> {
        use fn_dsa_kgen::{sign_key_size, vrfy_key_size, KeyPairGenerator};
        let logn = logn(*self);
        let mut sk = vec![0u8; sign_key_size(logn)];
        let mut vk = vec![0u8; vrfy_key_size(logn)];
        let mut kg = fn_dsa_kgen::KeyPairGeneratorStandard::default();
        kg.keygen(logn, &mut rand_core::OsRng, &mut sk, &mut vk);
        Ok(self.pack_keypair(vk, sk))
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
        use fn_dsa_kgen::{sign_key_size, vrfy_key_size, KeyPairGenerator};
        let logn = logn(*self);
        let mut sk = vec![0u8; sign_key_size(logn)];
        let mut vk = vec![0u8; vrfy_key_size(logn)];
        let mut kg = fn_dsa_kgen::KeyPairGeneratorStandard::default();
        kg.keygen_from_seed(logn, seed, &mut sk, &mut vk);
        Ok(self.pack_keypair(vk, sk))
    }

    #[cfg(feature = "kgen")]
    fn pack_keypair(&self, vk: Vec<u8>, sk: Vec<u8>) -> (FalconVerificationKey, FalconSigningKey) {
        (
            InnerFalcon {
                scheme: *self,
                value: vk,
            }
            .into(),
            InnerFalcon {
                scheme: *self,
                value: sk,
            }
            .into(),
        )
    }

    #[cfg(feature = "sign")]
    fn sign_inner(
        &self,
        message: &[u8],
        signing_key: &FalconSigningKey,
    ) -> Result<FalconSignature> {
        // Use the original Falcon hash-to-point (SHAKE256(nonce ‖ message), the NIST round-3
        // convention), which fn-dsa exposes as `HASH_ID_ORIGINAL_FALCON` — NOT `HASH_ID_RAW`.
        // This is the convention the on-chain CATX precompiles verify against. When FIPS-206
        // (FN-DSA) is published this hash-to-point may change and will need to be revisited.
        use fn_dsa_sign::{signature_size, SigningKey, DOMAIN_NONE, HASH_ID_ORIGINAL_FALCON};
        let mut sk = fn_dsa_sign::SigningKeyStandard::decode(signing_key.0.value.as_slice())
            .ok_or_else(|| Error::FnDsaError("an invalid signing key".to_string()))?;
        let mut sig = vec![0u8; signature_size(sk.get_logn())];
        sk.sign(
            &mut rand_core::OsRng,
            &DOMAIN_NONE,
            &HASH_ID_ORIGINAL_FALCON,
            message,
            &mut sig,
        );
        Ok(InnerFalcon {
            scheme: *self,
            value: sig,
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
        // Must match the signing convention: original-Falcon hash-to-point, for compatibility
        // with the signatures verified on-chain by the CATX precompiles (see `sign_inner`).
        use fn_dsa_vrfy::{VerifyingKey, DOMAIN_NONE, HASH_ID_ORIGINAL_FALCON};
        let vk = fn_dsa_vrfy::VerifyingKeyStandard::decode(verification_key.0.value.as_slice())
            .ok_or_else(|| Error::FnDsaError("an invalid public key".to_string()))?;
        if vk.verify(
            signature.0.value.as_slice(),
            &DOMAIN_NONE,
            &HASH_ID_ORIGINAL_FALCON,
            message,
        ) {
            Ok(())
        } else {
            Err(Error::FnDsaError(
                "signature verification failed".to_string(),
            ))
        }
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
    validate_signing_key,
    "a valid signing key"
);
impl_falcon_struct!(
    FalconVerificationKey,
    validate_public_key,
    "a valid public key"
);
impl_falcon_struct!(FalconSignature, validate_signature, "a valid signature");

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

    // Seeded Falcon keygen is deterministic, but the seed→key derivation is implementation
    // specific and not fixed by a published standard. These vectors are the current outputs.
    // On-chain verification does not depend on seeded-keygen reproducibility — only on the
    // standard NIST signature/public-key wire format. Once FIPS-206 (FN-DSA) is published the
    // seed derivation may change and these vectors will need to be regenerated.
    #[cfg(feature = "kgen")]
    #[test]
    fn expected_seed() {
        const SEED: &[u8] = &[1u8; 32];
        let (pk, sk) = FalconScheme::Dsa512.keypair_from_seed(SEED).unwrap();

        assert_eq!(
            &hex::encode(pk.to_raw_bytes()),
            "099e0e1530bdc063a39d69d6f2c43a88908d723703318825bec72bd79824aae2b56557595174c173199eb6491165290ac7726448e04a69abef4184ad5ae8ce9c2ab9fa06b3ed564078ae36dd4df81b9ad906fd5ed04bedba4143472a37ccdd6574a3588be5c49111ee2daafd8488ce991e1c3cbbc6204ce51eeeed400cc72a1b1cdea94e2f9a8f32d631f6542b47bca938cccb10b982f89069132f2e0288894c24ef7796f5f352adb504c95811b59bdc24a49c4199da36b778184470e9e52d0cfaf8288a558944e164f4aa173dfeacbbdb54291d7660a249c473b385514b5080acb0a222c4a152f66d8cf1a978a05404928fa8a9ad4c8965ab31cb439118de353ac604037e4657e93e06d77e0a5e7b9994d6b5a5b9836e58548ad55d690cd2071f71f484a51c3552b87c891c938d0db563884beee23192bd9806ef7245e8bfd886e3fb53d5e778ec69b62c4688a3668806b26a50f9f9e64f7be02da202c291824036327715789742043a54551e5a5df4f639edcfb8927ef970d0067e4887bbb71d0c1d1abd9092d45d6c260f7b2dce0cabd01051a286dbbf4df83488ae9d606cb7eb0adb8a33dc0a96148f65b538c6b6588fb5060867269c1ebd662cad92636b75a3545f090823d0416a1885c0ef48797dc7b3dfc82470d80ca28d172a4a81218b925cd669b6b0d272e83718c0b1b1f39bee3c4c57f8eb2bcd296998152d6ab06c78c522c70127a4b4e811bf99579f7ae1fa9c429287769c6414e62a2b965e96cfa509afb288995e56d670f89ca88248864c167a24becc341d08f9b2e4ab5a5e31c924a4564973badf8a5f485a2961f6294f451b5ebdfac0c36053831a72708d242b5fe6088782e18d593e05fb20c8680ae91f7b741d0a9242e0178a897171a8b0d0700995af34d8b74d4995174c90e524a2301201dbc7e7526e5c5add93ca8d3b95a4afd7fe9b362f91cf39fb8c0dbe8211a534ec523b9e63961b9242bcb17b0aa5a4cd2706d0ebd31a09030ab8a966685471305700e4a2ea15461f25b659e8ae6807faf5a6f0878aca7120e74c3ee2ef26495a338e016c678729dc78ec6c2080128a4bec76b88288046a1098d820d0bf13417b638ec0afac8900169951fe01297177d2eaf733aeae625cdfe1a685d3474ae902251e6f93480c4d80d0d24b100c6a54eda4a5852fbd63e6d0d1991f9b9f4240019b1f7ab9b19b76090138a17c8d315d9ec4a54ecaf55a48923c628343f5005c83e8ab71b70f389b0c1750a35b2b"
        );
        assert_eq!(
            &hex::encode(sk.to_raw_bytes()),
            "59f84e80f7e0040c2efef3d0c213bf3c082083f4108008807e20307eebef0207e0fd242fbf084ebc08a000f0603f187f8213f0b81bcf7e10207ef44ffe13ef84e7ef8603f17e0c1fbe07de87f49e7c006fc307f0bc0c20c3f40ffaebf1fdfc314513b081f3d07fdfd23f24407d07e082003f3efbaf7ef3a0040be03d17e1bc0b4f8003a046003d7ff040ff0fd08007a0400c3fc60bc084fc000303bfc71be03be3e1bb17f0b8fbbd7bfc00c1e79f82f080bafbb002f3d040ffc042e3bfbed8003eec804207e004104081f471841b9f7ef01fbf0c2f83f7f18313a0410ff0071fe049088f84084106fc61bbf04fbd03df3efbef7b03eefb17c27e0c2eff07f17cf7ff80f4003d084e7e0c20faef90050f9e43042f7dfbef8817d0c9f4413f00507f00017ddc30fdf811810c1fc3e00202143f3be00f04102142fc3ffff41f41dc5fbf005002ebf042e7cdbbec61c310607bfc11410bb18110404813bf041f917cf3cec70c4ffd13df3e17dfc0f0417cfc11b517eebc006f460bf13b07fe830830ff04307e0c01fbfc6fc00c1f890baec5efdefe148f4100217ff39002046fbfebef7f1c7e8213effc0810b90fcfc1ff9ec20bd040037f7b0022c90c0103ec0d80fbfff9042082ffcec1fc60c2fc203df3cffef3df3c17bf83083fffe87f7e106041efb03c003efce0518307b0b90befbf1c1fc5185fbd0fdebd08107fe430c5f00fc3183dc5100179e38f800ba07d0000c103c00607b1bffbdfbf0860fce08f02ec3f89000202ffb082f0507ef02185000103084082e850c700207c13f03c145efe0821f7ec8100000e420bdf431400be039ff6e81dc814004207af02e42044082fb9ec4e04e7e08010af3dfbff7efc303c0bef0003907b043fff0fef851830791bc04327bfbcfc5080141f3f0880bf1021000c70bafbe000180fff0fe002040081f4313bffb17c102ec1ec6f4908004203607f039e48f00082f810071bf006f83fbff80e46ffb04c1001c40c40fff4317debe041f3f0411800800c013c007040f440c2e82f47ebf0400baec10c0f40e810c123e1c200013f07c17df7afc1042df906fef319d1e836f60ff111fb0ff21fe219fffb0d1eea1ae508f5ef071f0cd3e601edfdf50d13dad9f60add212225f8fcf8131e0e202ac4f32d0810f7f9ecbb020705ef061c1d1ee3023245ffdb22f9271e0f20d9f7e80b0e0b05e61acee21221110dff07c922e501f6eaedf5efd3e70e33272923fa00e10401eaf000000dc8ecd7f713e30c25dbf0e2f2bcf31907bede0bed2e282513f00c270ef4fd36e2f6eaf3082938190e250405f21df6d212f107f8072203fb0dfbf9f215fcf2e5dc0c0708e6f9f6ede8c20c0e1a0604f6d6000e15f0f81b06d90ef130f8dfcd00f81cfb0adfdcdc3b3f230328dbe2e9fcfb0217f2f9e6f5f5f10e1004b9f6370ef5fe0cec0e2d20e21b25ddf4df252d1430201d231a200eddf3d311f1ecf717ecede4eb2ae0150fe6f2d40c0b2c2227fdfe2606dc2b2b2205c0fe100de7f3001535e1cffb1c12f92a06d7ff01f9c5f121fd013506e20fe7f41fe5e2e3e900f3e3100816d1e9d912edf613e2e3ed08fb1d53312f1af9f9f11a1eee1ae3fff32a18ff160cfcee11e731eaf1edfef7262c1410cd14f12ae30d09f2edfb0de709fc0a15d801290900fc07f7bd2dd2cbd3eddfff02030adf23cbfddc1a25f0ecddca01011ce8e02df6f309db04fc200de314f1eb231015da20f8f3081414f0fec91ff01f12d302f4051f330e0be122040ae412fffcccf61ccc3c162be1f2f9fb19f21df8f4f7"
        );
    }

    #[test]
    fn seed_boundaries() {
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[]).is_err());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 31]).is_err());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 32]).is_ok());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 33]).is_ok());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 48]).is_ok());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 64]).is_ok());
        assert!(FalconScheme::Dsa512.keypair_from_seed(&[1u8; 65]).is_err());
        assert!(FalconScheme::Dsa1024.keypair_from_seed(&[1u8; 31]).is_err());
        assert!(FalconScheme::Dsa1024.keypair_from_seed(&[1u8; 64]).is_ok());
        assert!(FalconScheme::Dsa1024.keypair_from_seed(&[1u8; 65]).is_err());
    }
}
