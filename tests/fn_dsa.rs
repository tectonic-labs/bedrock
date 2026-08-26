#![allow(missing_docs)]

use fn_dsa::{
    DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW, KeyPairGenerator, KeyPairGeneratorStandard,
    SigningKey, SigningKeyStandard, VerifyingKey, VerifyingKeyStandard,
};
#[cfg(feature = "falcon")]
use fn_dsa_comm::{CryptoRng, RngCore, RngError, signature_size};
#[cfg(feature = "falcon")]
use rand::{Rng as Rng10, SeedableRng};
#[cfg(feature = "falcon")]
use tectonic_bedrock::falcon::{FalconScheme, FalconSigningKey, FalconVerificationKey};

/// Adapts the Rand 0.10 ChaCha implementation to FN-DSA 0.3's rand_core 0.6
/// trait boundary without retaining rand_chacha 0.3 as a direct dependency.
#[cfg(feature = "falcon")]
struct FnDsaRng(rand_chacha::ChaCha8Rng);

#[cfg(feature = "falcon")]
impl FnDsaRng {
    fn from_seed(seed: [u8; 32]) -> Self {
        Self(rand_chacha::ChaCha8Rng::from_seed(seed))
    }
}

#[cfg(feature = "falcon")]
impl RngCore for FnDsaRng {
    fn next_u32(&mut self) -> u32 {
        Rng10::next_u32(&mut self.0)
    }

    fn next_u64(&mut self) -> u64 {
        Rng10::next_u64(&mut self.0)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Rng10::fill_bytes(&mut self.0, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(feature = "falcon")]
impl CryptoRng for FnDsaRng {}

#[cfg(all(feature = "eth_falcon", feature = "sign", feature = "vrfy"))]
#[test]
#[allow(clippy::unwrap_used)]
fn fn_dsa_to_eth_falcon_compatibility() {
    const MSG: &[u8] = &[0u8; 8];
    const SEED: [u8; 32] = [3u8; 32];
    const FALCON_SCHEME: FalconScheme = FalconScheme::Ethereum;

    let mut kg = KeyPairGeneratorStandard::default();
    let mut sk = [0u8; fn_dsa::sign_key_size(FN_DSA_LOGN_512)];
    let mut pk = [0u8; fn_dsa::vrfy_key_size(FN_DSA_LOGN_512)];
    kg.keygen_from_seed(FN_DSA_LOGN_512, &SEED, &mut sk, &mut pk);

    let eth_sk = FalconSigningKey::from_raw_bytes(FALCON_SCHEME, &sk).unwrap();
    let eth_pk = FalconVerificationKey::from_raw_bytes(FALCON_SCHEME, &pk).unwrap();

    let signature = FALCON_SCHEME.sign(MSG, &eth_sk).unwrap();

    assert!(FALCON_SCHEME.verify(MSG, &signature, &eth_pk).is_ok());
}

#[cfg(all(feature = "falcon", feature = "sign", feature = "vrfy"))]
#[test]
#[allow(clippy::unwrap_used)]
fn fn_dsa_to_bedrock_compatibility_512() {
    const MSG: &[u8] = &[0u8; 8];
    const SEED: [u8; 32] = [3u8; 32];
    const FALCON_SCHEME: FalconScheme = FalconScheme::Dsa512;

    let mut rng = FnDsaRng::from_seed(SEED);
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sk = [0u8; fn_dsa::sign_key_size(FN_DSA_LOGN_512)];
    let mut pk = [0u8; fn_dsa::vrfy_key_size(FN_DSA_LOGN_512)];
    kg.keygen(FN_DSA_LOGN_512, &mut rng, &mut sk, &mut pk);

    let res = FalconSigningKey::from_raw_bytes(FALCON_SCHEME, &sk[..]);
    assert!(res.is_ok());
    let bedrock_sk = res.unwrap();
    let res = FalconVerificationKey::from_raw_bytes(FALCON_SCHEME, &pk[..]);
    assert!(res.is_ok());
    let bedrock_pk = res.unwrap();
    let res = FALCON_SCHEME.sign(MSG, &bedrock_sk);
    assert!(res.is_ok());
    let bedrock_sig = res.unwrap();

    assert!(FALCON_SCHEME.verify(MSG, &bedrock_sig, &bedrock_pk).is_ok());
}

#[cfg(feature = "falcon")]
#[test]
#[allow(clippy::unwrap_used)]
fn bedrock_to_fn_dsa_compatibility_512() {
    const MSG: &[u8] = &[0u8; 8];
    const FALCON_SCHEME: FalconScheme = FalconScheme::Dsa512;

    let (pk, sk) = FALCON_SCHEME.keypair().unwrap();

    let res = SigningKeyStandard::decode(sk.as_ref());
    assert!(res.is_some());
    let mut fn_sk = res.unwrap();
    let mut signature = [0u8; signature_size(FN_DSA_LOGN_512)];

    let mut rng = FnDsaRng::from_seed([3u8; 32]);
    fn_sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, MSG, &mut signature);

    let res = VerifyingKeyStandard::decode(pk.as_ref());
    assert!(res.is_some());
    let fn_pk = res.unwrap();

    let res = fn_pk.verify(&signature, &DOMAIN_NONE, &HASH_ID_RAW, MSG);
    assert!(res);
}
