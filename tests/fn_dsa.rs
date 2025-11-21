//! Tests for compatibility of crate `fn_dsa`

use bedrock::falcon::FalconScheme;
use fn_dsa::{
    DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW, KeyPairGenerator, KeyPairGeneratorStandard,
    SigningKey, SigningKeyStandard, VerifyingKey, VerifyingKeyStandard,
};
use rand::SeedableRng;

// Doesn't work yet
#[ignore]
#[test]
fn fn_dsa_to_bedrock_compatibility_512() {
    const MSG: &[u8] = &[0u8; 8];
    const SEED: [u8; 32] = [3u8; 32];
    const FALCON_SCHEME: FalconScheme = FalconScheme::Dsa512;

    let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sk = [0u8; fn_dsa::sign_key_size(FN_DSA_LOGN_512)];
    let mut pk = [0u8; fn_dsa::vrfy_key_size(FN_DSA_LOGN_512)];
    kg.keygen(FN_DSA_LOGN_512, &mut rng, &mut sk, &mut pk);

    let mut sign_key = SigningKeyStandard::decode(&sk).unwrap();
    let mut sig = [0u8; fn_dsa::signature_size(FN_DSA_LOGN_512)];

    sign_key.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, MSG, &mut sig);

    let res = bedrock::falcon::FalconSigningKey::from_raw_bytes(&sk[..]);
    assert!(res.is_ok());
    let res = bedrock::falcon::FalconVerificationKey::from_raw_bytes(&pk[..]);
    assert!(res.is_ok());
    let bedrock_pk = res.unwrap();
    let res = bedrock::falcon::FalconSignature::from_raw_bytes(&sig[..]);
    assert!(res.is_ok());
    let bedrock_sig = res.unwrap();

    assert!(
        FALCON_SCHEME
            .verify(&MSG, &bedrock_sig, &bedrock_pk)
            .is_ok()
    );
}

// Doesn't work yet
#[ignore]
#[test]
fn bedrock_to_fn_dsa_compatibility_512() {
    const MSG: &[u8] = &[0u8; 8];
    const SEED: [u8; 32] = [3u8; 32];
    const FALCON_SCHEME: FalconScheme = FalconScheme::Dsa512;

    let (pk, sk) = FALCON_SCHEME.keypair().unwrap();
    let sig = FALCON_SCHEME.sign(&MSG, &sk).unwrap();

    let vrfy_key = VerifyingKeyStandard::decode(&pk.to_raw_bytes()).unwrap();

    let res = vrfy_key.verify(&sig.to_raw_bytes(), &DOMAIN_NONE, &HASH_ID_RAW, &MSG);
    assert!(res);
}
