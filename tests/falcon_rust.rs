#![allow(missing_docs)]

use bedrock::falcon::FalconScheme;
use falcon_rust::falcon512;
use rand::{Rng, SeedableRng};

#[ignore]
#[test]
fn falcon_rust_to_bedrock_512_compatibility() {
    const MSG: &[u8] = &[0u8; 8];
    const FALCON_SCHEME: FalconScheme = FalconScheme::Dsa512;
    const SEED: [u8; 32] = [3u8; 32];

    let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
    let (sk, pk) = falcon512::keygen(rng.r#gen());
    let sig = falcon512::sign(MSG, &sk);

    let res = bedrock::falcon::FalconSigningKey::from_raw_bytes(&sk.to_bytes());
    assert!(res.is_ok());
    let res = bedrock::falcon::FalconVerificationKey::from_raw_bytes(&pk.to_bytes());
    assert!(res.is_ok());
    let bedrock_pk = res.unwrap();
    let res = bedrock::falcon::FalconSignature::from_raw_bytes(&sig.to_bytes());
    assert!(res.is_ok());
    let bedrock_sig = res.unwrap();

    let res = FALCON_SCHEME.verify(MSG, &bedrock_sig, &bedrock_pk);
    assert!(res.is_ok());
}
