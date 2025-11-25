#![allow(missing_docs)]

use bedrock::falcon::FalconScheme;
use pqcrypto::sign::falconpadded512;
use pqcrypto::traits::sign::{DetachedSignature, PublicKey, SecretKey};

#[test]
fn pqcrypto_to_bedrock_compatibility_512() {
    const MSG: &[u8] = &[0u8; 8];
    const FALCON_SCHEME: FalconScheme = FalconScheme::Dsa512;

    let (pk, sk) = falconpadded512::keypair();
    let sig = falconpadded512::detached_sign(&MSG, &sk);

    let res = bedrock::falcon::FalconSigningKey::from_raw_bytes(sk.as_bytes());
    assert!(res.is_ok());
    let res = bedrock::falcon::FalconVerificationKey::from_raw_bytes(pk.as_bytes());
    assert!(res.is_ok());
    let bedrock_pk = res.unwrap();
    let res = bedrock::falcon::FalconSignature::from_raw_bytes(sig.as_bytes());
    assert!(res.is_ok());

    let bedrock_sig = res.unwrap();
    let res = FALCON_SCHEME.verify(MSG, &bedrock_sig, &bedrock_pk);
    assert!(res.is_ok());
}

#[test]
fn bedrock_to_pqcrypto_compatibility_512() {
    const MSG: &[u8] = &[0u8; 8];
    const FALCON_SCHEME: FalconScheme = FalconScheme::Dsa512;

    let (pk, sk) = FALCON_SCHEME.keypair().unwrap();
    let sig = FALCON_SCHEME.sign(&MSG, &sk).unwrap();

    let res = falconpadded512::SecretKey::from_bytes(&sk.to_raw_bytes());
    assert!(res.is_ok());
    let res = falconpadded512::PublicKey::from_bytes(&pk.to_raw_bytes());
    assert!(res.is_ok());
    let pqpk = res.unwrap();
    let res = falconpadded512::DetachedSignature::from_bytes(&sig.to_raw_bytes());
    assert!(res.is_ok());
    let pqsig = res.unwrap();

    let res = falconpadded512::verify_detached_signature(&pqsig, MSG, &pqpk);
    assert!(res.is_ok());
}
