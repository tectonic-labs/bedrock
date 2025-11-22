//! Key generation methods for ETHFALCON

use super::*;

use fn_dsa_comm::{FN_DSA_LOGN_512, sign_key_size, vrfy_key_size};
use fn_dsa_kgen::{KeyPairGenerator, KeyPairGeneratorStandard};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

/// Generate a keypair from a given seed
pub fn keygen_from_seed(seed: &[u8]) -> (EthFalconVerifyingKey, EthFalconSigningKey) {
    let mut sk = [0u8; sign_key_size(FN_DSA_LOGN_512)];
    let mut pk = [0u8; vrfy_key_size(FN_DSA_LOGN_512)];

    let mut kg = KeyPairGeneratorStandard::default();
    kg.keygen_from_seed(FN_DSA_LOGN_512, seed, &mut sk, &mut pk);
    (pk, sk)
}

/// Generate a keypair from a given seed
pub fn keygen_random() -> (EthFalconVerifyingKey, EthFalconSigningKey) {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut sk = [0u8; sign_key_size(FN_DSA_LOGN_512)];
    let mut pk = [0u8; vrfy_key_size(FN_DSA_LOGN_512)];

    let mut kg = KeyPairGeneratorStandard::default();
    kg.keygen(FN_DSA_LOGN_512, &mut rng, &mut sk, &mut pk);
    (pk, sk)
}
