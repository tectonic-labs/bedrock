//! HQC keypair derivation for the hybrid HD wallet.
//!
//! The BIP-85 scheme root is expanded into a hardened SLIP-0010 keychain using a
//! parameter-set-specific domain separator. The resulting 32-byte child key is passed
//! directly to HQC deterministic key generation.

use crate::hhd::kems::{self, HQC_HARDENED_BASE_PATH, HQC_KEY_GENERATION_SEED_SIZE};
use crate::hhd::keys::KeyError;
use crate::hhd::slip10::{Slip10, Slip10XPrvKey};
use crate::kem::{KemDecapsulationKey, KemEncapsulationKey, KemScheme};
use bip32::secp256k1::ecdsa::SigningKey;
use zeroize::Zeroize;

pub(crate) fn derive_hqc_keypair(
    scheme: KemScheme,
    seed: &[u8],
    address_index: u32,
) -> Result<(KemEncapsulationKey, KemDecapsulationKey), KeyError> {
    kems::ensure_hhd_supported(scheme)
        .map_err(|error| KeyError::KeyGenerationFailed(error.to_string()))?;

    let derivation_path = format!("{HQC_HARDENED_BASE_PATH}/{address_index}'").parse()?;
    let child_xprv: Slip10XPrvKey<SigningKey> =
        Slip10::derive_kem_from_path(seed, &derivation_path, scheme)?;
    let mut child_key = child_xprv.private_key_bytes();

    debug_assert_eq!(child_key.len(), HQC_KEY_GENERATION_SEED_SIZE);
    let keypair = scheme
        .keypair_from_seed(&child_key)
        .map_err(|error| KeyError::KeyGenerationFailed(error.to_string()));
    child_key.zeroize();

    keypair
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rstest::rstest;

    const TEST_ROOT_SEED: [u8; kems::HQC_ROOT_SEED_SIZE] = [0x5a; kems::HQC_ROOT_SEED_SIZE];

    #[rstest]
    #[case::hqc128(KemScheme::Hqc128)]
    #[case::hqc192(KemScheme::Hqc192)]
    #[case::hqc256(KemScheme::Hqc256)]
    fn hqc_derivation_is_deterministic(#[case] scheme: KemScheme) {
        let first = derive_hqc_keypair(scheme, &TEST_ROOT_SEED, 7).unwrap();
        let second = derive_hqc_keypair(scheme, &TEST_ROOT_SEED, 7).unwrap();

        assert_eq!(first.0.to_raw_bytes(), second.0.to_raw_bytes());
        assert_eq!(first.1.to_raw_bytes(), second.1.to_raw_bytes());
        assert_eq!(first.0.scheme(), scheme);
        assert_eq!(first.1.scheme(), scheme);
    }

    #[rstest]
    #[case::hqc128(KemScheme::Hqc128)]
    #[case::hqc192(KemScheme::Hqc192)]
    #[case::hqc256(KemScheme::Hqc256)]
    fn hqc_derivation_uses_the_full_slip10_child_key(#[case] scheme: KemScheme) {
        let address_index = 3;
        let derived = derive_hqc_keypair(scheme, &TEST_ROOT_SEED, address_index).unwrap();
        let path = format!("{HQC_HARDENED_BASE_PATH}/{address_index}'")
            .parse()
            .unwrap();
        let child_xprv: Slip10XPrvKey<SigningKey> =
            Slip10::derive_kem_from_path(TEST_ROOT_SEED, &path, scheme).unwrap();
        let child_key = child_xprv.private_key_bytes();
        let direct = scheme.keypair_from_seed(&child_key).unwrap();

        assert_eq!(child_key.len(), HQC_KEY_GENERATION_SEED_SIZE);
        assert_eq!(derived.0.to_raw_bytes(), direct.0.to_raw_bytes());
        assert_eq!(derived.1.to_raw_bytes(), direct.1.to_raw_bytes());
    }

    #[test]
    fn different_address_indices_produce_different_keys() {
        let first = derive_hqc_keypair(KemScheme::Hqc128, &TEST_ROOT_SEED, 0).unwrap();
        let second = derive_hqc_keypair(KemScheme::Hqc128, &TEST_ROOT_SEED, 1).unwrap();

        assert_ne!(first.0.to_raw_bytes(), second.0.to_raw_bytes());
        assert_ne!(first.1.to_raw_bytes(), second.1.to_raw_bytes());
    }
}
