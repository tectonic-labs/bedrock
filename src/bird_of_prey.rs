//! Bird-of-Prey-2 hybrid signature combiner.
//!
//! Combines Ed25519, treated as a Fiat-Shamir identification scheme with
//! unique responses, with a post-quantum signature (ML-DSA-65 or FN-DSA-512),
//! following the strong-unforgeability-preserving construction of "Bird of
//! Prey" (ePrint 2025/1844) and Section 4 of `draft-prabel-cfrg-suf-hybrid-sigs`.
//!
//! The Ed25519 commitment `R` is recovered at verification
//! (`R = rsp*B - chl*A`) rather than transmitted, so the classical part of the
//! signature is a single 32-byte scalar instead of a full 64-byte EdDSA
//! signature. The classical component is serialized first in both keys and
//! signatures.
//!
//! Bedrock defines seeded hybrid key generation, which Keystone does not:
//! `ed_seed = SHA512("BoP2-seed-ed25519" || master)[..32]` and
//! `pq_seed = SHA512("BoP2-seed-pq" || master)[..32]`. Unseeded key generation
//! draws 32 random bytes and routes through the same path.
//!
//! The ML-DSA-65 branch intentionally uses Bedrock's deterministic
//! `MlDsaScheme::Dsa65.sign` directly and does not use the DRBG. The FN-DSA-512
//! branch intentionally uses `HASH_ID_RAW` for byte identity with Keystone's
//! internal combiner signature format.

use crate::det_rng::DetRng;
use crate::error::{Error, Result};
use crate::ml_dsa::{MlDsaScheme, MlDsaSignature, MlDsaSigningKey, MlDsaVerificationKey};
use crate::{deserialize_hex_or_bin, os_rng, serialize_hex_or_bin};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::EdwardsPoint;
use fn_dsa_comm::{sign_key_size, signature_size, vrfy_key_size, DOMAIN_NONE, HASH_ID_RAW};
#[cfg(feature = "kgen")]
use fn_dsa_kgen::{KeyPairGenerator, KeyPairGeneratorStandard};
#[cfg(feature = "sign")]
use fn_dsa_sign::{SigningKey, SigningKeyStandard};
#[cfg(feature = "vrfy")]
use fn_dsa_vrfy::{VerifyingKey, VerifyingKeyStandard};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

const PREFIX: &[u8] = b"SUFHybridSignature2025";
const DOM_COMMIT: &[u8] = b"BoP2-commit";
const TAG1: &[u8] = &[0x01];
const TAG2: &[u8] = &[0x02];
const LABEL_MLDSA65: &[u8] = b"Ed25519MLDSA65";
const LABEL_FNDSA512: &[u8] = b"Ed25519FNDSA512";
const ED_PK_LEN: usize = 32;
const RSP_LEN: usize = 32;
const HYBRID_SK_HEADER_LEN: usize = 36;
const SEED_LEN: usize = 32;
const FN_DSA_LOGN: u32 = 9;
const DET_DOMAIN: &[u8] = b"keystone-fn-dsa-deterministic-v1";
const ED_SEED_DOMAIN: &[u8] = b"BoP2-seed-ed25519";
const PQ_SEED_DOMAIN: &[u8] = b"BoP2-seed-pq";

// ML-DSA-65 fixed sizes from FIPS 204, as exposed by Bedrock's `ml_dsa` wrapper.
const ML_DSA_65_PK_LEN: usize = 1952;
const ML_DSA_65_SK_LEN: usize = 4032;
const ML_DSA_65_SIG_LEN: usize = 3309;

macro_rules! impl_bird_of_prey_struct {
    ($name:ident, $validate:ident) => {
        #[derive(Clone, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A byte-backed [`", stringify!($name), "`] value for the Bird-of-Prey-2 combiner.")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerBirdOfPrey);

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

        impl From<InnerBirdOfPrey> for $name {
            fn from(inner: InnerBirdOfPrey) -> Self {
                Self(inner)
            }
        }

        impl $name {
            /// Returns the [`BirdOfPreyScheme`] represented by this value.
            pub fn scheme(&self) -> BirdOfPreyScheme {
                self.0.scheme
            }

            /// Converts this value to its raw byte representation.
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            /// Constructs this wrapper from raw bytes and an explicit scheme.
            pub fn from_raw_bytes(scheme: BirdOfPreyScheme, bytes: &[u8]) -> Result<Self> {
                scheme.$validate(bytes)?;
                Ok(InnerBirdOfPrey {
                    scheme,
                    value: bytes.to_vec(),
                }
                .into())
            }
        }
    };
}

scheme_impl_pure!(
    /// Supported Bird-of-Prey-2 combiner variants.
    BirdOfPreyScheme,
    #[default]
    /// Ed25519 combined with ML-DSA-65.
    Ed25519MlDsa65 => "Ed25519-ML-DSA-65" ; 1 ; 32,
    /// Ed25519 combined with FN-DSA-512.
    Ed25519FnDsa512 => "Ed25519-FN-DSA-512" ; 2 ; 32,
);

serde_impl!(BirdOfPreyScheme);

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerBirdOfPrey {
    scheme: BirdOfPreyScheme,
    #[serde(
        serialize_with = "serialize_hex_or_bin",
        deserialize_with = "deserialize_hex_or_bin"
    )]
    value: Vec<u8>,
}

impl core::fmt::Debug for InnerBirdOfPrey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InnerBirdOfPrey")
            .field("scheme", &self.scheme)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl_bird_of_prey_struct!(BirdOfPreySigningKey, validate_signing_key_bytes);
impl_bird_of_prey_struct!(BirdOfPreyVerificationKey, validate_verification_key_bytes);
impl_bird_of_prey_struct!(BirdOfPreySignature, validate_signature_bytes);

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for InnerBirdOfPrey {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for BirdOfPreySigningKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for BirdOfPreySigningKey {}

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn ed25519_expand(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hash = sha512(&[seed]);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&hash[32..]);
    (scalar, prefix)
}

fn ed_scalar(clamped: [u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(clamped)
}

fn message_rep(label: &[u8], pk_ed: &[u8], pk_pq: &[u8], message: &[u8]) -> Vec<u8> {
    let phm = sha512(&[message]);
    let mut rep =
        Vec::with_capacity(PREFIX.len() + label.len() + 1 + pk_ed.len() + pk_pq.len() + phm.len());
    rep.extend_from_slice(PREFIX);
    rep.extend_from_slice(label);
    rep.push(0u8);
    rep.extend_from_slice(pk_ed);
    rep.extend_from_slice(pk_pq);
    rep.extend_from_slice(&phm);
    rep
}

fn split_hybrid_secret_key(sk: &[u8]) -> Result<(&[u8], &[u8])> {
    if sk.len() < HYBRID_SK_HEADER_LEN {
        return Err(Error::BirdOfPreyError(
            "hybrid secret key too short".to_string(),
        ));
    }
    let pk_len_bytes: [u8; 4] = sk[SEED_LEN..HYBRID_SK_HEADER_LEN]
        .try_into()
        .map_err(|_| Error::BirdOfPreyError("hybrid secret key malformed".to_string()))?;
    let pk_len = u32::from_le_bytes(pk_len_bytes) as usize;
    let rest = &sk[HYBRID_SK_HEADER_LEN..];
    if rest.len() < pk_len {
        return Err(Error::BirdOfPreyError(
            "hybrid secret key malformed".to_string(),
        ));
    }
    Ok(rest.split_at(pk_len))
}

fn derive_seed(domain: &[u8], master: &[u8]) -> [u8; SEED_LEN] {
    let hash = sha512(&[domain, master]);
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&hash[..SEED_LEN]);
    seed
}

impl BirdOfPreyScheme {
    fn ensure_scheme(self, actual: Self) -> Result<()> {
        if actual == self {
            Ok(())
        } else {
            Err(Error::SchemeMismatch {
                expected: self.to_string(),
                actual: actual.to_string(),
            })
        }
    }

    fn pq_sizes(self) -> (usize, usize, usize) {
        match self {
            Self::Ed25519MlDsa65 => (ML_DSA_65_PK_LEN, ML_DSA_65_SK_LEN, ML_DSA_65_SIG_LEN),
            Self::Ed25519FnDsa512 => (
                vrfy_key_size(FN_DSA_LOGN),
                sign_key_size(FN_DSA_LOGN),
                signature_size(FN_DSA_LOGN),
            ),
        }
    }

    fn label(self) -> &'static [u8] {
        match self {
            Self::Ed25519MlDsa65 => LABEL_MLDSA65,
            Self::Ed25519FnDsa512 => LABEL_FNDSA512,
        }
    }
}

#[cfg(feature = "kgen")]
impl BirdOfPreyScheme {
    fn keypair_from_seed_inner(
        self,
        seed: &[u8],
    ) -> Result<(BirdOfPreyVerificationKey, BirdOfPreySigningKey)> {
        if seed.len() != SEED_LEN {
            return Err(Error::InvalidSeedLength(seed.len()));
        }

        let ed_seed = derive_seed(ED_SEED_DOMAIN, seed);
        let pq_seed = derive_seed(PQ_SEED_DOMAIN, seed);
        let (s_clamped, _) = ed25519_expand(&ed_seed);
        let a = EdwardsPoint::mul_base(&ed_scalar(s_clamped));
        let pk_ed = a.compress().to_bytes();

        let (pk_pq, sk_pq) = match self {
            Self::Ed25519MlDsa65 => {
                let (vk, sk) = MlDsaScheme::Dsa65.keypair_from_seed(&pq_seed)?;
                (vk.to_raw_bytes(), sk.to_raw_bytes())
            }
            Self::Ed25519FnDsa512 => {
                let mut generator = KeyPairGeneratorStandard::default();
                let mut sk = vec![0u8; sign_key_size(FN_DSA_LOGN)];
                let mut vk = vec![0u8; vrfy_key_size(FN_DSA_LOGN)];
                generator.keygen_from_seed(FN_DSA_LOGN, &pq_seed, &mut sk, &mut vk);
                (vk, sk)
            }
        };

        let mut public_key = Vec::with_capacity(ED_PK_LEN + pk_pq.len());
        public_key.extend_from_slice(&pk_ed);
        public_key.extend_from_slice(&pk_pq);

        let mut secret_key = Vec::with_capacity(SEED_LEN + 4 + pk_pq.len() + sk_pq.len());
        secret_key.extend_from_slice(&ed_seed);
        secret_key.extend_from_slice(&(pk_pq.len() as u32).to_le_bytes());
        secret_key.extend_from_slice(&pk_pq);
        secret_key.extend_from_slice(&sk_pq);

        Ok((
            BirdOfPreyVerificationKey::from_raw_bytes(self, &public_key)?,
            BirdOfPreySigningKey::from_raw_bytes(self, &secret_key)?,
        ))
    }
}

#[cfg(feature = "sign")]
fn sign_with_mldsa(sk: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let (pk_pq, sk_pq) = split_hybrid_secret_key(sk)?;
    let seed = &sk[..SEED_LEN];
    let (s_clamped, prefix) = ed25519_expand(seed);
    let s = ed_scalar(s_clamped);
    let pk_ed = EdwardsPoint::mul_base(&s).compress().to_bytes();

    let mprime = message_rep(LABEL_MLDSA65, &pk_ed, pk_pq, message);
    let r = Scalar::from_bytes_mod_order_wide(&sha512(&[DOM_COMMIT, &prefix, &mprime]));
    let com = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let mpp = sha512(&[TAG1, &mprime, &com]);

    // ML-DSA signing here is already deterministic under FIPS 204 with an empty context,
    // so the extra DRBG used by the FN-DSA path is unnecessary.
    let pq_signing_key = MlDsaSigningKey::from_raw_bytes(MlDsaScheme::Dsa65, sk_pq)?;
    let s2 = MlDsaScheme::Dsa65
        .sign(&mpp, &pq_signing_key)?
        .to_raw_bytes();

    let chl = Scalar::from_bytes_mod_order_wide(&sha512(&[TAG2, &s2]));
    let rsp = r + chl * s;

    let mut sig = Vec::with_capacity(RSP_LEN + s2.len());
    sig.extend_from_slice(&rsp.to_bytes());
    sig.extend_from_slice(&s2);
    Ok(sig)
}

#[cfg(feature = "sign")]
fn sign_with_fndsa(sk: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let (pk_pq, sk_pq) = split_hybrid_secret_key(sk)?;
    let seed = &sk[..SEED_LEN];
    let (s_clamped, prefix) = ed25519_expand(seed);
    let s = ed_scalar(s_clamped);
    let pk_ed = EdwardsPoint::mul_base(&s).compress().to_bytes();

    let mprime = message_rep(LABEL_FNDSA512, &pk_ed, pk_pq, message);
    let r = Scalar::from_bytes_mod_order_wide(&sha512(&[DOM_COMMIT, &prefix, &mprime]));
    let com = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let mpp = sha512(&[TAG1, &mprime, &com]);

    let mut signing_key = SigningKeyStandard::decode(sk_pq)
        .ok_or_else(|| Error::BirdOfPreyError("failed to decode FN-DSA signing key".to_string()))?;
    let mut s2 = vec![0u8; signature_size(signing_key.get_logn())];
    let mut rng = DetRng::new(DET_DOMAIN, sk_pq, &mpp)?;
    // This inner PQ signature is only used inside the combiner, never through
    // FalconScheme::verify, so HASH_ID_RAW is required for byte identity with Keystone.
    signing_key.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, &mpp, &mut s2);

    let chl = Scalar::from_bytes_mod_order_wide(&sha512(&[TAG2, &s2]));
    let rsp = r + chl * s;

    let mut sig = Vec::with_capacity(RSP_LEN + s2.len());
    sig.extend_from_slice(&rsp.to_bytes());
    sig.extend_from_slice(&s2);
    Ok(sig)
}

#[cfg(feature = "vrfy")]
impl BirdOfPreyScheme {
    fn verify_inner(self, pk: &[u8], message: &[u8], sig: &[u8]) -> Result<()> {
        if pk.len() < ED_PK_LEN || sig.len() < RSP_LEN {
            return Err(Error::BirdOfPreyError(
                "hybrid public key or signature too short".to_string(),
            ));
        }

        let pk_ed = &pk[..ED_PK_LEN];
        let pk_pq = &pk[ED_PK_LEN..];
        let rsp_bytes: [u8; RSP_LEN] = sig[..RSP_LEN]
            .try_into()
            .map_err(|_| Error::BirdOfPreyError("invalid response length".to_string()))?;
        let s2 = &sig[RSP_LEN..];

        let rsp = Option::<Scalar>::from(Scalar::from_canonical_bytes(rsp_bytes))
            .ok_or_else(|| Error::BirdOfPreyError("non-canonical response scalar".to_string()))?;
        let a = CompressedEdwardsY::from_slice(pk_ed)
            .map_err(|_| Error::BirdOfPreyError("invalid Ed25519 public key".to_string()))?
            .decompress()
            .ok_or_else(|| Error::BirdOfPreyError("invalid Ed25519 public key".to_string()))?;

        let chl = Scalar::from_bytes_mod_order_wide(&sha512(&[TAG2, s2]));
        let com = EdwardsPoint::vartime_double_scalar_mul_basepoint(&(-chl), &a, &rsp)
            .compress()
            .to_bytes();

        let mprime = message_rep(self.label(), pk_ed, pk_pq, message);
        let mpp = sha512(&[TAG1, &mprime, &com]);

        match self {
            Self::Ed25519MlDsa65 => {
                let pq_key = MlDsaVerificationKey::from_raw_bytes(MlDsaScheme::Dsa65, pk_pq)?;
                let pq_sig = MlDsaSignature::from_raw_bytes(MlDsaScheme::Dsa65, s2)?;
                MlDsaScheme::Dsa65.verify(&mpp, &pq_sig, &pq_key)
            }
            Self::Ed25519FnDsa512 => {
                let verifying_key = VerifyingKeyStandard::decode(pk_pq).ok_or_else(|| {
                    Error::BirdOfPreyError("failed to decode FN-DSA verification key".to_string())
                })?;
                // This inner PQ signature is only used inside the combiner, never through
                // FalconScheme::verify, so HASH_ID_RAW is required for byte identity with Keystone.
                if verifying_key.verify(s2, &DOMAIN_NONE, &HASH_ID_RAW, &mpp) {
                    Ok(())
                } else {
                    Err(Error::BirdOfPreyError(
                        "FN-DSA verification failed".to_string(),
                    ))
                }
            }
        }
    }
}

impl BirdOfPreyScheme {
    /// Validates the raw bytes of a Bird-of-Prey verification key for this scheme.
    fn validate_verification_key_bytes(&self, bytes: &[u8]) -> Result<()> {
        let (pq_pk_len, _, _) = self.pq_sizes();
        let expected = ED_PK_LEN + pq_pk_len;
        if bytes.len() == expected {
            Ok(())
        } else {
            Err(Error::InvalidLength(bytes.len()))
        }
    }

    /// Validates the raw bytes of a Bird-of-Prey signing key for this scheme.
    fn validate_signing_key_bytes(&self, bytes: &[u8]) -> Result<()> {
        let (pq_pk_len, pq_sk_len, _) = self.pq_sizes();
        let expected = SEED_LEN + 4 + pq_pk_len + pq_sk_len;
        if bytes.len() == expected {
            Ok(())
        } else {
            Err(Error::InvalidLength(bytes.len()))
        }
    }

    /// Validates the raw bytes of a Bird-of-Prey signature for this scheme.
    fn validate_signature_bytes(&self, bytes: &[u8]) -> Result<()> {
        let (_, _, pq_sig_len) = self.pq_sizes();
        let expected = RSP_LEN + pq_sig_len;
        if bytes.len() == expected {
            Ok(())
        } else {
            Err(Error::InvalidLength(bytes.len()))
        }
    }

    /// Generates a fresh Bird-of-Prey keypair for this scheme.
    #[cfg(feature = "kgen")]
    pub fn keypair(&self) -> Result<(BirdOfPreyVerificationKey, BirdOfPreySigningKey)> {
        let mut seed = [0u8; SEED_LEN];
        let mut rng = os_rng();
        rand_core_010::Rng::fill_bytes(&mut rng, &mut seed);
        self.keypair_from_seed(&seed)
    }

    /// Generates a deterministic Bird-of-Prey keypair for this scheme from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn keypair_from_seed(
        &self,
        seed: &[u8],
    ) -> Result<(BirdOfPreyVerificationKey, BirdOfPreySigningKey)> {
        self.keypair_from_seed_inner(seed)
    }

    /// Signs a message with a Bird-of-Prey signing key for this scheme.
    #[cfg(feature = "sign")]
    pub fn sign(
        &self,
        message: &[u8],
        signing_key: &BirdOfPreySigningKey,
    ) -> Result<BirdOfPreySignature> {
        self.ensure_scheme(signing_key.0.scheme)?;

        let signature = match self {
            BirdOfPreyScheme::Ed25519MlDsa65 => sign_with_mldsa(&signing_key.0.value, message)?,
            BirdOfPreyScheme::Ed25519FnDsa512 => sign_with_fndsa(&signing_key.0.value, message)?,
        };
        BirdOfPreySignature::from_raw_bytes(*self, &signature)
    }

    /// Verifies a Bird-of-Prey signature for this scheme.
    #[cfg(feature = "vrfy")]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &BirdOfPreySignature,
        verification_key: &BirdOfPreyVerificationKey,
    ) -> Result<()> {
        self.ensure_scheme(verification_key.0.scheme)?;
        self.ensure_scheme(signature.0.scheme)?;

        self.verify_inner(&verification_key.0.value, message, &signature.0.value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    fn sample_seed(tag: u8) -> [u8; SEED_LEN] {
        [tag; SEED_LEN]
    }

    fn expected_sig_len(scheme: BirdOfPreyScheme) -> usize {
        let (_, _, pq_sig_len) = scheme.pq_sizes();
        RSP_LEN + pq_sig_len
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn signature_verifies(#[case] scheme: BirdOfPreyScheme) {
        let (vk, sk) = scheme.keypair_from_seed(&sample_seed(1)).unwrap();
        let sig = scheme.sign(b"message", &sk).unwrap();
        scheme.verify(b"message", &sig, &vk).unwrap();
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn tampered_message_fails(#[case] scheme: BirdOfPreyScheme) {
        let (vk, sk) = scheme.keypair_from_seed(&sample_seed(2)).unwrap();
        let sig = scheme.sign(b"message", &sk).unwrap();
        assert!(scheme.verify(b"message2", &sig, &vk).is_err());
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn tampered_classical_half_fails(#[case] scheme: BirdOfPreyScheme) {
        let (vk, sk) = scheme.keypair_from_seed(&sample_seed(3)).unwrap();
        let mut raw = scheme.sign(b"message", &sk).unwrap().to_raw_bytes();
        raw[0] ^= 0x01;
        let sig = BirdOfPreySignature::from_raw_bytes(scheme, &raw).unwrap();
        assert!(scheme.verify(b"message", &sig, &vk).is_err());
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn tampered_pq_half_fails(#[case] scheme: BirdOfPreyScheme) {
        let (vk, sk) = scheme.keypair_from_seed(&sample_seed(4)).unwrap();
        let mut raw = scheme.sign(b"message", &sk).unwrap().to_raw_bytes();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let sig = BirdOfPreySignature::from_raw_bytes(scheme, &raw).unwrap();
        assert!(scheme.verify(b"message", &sig, &vk).is_err());
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn classical_component_is_32_bytes(#[case] scheme: BirdOfPreyScheme) {
        let (_, sk) = scheme.keypair_from_seed(&sample_seed(5)).unwrap();
        let sig = scheme.sign(b"message", &sk).unwrap();
        assert_eq!(sig.as_ref().len(), expected_sig_len(scheme));
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn deterministic_signing(#[case] scheme: BirdOfPreyScheme) {
        let (_, sk) = scheme.keypair_from_seed(&sample_seed(6)).unwrap();
        let sig1 = scheme.sign(b"message", &sk).unwrap();
        let sig2 = scheme.sign(b"message", &sk).unwrap();
        let sig3 = scheme.sign(b"message-2", &sk).unwrap();
        assert_eq!(sig1, sig2);
        assert_ne!(sig1, sig3);
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn signature_rejects_other_public_key(#[case] scheme: BirdOfPreyScheme) {
        let (vk1, sk1) = scheme.keypair_from_seed(&sample_seed(7)).unwrap();
        let (vk2, _) = scheme.keypair_from_seed(&sample_seed(8)).unwrap();
        let sig = scheme.sign(b"message", &sk1).unwrap();
        scheme.verify(b"message", &sig, &vk1).unwrap();
        assert!(scheme.verify(b"message", &sig, &vk2).is_err());
    }

    #[test]
    fn cross_scheme_sign_guards() {
        let (_, ml_sk) = BirdOfPreyScheme::Ed25519MlDsa65
            .keypair_from_seed(&sample_seed(9))
            .unwrap();
        let (_, fn_sk) = BirdOfPreyScheme::Ed25519FnDsa512
            .keypair_from_seed(&sample_seed(10))
            .unwrap();

        assert!(matches!(
            BirdOfPreyScheme::Ed25519FnDsa512.sign(b"message", &ml_sk),
            Err(Error::SchemeMismatch { .. })
        ));
        assert!(matches!(
            BirdOfPreyScheme::Ed25519MlDsa65.sign(b"message", &fn_sk),
            Err(Error::SchemeMismatch { .. })
        ));
    }

    #[test]
    fn cross_scheme_verify_guards() {
        let (ml_vk, ml_sk) = BirdOfPreyScheme::Ed25519MlDsa65
            .keypair_from_seed(&sample_seed(11))
            .unwrap();
        let (fn_vk, fn_sk) = BirdOfPreyScheme::Ed25519FnDsa512
            .keypair_from_seed(&sample_seed(12))
            .unwrap();
        let ml_sig = BirdOfPreyScheme::Ed25519MlDsa65
            .sign(b"message", &ml_sk)
            .unwrap();
        let fn_sig = BirdOfPreyScheme::Ed25519FnDsa512
            .sign(b"message", &fn_sk)
            .unwrap();

        assert!(matches!(
            BirdOfPreyScheme::Ed25519FnDsa512.verify(b"message", &ml_sig, &fn_vk),
            Err(Error::SchemeMismatch { .. })
        ));
        assert!(matches!(
            BirdOfPreyScheme::Ed25519MlDsa65.verify(b"message", &fn_sig, &ml_vk),
            Err(Error::SchemeMismatch { .. })
        ));
        assert!(matches!(
            BirdOfPreyScheme::Ed25519MlDsa65.verify(b"message", &ml_sig, &fn_vk),
            Err(Error::SchemeMismatch { .. })
        ));
        assert!(matches!(
            BirdOfPreyScheme::Ed25519FnDsa512.verify(b"message", &fn_sig, &ml_vk),
            Err(Error::SchemeMismatch { .. })
        ));
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn seeded_keygen_is_deterministic(#[case] scheme: BirdOfPreyScheme) {
        let seed = sample_seed(13);
        let (vk1, sk1) = scheme.keypair_from_seed(&seed).unwrap();
        let (vk2, sk2) = scheme.keypair_from_seed(&seed).unwrap();
        assert_eq!(vk1, vk2);
        assert_eq!(sk1, sk2);
        assert!(matches!(
            scheme.keypair_from_seed(&seed[..SEED_LEN - 1]),
            Err(Error::InvalidSeedLength(31))
        ));
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn serde_roundtrip_wrappers(#[case] scheme: BirdOfPreyScheme) {
        let (vk, sk) = scheme.keypair_from_seed(&sample_seed(14)).unwrap();
        let sig = scheme.sign(b"message", &sk).unwrap();

        let sk_postcard = postcard::to_stdvec(&sk).unwrap();
        let vk_postcard = postcard::to_stdvec(&vk).unwrap();
        let sig_postcard = postcard::to_stdvec(&sig).unwrap();
        assert_eq!(
            postcard::from_bytes::<BirdOfPreySigningKey>(&sk_postcard).unwrap(),
            sk
        );
        assert_eq!(
            postcard::from_bytes::<BirdOfPreyVerificationKey>(&vk_postcard).unwrap(),
            vk
        );
        assert_eq!(
            postcard::from_bytes::<BirdOfPreySignature>(&sig_postcard).unwrap(),
            sig
        );

        let sk_json = serde_json::to_string(&sk).unwrap();
        let vk_json = serde_json::to_string(&vk).unwrap();
        let sig_json = serde_json::to_string(&sig).unwrap();
        assert_eq!(
            serde_json::from_str::<BirdOfPreySigningKey>(&sk_json).unwrap(),
            sk
        );
        assert_eq!(
            serde_json::from_str::<BirdOfPreyVerificationKey>(&vk_json).unwrap(),
            vk
        );
        assert_eq!(
            serde_json::from_str::<BirdOfPreySignature>(&sig_json).unwrap(),
            sig
        );
    }

    #[rstest]
    #[case(BirdOfPreyScheme::Ed25519MlDsa65)]
    #[case(BirdOfPreyScheme::Ed25519FnDsa512)]
    fn from_raw_bytes_rejects_wrong_lengths(#[case] scheme: BirdOfPreyScheme) {
        let (pq_pk_len, pq_sk_len, pq_sig_len) = scheme.pq_sizes();

        assert!(matches!(
            BirdOfPreyVerificationKey::from_raw_bytes(
                scheme,
                &vec![0u8; ED_PK_LEN + pq_pk_len - 1]
            ),
            Err(Error::InvalidLength(_))
        ));
        assert!(matches!(
            BirdOfPreySigningKey::from_raw_bytes(
                scheme,
                &vec![0u8; SEED_LEN + 4 + pq_pk_len + pq_sk_len - 1]
            ),
            Err(Error::InvalidLength(_))
        ));
        assert!(matches!(
            BirdOfPreySignature::from_raw_bytes(scheme, &vec![0u8; RSP_LEN + pq_sig_len - 1]),
            Err(Error::InvalidLength(_))
        ));
    }

    #[test]
    fn scheme_enum_roundtrips_and_rejects_unknowns() {
        for scheme in [
            BirdOfPreyScheme::Ed25519MlDsa65,
            BirdOfPreyScheme::Ed25519FnDsa512,
        ] {
            let byte = u8::from(scheme);
            assert_eq!(BirdOfPreyScheme::try_from(byte).unwrap(), scheme);

            let display = scheme.to_string();
            assert_eq!(BirdOfPreyScheme::from_str(&display).unwrap(), scheme);
        }

        assert!(BirdOfPreyScheme::try_from(99u8).is_err());
        assert!(BirdOfPreyScheme::from_str("unknown-scheme").is_err());
    }
}
