//! ML-DSA key and signature methods.

use crate::error::*;
#[cfg(any(feature = "kgen", feature = "sign"))]
use crate::os_rng;
use serde::{Deserialize, Serialize};

macro_rules! impl_ml_dsa_struct {
    ($name:ident, $validate:ident, $expect:expr, $($multiformat:tt)+) => {
        #[derive(Clone)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A byte-backed [`", stringify!($name), "`] value for ML-DSA.")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerMlDsa);

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

        impl From<InnerMlDsa> for $name {
            fn from(inner: InnerMlDsa) -> Self {
                Self(inner)
            }
        }

        impl $name {
            /// Returns the [`MlDsaScheme`] represented by this value.
            pub fn scheme(&self) -> MlDsaScheme {
                self.0.scheme
            }

            #[doc = concat!("Converts [`", stringify!($name), "`] to its raw byte representation.")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = concat!("Constructs [`", stringify!($name), "`] from raw bytes and a scheme.")]
            pub fn from_raw_bytes(scheme: MlDsaScheme, bytes: &[u8]) -> Result<Self> {
                scheme.$validate(bytes)?;
                Ok(InnerMlDsa {
                    scheme,
                    value: bytes.to_vec(),
                }
                .into())
            }
        }

        raw_bytes_impl!($name, MlDsaScheme);
        #[cfg(feature = "multiformats")]
        $($multiformat)+;
    };
}

scheme_impl_pure!(
    /// ML-DSA schemes.
    MlDsaScheme,
    /// ML-DSA-44 (NIST Level 2).
    #[deprecated(since = "0.3.0", note = "use ML-DSA-65 or a stronger parameter set")]
    Dsa44 => "ML-DSA-44" ; 1 ; 32,
    #[default]
    /// ML-DSA-65 (NIST Level 3).
    Dsa65 => "ML-DSA-65" ; 2 ; 32,
    /// ML-DSA-87 (NIST Level 5).
    Dsa87 => "ML-DSA-87" ; 3 ; 32,
);

serde_impl!(MlDsaScheme);

// Signing keys use identity: bedrock stores the expanded FIPS 204 key, and the ML-DSA
// private-key multicodecs hold the 32-byte seed.
#[cfg(feature = "multiformats")]
multicodec_table!(MlDsaScheme {
    Dsa65, PublicKey => MlDsa65Pub;
    Dsa65, Signature => MlDsa65Msig;
    Dsa87, PublicKey => MlDsa87Pub;
    Dsa87, Signature => MlDsa87Msig;
});

/// Dispatch a block generic over the concrete `ml_dsa` parameter type `$P` for each scheme.
macro_rules! with_ml_dsa_params {
    ($scheme:expr, |$P:ident| $body:block) => {
        match $scheme {
            MlDsaScheme::Dsa44 => {
                type $P = ml_dsa::MlDsa44;
                $body
            }
            MlDsaScheme::Dsa65 => {
                type $P = ml_dsa::MlDsa65;
                $body
            }
            MlDsaScheme::Dsa87 => {
                type $P = ml_dsa::MlDsa87;
                $body
            }
        }
    };
}

/// Maximum FIPS 204 context-string length in bytes (the length is encoded in one byte).
const MAX_CONTEXT_LEN: usize = 255;

/// Rejects a FIPS 204 context string longer than [`MAX_CONTEXT_LEN`] bytes.
fn check_context(context: &[u8]) -> Result<()> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(Error::MlDsaError(format!(
            "context must be at most {MAX_CONTEXT_LEN} bytes, got {}",
            context.len()
        )));
    }
    Ok(())
}

impl MlDsaScheme {
    /// Validates a verification (public) key encoding for this scheme.
    fn validate_public_key(&self, bytes: &[u8]) -> Result<()> {
        with_ml_dsa_params!(self, |P| {
            use ml_dsa::EncodedVerifyingKey;
            EncodedVerifyingKey::<P>::try_from(bytes)
                .map_err(|_| Error::MlDsaError("an invalid public key".to_string()))?;
            Ok(())
        })
    }

    /// Validates a signing (secret) key encoding for this scheme (expanded FIPS 204 form).
    fn validate_signing_key(&self, bytes: &[u8]) -> Result<()> {
        with_ml_dsa_params!(self, |P| {
            use ml_dsa::ExpandedSigningKeyBytes;
            ExpandedSigningKeyBytes::<P>::try_from(bytes)
                .map_err(|_| Error::MlDsaError("an invalid signing key".to_string()))?;
            Ok(())
        })
    }

    /// Validates a signature encoding for this scheme.
    fn validate_signature(&self, bytes: &[u8]) -> Result<()> {
        with_ml_dsa_params!(self, |P| {
            ml_dsa::Signature::<P>::try_from(bytes)
                .map_err(|_| Error::MlDsaError("an invalid signature".to_string()))?;
            Ok(())
        })
    }

    #[cfg(feature = "kgen")]
    /// Generates a new ML-DSA verification and signing keypair.
    // `to_expanded` is deprecated upstream in favor of the seed form, but the wire format is the
    // expanded key, so we keep using it.
    #[allow(deprecated)]
    pub fn keypair(&self) -> Result<(MlDsaVerificationKey, MlDsaSigningKey)> {
        use ml_dsa::{Generate, SigningKey, signature::Keypair};
        with_ml_dsa_params!(self, |P| {
            let sk = SigningKey::<P>::try_generate_from_rng(&mut os_rng())
                .map_err(|_| Error::MlDsaError("ML-DSA key generation failed".to_string()))?;
            Ok(self.pack_keypair(
                sk.verifying_key().encode().to_vec(),
                sk.expanded_key().to_expanded().to_vec(),
            ))
        })
    }

    #[cfg(feature = "kgen")]
    /// Generates a new ML-DSA verification and signing keypair from a 32-byte seed (FIPS 204 ξ).
    #[allow(deprecated)]
    pub fn keypair_from_seed(
        &self,
        seed: &[u8],
    ) -> Result<(MlDsaVerificationKey, MlDsaSigningKey)> {
        if seed.len() != self.seed_size() {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        use ml_dsa::{B32, SigningKey, signature::Keypair};
        with_ml_dsa_params!(self, |P| {
            let xi = B32::try_from(seed).map_err(|_| Error::InvalidSeedLength(seed.len()))?;
            let sk = SigningKey::<P>::from_seed(&xi);
            Ok(self.pack_keypair(
                sk.verifying_key().encode().to_vec(),
                sk.expanded_key().to_expanded().to_vec(),
            ))
        })
    }

    #[cfg(feature = "kgen")]
    /// Packs raw verification and signing key bytes into Bedrock's byte-backed key types.
    fn pack_keypair(&self, vk: Vec<u8>, sk: Vec<u8>) -> (MlDsaVerificationKey, MlDsaSigningKey) {
        (
            InnerMlDsa {
                scheme: *self,
                value: vk,
            }
            .into(),
            InnerMlDsa {
                scheme: *self,
                value: sk,
            }
            .into(),
        )
    }

    #[cfg(feature = "sign")]
    /// Signs a message with the specified signing key (deterministic, empty context).
    ///
    /// Equivalent to [`MlDsaScheme::sign_with_context`] with an empty context.
    pub fn sign(&self, message: &[u8], signing_key: &MlDsaSigningKey) -> Result<MlDsaSignature> {
        self.sign_with_context(message, &[], signing_key)
    }

    #[cfg(feature = "sign")]
    /// Signs a message under a FIPS 204 context string (deterministic).
    ///
    /// The `context` is the optional context parameter of ML-DSA.Sign in FIPS 204
    /// (Algorithm 2): it is bound into the signed message representative, so a
    /// signature only verifies under the same context. It may be at most 255 bytes;
    /// a longer context returns [`Error::MlDsaError`]. An empty context yields
    /// exactly the bytes [`MlDsaScheme::sign`] produces.
    #[allow(deprecated)]
    pub fn sign_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signing_key: &MlDsaSigningKey,
    ) -> Result<MlDsaSignature> {
        use ml_dsa::{ExpandedSigningKey, ExpandedSigningKeyBytes};
        check_context(context)?;
        with_ml_dsa_params!(self, |P| {
            let enc = ExpandedSigningKeyBytes::<P>::try_from(signing_key.0.value.as_slice())
                .map_err(|_| Error::MlDsaError("an invalid signing key".to_string()))?;
            let sk = ExpandedSigningKey::<P>::from_expanded(&enc);
            let signature = sk
                .sign_deterministic(message, context)
                .map_err(|e| Error::MlDsaError(e.to_string()))?;
            Ok(InnerMlDsa {
                scheme: *self,
                value: signature.encode().to_vec(),
            }
            .into())
        })
    }

    #[cfg(feature = "sign")]
    /// Signs a message with the specified signing key using the FIPS 204 hedged
    /// (randomized) variant with an empty context, drawing fresh randomness per call.
    ///
    /// Prefer this over [`MlDsaScheme::sign`] wherever the signer may be exposed to
    /// fault or side-channel adversaries: deterministic ML-DSA lets a single induced
    /// fault over a known message recover the signing key, and lets a side-channel
    /// attacker replay the identical secret-dependent computation. The signature is a
    /// valid ML-DSA signature verifiable by [`MlDsaScheme::verify`]; only the signing
    /// randomness differs, so two calls over the same message produce different bytes.
    ///
    /// Equivalent to [`MlDsaScheme::sign_randomized_with_context`] with an empty context.
    pub fn sign_randomized(
        &self,
        message: &[u8],
        signing_key: &MlDsaSigningKey,
    ) -> Result<MlDsaSignature> {
        self.sign_randomized_with_context(message, &[], signing_key)
    }

    #[cfg(feature = "sign")]
    /// Signs a message under a FIPS 204 context string using the hedged (randomized)
    /// variant, drawing fresh randomness per call.
    ///
    /// The `context` is the optional context parameter of ML-DSA.Sign in FIPS 204
    /// (Algorithm 2); see [`MlDsaScheme::sign_with_context`] for its semantics and the
    /// 255-byte limit. See [`MlDsaScheme::sign_randomized`] for why hedged signing is
    /// preferred where the signer may face fault or side-channel adversaries. The result
    /// verifies with [`MlDsaScheme::verify_with_context`] under the same context.
    #[allow(deprecated)]
    pub fn sign_randomized_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signing_key: &MlDsaSigningKey,
    ) -> Result<MlDsaSignature> {
        use ml_dsa::{ExpandedSigningKey, ExpandedSigningKeyBytes};
        check_context(context)?;
        with_ml_dsa_params!(self, |P| {
            let enc = ExpandedSigningKeyBytes::<P>::try_from(signing_key.0.value.as_slice())
                .map_err(|_| Error::MlDsaError("an invalid signing key".to_string()))?;
            let sk = ExpandedSigningKey::<P>::from_expanded(&enc);
            let signature = sk
                .sign_randomized(message, context, &mut os_rng())
                .map_err(|e| Error::MlDsaError(e.to_string()))?;
            Ok(InnerMlDsa {
                scheme: *self,
                value: signature.encode().to_vec(),
            }
            .into())
        })
    }

    #[cfg(feature = "vrfy")]
    /// Verifies a signature (empty context).
    ///
    /// Equivalent to [`MlDsaScheme::verify_with_context`] with an empty context.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &MlDsaSignature,
        verification_key: &MlDsaVerificationKey,
    ) -> Result<()> {
        self.verify_with_context(message, &[], signature, verification_key)
    }

    #[cfg(feature = "vrfy")]
    /// Verifies a signature under a FIPS 204 context string.
    ///
    /// The `context` is the optional context parameter of ML-DSA.Verify in FIPS 204
    /// (Algorithm 3) and must equal the one used when signing. It may be at most 255
    /// bytes; a longer context returns [`Error::MlDsaError`] rather than a plain
    /// verification failure.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &MlDsaSignature,
        verification_key: &MlDsaVerificationKey,
    ) -> Result<()> {
        use ml_dsa::{EncodedVerifyingKey, Signature, VerifyingKey};
        check_context(context)?;
        with_ml_dsa_params!(self, |P| {
            let enc = EncodedVerifyingKey::<P>::try_from(verification_key.0.value.as_slice())
                .map_err(|_| Error::MlDsaError("an invalid public key".to_string()))?;
            let vk = VerifyingKey::<P>::decode(&enc);
            let sig = Signature::<P>::try_from(signature.0.value.as_slice())
                .map_err(|_| Error::MlDsaError("an invalid signature".to_string()))?;
            if vk.verify_with_context(message, context, &sig) {
                Ok(())
            } else {
                Err(Error::MlDsaError(
                    "signature verification failed".to_string(),
                ))
            }
        })
    }
}

impl_ml_dsa_struct!(
    MlDsaSigningKey,
    validate_signing_key,
    "a valid signing key",
    multikey_impl!(MlDsaSigningKey, SecretKey)
);

impl_ml_dsa_struct!(
    MlDsaVerificationKey,
    validate_public_key,
    "a valid public key",
    multikey_impl!(MlDsaVerificationKey, PublicKey)
);

impl_ml_dsa_struct!(
    MlDsaSignature,
    validate_signature,
    "a valid signature",
    multisig_impl!(MlDsaSignature)
);

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerMlDsa {
    scheme: MlDsaScheme,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    value: Vec<u8>,
}

impl std::fmt::Debug for InnerMlDsa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerMlDsa")
            .field("scheme", &self.scheme)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for InnerMlDsa {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for MlDsaSigningKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for MlDsaSigningKey {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rstest::*;

    #[cfg(all(feature = "multiformats", feature = "kgen", feature = "sign"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn serdes(#[case] scheme: MlDsaScheme) {
        let (pk, sk) = scheme.keypair().unwrap();

        let bytes = postcard::to_stdvec(&sk).unwrap();
        let sk2 = postcard::from_bytes::<MlDsaSigningKey>(&bytes).unwrap();
        assert_eq!(sk, sk2);

        let string = serde_json::to_string(&sk).unwrap();
        let sk2 = serde_json::from_str::<MlDsaSigningKey>(&string).unwrap();
        assert_eq!(sk, sk2);

        let bytes = postcard::to_stdvec(&pk).unwrap();
        let pk2 = postcard::from_bytes::<MlDsaVerificationKey>(&bytes).unwrap();
        assert_eq!(pk, pk2);

        let string = serde_json::to_string(&pk).unwrap();
        let pk2 = serde_json::from_str::<MlDsaVerificationKey>(&string).unwrap();
        assert_eq!(pk, pk2);

        let msg = [0u8; 8];
        let sig = sk.0.scheme.sign(&msg, &sk).unwrap();

        let bytes = postcard::to_stdvec(&sig).unwrap();
        let sig2 = postcard::from_bytes::<MlDsaSignature>(&bytes).unwrap();
        assert_eq!(sig, sig2);

        let string = serde_json::to_string(&sig).unwrap();
        let sig2 = serde_json::from_str::<MlDsaSignature>(&string).unwrap();
        assert_eq!(sig, sig2);
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn flow(#[case] scheme: MlDsaScheme) {
        const MSG: &[u8] = &[0u8; 8];
        let (pk, sk) = scheme.keypair().unwrap();

        let signature = sk.0.scheme.sign(MSG, &sk).unwrap();
        let res = pk.0.scheme.verify(MSG, &signature, &pk);
        assert!(res.is_ok());

        let res = pk.0.scheme.verify(&[1u8; 8], &signature, &pk);
        assert!(res.is_err());
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn hedged_flow(#[case] scheme: MlDsaScheme) {
        const MSG: &[u8] = &[0u8; 8];
        let (pk, sk) = scheme.keypair().unwrap();

        // A hedged signature verifies like any valid ML-DSA signature.
        let signature = sk.0.scheme.sign_randomized(MSG, &sk).unwrap();
        assert!(pk.0.scheme.verify(MSG, &signature, &pk).is_ok());
        assert!(pk.0.scheme.verify(&[1u8; 8], &signature, &pk).is_err());

        // Two hedged signatures over the same message differ (fresh randomness per
        // call) — the property deterministic signing lacked. Both still verify.
        let signature2 = sk.0.scheme.sign_randomized(MSG, &sk).unwrap();
        assert_ne!(signature.as_ref(), signature2.as_ref());
        assert!(pk.0.scheme.verify(MSG, &signature2, &pk).is_ok());

        // The deterministic path remains deterministic (unchanged for other callers).
        let det1 = sk.0.scheme.sign(MSG, &sk).unwrap();
        let det2 = sk.0.scheme.sign(MSG, &sk).unwrap();
        assert_eq!(det1.as_ref(), det2.as_ref());
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn context_flow(#[case] scheme: MlDsaScheme) {
        const MSG: &[u8] = &[0u8; 8];
        const CTX: &[u8] = b"warden/genesis/v1";
        let (pk, sk) = scheme.keypair().unwrap();

        for sign in [
            MlDsaScheme::sign_with_context,
            MlDsaScheme::sign_randomized_with_context,
        ] {
            let sig = sign(&scheme, MSG, CTX, &sk).unwrap();
            assert!(scheme.verify_with_context(MSG, CTX, &sig, &pk).is_ok());
            assert!(
                scheme
                    .verify_with_context(MSG, b"other-context", &sig, &pk)
                    .is_err()
            );
            assert!(scheme.verify_with_context(MSG, &[], &sig, &pk).is_err());
            assert!(scheme.verify(MSG, &sig, &pk).is_err());
            assert!(
                scheme
                    .verify_with_context(&[1u8; 8], CTX, &sig, &pk)
                    .is_err()
            );
        }
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn empty_context_is_backward_compatible(#[case] scheme: MlDsaScheme) {
        const MSG: &[u8] = &[0u8; 8];
        let (pk, sk) = scheme.keypair().unwrap();

        let sig = scheme.sign(MSG, &sk).unwrap();
        assert!(scheme.verify(MSG, &sig, &pk).is_ok());
        assert!(scheme.verify_with_context(MSG, &[], &sig, &pk).is_ok());

        // Deterministic signing with an empty context is byte-identical to `sign`.
        let sig_ctx = scheme.sign_with_context(MSG, &[], &sk).unwrap();
        assert_eq!(sig.as_ref(), sig_ctx.as_ref());

        // Hedged signing with an empty context verifies under `verify`.
        let hedged = scheme.sign_randomized_with_context(MSG, &[], &sk).unwrap();
        assert!(scheme.verify(MSG, &hedged, &pk).is_ok());
        let hedged = scheme.sign_randomized(MSG, &sk).unwrap();
        assert!(scheme.verify_with_context(MSG, &[], &hedged, &pk).is_ok());
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn context_length_limit(#[case] scheme: MlDsaScheme) {
        const MSG: &[u8] = &[0u8; 8];
        let (pk, sk) = scheme.keypair().unwrap();
        let max = [0xA5u8; 255];
        let too_long = [0xA5u8; 256];

        let sig = scheme.sign_with_context(MSG, &max, &sk).unwrap();
        assert!(scheme.verify_with_context(MSG, &max, &sig, &pk).is_ok());
        let sig = scheme.sign_randomized_with_context(MSG, &max, &sk).unwrap();
        assert!(scheme.verify_with_context(MSG, &max, &sig, &pk).is_ok());

        let err = scheme.sign_with_context(MSG, &too_long, &sk).unwrap_err();
        assert!(matches!(&err, Error::MlDsaError(m) if m.contains("at most 255 bytes, got 256")));
        assert!(
            scheme
                .sign_randomized_with_context(MSG, &too_long, &sk)
                .is_err()
        );
        let err = scheme
            .verify_with_context(MSG, &too_long, &sig, &pk)
            .unwrap_err();
        assert!(matches!(&err, Error::MlDsaError(m) if m.contains("at most 255 bytes, got 256")));
    }

    #[cfg(all(feature = "kgen", feature = "sign", feature = "vrfy"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44, 1312, 2560, 2420)]
    #[case::mldsa65(MlDsaScheme::Dsa65, 1952, 4032, 3309)]
    #[case::mldsa87(MlDsaScheme::Dsa87, 2592, 4896, 4627)]
    fn fixed_sizes(
        #[case] scheme: MlDsaScheme,
        #[case] pk_len: usize,
        #[case] sk_len: usize,
        #[case] sig_len: usize,
    ) {
        let (pk, sk) = scheme.keypair().unwrap();
        assert_eq!(pk.to_raw_bytes().len(), pk_len);
        assert_eq!(sk.to_raw_bytes().len(), sk_len);
        let sig = scheme.sign(&[0u8; 8], &sk).unwrap();
        assert_eq!(sig.to_raw_bytes().len(), sig_len);
    }

    #[cfg(feature = "kgen")]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn seed_determinism(#[case] scheme: MlDsaScheme) {
        let seed = [7u8; 32];
        let (pk1, sk1) = scheme.keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = scheme.keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1.as_ref(), pk2.as_ref());
        assert_eq!(sk1.as_ref(), sk2.as_ref());
        assert!(scheme.keypair_from_seed(&[0u8; 31]).is_err());
    }

    /// The deprecated ML-DSA-44 scheme remains compatible with its wire discriminant and name.
    #[test]
    fn ml_dsa_44_is_deprecated() {
        assert!(matches!(MlDsaScheme::try_from(1), Ok(MlDsaScheme::Dsa44)));
        assert!(matches!("ML-DSA-44".parse(), Ok(MlDsaScheme::Dsa44)));
    }

    #[cfg(all(feature = "kgen", feature = "sign"))]
    #[rstest]
    #[case::mldsa44(MlDsaScheme::Dsa44)]
    #[case::mldsa65(MlDsaScheme::Dsa65)]
    #[case::mldsa87(MlDsaScheme::Dsa87)]
    fn plain_encoding_is_unchanged(#[case] scheme: MlDsaScheme) {
        let (pk, sk) = scheme.keypair().unwrap();
        crate::test_utils::assert_plain_compatible(&pk, &pk.0);
        crate::test_utils::assert_plain_compatible(&sk, &sk.0);
        let sig = scheme.sign(b"bedrock", &sk).unwrap();
        crate::test_utils::assert_plain_compatible(&sig, &sig.0);
    }

    #[cfg(all(feature = "multiformats", feature = "kgen", feature = "sign"))]
    #[rstest]
    #[case::mldsa44(
        MlDsaScheme::Dsa44,
        crate::multiformats::Codec::Identity,
        crate::multiformats::Codec::Identity,
        crate::multiformats::Codec::Identity
    )]
    #[case::mldsa65(
        MlDsaScheme::Dsa65,
        crate::multiformats::Codec::MlDsa65Pub,
        crate::multiformats::Codec::Identity,
        crate::multiformats::Codec::MlDsa65Msig
    )]
    #[case::mldsa87(
        MlDsaScheme::Dsa87,
        crate::multiformats::Codec::MlDsa87Pub,
        crate::multiformats::Codec::Identity,
        crate::multiformats::Codec::MlDsa87Msig
    )]
    fn multiformat_encoding(
        #[case] scheme: MlDsaScheme,
        #[case] public: crate::multiformats::Codec,
        #[case] secret: crate::multiformats::Codec,
        #[case] signature: crate::multiformats::Codec,
    ) {
        use crate::{multiformats::Multikey, test_utils::*};
        let (pk, sk) = scheme.keypair().unwrap();
        assert_multikey(&pk, public);
        assert_multikey(&sk, secret);
        // a key never decodes as the other half of its pair
        assert!(MlDsaSigningKey::try_from(&Multikey::try_from(&pk).unwrap()).is_err());
        assert!(MlDsaVerificationKey::try_from(&Multikey::try_from(&sk).unwrap()).is_err());
        let sig = scheme.sign(b"bedrock", &sk).unwrap();
        assert_multisig(&sig, signature);
    }

    #[cfg(feature = "multiformats")]
    #[test]
    fn multicodec_table_is_invertible() {
        use crate::multiformats::{Role, SchemeCodec};
        for scheme in [MlDsaScheme::Dsa44, MlDsaScheme::Dsa65, MlDsaScheme::Dsa87] {
            for role in [Role::PublicKey, Role::SecretKey, Role::Signature] {
                if let Some(codec) = scheme.codec(role) {
                    assert_eq!(MlDsaScheme::from_codec(codec, role), Some(scheme));
                }
            }
        }
    }
}
