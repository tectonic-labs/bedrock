//! KEM methods
//! ClassicMcEliece348864
//! ML-KEM are supported

use crate::{deserialize_hex_or_bin, error::*, serialize_hex_or_bin};
use serde::{Deserialize, Serialize};

#[cfg(feature = "mceliece")]
use oqs::kem::{Algorithm, Kem};

macro_rules! impl_kem_struct {
    ($name:ident, $validate:ident) => {

        #[derive(Clone, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A [`", stringify!($name), "`] for kems")]
        #[repr(transparent)]
        pub struct $name(pub(crate) InnerKem);

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

        impl From<InnerKem> for $name {
            fn from(inner: InnerKem) -> Self {
                Self(inner)
            }
        }

        impl $name {
            /// The [`KemScheme`] represented by this struct
            pub fn scheme(&self) -> KemScheme {
                self.0.scheme
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] to its raw byte representation")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = concat!("Convert [`", stringify!($name), "`] from its raw byte representation and scheme")]
            pub fn from_raw_bytes(scheme: KemScheme, bytes: &[u8]) -> Result<Self> {
                scheme.$validate(bytes)?;
                Ok(InnerKem {
                    scheme,
                    value: bytes.to_vec(),
                }.into())
            }
        }
    };
}

scheme_impl_pure!(
    /// KEM schemes
    KemScheme,
    @cfg(feature = "ml-kem")
    #[cfg_attr(feature = "ml-kem", default)]
    /// ML-KEM 512 (NIST Level 1)
    MlKem512 => "ML-KEM-512" ; 1 ; 64,
    @cfg(feature = "ml-kem")
    /// ML-KEM 768 (NIST Level 3)
    MlKem768 => "ML-KEM-768" ; 2 ; 64,
    @cfg(feature = "ml-kem")
    /// ML-KEM 1024 (NIST Level 5)
    MlKem1024 => "ML-KEM-1024" ; 3 ; 64,
    @cfg(feature = "mceliece")
    #[cfg_attr(not(feature = "ml-kem"), default)]
    /// Classic McEliece 348864 (NIST Level 1)
    ClassicMcEliece348864 => "ClassicMcEliece-348864" ; 4 ; 32,
);

serde_impl!(KemScheme);

/// Dispatch a block generic over the concrete `ml_kem` parameter type `$P` for each ML-KEM scheme.
///
/// Only the ML-KEM schemes are handled here; Classic McEliece is dispatched separately via `oqs`.
#[cfg(feature = "ml-kem")]
macro_rules! with_ml_kem_params {
    ($scheme:expr, |$P:ident| $body:block) => {{
        match $scheme {
            KemScheme::MlKem512 => {
                type $P = ml_kem::MlKem512;
                $body
            }
            KemScheme::MlKem768 => {
                type $P = ml_kem::MlKem768;
                $body
            }
            KemScheme::MlKem1024 => {
                type $P = ml_kem::MlKem1024;
                $body
            }
            #[cfg(feature = "mceliece")]
            KemScheme::ClassicMcEliece348864 => unreachable!("McEliece is dispatched via oqs"),
        }
    }};
}

impl KemScheme {
    #[cfg(feature = "kgen")]
    /// Generate a new Key-Encapsulation encapsulating / decapsulating key pair
    pub fn keypair(&self) -> Result<(KemEncapsulationKey, KemDecapsulationKey)> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem512 | KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::KeyExport;
                with_ml_kem_params!(*self, |P| {
                    let (dk, ek) = <P as ml_kem::Kem>::generate_keypair();
                    Ok(self.pack_keypair(ek.to_bytes().to_vec(), dk.to_bytes().to_vec()))
                })
            }
            #[cfg(feature = "mceliece")]
            KemScheme::ClassicMcEliece348864 => {
                let scheme = Kem::new(Algorithm::ClassicMcEliece348864)?;
                let (pk, sk) = scheme.keypair()?;
                Ok(self.pack_keypair(pk.into_vec(), sk.into_vec()))
            }
        }
    }

    #[cfg(feature = "kgen")]
    /// Generate a new Key-Encapsulation encapsulating / decapsulating key pair from a seed
    pub fn keypair_from_seed(
        &self,
        seed: &[u8],
    ) -> Result<(KemEncapsulationKey, KemDecapsulationKey)> {
        if seed.len() != self.seed_size() {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem512 | KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::KeyExport;
                with_ml_kem_params!(*self, |P| {
                    let seed = ml_kem::Seed::try_from(seed)
                        .map_err(|_| Error::InvalidSeedLength(seed.len()))?;
                    let (dk, ek) = <P as ml_kem::FromSeed>::from_seed(&seed);
                    Ok(self.pack_keypair(ek.to_bytes().to_vec(), dk.to_bytes().to_vec()))
                })
            }
            #[cfg(feature = "mceliece")]
            KemScheme::ClassicMcEliece348864 => {
                let scheme = Kem::new(Algorithm::ClassicMcEliece348864)?;
                let seed = scheme
                    .keypair_seed_from_bytes(seed)
                    .ok_or(Error::OqsError("an invalid seed length".to_string()))?;
                let (pk, sk) = scheme.keypair_derand(seed)?;
                Ok(self.pack_keypair(pk.into_vec(), sk.into_vec()))
            }
        }
    }

    #[cfg(feature = "kgen")]
    /// Pack raw encapsulation/decapsulation key bytes into bedrock's byte-backed key types.
    fn pack_keypair(&self, ek: Vec<u8>, dk: Vec<u8>) -> (KemEncapsulationKey, KemDecapsulationKey) {
        (
            InnerKem {
                scheme: *self,
                value: ek,
            }
            .into(),
            InnerKem {
                scheme: *self,
                value: dk,
            }
            .into(),
        )
    }

    #[cfg(feature = "encp")]
    /// Encapsulate to the provided public key
    pub fn encapsulate(
        &self,
        encapsulation_key: &KemEncapsulationKey,
    ) -> Result<(KemCiphertext, KemSharedSecret)> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem512 | KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::{Encapsulate, TryKeyInit};
                with_ml_kem_params!(*self, |P| {
                    let ek = ml_kem::EncapsulationKey::<P>::new_from_slice(
                        encapsulation_key.0.value.as_slice(),
                    )
                    .map_err(|_| Error::MlKemError("an invalid encapsulation key".to_string()))?;
                    let (ct, ss) = ek.encapsulate();
                    Ok((
                        InnerKem {
                            scheme: *self,
                            value: ct.to_vec(),
                        }
                        .into(),
                        InnerKem {
                            scheme: *self,
                            value: ss.to_vec(),
                        }
                        .into(),
                    ))
                })
            }
            #[cfg(feature = "mceliece")]
            KemScheme::ClassicMcEliece348864 => {
                let scheme = Kem::new(Algorithm::ClassicMcEliece348864)?;
                let ek = scheme
                    .public_key_from_bytes(encapsulation_key.0.value.as_slice())
                    .ok_or_else(|| Error::OqsError("an invalid encapsulation key".to_string()))?;
                let (ct, ss) = scheme.encapsulate(ek)?;
                Ok((
                    InnerKem {
                        scheme: *self,
                        value: ct.into_vec(),
                    }
                    .into(),
                    InnerKem {
                        scheme: *self,
                        value: ss.into_vec(),
                    }
                    .into(),
                ))
            }
        }
    }

    #[cfg(feature = "decp")]
    /// Decapsulate the provided ciphertext
    pub fn decapsulate(
        &self,
        ciphertext: &KemCiphertext,
        decapsulation_key: &KemDecapsulationKey,
    ) -> Result<KemSharedSecret> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem512 | KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::{Decapsulate, KeyInit};
                with_ml_kem_params!(*self, |P| {
                    let dk = ml_kem::DecapsulationKey::<P>::new_from_slice(
                        decapsulation_key.0.value.as_slice(),
                    )
                    .map_err(|_| Error::MlKemError("an invalid decapsulation key".to_string()))?;
                    let ss = dk
                        .decapsulate_slice(ciphertext.0.value.as_slice())
                        .map_err(|_| Error::MlKemError("an invalid ciphertext".to_string()))?;
                    Ok(InnerKem {
                        scheme: *self,
                        value: ss.to_vec(),
                    }
                    .into())
                })
            }
            #[cfg(feature = "mceliece")]
            KemScheme::ClassicMcEliece348864 => {
                let scheme = Kem::new(Algorithm::ClassicMcEliece348864)?;
                let ct = scheme
                    .ciphertext_from_bytes(ciphertext.0.value.as_slice())
                    .ok_or_else(|| Error::OqsError("an invalid ciphertext".to_string()))?;
                let sk = scheme
                    .secret_key_from_bytes(decapsulation_key.0.value.as_slice())
                    .ok_or_else(|| Error::OqsError("an invalid decapsulation key".to_string()))?;
                let ss = scheme.decapsulate(sk, ct)?;
                Ok(InnerKem {
                    scheme: *self,
                    value: ss.into_vec(),
                }
                .into())
            }
        }
    }

    /// Validate an encapsulation (public) key encoding for this scheme.
    fn validate_encapsulation_key(&self, bytes: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem512 | KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::TryKeyInit;
                with_ml_kem_params!(*self, |P| {
                    ml_kem::EncapsulationKey::<P>::new_from_slice(bytes).map_err(|_| {
                        Error::MlKemError("an invalid encapsulation key".to_string())
                    })?;
                    Ok(())
                })
            }
            #[cfg(feature = "mceliece")]
            KemScheme::ClassicMcEliece348864 => {
                let scheme = Kem::new(Algorithm::ClassicMcEliece348864)?;
                scheme
                    .public_key_from_bytes(bytes)
                    .ok_or_else(|| Error::OqsError("an invalid encapsulation key".to_string()))?;
                Ok(())
            }
        }
    }

    /// Validate a decapsulation (secret) key encoding for this scheme.
    fn validate_decapsulation_key(&self, bytes: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem512 | KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::KeyInit;
                with_ml_kem_params!(*self, |P| {
                    ml_kem::DecapsulationKey::<P>::new_from_slice(bytes).map_err(|_| {
                        Error::MlKemError("an invalid decapsulation key".to_string())
                    })?;
                    Ok(())
                })
            }
            #[cfg(feature = "mceliece")]
            KemScheme::ClassicMcEliece348864 => {
                let scheme = Kem::new(Algorithm::ClassicMcEliece348864)?;
                scheme
                    .secret_key_from_bytes(bytes)
                    .ok_or_else(|| Error::OqsError("an invalid decapsulation key".to_string()))?;
                Ok(())
            }
        }
    }

    /// Validate a ciphertext encoding for this scheme.
    fn validate_ciphertext(&self, bytes: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem512 | KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                with_ml_kem_params!(*self, |P| {
                    ml_kem::Ciphertext::<P>::try_from(bytes)
                        .map_err(|_| Error::MlKemError("an invalid kem ciphertext".to_string()))?;
                    Ok(())
                })
            }
            #[cfg(feature = "mceliece")]
            KemScheme::ClassicMcEliece348864 => {
                let scheme = Kem::new(Algorithm::ClassicMcEliece348864)?;
                scheme
                    .ciphertext_from_bytes(bytes)
                    .ok_or_else(|| Error::OqsError("an invalid kem ciphertext".to_string()))?;
                Ok(())
            }
        }
    }

    /// Validate a shared secret encoding for this scheme.
    fn validate_shared_secret(&self, bytes: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem512 | KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                if bytes.len() == 32 {
                    Ok(())
                } else {
                    Err(Error::MlKemError("an invalid shared secret".to_string()))
                }
            }
            #[cfg(feature = "mceliece")]
            KemScheme::ClassicMcEliece348864 => {
                let scheme = Kem::new(Algorithm::ClassicMcEliece348864)?;
                scheme
                    .shared_secret_from_bytes(bytes)
                    .ok_or_else(|| Error::OqsError("an invalid shared secret".to_string()))?;
                Ok(())
            }
        }
    }
}

impl_kem_struct!(KemEncapsulationKey, validate_encapsulation_key);
impl_kem_struct!(KemDecapsulationKey, validate_decapsulation_key);
impl_kem_struct!(KemCiphertext, validate_ciphertext);
impl_kem_struct!(KemSharedSecret, validate_shared_secret);

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for KemDecapsulationKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for KemDecapsulationKey {}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for KemSharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for KemSharedSecret {}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct InnerKem {
    scheme: KemScheme,
    #[serde(
        serialize_with = "serialize_hex_or_bin",
        deserialize_with = "deserialize_hex_or_bin"
    )]
    value: Vec<u8>,
}

impl std::fmt::Debug for InnerKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerKem")
            .field("scheme", &self.scheme)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for InnerKem {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rstest::*;

    #[cfg(all(feature = "kgen", feature = "encp"))]
    #[rstest]
    #[cfg_attr(feature = "ml-kem", case::mlkem512(KemScheme::MlKem512))]
    #[cfg_attr(feature = "ml-kem", case::mlkem768(KemScheme::MlKem768))]
    #[cfg_attr(feature = "ml-kem", case::mlkem1024(KemScheme::MlKem1024))]
    #[cfg_attr(feature = "mceliece", case::mceliece(KemScheme::ClassicMcEliece348864))]
    fn serdes(#[case] scheme: KemScheme) {
        let (ek, dk) = scheme.keypair().unwrap();

        let bytes = postcard::to_stdvec(&ek).unwrap();
        let ek2 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ek, ek2);

        let string = serde_json::to_string(&ek).unwrap();
        let ek2 = serde_json::from_str::<KemEncapsulationKey>(&string).unwrap();
        assert_eq!(ek, ek2);

        let bytes = postcard::to_stdvec(&dk).unwrap();
        let dk2 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(dk, dk2);

        let string = serde_json::to_string(&dk).unwrap();
        let dk2 = serde_json::from_str::<KemDecapsulationKey>(&string).unwrap();
        assert_eq!(dk, dk2);

        let (ct, ss) = scheme.encapsulate(&ek).unwrap();

        let bytes = postcard::to_stdvec(&ct).unwrap();
        let ct2 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ct, ct2);

        let string = serde_json::to_string(&ct).unwrap();
        let ct2 = serde_json::from_str::<KemCiphertext>(&string).unwrap();
        assert_eq!(ct, ct2);

        let bytes = postcard::to_stdvec(&ss).unwrap();
        let ss2 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ss, ss2);

        let string = serde_json::to_string(&ss).unwrap();
        let ss2 = serde_json::from_str::<KemSharedSecret>(&string).unwrap();
        assert_eq!(ss, ss2);
    }

    #[cfg(all(feature = "kgen", feature = "encp", feature = "decp"))]
    #[rstest]
    #[cfg_attr(feature = "ml-kem", case::mlkem512(KemScheme::MlKem512))]
    #[cfg_attr(feature = "ml-kem", case::mlkem768(KemScheme::MlKem768))]
    #[cfg_attr(feature = "ml-kem", case::mlkem1024(KemScheme::MlKem1024))]
    #[cfg_attr(feature = "mceliece", case::mceliece(KemScheme::ClassicMcEliece348864))]
    fn flow(#[case] scheme: KemScheme) {
        let (ek, dk) = scheme.keypair().unwrap();

        let (mut ct, ss) = scheme.encapsulate(&ek).unwrap();
        let ss2 = scheme.decapsulate(&ct, &dk).unwrap();
        assert_eq!(ss, ss2);

        ct.0.value.iter_mut().for_each(|v| *v = v.saturating_add(1));
        let ss2 = scheme.decapsulate(&ct, &dk).unwrap();
        assert_ne!(ss, ss2);
    }

    #[cfg(feature = "kgen")]
    #[rstest]
    #[cfg_attr(feature = "ml-kem", case::mlkem512(KemScheme::MlKem512, 64))]
    #[cfg_attr(feature = "ml-kem", case::mlkem768(KemScheme::MlKem768, 64))]
    #[cfg_attr(feature = "ml-kem", case::mlkem1024(KemScheme::MlKem1024, 64))]
    #[cfg_attr(
        feature = "mceliece",
        case::mceliece(KemScheme::ClassicMcEliece348864, 32)
    )]
    fn keypair_from_seed_valid(#[case] scheme: KemScheme, #[case] seed_len: usize) {
        let seed = vec![0xABu8; seed_len];
        let result = scheme.keypair_from_seed(&seed);
        assert!(result.is_ok());

        // Determinism: same seed produces same keypair
        let (ek1, dk1) = result.unwrap();
        let (ek2, dk2) = scheme.keypair_from_seed(&seed).unwrap();
        assert_eq!(ek1.as_ref(), ek2.as_ref());
        assert_eq!(dk1.as_ref(), dk2.as_ref());
    }

    #[cfg(feature = "kgen")]
    #[rstest]
    #[cfg_attr(
        feature = "mceliece",
        case::mceliece_too_long(KemScheme::ClassicMcEliece348864, 64)
    )]
    #[cfg_attr(
        feature = "mceliece",
        case::mceliece_too_short(KemScheme::ClassicMcEliece348864, 16)
    )]
    #[cfg_attr(feature = "ml-kem", case::mlkem_too_short(KemScheme::MlKem512, 32))]
    #[cfg_attr(feature = "ml-kem", case::mlkem_too_long(KemScheme::MlKem512, 100))]
    fn keypair_from_seed_invalid(#[case] scheme: KemScheme, #[case] seed_len: usize) {
        let seed = vec![0xABu8; seed_len];
        let result = scheme.keypair_from_seed(&seed);
        assert!(result.is_err());
    }
}
