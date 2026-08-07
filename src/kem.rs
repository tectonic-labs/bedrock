//! Key-encapsulation mechanism methods.
//!
//! Supports the KEM families enabled through Cargo features.

#[cfg(any(
    feature = "frodo",
    feature = "hqc",
    feature = "mceliece",
    feature = "sntrup"
))]
use crate::os_rng;
use crate::{deserialize_hex_or_bin, error::*, serialize_hex_or_bin};
use serde::{Deserialize, Serialize};

#[cfg(feature = "mceliece")]
use pq_mceliece::Algorithm as McElieceAlgorithm;

macro_rules! impl_kem_struct {
    ($name:ident, $validate:ident) => {
        #[derive(Clone, Serialize, Deserialize)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        #[doc = concat!("A byte-backed [`", stringify!($name), "`] value for a KEM.")]
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
            /// Returns the [`KemScheme`] represented by this value.
            pub fn scheme(&self) -> KemScheme {
                self.0.scheme
            }

            #[doc = concat!("Converts [`", stringify!($name), "`] to its raw byte representation.")]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = concat!("Constructs [`", stringify!($name), "`] from raw bytes and a scheme.")]
            pub fn from_raw_bytes(scheme: KemScheme, bytes: &[u8]) -> Result<Self> {
                scheme.$validate(bytes)?;
                Ok(InnerKem {
                    scheme,
                    value: bytes.to_vec(),
                }
                .into())
            }
        }
    };
}

scheme_impl_pure!(
    /// KEM schemes.
    KemScheme,
    @cfg(feature = "ml-kem")
    #[cfg_attr(feature = "ml-kem", default)]
    /// ML-KEM 768 (NIST Level 3).
    MlKem768 => "ML-KEM-768" ; 2 ; 64,
    @cfg(feature = "ml-kem")
    /// ML-KEM 1024 (NIST Level 5).
    MlKem1024 => "ML-KEM-1024" ; 3 ; 64,
    @cfg(feature = "mceliece")
    /// Classic McEliece 348864 (legacy NIST Level 1; not ISO standardized).
    ClassicMcEliece348864 => "ClassicMcEliece-348864" ; 4 ; 32,
    @cfg(feature = "mceliece")
    #[cfg_attr(not(feature = "ml-kem"), default)]
    /// Classic McEliece 460896 (NIST Level 3).
    ClassicMcEliece460896 => "ClassicMcEliece-460896" ; 21 ; 32,
    @cfg(feature = "mceliece")
    /// Classic McEliece 6688128 (NIST Level 5).
    ClassicMcEliece6688128 => "ClassicMcEliece-6688128" ; 22 ; 32,
    @cfg(feature = "mceliece")
    /// Classic McEliece 6960119 (NIST Level 5).
    ClassicMcEliece6960119 => "ClassicMcEliece-6960119" ; 23 ; 32,
    @cfg(feature = "mceliece")
    /// Classic McEliece 8192128 (NIST Level 5).
    ClassicMcEliece8192128 => "ClassicMcEliece-8192128" ; 24 ; 32,
    @cfg(feature = "hqc")
    /// HQC-128 (NIST Level 1), selected by NIST for standardization.
    Hqc128 => "HQC-128" ; 6 ; 32,
    @cfg(feature = "hqc")
    #[cfg_attr(all(not(feature = "ml-kem"), not(feature = "mceliece")), default)]
    /// HQC-192 (NIST Level 3), selected by NIST for standardization.
    Hqc192 => "HQC-192" ; 7 ; 32,
    @cfg(feature = "hqc")
    /// HQC-256 (NIST Level 5), selected by NIST for standardization.
    Hqc256 => "HQC-256" ; 8 ; 32,
    @cfg(feature = "sntrup")
    /// Streamlined NTRU Prime 653 (NIST Level 1)—the family's lowest-margin set.
    Sntrup653 => "sntrup653" ; 9 ; 32,
    @cfg(feature = "sntrup")
    #[cfg_attr(
        all(
            not(feature = "ml-kem"),
            not(feature = "mceliece"),
            not(feature = "hqc")
        ),
        default
    )]
    /// Streamlined NTRU Prime 761 (NIST Level 2)—the parameter set used by OpenSSH.
    Sntrup761 => "sntrup761" ; 10 ; 32,
    @cfg(feature = "sntrup")
    /// Streamlined NTRU Prime 857 (NIST Level 3).
    Sntrup857 => "sntrup857" ; 11 ; 32,
    @cfg(feature = "sntrup")
    /// Streamlined NTRU Prime 953 (NIST Level 4).
    Sntrup953 => "sntrup953" ; 12 ; 32,
    @cfg(feature = "sntrup")
    /// Streamlined NTRU Prime 1013 (NIST Level 5).
    Sntrup1013 => "sntrup1013" ; 13 ; 32,
    @cfg(feature = "sntrup")
    /// Streamlined NTRU Prime 1277 (NIST Level 5).
    Sntrup1277 => "sntrup1277" ; 14 ; 32,
    // FrodoKEM seeds are 48 bytes or more, so these schemes carry a `seed_size` of 0
    // and refuse `keypair_from_seed` outright — they are deliberately excluded from
    // seed-derived and HD-wallet key generation.
    @cfg(feature = "frodo")
    #[cfg_attr(
        all(
            not(feature = "ml-kem"),
            not(feature = "mceliece"),
            not(feature = "hqc"),
            not(feature = "sntrup")
        ),
        default
    )]
    /// FrodoKEM-640-AES (NIST Level 1).
    FrodoKem640Aes => "FrodoKEM-640-AES" ; 15 ; 0,
    @cfg(feature = "frodo")
    /// FrodoKEM-640-SHAKE (NIST Level 1).
    FrodoKem640Shake => "FrodoKEM-640-SHAKE" ; 16 ; 0,
    @cfg(feature = "frodo")
    /// FrodoKEM-976-AES (NIST Level 3).
    FrodoKem976Aes => "FrodoKEM-976-AES" ; 17 ; 0,
    @cfg(feature = "frodo")
    /// FrodoKEM-976-SHAKE (NIST Level 3).
    FrodoKem976Shake => "FrodoKEM-976-SHAKE" ; 18 ; 0,
    @cfg(feature = "frodo")
    /// FrodoKEM-1344-AES (NIST Level 5).
    FrodoKem1344Aes => "FrodoKEM-1344-AES" ; 19 ; 0,
    @cfg(feature = "frodo")
    /// FrodoKEM-1344-SHAKE (NIST Level 5).
    FrodoKem1344Shake => "FrodoKEM-1344-SHAKE" ; 20 ; 0,
    // Deprecated: ML-KEM-512 (NIST Level 1) was removed for being too weak. Discriminant
    // 1 stays reserved so older serialized keys report a clear migration error.
    @deprecated
    "ML-KEM-512" => 1 ; "ML-KEM-768",
);

serde_impl!(KemScheme);

/// Every Classic McEliece parameter size exposed by Bedrock.
#[cfg(feature = "mceliece")]
macro_rules! mceliece_schemes {
    () => {
        KemScheme::ClassicMcEliece348864
            | KemScheme::ClassicMcEliece460896
            | KemScheme::ClassicMcEliece6688128
            | KemScheme::ClassicMcEliece6960119
            | KemScheme::ClassicMcEliece8192128
    };
}

/// Dispatch a block generic over the concrete `ml_kem` parameter type `$P` for each ML-KEM scheme.
///
/// Only the ML-KEM schemes are handled here; Classic McEliece is dispatched separately.
#[cfg(feature = "ml-kem")]
macro_rules! with_ml_kem_params {
    ($scheme:expr, |$P:ident| $body:block) => {{
        match $scheme {
            KemScheme::MlKem768 => {
                type $P = ml_kem::MlKem768;
                $body
            }
            KemScheme::MlKem1024 => {
                type $P = ml_kem::MlKem1024;
                $body
            }
            #[cfg(feature = "mceliece")]
            mceliece_schemes!() => {
                return Err(Error::SchemeDispatch(
                    "Classic McEliece reached the ML-KEM dispatcher",
                ));
            }
            #[cfg(feature = "hqc")]
            KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256 => {
                return Err(Error::SchemeDispatch("HQC reached the ML-KEM dispatcher"));
            }
            #[cfg(feature = "sntrup")]
            KemScheme::Sntrup653
            | KemScheme::Sntrup761
            | KemScheme::Sntrup857
            | KemScheme::Sntrup953
            | KemScheme::Sntrup1013
            | KemScheme::Sntrup1277 => {
                return Err(Error::SchemeDispatch(
                    "sntrup reached the ML-KEM dispatcher",
                ));
            }
            #[cfg(feature = "frodo")]
            KemScheme::FrodoKem640Aes
            | KemScheme::FrodoKem640Shake
            | KemScheme::FrodoKem976Aes
            | KemScheme::FrodoKem976Shake
            | KemScheme::FrodoKem1344Aes
            | KemScheme::FrodoKem1344Shake => {
                return Err(Error::SchemeDispatch(
                    "FrodoKEM reached the ML-KEM dispatcher",
                ));
            }
        }
    }};
}

/// Every `KemScheme` variant in the sntrup family, for use as a match arm pattern.
#[cfg(feature = "sntrup")]
macro_rules! sntrup_schemes {
    () => {
        KemScheme::Sntrup653
            | KemScheme::Sntrup761
            | KemScheme::Sntrup857
            | KemScheme::Sntrup953
            | KemScheme::Sntrup1013
            | KemScheme::Sntrup1277
    };
}

/// Every `KemScheme` variant in the FrodoKEM family, for use as a match arm pattern.
#[cfg(feature = "frodo")]
macro_rules! frodo_schemes {
    () => {
        KemScheme::FrodoKem640Aes
            | KemScheme::FrodoKem640Shake
            | KemScheme::FrodoKem976Aes
            | KemScheme::FrodoKem976Shake
            | KemScheme::FrodoKem1344Aes
            | KemScheme::FrodoKem1344Shake
    };
}

/// Dispatch a block generic over the concrete `sntrup` parameter type `$P`.
///
/// The `sntrup` crate parameterizes every key, ciphertext, and shared-secret type over
/// the parameter set, so each operation needs the concrete type threaded through.
#[cfg(feature = "sntrup")]
macro_rules! with_sntrup_params {
    ($scheme:expr, |$P:ident| $body:block) => {{
        match $scheme {
            KemScheme::Sntrup653 => {
                type $P = sntrup::Sntrup653Params;
                $body
            }
            KemScheme::Sntrup761 => {
                type $P = sntrup::Sntrup761Params;
                $body
            }
            KemScheme::Sntrup857 => {
                type $P = sntrup::Sntrup857Params;
                $body
            }
            KemScheme::Sntrup953 => {
                type $P = sntrup::Sntrup953Params;
                $body
            }
            KemScheme::Sntrup1013 => {
                type $P = sntrup::Sntrup1013Params;
                $body
            }
            KemScheme::Sntrup1277 => {
                type $P = sntrup::Sntrup1277Params;
                $body
            }
            _ => {
                return Err(Error::SchemeDispatch(
                    "non-sntrup scheme reached the sntrup dispatcher",
                ));
            }
        }
    }};
}

/// Dispatch a block generic over the concrete `hqc_kem` parameter type `$P` for each HQC scheme.
///
/// HQC's key, ciphertext and shared-secret types are all generic over the parameter set, so
/// every operation needs the concrete type threaded through. Only HQC schemes reach here.
#[cfg(feature = "hqc")]
macro_rules! with_hqc_params {
    ($scheme:expr, |$P:ident| $body:block) => {{
        match $scheme {
            KemScheme::Hqc128 => {
                type $P = hqc_kem::Hqc128Params;
                $body
            }
            KemScheme::Hqc192 => {
                type $P = hqc_kem::Hqc192Params;
                $body
            }
            KemScheme::Hqc256 => {
                type $P = hqc_kem::Hqc256Params;
                $body
            }
            _ => {
                return Err(Error::SchemeDispatch(
                    "non-HQC scheme reached the HQC dispatcher",
                ));
            }
        }
    }};
}

impl KemScheme {
    /// Maps this scheme onto the upstream Classic McEliece runtime algorithm.
    #[cfg(feature = "mceliece")]
    fn mceliece_algorithm(self) -> Result<McElieceAlgorithm> {
        Ok(match self {
            Self::ClassicMcEliece348864 => McElieceAlgorithm::McEliece348864,
            Self::ClassicMcEliece460896 => McElieceAlgorithm::McEliece460896,
            Self::ClassicMcEliece6688128 => McElieceAlgorithm::McEliece6688128,
            Self::ClassicMcEliece6960119 => McElieceAlgorithm::McEliece6960119,
            Self::ClassicMcEliece8192128 => McElieceAlgorithm::McEliece8192128,
            #[cfg(any(
                feature = "frodo",
                feature = "hqc",
                feature = "ml-kem",
                feature = "sntrup"
            ))]
            _ => {
                return Err(Error::McElieceError(
                    "not a Classic McEliece scheme".to_string(),
                ));
            }
        })
    }

    /// Maps this scheme onto the upstream FrodoKEM runtime algorithm.
    ///
    /// The upstream `Algorithm` carries itself inside every key and ciphertext and
    /// rejects mismatched pairings. At equal `n`, the AES and SHAKE variants have
    /// identical encoding lengths, so length checks cannot distinguish them.
    #[cfg(feature = "frodo")]
    fn frodo_algorithm(self) -> Result<frodo_kem_rs::Algorithm> {
        Ok(match self {
            Self::FrodoKem640Aes => frodo_kem_rs::Algorithm::FrodoKem640Aes,
            Self::FrodoKem640Shake => frodo_kem_rs::Algorithm::FrodoKem640Shake,
            Self::FrodoKem976Aes => frodo_kem_rs::Algorithm::FrodoKem976Aes,
            Self::FrodoKem976Shake => frodo_kem_rs::Algorithm::FrodoKem976Shake,
            Self::FrodoKem1344Aes => frodo_kem_rs::Algorithm::FrodoKem1344Aes,
            Self::FrodoKem1344Shake => frodo_kem_rs::Algorithm::FrodoKem1344Shake,
            _ => return Err(Error::FrodoError("not a FrodoKEM scheme".to_string())),
        })
    }

    #[cfg(feature = "kgen")]
    /// Generates a new encapsulation and decapsulation keypair.
    pub fn keypair(&self) -> Result<(KemEncapsulationKey, KemDecapsulationKey)> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::KeyExport;
                with_ml_kem_params!(*self, |P| {
                    let (dk, ek) = <P as ml_kem::Kem>::generate_keypair();
                    Ok(self.pack_keypair(ek.to_bytes().to_vec(), dk.to_bytes().to_vec()))
                })
            }
            #[cfg(feature = "mceliece")]
            mceliece_schemes!() => {
                let (ek, dk) = self.mceliece_algorithm()?.generate_keypair(os_rng());
                Ok(self.pack_keypair(ek.as_ref().to_vec(), dk.as_ref().to_vec()))
            }
            #[cfg(feature = "hqc")]
            KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256 => {
                with_hqc_params!(*self, |P| {
                    let mut rng = os_rng();
                    let (ek, dk) = hqc_kem::HqcKem::<P>::generate_key(&mut rng);
                    Ok(self.pack_keypair(ek.as_ref().to_vec(), dk.as_ref().to_vec()))
                })
            }
            #[cfg(feature = "sntrup")]
            sntrup_schemes!() => with_sntrup_params!(*self, |P| {
                let mut rng = os_rng();
                let (ek, dk) = sntrup::SntrupKem::<P>::generate_key(&mut rng);
                Ok(self.pack_keypair(ek.as_ref().to_vec(), dk.as_ref().to_vec()))
            }),
            #[cfg(feature = "frodo")]
            frodo_schemes!() => {
                let (ek, dk) = self.frodo_algorithm()?.generate_keypair(os_rng());
                Ok(self.pack_keypair(ek.value().to_vec(), dk.value().to_vec()))
            }
        }
    }

    #[cfg(feature = "kgen")]
    /// Generates a new encapsulation and decapsulation keypair from a seed.
    pub fn keypair_from_seed(
        &self,
        seed: &[u8],
    ) -> Result<(KemEncapsulationKey, KemDecapsulationKey)> {
        if seed.len() != self.seed_size() {
            return Err(Error::InvalidSeedLength(seed.len()));
        }
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::KeyExport;
                with_ml_kem_params!(*self, |P| {
                    let seed = ml_kem::Seed::try_from(seed)
                        .map_err(|_| Error::InvalidSeedLength(seed.len()))?;
                    let (dk, ek) = <P as ml_kem::FromSeed>::from_seed(&seed);
                    Ok(self.pack_keypair(ek.to_bytes().to_vec(), dk.to_bytes().to_vec()))
                })
            }
            #[cfg(feature = "mceliece")]
            mceliece_schemes!() => {
                let (ek, dk) = self
                    .mceliece_algorithm()?
                    .generate_keypair_from_seed(seed)
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                Ok(self.pack_keypair(ek.as_ref().to_vec(), dk.as_ref().to_vec()))
            }
            #[cfg(feature = "hqc")]
            KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256 => {
                // `seed.len()` is already validated to equal `seed_size()` (32) above.
                let seed_arr: [u8; 32] = seed
                    .try_into()
                    .map_err(|_| Error::InvalidSeedLength(seed.len()))?;
                with_hqc_params!(*self, |P| {
                    let (ek, dk) = hqc_kem::HqcKem::<P>::generate_key_deterministic(&seed_arr);
                    Ok(self.pack_keypair(ek.as_ref().to_vec(), dk.as_ref().to_vec()))
                })
            }
            #[cfg(feature = "sntrup")]
            sntrup_schemes!() => {
                // `seed.len()` is already validated to equal `seed_size()` (32) above.
                let seed_arr: [u8; 32] = seed
                    .try_into()
                    .map_err(|_| Error::InvalidSeedLength(seed.len()))?;
                with_sntrup_params!(*self, |P| {
                    let (ek, dk) = sntrup::SntrupKem::<P>::generate_key_deterministic(&seed_arr);
                    Ok(self.pack_keypair(ek.as_ref().to_vec(), dk.as_ref().to_vec()))
                })
            }
            // FrodoKEM's key seed is 48 bytes or more, above the 32-byte ceiling that
            // seed-derived and HD-wallet key generation works within, so it is refused
            // outright. This arm must reject explicitly rather than lean on the length
            // check above: a `seed_size` of 0 would otherwise admit an empty seed.
            #[cfg(feature = "frodo")]
            frodo_schemes!() => Err(Error::DeterministicKeygenUnsupported(
                "FrodoKEM: key seed exceeds the 32-byte limit for seed-derived generation",
            )),
        }
    }

    /// Whether this scheme offers seed-derived key generation.
    ///
    /// Seed-derived generation is offered only where the scheme's deterministic seed is
    /// small enough to come from a single SLIP-0010 child key without expansion.
    /// FrodoKEM needs 48 bytes or more and therefore declines. Callers that build a seed
    /// generically should consult this rather than inferring intent from a
    /// [`seed_size`](Self::seed_size) of zero, which would otherwise be ambiguous between
    /// "no seeded generation" and "seeded generation taking an empty seed".
    pub fn supports_seeded_keygen(&self) -> bool {
        self.seed_size() != 0
    }

    /// Rejects a key, ciphertext, or shared secret that belongs to a different scheme.
    ///
    /// Byte length is not a reliable discriminator between parameter sets, so every
    /// dispatch path binds to the value's own stored scheme rather than inferring it
    /// from the encoding. See [`Error::SchemeMismatch`].
    fn ensure_scheme(&self, actual: KemScheme) -> Result<()> {
        if actual == *self {
            Ok(())
        } else {
            Err(Error::SchemeMismatch {
                expected: self.to_string(),
                actual: actual.to_string(),
            })
        }
    }

    #[cfg(feature = "kgen")]
    /// Packs raw encapsulation and decapsulation key bytes into Bedrock's byte-backed key types.
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
    /// Encapsulates to the provided public key.
    pub fn encapsulate(
        &self,
        encapsulation_key: &KemEncapsulationKey,
    ) -> Result<(KemCiphertext, KemSharedSecret)> {
        self.ensure_scheme(encapsulation_key.0.scheme)?;
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem768 | KemScheme::MlKem1024 => {
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
            mceliece_schemes!() => {
                let alg = self.mceliece_algorithm()?;
                let ek = alg
                    .encapsulation_key_from_bytes(encapsulation_key.0.value.as_slice())
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                let (ct, ss) = alg
                    .encapsulate(&ek, os_rng())
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                Ok((
                    InnerKem {
                        scheme: *self,
                        value: ct.as_ref().to_vec(),
                    }
                    .into(),
                    InnerKem {
                        scheme: *self,
                        value: ss.as_ref().to_vec(),
                    }
                    .into(),
                ))
            }
            #[cfg(feature = "hqc")]
            KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256 => {
                with_hqc_params!(*self, |P| {
                    let ek = hqc_kem::EncapsulationKey::<P>::try_from(
                        encapsulation_key.0.value.as_slice(),
                    )
                    .map_err(|_| Error::HqcError("an invalid encapsulation key".to_string()))?;
                    let mut rng = os_rng();
                    let (ct, ss) = ek.encapsulate(&mut rng);
                    Ok(self.pack_encapsulation(ct.as_ref().to_vec(), ss.as_ref().to_vec()))
                })
            }
            #[cfg(feature = "sntrup")]
            sntrup_schemes!() => {
                with_sntrup_params!(*self, |P| {
                    let ek = sntrup::EncapsulationKey::<P>::try_from(
                        encapsulation_key.0.value.as_slice(),
                    )
                    .map_err(|_| Error::SntrupError("an invalid encapsulation key".to_string()))?;
                    let mut rng = os_rng();
                    let (ct, ss) = ek.encapsulate(&mut rng);
                    Ok(self.pack_encapsulation(ct.as_ref().to_vec(), ss.as_ref().to_vec()))
                })
            }
            #[cfg(feature = "frodo")]
            frodo_schemes!() => {
                let alg = self.frodo_algorithm()?;
                let ek = alg
                    .encryption_key_from_bytes(encapsulation_key.0.value.as_slice())
                    .map_err(|e| Error::FrodoError(e.to_string()))?;
                let (ct, ss) = alg
                    .encapsulate_with_rng(&ek, os_rng())
                    .map_err(|e| Error::FrodoError(e.to_string()))?;
                Ok(self.pack_encapsulation(ct.value().to_vec(), ss.value().to_vec()))
            }
        }
    }

    /// Packs raw ciphertext and shared-secret bytes into Bedrock's byte-backed types.
    #[cfg(all(
        feature = "encp",
        any(feature = "hqc", feature = "sntrup", feature = "frodo")
    ))]
    fn pack_encapsulation(&self, ct: Vec<u8>, ss: Vec<u8>) -> (KemCiphertext, KemSharedSecret) {
        (
            InnerKem {
                scheme: *self,
                value: ct,
            }
            .into(),
            InnerKem {
                scheme: *self,
                value: ss,
            }
            .into(),
        )
    }

    #[cfg(feature = "decp")]
    /// Decapsulates the provided ciphertext.
    pub fn decapsulate(
        &self,
        ciphertext: &KemCiphertext,
        decapsulation_key: &KemDecapsulationKey,
    ) -> Result<KemSharedSecret> {
        self.ensure_scheme(ciphertext.0.scheme)?;
        self.ensure_scheme(decapsulation_key.0.scheme)?;
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem768 | KemScheme::MlKem1024 => {
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
            mceliece_schemes!() => {
                let alg = self.mceliece_algorithm()?;
                let ct = alg
                    .ciphertext_from_bytes(ciphertext.0.value.as_slice())
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                let dk = alg
                    .decapsulation_key_from_bytes(decapsulation_key.0.value.as_slice())
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                let ss = alg
                    .decapsulate(&dk, &ct)
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                Ok(InnerKem {
                    scheme: *self,
                    value: ss.as_ref().to_vec(),
                }
                .into())
            }
            #[cfg(feature = "hqc")]
            KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256 => {
                with_hqc_params!(*self, |P| {
                    let dk = hqc_kem::DecapsulationKey::<P>::try_from(
                        decapsulation_key.0.value.as_slice(),
                    )
                    .map_err(|_| Error::HqcError("an invalid decapsulation key".to_string()))?;
                    let ct = hqc_kem::Ciphertext::<P>::try_from(ciphertext.0.value.as_slice())
                        .map_err(|_| Error::HqcError("an invalid kem ciphertext".to_string()))?;
                    let ss = dk.decapsulate(&ct);
                    Ok(InnerKem {
                        scheme: *self,
                        value: ss.as_ref().to_vec(),
                    }
                    .into())
                })
            }
            #[cfg(feature = "sntrup")]
            sntrup_schemes!() => {
                with_sntrup_params!(*self, |P| {
                    let dk = sntrup::DecapsulationKey::<P>::try_from(
                        decapsulation_key.0.value.as_slice(),
                    )
                    .map_err(|_| Error::SntrupError("an invalid decapsulation key".to_string()))?;
                    let ct = sntrup::Ciphertext::<P>::try_from(ciphertext.0.value.as_slice())
                        .map_err(|_| Error::SntrupError("an invalid kem ciphertext".to_string()))?;
                    let ss = dk.decapsulate(&ct);
                    Ok(InnerKem {
                        scheme: *self,
                        value: ss.as_ref().to_vec(),
                    }
                    .into())
                })
            }
            #[cfg(feature = "frodo")]
            frodo_schemes!() => {
                let alg = self.frodo_algorithm()?;
                let dk = alg
                    .decryption_key_from_bytes(decapsulation_key.0.value.as_slice())
                    .map_err(|e| Error::FrodoError(e.to_string()))?;
                let ct = alg
                    .ciphertext_from_bytes(ciphertext.0.value.as_slice())
                    .map_err(|e| Error::FrodoError(e.to_string()))?;
                let (ss, _message) = alg
                    .decapsulate(&dk, &ct)
                    .map_err(|e| Error::FrodoError(e.to_string()))?;
                Ok(InnerKem {
                    scheme: *self,
                    value: ss.value().to_vec(),
                }
                .into())
            }
        }
    }

    /// Validates an encapsulation (public) key encoding for this scheme.
    fn validate_encapsulation_key(&self, bytes: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::TryKeyInit;
                with_ml_kem_params!(*self, |P| {
                    ml_kem::EncapsulationKey::<P>::new_from_slice(bytes).map_err(|_| {
                        Error::MlKemError("an invalid encapsulation key".to_string())
                    })?;
                    Ok(())
                })
            }
            #[cfg(feature = "mceliece")]
            mceliece_schemes!() => {
                self.mceliece_algorithm()?
                    .encapsulation_key_from_bytes(bytes)
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                Ok(())
            }
            #[cfg(feature = "hqc")]
            KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256 => {
                with_hqc_params!(*self, |P| {
                    hqc_kem::EncapsulationKey::<P>::try_from(bytes)
                        .map_err(|_| Error::HqcError("an invalid encapsulation key".to_string()))?;
                    Ok(())
                })
            }
            #[cfg(feature = "sntrup")]
            sntrup_schemes!() => with_sntrup_params!(*self, |P| {
                sntrup::EncapsulationKey::<P>::try_from(bytes)
                    .map_err(|_| Error::SntrupError("an invalid encapsulation key".to_string()))?;
                Ok(())
            }),
            #[cfg(feature = "frodo")]
            frodo_schemes!() => {
                self.frodo_algorithm()?
                    .encryption_key_from_bytes(bytes)
                    .map_err(|e| Error::FrodoError(e.to_string()))?;
                Ok(())
            }
        }
    }

    /// Validates a decapsulation (secret) key encoding for this scheme.
    fn validate_decapsulation_key(&self, bytes: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                use ml_kem::KeyInit;
                with_ml_kem_params!(*self, |P| {
                    ml_kem::DecapsulationKey::<P>::new_from_slice(bytes).map_err(|_| {
                        Error::MlKemError("an invalid decapsulation key".to_string())
                    })?;
                    Ok(())
                })
            }
            #[cfg(feature = "mceliece")]
            mceliece_schemes!() => {
                self.mceliece_algorithm()?
                    .decapsulation_key_from_bytes(bytes)
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                Ok(())
            }
            #[cfg(feature = "hqc")]
            KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256 => {
                with_hqc_params!(*self, |P| {
                    hqc_kem::DecapsulationKey::<P>::try_from(bytes)
                        .map_err(|_| Error::HqcError("an invalid decapsulation key".to_string()))?;
                    Ok(())
                })
            }
            #[cfg(feature = "sntrup")]
            sntrup_schemes!() => with_sntrup_params!(*self, |P| {
                sntrup::DecapsulationKey::<P>::try_from(bytes)
                    .map_err(|_| Error::SntrupError("an invalid decapsulation key".to_string()))?;
                Ok(())
            }),
            #[cfg(feature = "frodo")]
            frodo_schemes!() => {
                self.frodo_algorithm()?
                    .decryption_key_from_bytes(bytes)
                    .map_err(|e| Error::FrodoError(e.to_string()))?;
                Ok(())
            }
        }
    }

    /// Validates a ciphertext encoding for this scheme.
    fn validate_ciphertext(&self, bytes: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                with_ml_kem_params!(*self, |P| {
                    ml_kem::Ciphertext::<P>::try_from(bytes)
                        .map_err(|_| Error::MlKemError("an invalid kem ciphertext".to_string()))?;
                    Ok(())
                })
            }
            #[cfg(feature = "mceliece")]
            mceliece_schemes!() => {
                self.mceliece_algorithm()?
                    .ciphertext_from_bytes(bytes)
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                Ok(())
            }
            #[cfg(feature = "hqc")]
            KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256 => {
                with_hqc_params!(*self, |P| {
                    hqc_kem::Ciphertext::<P>::try_from(bytes)
                        .map_err(|_| Error::HqcError("an invalid kem ciphertext".to_string()))?;
                    Ok(())
                })
            }
            #[cfg(feature = "sntrup")]
            sntrup_schemes!() => with_sntrup_params!(*self, |P| {
                sntrup::Ciphertext::<P>::try_from(bytes)
                    .map_err(|_| Error::SntrupError("an invalid kem ciphertext".to_string()))?;
                Ok(())
            }),
            #[cfg(feature = "frodo")]
            frodo_schemes!() => {
                self.frodo_algorithm()?
                    .ciphertext_from_bytes(bytes)
                    .map_err(|e| Error::FrodoError(e.to_string()))?;
                Ok(())
            }
        }
    }

    /// Validates a shared-secret encoding for this scheme.
    fn validate_shared_secret(&self, bytes: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "ml-kem")]
            KemScheme::MlKem768 | KemScheme::MlKem1024 => {
                if bytes.len() == 32 {
                    Ok(())
                } else {
                    Err(Error::MlKemError("an invalid shared secret".to_string()))
                }
            }
            #[cfg(feature = "mceliece")]
            mceliece_schemes!() => {
                self.mceliece_algorithm()?
                    .shared_secret_from_bytes(bytes)
                    .map_err(|e| Error::McElieceError(e.to_string()))?;
                Ok(())
            }
            #[cfg(feature = "hqc")]
            KemScheme::Hqc128 | KemScheme::Hqc192 | KemScheme::Hqc256 => {
                with_hqc_params!(*self, |P| {
                    hqc_kem::SharedSecret::<P>::try_from(bytes)
                        .map_err(|_| Error::HqcError("an invalid shared secret".to_string()))?;
                    Ok(())
                })
            }
            // Every sntrup parameter set shares one shared-secret length, so this is a
            // plain length check rather than a per-parameter parse.
            #[cfg(feature = "sntrup")]
            sntrup_schemes!() => {
                if bytes.len() == sntrup::sntrup761::SHARED_SECRET_SIZE {
                    Ok(())
                } else {
                    Err(Error::SntrupError("an invalid shared secret".to_string()))
                }
            }
            #[cfg(feature = "frodo")]
            frodo_schemes!() => {
                self.frodo_algorithm()?
                    .shared_secret_from_bytes(bytes)
                    .map_err(|e| Error::FrodoError(e.to_string()))?;
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

    /// Round-trip a value through every serialization format the project mandates:
    /// postcard, CBOR, JSON, TOML and YAML.
    ///
    /// The binary formats (postcard, CBOR) and the human-readable ones (JSON, TOML,
    /// YAML) take different paths through `serdect`, which encodes byte strings as hex
    /// for human-readable formats and as raw bytes otherwise. Exercising both sides is
    /// the point: a change that breaks only the hex path would pass a postcard-only test.
    fn round_trip_all_formats<T>(value: &T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let bytes = postcard::to_stdvec(value).unwrap();
        assert_eq!(
            value,
            &postcard::from_bytes::<T>(&bytes).unwrap(),
            "postcard"
        );

        let mut cbor = Vec::new();
        ciborium::into_writer(value, &mut cbor).unwrap();
        assert_eq!(
            value,
            &ciborium::from_reader::<T, _>(cbor.as_slice()).unwrap(),
            "cbor"
        );

        let json = serde_json::to_string(value).unwrap();
        assert_eq!(value, &serde_json::from_str::<T>(&json).unwrap(), "json");

        let toml_text = toml::to_string(value).unwrap();
        assert_eq!(value, &toml::from_str::<T>(&toml_text).unwrap(), "toml");

        let yaml = yaml_serde::to_string(value).unwrap();
        assert_eq!(value, &yaml_serde::from_str::<T>(&yaml).unwrap(), "yaml");
    }

    /// A named field gives self-describing formats such as TOML a document-shaped root.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct SchemeDocument {
        scheme: KemScheme,
    }

    /// Every `KemScheme` that is compiled in, for exhaustive cross-scheme testing.
    #[cfg(feature = "kgen")]
    fn all_schemes() -> Vec<KemScheme> {
        #[allow(unused_mut)]
        let mut v: Vec<KemScheme> = Vec::new();
        #[cfg(feature = "ml-kem")]
        v.extend_from_slice(&[KemScheme::MlKem768, KemScheme::MlKem1024]);
        #[cfg(feature = "mceliece")]
        v.extend_from_slice(&[
            KemScheme::ClassicMcEliece348864,
            KemScheme::ClassicMcEliece460896,
            KemScheme::ClassicMcEliece6688128,
            KemScheme::ClassicMcEliece6960119,
            KemScheme::ClassicMcEliece8192128,
        ]);
        #[cfg(feature = "hqc")]
        v.extend_from_slice(&[KemScheme::Hqc128, KemScheme::Hqc192, KemScheme::Hqc256]);
        #[cfg(feature = "sntrup")]
        v.extend_from_slice(&[
            KemScheme::Sntrup653,
            KemScheme::Sntrup761,
            KemScheme::Sntrup857,
            KemScheme::Sntrup953,
            KemScheme::Sntrup1013,
            KemScheme::Sntrup1277,
        ]);
        #[cfg(feature = "frodo")]
        v.extend_from_slice(&[
            KemScheme::FrodoKem640Aes,
            KemScheme::FrodoKem640Shake,
            KemScheme::FrodoKem976Aes,
            KemScheme::FrodoKem976Shake,
            KemScheme::FrodoKem1344Aes,
            KemScheme::FrodoKem1344Shake,
        ]);
        v
    }

    /// For EVERY ordered pair of distinct schemes, a key or ciphertext from one must be
    /// refused by the other.
    ///
    /// This is the test that a per-family check cannot replace. Length is not a
    /// discriminator anywhere: MAYO-1/2 once shared a 24-byte secret key, and FrodoKEM's
    /// AES and SHAKE variants have identical lengths in every dimension at equal `n`. Worse,
    /// a KEM that fails to reject simply returns a pseudorandom shared secret — no error,
    /// no panic, no failing round-trip test. Only an exhaustive pairing catches it.
    #[cfg(all(feature = "kgen", feature = "encp", feature = "decp"))]
    #[test]
    fn every_cross_scheme_pair_is_rejected() {
        let schemes = all_schemes();
        if schemes.len() < 2 {
            // Only one KEM family is compiled in, so there is no cross-scheme pair to
            // test. Nothing to assert rather than a failure.
            return;
        }

        let mut checked = 0usize;
        for owner in &schemes {
            // Scheme mismatch is required to be rejected before parsing the value. Sentinel
            // bytes isolate that invariant and avoid generating megabyte-scale keys which no
            // caller in this loop is allowed to inspect.
            let ek = KemEncapsulationKey(InnerKem {
                scheme: *owner,
                value: Vec::new(),
            });
            let dk = KemDecapsulationKey(InnerKem {
                scheme: *owner,
                value: Vec::new(),
            });
            let ct = KemCiphertext(InnerKem {
                scheme: *owner,
                value: Vec::new(),
            });
            for caller in &schemes {
                if caller == owner {
                    continue;
                }
                assert!(
                    matches!(caller.encapsulate(&ek), Err(Error::SchemeMismatch { .. })),
                    "{caller} accepted an encapsulation key belonging to {owner}"
                );
                assert!(
                    matches!(
                        caller.decapsulate(&ct, &dk),
                        Err(Error::SchemeMismatch { .. })
                    ),
                    "{caller} accepted a ciphertext/key pair belonging to {owner}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, schemes.len() * (schemes.len() - 1));
    }

    /// `supports_seeded_keygen` must agree with what `keypair_from_seed` actually does.
    ///
    /// Without this, `seed_size() == 0` is ambiguous between "declines seeded generation"
    /// and "accepts an empty seed", and a generic caller cannot tell which it is.
    #[cfg(feature = "kgen")]
    #[test]
    fn seeded_keygen_support_matches_behaviour() {
        for scheme in all_schemes() {
            let seed = vec![0u8; scheme.seed_size()];
            let result = scheme.keypair_from_seed(&seed);
            if scheme.supports_seeded_keygen() {
                assert!(
                    result.is_ok(),
                    "{scheme} claims seeded keygen but refused a {}-byte seed",
                    seed.len()
                );
                assert!(scheme.seed_size() <= 64);
            } else {
                assert!(
                    matches!(result, Err(Error::DeterministicKeygenUnsupported(_))),
                    "{scheme} declines seeded keygen but did not say so clearly"
                );
            }
        }
    }

    /// FrodoKEM must refuse seed-derived key generation outright.
    ///
    /// Its key seed is 48 bytes or more, past the 32-byte ceiling that seed-derived and
    /// HD-wallet generation works within. The empty-seed case matters specifically: these
    /// schemes carry a `seed_size` of 0, so the generic length check admits an empty slice
    /// and the scheme's own arm has to be what rejects it.
    #[cfg(all(feature = "frodo", feature = "kgen"))]
    #[rstest]
    #[case::frodo640aes(KemScheme::FrodoKem640Aes)]
    #[case::frodo640shake(KemScheme::FrodoKem640Shake)]
    #[case::frodo976aes(KemScheme::FrodoKem976Aes)]
    #[case::frodo976shake(KemScheme::FrodoKem976Shake)]
    #[case::frodo1344aes(KemScheme::FrodoKem1344Aes)]
    #[case::frodo1344shake(KemScheme::FrodoKem1344Shake)]
    fn frodo_refuses_seeded_keygen(#[case] scheme: KemScheme) {
        assert!(matches!(
            scheme.keypair_from_seed(&[]),
            Err(Error::DeterministicKeygenUnsupported(_))
        ));
        assert!(scheme.keypair_from_seed(&[0u8; 32]).is_err());
        assert!(scheme.keypair_from_seed(&[0u8; 48]).is_err());
    }

    /// Every scheme that offers seed-derived generation must fit within 32 bytes.
    ///
    /// This is the rule itself expressed as a probe, so a future scheme added with a
    /// larger seed fails here rather than quietly widening the HD-derivation contract.
    #[test]
    fn seeded_schemes_stay_within_the_32_byte_ceiling() {
        #[cfg(feature = "hqc")]
        for scheme in [KemScheme::Hqc128, KemScheme::Hqc192, KemScheme::Hqc256] {
            assert_eq!(scheme.seed_size(), 32);
        }
        #[cfg(feature = "frodo")]
        for scheme in [
            KemScheme::FrodoKem640Aes,
            KemScheme::FrodoKem640Shake,
            KemScheme::FrodoKem976Aes,
            KemScheme::FrodoKem976Shake,
            KemScheme::FrodoKem1344Aes,
            KemScheme::FrodoKem1344Shake,
        ] {
            assert_eq!(scheme.seed_size(), 0, "FrodoKEM must not advertise a seed");
        }
        #[cfg(feature = "sntrup")]
        for scheme in [
            KemScheme::Sntrup653,
            KemScheme::Sntrup761,
            KemScheme::Sntrup857,
            KemScheme::Sntrup953,
            KemScheme::Sntrup1013,
            KemScheme::Sntrup1277,
        ] {
            assert_eq!(scheme.seed_size(), 32);
        }
    }

    /// FrodoKEM's AES and SHAKE variants are byte-identical in size at equal `n`, so a
    /// length-based guard could never separate them. Only the stored scheme can.
    #[cfg(all(
        feature = "frodo",
        feature = "kgen",
        feature = "encp",
        feature = "decp"
    ))]
    #[rstest]
    #[case::n640(KemScheme::FrodoKem640Aes, KemScheme::FrodoKem640Shake)]
    #[case::n976(KemScheme::FrodoKem976Aes, KemScheme::FrodoKem976Shake)]
    #[case::n1344(KemScheme::FrodoKem1344Aes, KemScheme::FrodoKem1344Shake)]
    fn frodo_aes_and_shake_are_mutually_rejected(#[case] aes: KemScheme, #[case] shake: KemScheme) {
        let (ek_aes, dk_aes) = aes.keypair().unwrap();
        let (ct_aes, _) = aes.encapsulate(&ek_aes).unwrap();

        // The premise of the test: identical encoding lengths in every dimension.
        let (ek_shake, _) = shake.keypair().unwrap();
        assert_eq!(ek_aes.to_raw_bytes().len(), ek_shake.to_raw_bytes().len());

        assert!(matches!(
            shake.encapsulate(&ek_aes),
            Err(Error::SchemeMismatch { .. })
        ));
        assert!(matches!(
            shake.decapsulate(&ct_aes, &dk_aes),
            Err(Error::SchemeMismatch { .. })
        ));
    }

    /// A key from one sntrup size must not be usable at another.
    #[cfg(all(
        feature = "sntrup",
        feature = "kgen",
        feature = "encp",
        feature = "decp"
    ))]
    #[test]
    fn cross_size_sntrup_rejected() {
        let (ek_761, dk_761) = KemScheme::Sntrup761.keypair().unwrap();
        let (ct_761, _) = KemScheme::Sntrup761.encapsulate(&ek_761).unwrap();

        assert!(matches!(
            KemScheme::Sntrup857.encapsulate(&ek_761),
            Err(Error::SchemeMismatch { .. })
        ));
        assert!(matches!(
            KemScheme::Sntrup653.decapsulate(&ct_761, &dk_761),
            Err(Error::SchemeMismatch { .. })
        ));
    }

    #[cfg(any(
        feature = "mceliece",
        feature = "hqc",
        feature = "sntrup",
        feature = "frodo"
    ))]
    /// Encapsulation and decapsulation agree on the shared secret.
    ///
    /// This is an end-to-end property of the KEM, not a restatement of the wrapper's
    /// own arithmetic: the secret is produced by two independent code paths (the
    /// encapsulator derives it from its own randomness, the decapsulator recovers it
    /// from the ciphertext) and the test asserts they coincide.
    #[cfg(all(feature = "kgen", feature = "encp", feature = "decp"))]
    #[rstest]
    #[cfg_attr(feature = "mceliece", case::mceliece(KemScheme::ClassicMcEliece348864))]
    #[cfg_attr(feature = "hqc", case::hqc128(KemScheme::Hqc128))]
    #[cfg_attr(feature = "hqc", case::hqc192(KemScheme::Hqc192))]
    #[cfg_attr(feature = "hqc", case::hqc256(KemScheme::Hqc256))]
    #[cfg_attr(feature = "sntrup", case::sntrup653(KemScheme::Sntrup653))]
    #[cfg_attr(feature = "sntrup", case::sntrup761(KemScheme::Sntrup761))]
    #[cfg_attr(feature = "sntrup", case::sntrup857(KemScheme::Sntrup857))]
    #[cfg_attr(feature = "sntrup", case::sntrup953(KemScheme::Sntrup953))]
    #[cfg_attr(feature = "sntrup", case::sntrup1013(KemScheme::Sntrup1013))]
    #[cfg_attr(feature = "sntrup", case::sntrup1277(KemScheme::Sntrup1277))]
    #[cfg_attr(feature = "frodo", case::frodo640aes(KemScheme::FrodoKem640Aes))]
    #[cfg_attr(feature = "frodo", case::frodo640shake(KemScheme::FrodoKem640Shake))]
    #[cfg_attr(feature = "frodo", case::frodo976aes(KemScheme::FrodoKem976Aes))]
    #[cfg_attr(feature = "frodo", case::frodo976shake(KemScheme::FrodoKem976Shake))]
    #[cfg_attr(feature = "frodo", case::frodo1344aes(KemScheme::FrodoKem1344Aes))]
    #[cfg_attr(feature = "frodo", case::frodo1344shake(KemScheme::FrodoKem1344Shake))]
    fn encapsulation_round_trip(#[case] scheme: KemScheme) {
        let (ek, dk) = scheme.keypair().unwrap();
        let (ct, ss_sender) = scheme.encapsulate(&ek).unwrap();
        let ss_receiver = scheme.decapsulate(&ct, &dk).unwrap();
        assert_eq!(ss_sender.to_raw_bytes(), ss_receiver.to_raw_bytes());
        assert!(!ss_sender.to_raw_bytes().is_empty());
    }

    #[cfg(any(feature = "hqc", feature = "sntrup"))]
    /// Seeded key generation is deterministic, and distinct seeds give distinct keys.
    #[cfg(feature = "kgen")]
    #[rstest]
    #[cfg_attr(feature = "hqc", case::hqc128(KemScheme::Hqc128))]
    #[cfg_attr(feature = "hqc", case::hqc192(KemScheme::Hqc192))]
    #[cfg_attr(feature = "hqc", case::hqc256(KemScheme::Hqc256))]
    #[cfg_attr(feature = "sntrup", case::sntrup653(KemScheme::Sntrup653))]
    #[cfg_attr(feature = "sntrup", case::sntrup761(KemScheme::Sntrup761))]
    #[cfg_attr(feature = "sntrup", case::sntrup857(KemScheme::Sntrup857))]
    #[cfg_attr(feature = "sntrup", case::sntrup953(KemScheme::Sntrup953))]
    #[cfg_attr(feature = "sntrup", case::sntrup1013(KemScheme::Sntrup1013))]
    #[cfg_attr(feature = "sntrup", case::sntrup1277(KemScheme::Sntrup1277))]
    fn seeded_keygen_is_deterministic(#[case] scheme: KemScheme) {
        let seed = [7u8; 32];
        let (ek1, dk1) = scheme.keypair_from_seed(&seed).unwrap();
        let (ek2, dk2) = scheme.keypair_from_seed(&seed).unwrap();
        assert_eq!(ek1.to_raw_bytes(), ek2.to_raw_bytes());
        assert_eq!(dk1.to_raw_bytes(), dk2.to_raw_bytes());

        let mut other = [7u8; 32];
        other[0] = 8;
        let (ek3, _) = scheme.keypair_from_seed(&other).unwrap();
        assert_ne!(ek1.to_raw_bytes(), ek3.to_raw_bytes());
    }

    #[cfg(any(feature = "hqc", feature = "sntrup"))]
    /// A seed of the wrong length is rejected rather than silently truncated or padded.
    #[cfg(feature = "kgen")]
    #[rstest]
    #[cfg_attr(feature = "hqc", case::hqc192(KemScheme::Hqc192))]
    #[cfg_attr(feature = "sntrup", case::sntrup761(KemScheme::Sntrup761))]
    fn wrong_seed_length_rejected(#[case] scheme: KemScheme) {
        assert!(matches!(
            scheme.keypair_from_seed(&[0u8; 31]),
            Err(Error::InvalidSeedLength(31))
        ));
    }

    /// A key belonging to one HQC parameter set must not be usable under another.
    ///
    /// The guard binds to the key's stored scheme rather than its byte length; this
    /// test would still pass if two parameter sets ever shared an encoding size.
    #[cfg(all(feature = "hqc", feature = "kgen", feature = "encp", feature = "decp"))]
    #[test]
    fn cross_scheme_hqc_rejected() {
        let (ek_192, dk_192) = KemScheme::Hqc192.keypair().unwrap();
        let (ct_192, _) = KemScheme::Hqc192.encapsulate(&ek_192).unwrap();

        assert!(matches!(
            KemScheme::Hqc128.encapsulate(&ek_192),
            Err(Error::SchemeMismatch { .. })
        ));
        assert!(matches!(
            KemScheme::Hqc256.decapsulate(&ct_192, &dk_192),
            Err(Error::SchemeMismatch { .. })
        ));
    }

    /// A ciphertext from one scheme must not decapsulate under a key from another.
    #[cfg(all(
        feature = "hqc",
        feature = "sntrup",
        feature = "kgen",
        feature = "encp",
        feature = "decp"
    ))]
    #[test]
    fn cross_family_kem_rejected() {
        let (ek_hqc, _) = KemScheme::Hqc192.keypair().unwrap();
        let (ct_hqc, _) = KemScheme::Hqc192.encapsulate(&ek_hqc).unwrap();
        let (_, dk_ntru) = KemScheme::Sntrup761.keypair().unwrap();

        assert!(matches!(
            KemScheme::Sntrup761.decapsulate(&ct_hqc, &dk_ntru),
            Err(Error::SchemeMismatch { .. })
        ));
    }

    #[cfg(any(
        feature = "mceliece",
        feature = "hqc",
        feature = "sntrup",
        feature = "frodo"
    ))]
    /// Raw-byte encodings round-trip, and a truncated encoding is refused.
    #[cfg(feature = "kgen")]
    #[rstest]
    #[cfg_attr(feature = "mceliece", case::m460896(KemScheme::ClassicMcEliece460896))]
    #[cfg_attr(
        feature = "mceliece",
        case::m8192128(KemScheme::ClassicMcEliece8192128)
    )]
    #[cfg_attr(feature = "hqc", case::hqc128(KemScheme::Hqc128))]
    #[cfg_attr(feature = "hqc", case::hqc256(KemScheme::Hqc256))]
    #[cfg_attr(feature = "sntrup", case::sntrup653(KemScheme::Sntrup653))]
    #[cfg_attr(feature = "sntrup", case::sntrup1277(KemScheme::Sntrup1277))]
    #[cfg_attr(feature = "frodo", case::frodo640aes(KemScheme::FrodoKem640Aes))]
    #[cfg_attr(feature = "frodo", case::frodo976shake(KemScheme::FrodoKem976Shake))]
    #[cfg_attr(feature = "frodo", case::frodo1344aes(KemScheme::FrodoKem1344Aes))]
    fn raw_bytes_round_trip(#[case] scheme: KemScheme) {
        #[cfg(feature = "mceliece")]
        let mceliece_bytes = matches!(scheme, mceliece_schemes!()).then(|| {
            let params = scheme.mceliece_algorithm().unwrap().params();
            (
                vec![0; params.encapsulation_key_length],
                vec![0; params.decapsulation_key_length],
            )
        });
        #[cfg(not(feature = "mceliece"))]
        let mceliece_bytes: Option<(Vec<u8>, Vec<u8>)> = None;
        #[cfg(feature = "frodo")]
        let frodo_bytes = matches!(scheme, frodo_schemes!()).then(|| {
            let params = scheme.frodo_algorithm().unwrap().params();
            (
                vec![0; params.encryption_key_length],
                vec![0; params.decryption_key_length],
            )
        });
        #[cfg(not(feature = "frodo"))]
        let frodo_bytes: Option<(Vec<u8>, Vec<u8>)> = None;
        #[cfg(feature = "hqc")]
        let hqc_bytes = match scheme {
            KemScheme::Hqc128 => Some((
                vec![0; hqc_kem::hqc128::PUBLIC_KEY_SIZE],
                vec![0; hqc_kem::hqc128::SECRET_KEY_SIZE],
            )),
            KemScheme::Hqc256 => Some((
                vec![0; hqc_kem::hqc256::PUBLIC_KEY_SIZE],
                vec![0; hqc_kem::hqc256::SECRET_KEY_SIZE],
            )),
            _ => None,
        };
        #[cfg(not(feature = "hqc"))]
        let hqc_bytes: Option<(Vec<u8>, Vec<u8>)> = None;
        #[cfg(feature = "sntrup")]
        let sntrup_bytes = match scheme {
            KemScheme::Sntrup653 => Some((
                vec![0; sntrup::sntrup653::PUBLIC_KEY_SIZE],
                vec![0; sntrup::sntrup653::SECRET_KEY_SIZE],
            )),
            KemScheme::Sntrup1277 => Some((
                vec![0; sntrup::sntrup1277::PUBLIC_KEY_SIZE],
                vec![0; sntrup::sntrup1277::SECRET_KEY_SIZE],
            )),
            _ => None,
        };
        #[cfg(not(feature = "sntrup"))]
        let sntrup_bytes: Option<(Vec<u8>, Vec<u8>)> = None;

        let (ek_bytes, dk_bytes) = mceliece_bytes
            .or(frodo_bytes)
            .or(hqc_bytes)
            .or(sntrup_bytes)
            .unwrap_or_else(|| {
                let (ek, dk) = scheme.keypair().unwrap();
                (ek.to_raw_bytes(), dk.to_raw_bytes())
            });

        let ek2 = KemEncapsulationKey::from_raw_bytes(scheme, &ek_bytes).unwrap();
        assert_eq!(ek_bytes, ek2.to_raw_bytes());
        assert_eq!(scheme, ek2.scheme());

        let dk2 = KemDecapsulationKey::from_raw_bytes(scheme, &dk_bytes).unwrap();
        assert_eq!(dk_bytes, dk2.to_raw_bytes());

        assert!(
            KemEncapsulationKey::from_raw_bytes(scheme, &ek_bytes[..ek_bytes.len() - 1]).is_err()
        );
    }

    #[cfg(any(
        feature = "mceliece",
        feature = "hqc",
        feature = "sntrup",
        feature = "frodo"
    ))]
    /// The scheme enum survives both serde representations and its wire byte is stable.
    #[rstest]
    #[cfg_attr(
        feature = "mceliece",
        case::m348864(KemScheme::ClassicMcEliece348864, "ClassicMcEliece-348864", 4)
    )]
    #[cfg_attr(
        feature = "mceliece",
        case::m460896(KemScheme::ClassicMcEliece460896, "ClassicMcEliece-460896", 21)
    )]
    #[cfg_attr(
        feature = "mceliece",
        case::m6688128(KemScheme::ClassicMcEliece6688128, "ClassicMcEliece-6688128", 22)
    )]
    #[cfg_attr(
        feature = "mceliece",
        case::m6960119(KemScheme::ClassicMcEliece6960119, "ClassicMcEliece-6960119", 23)
    )]
    #[cfg_attr(
        feature = "mceliece",
        case::m8192128(KemScheme::ClassicMcEliece8192128, "ClassicMcEliece-8192128", 24)
    )]
    #[cfg_attr(feature = "hqc", case::hqc128(KemScheme::Hqc128, "HQC-128", 6))]
    #[cfg_attr(feature = "hqc", case::hqc192(KemScheme::Hqc192, "HQC-192", 7))]
    #[cfg_attr(feature = "hqc", case::hqc256(KemScheme::Hqc256, "HQC-256", 8))]
    #[cfg_attr(
        feature = "sntrup",
        case::sntrup653(KemScheme::Sntrup653, "sntrup653", 9)
    )]
    #[cfg_attr(
        feature = "sntrup",
        case::sntrup761(KemScheme::Sntrup761, "sntrup761", 10)
    )]
    #[cfg_attr(
        feature = "sntrup",
        case::sntrup857(KemScheme::Sntrup857, "sntrup857", 11)
    )]
    #[cfg_attr(
        feature = "sntrup",
        case::sntrup953(KemScheme::Sntrup953, "sntrup953", 12)
    )]
    #[cfg_attr(
        feature = "sntrup",
        case::sntrup1013(KemScheme::Sntrup1013, "sntrup1013", 13)
    )]
    #[cfg_attr(
        feature = "sntrup",
        case::sntrup1277(KemScheme::Sntrup1277, "sntrup1277", 14)
    )]
    #[cfg_attr(
        feature = "frodo",
        case::f640a(KemScheme::FrodoKem640Aes, "FrodoKEM-640-AES", 15)
    )]
    #[cfg_attr(
        feature = "frodo",
        case::f640s(KemScheme::FrodoKem640Shake, "FrodoKEM-640-SHAKE", 16)
    )]
    #[cfg_attr(
        feature = "frodo",
        case::f976a(KemScheme::FrodoKem976Aes, "FrodoKEM-976-AES", 17)
    )]
    #[cfg_attr(
        feature = "frodo",
        case::f976s(KemScheme::FrodoKem976Shake, "FrodoKEM-976-SHAKE", 18)
    )]
    #[cfg_attr(
        feature = "frodo",
        case::f1344a(KemScheme::FrodoKem1344Aes, "FrodoKEM-1344-AES", 19)
    )]
    #[cfg_attr(
        feature = "frodo",
        case::f1344s(KemScheme::FrodoKem1344Shake, "FrodoKEM-1344-SHAKE", 20)
    )]
    fn scheme_wire_contract(#[case] scheme: KemScheme, #[case] display: &str, #[case] wire: u8) {
        round_trip_all_formats(&SchemeDocument { scheme });
        assert_eq!(scheme.to_string(), display);
        assert_eq!(u8::from(scheme), wire);
        assert_eq!(KemScheme::try_from(wire).unwrap(), scheme);
        assert_eq!(display.parse::<KemScheme>().unwrap(), scheme);

        let json = serde_json::to_string(&scheme).unwrap();
        assert_eq!(json, format!("\"{display}\""));
        assert_eq!(serde_json::from_str::<KemScheme>(&json).unwrap(), scheme);

        let bytes = postcard::to_stdvec(&scheme).unwrap();
        assert_eq!(bytes, vec![wire]);
        assert_eq!(postcard::from_bytes::<KemScheme>(&bytes).unwrap(), scheme);
    }

    #[cfg(all(feature = "kgen", feature = "encp"))]
    #[rstest]
    #[cfg_attr(feature = "hqc", case::hqc192(KemScheme::Hqc192))]
    #[cfg_attr(feature = "sntrup", case::sntrup761(KemScheme::Sntrup761))]
    #[cfg_attr(feature = "frodo", case::frodo640aes(KemScheme::FrodoKem640Aes))]
    #[cfg_attr(feature = "frodo", case::frodo976shake(KemScheme::FrodoKem976Shake))]
    #[cfg_attr(feature = "ml-kem", case::mlkem768(KemScheme::MlKem768))]
    #[cfg_attr(feature = "ml-kem", case::mlkem1024(KemScheme::MlKem1024))]
    #[cfg_attr(feature = "mceliece", case::mceliece(KemScheme::ClassicMcEliece460896))]
    fn serdes(#[case] scheme: KemScheme) {
        let (ek, dk) = scheme.keypair().unwrap();
        let (ct, ss) = scheme.encapsulate(&ek).unwrap();

        round_trip_all_formats(&ek);
        round_trip_all_formats(&dk);
        round_trip_all_formats(&ct);
        round_trip_all_formats(&ss);
    }

    // Cases here cover only ML-KEM and Classic McEliece, so the test is compiled
    // only when one of those is enabled — otherwise rstest sees zero cases.
    #[cfg(any(feature = "ml-kem", feature = "mceliece"))]
    #[cfg(all(feature = "kgen", feature = "encp", feature = "decp"))]
    #[rstest]
    #[cfg_attr(feature = "ml-kem", case::mlkem768(KemScheme::MlKem768))]
    #[cfg_attr(feature = "ml-kem", case::mlkem1024(KemScheme::MlKem1024))]
    #[cfg_attr(feature = "mceliece", case::mceliece(KemScheme::ClassicMcEliece460896))]
    fn flow(#[case] scheme: KemScheme) {
        let (ek, dk) = scheme.keypair().unwrap();

        let (mut ct, ss) = scheme.encapsulate(&ek).unwrap();
        let ss2 = scheme.decapsulate(&ct, &dk).unwrap();
        assert_eq!(ss, ss2);

        ct.0.value.iter_mut().for_each(|v| *v = v.saturating_add(1));
        let ss2 = scheme.decapsulate(&ct, &dk).unwrap();
        assert_ne!(ss, ss2);
    }

    // Cases here cover only ML-KEM and Classic McEliece, so the test is compiled
    // only when one of those is enabled — otherwise rstest sees zero cases.
    #[cfg(any(feature = "ml-kem", feature = "mceliece"))]
    #[cfg(feature = "kgen")]
    #[rstest]
    #[cfg_attr(feature = "ml-kem", case::mlkem768(KemScheme::MlKem768, 64))]
    #[cfg_attr(feature = "ml-kem", case::mlkem1024(KemScheme::MlKem1024, 64))]
    #[cfg_attr(
        feature = "mceliece",
        case::mceliece(KemScheme::ClassicMcEliece460896, 32)
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

    // Cases here cover only ML-KEM and Classic McEliece, so the test is compiled
    // only when one of those is enabled — otherwise rstest sees zero cases.
    #[cfg(any(feature = "ml-kem", feature = "mceliece"))]
    #[cfg(feature = "kgen")]
    #[rstest]
    #[cfg_attr(
        feature = "mceliece",
        case::mceliece_too_long(KemScheme::ClassicMcEliece460896, 64)
    )]
    #[cfg_attr(
        feature = "mceliece",
        case::mceliece_too_short(KemScheme::ClassicMcEliece460896, 16)
    )]
    #[cfg_attr(feature = "ml-kem", case::mlkem_too_short(KemScheme::MlKem768, 32))]
    #[cfg_attr(feature = "ml-kem", case::mlkem_too_long(KemScheme::MlKem768, 100))]
    fn keypair_from_seed_invalid(#[case] scheme: KemScheme, #[case] seed_len: usize) {
        let seed = vec![0xABu8; seed_len];
        let result = scheme.keypair_from_seed(&seed);
        assert!(result.is_err());
    }

    /// The removed ML-KEM-512 scheme reports a deprecation error (not a generic
    /// `InvalidScheme`) via its old wire discriminant and display string, so data from
    /// an older library version fails with a clear migration message.
    #[test]
    fn ml_kem_512_is_deprecated() {
        assert!(matches!(
            KemScheme::try_from(1),
            Err(Error::DeprecatedScheme {
                scheme: "ML-KEM-512",
                replacement: "ML-KEM-768",
            })
        ));
        assert!(matches!(
            "ML-KEM-512".parse::<KemScheme>(),
            Err(Error::DeprecatedScheme {
                scheme: "ML-KEM-512",
                ..
            })
        ));
    }
}
