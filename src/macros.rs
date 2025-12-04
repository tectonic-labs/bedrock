/// Implements serde::{Serialize, Deserialize} using Strings for human readable formats
/// and u8 for non-human readable formats
macro_rules! serde_impl {
    ($name:ident) => {
        impl serde::Serialize for $name {
            fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if s.is_human_readable() {
                    s.serialize_str(&self.to_string())
                } else {
                    s.serialize_u8(self.into())
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if d.is_human_readable() {
                    let s = String::deserialize(d)?;
                    Ok(s.parse().map_err(serde::de::Error::custom)?)
                } else {
                    let u8 = u8::deserialize(d)?;
                    Ok(u8.try_into().map_err(serde::de::Error::custom)?)
                }
            }
        }
    };
}

macro_rules! scheme_impl {
    (
        $(#[$meta:meta])*
        $name:ident,
        $convert:ident,
        $(
            $(@cfg($($cfg:tt)+))?
            $(#[$variant_meta:meta])*
            $variant:ident => $algorithm:path ; $display:literal ; $value:literal
        ),+
        $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash)]
        pub enum $name {
            $(
                $(#[cfg($($cfg)+)])?
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl From<$name> for $convert {
            fn from(scheme: $name) -> Self {
                match scheme {
                    $(
                        $(#[cfg($($cfg)+)])?
                        $name::$variant => $algorithm,
                    )+
                }
            }
        }

        impl From<&$name> for $convert {
            fn from(scheme: &$name) -> Self {
                Self::from(*scheme)
            }
        }

        impl From<$name> for u8 {
            fn from(scheme: $name) -> Self {
                match scheme {
                    $(
                        $(#[cfg($($cfg)+)])?
                        $name::$variant => $value,
                    )+
                }
            }
        }

        impl From<&$name> for u8 {
            fn from(scheme: &$name) -> Self {
                Self::from(*scheme)
            }
        }

        impl TryFrom<u8> for $name {
            type Error = Error;

            fn try_from(v: u8) -> Result<Self> {
                match v {
                    $(
                        $(#[cfg($($cfg)+)])?
                        $value => Ok($name::$variant),
                    )+
                    _ => Err(Error::InvalidScheme(v)),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}",
                    match self {
                        $(
                            $(#[cfg($($cfg)+)])?
                            $name::$variant => $display,
                        )+
                    }
                )
            }
        }

        impl std::str::FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self> {
                match s {
                    $(
                        $(#[cfg($($cfg)+)])?
                        $display => Ok($name::$variant),
                    )+
                    _ => Err(Error::InvalidSchemeStr(s.to_string())),
                }
            }
        }
    };
}

#[cfg(feature = "ml-dsa")]
macro_rules! base_sign_impl {
    (
        $enum_name:ident,
        $string_name:literal,
        $signing_key:ident,
        $verifying_key:ident,
        $signature:ident,
        $inner:ident,
        $algorithm:ident,
    ) => {
        impl $enum_name {
            #[cfg(feature = "kgen")]
            #[doc = concat!("Generate a new ", stringify!($string_name), " signing and verifying key pair")]
            pub fn keypair(&self) -> Result<($verifying_key, $signing_key)> {
                let alg = self.into();
                let scheme = $algorithm::new(alg)?;
                let (pk, sk) = scheme.keypair()?;

                Ok((
                    $inner {
                        scheme: *self,
                        value: pk.into_vec(),
                    }.into(),
                    $inner {
                        scheme: *self,
                        value: sk.into_vec(),
                    }.into()
                ))
            }

            #[cfg(feature = "kgen")]
            #[doc = concat!("Generate a new ", stringify!($string_name), " signing and verifying key pair")]
            pub fn keypair_from_seed(
                &self,
                seed: &[u8],
            ) -> Result<($verifying_key, $signing_key)> {
                if seed.len() < 32 || seed.len() > 64 {
                    return Err(Error::InvalidSeedLength(seed.len()));
                }
                let alg = self.into();
                let scheme = Sig::new(alg)?;
                let (pk, sk) = scheme.keypair_from_seed(seed)?;
                Ok((
                    $inner {
                        scheme: *self,
                        value: pk.into_vec(),
                    }
                    .into(),
                    $inner {
                        scheme: *self,
                        value: sk.into_vec(),
                    }
                    .into(),
                ))
            }

            #[cfg(feature = "sign")]
            /// Sign a message with the specified signing key
            pub fn sign(&self, message: &[u8], signing_key: &$signing_key) -> Result<$signature> {
                let alg = self.into();
                let scheme = $algorithm::new(alg)?;
                let sk = scheme
                    .secret_key_from_bytes(signing_key.0.value.as_slice())
                    .ok_or_else(|| Error::OqsError("an invalid signing key".to_string()))?;
                let signature = scheme.sign(message, sk)?;
                Ok($inner {
                    scheme: *self,
                    value: signature.into_vec(),
                }
                .into())
            }

            #[cfg(feature = "vrfy")]
            /// Verify a signature
            pub fn verify(
                &self,
                message: &[u8],
                signature: &$signature,
                verification_key: &$verifying_key,
            ) -> Result<()> {
                let alg = self.into();
                let scheme = $algorithm::new(alg)?;
                let sig = scheme
                    .signature_from_bytes(signature.0.value.as_slice())
                    .ok_or_else(|| Error::OqsError("an invalid signature".to_string()))?;
                let vk = scheme
                    .public_key_from_bytes(verification_key.0.value.as_slice())
                    .ok_or_else(|| Error::OqsError("an invalid public key".to_string()))?;
                scheme.verify(message, sig, vk)?;
                Ok(())
            }
        }
    };
}

#[cfg(any(feature = "mceliece", feature = "ml-kem"))]
macro_rules! base_kem_impl {
    (
        $enum_name:ident,
        $string_name:literal,
        $encapsulation_key:ident,
        $decapsulation_key:ident,
        $ciphertext:ident,
        $sharedsecret:ident,
        $inner:ident,
        $algorithm:ident,
    ) => {
        impl $enum_name {
            #[cfg(feature = "kgen")]
            #[doc = concat!("Generate a new ", stringify!($string_name), " encapsulating / decapsulating key pair")]
            pub fn keypair(&self) -> Result<($encapsulation_key, $decapsulation_key)> {
                let alg = self.into();
                let scheme = $algorithm::new(alg)?;
                let (pk, sk) = scheme.keypair()?;

                Ok((
                    $inner {
                        scheme: *self,
                        value: pk.into_vec(),
                    }.into(),
                    $inner {
                        scheme: *self,
                        value: sk.into_vec(),
                    }.into()
                ))
            }

            #[cfg(feature = "kgen")]
            #[doc = concat!("Generate a new ", stringify!($string_name), " encapsulating / decapsulating key pair from a seed")]
            pub fn keypair_from_seed(&self, seed: &[u8]) -> Result<($encapsulation_key, $decapsulation_key)> {
                let alg = self.into();
                let scheme = $algorithm::new(alg)?;
                let seed = scheme.keypair_seed_from_bytes(seed).ok_or(Error::OqsError("an invalid seed length".to_string()))?;

                let (pk, sk) = scheme.keypair_derand(seed)?;

                Ok((
                    $inner {
                        scheme: *self,
                        value: pk.into_vec(),
                    }.into(),
                    $inner {
                        scheme: *self,
                        value: sk.into_vec(),
                    }.into()
                ))
            }

            #[cfg(feature = "encp")]
            /// Encapsulate to the provided public key
            pub fn encapsulate(&self, encapsulation_key: &$encapsulation_key) -> Result<($ciphertext, $sharedsecret)> {
                let alg = self.into();
                let scheme = $algorithm::new(alg)?;
                let ek = scheme
                    .public_key_from_bytes(encapsulation_key.0.value.as_slice())
                    .ok_or_else(|| Error::OqsError("an invalid signing key".to_string()))?;
                let (ct, ss) = scheme.encapsulate(ek)?;
                Ok((
                    $inner {
                        scheme: *self,
                        value: ct.into_vec(),
                    }.into(),
                    $inner {
                        scheme: *self,
                        value: ss.into_vec(),
                    }.into()
                ))
            }

            #[cfg(feature = "decp")]
            /// Decapsulate the provided ciphertext
            pub fn decapsulate(
                &self,
                ciphertext: &$ciphertext,
                decapsulation_key: &$decapsulation_key,
            ) -> Result<$sharedsecret> {
                let alg = self.into();
                let scheme = $algorithm::new(alg)?;
                let ct = scheme
                    .ciphertext_from_bytes(ciphertext.0.value.as_slice())
                    .ok_or_else(|| Error::OqsError("an invalid ciphertext".to_string()))?;
                let sk = scheme
                    .secret_key_from_bytes(decapsulation_key.0.value.as_slice())
                    .ok_or_else(|| Error::OqsError("an invalid decapsulation key".to_string()))?;
                let ss = scheme.decapsulate(sk, ct)?;
                Ok($inner {
                    scheme: *self,
                    value: ss.into_vec(),
                }.into())
            }
        }
    };
}
