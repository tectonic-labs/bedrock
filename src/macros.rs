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

/// Like [`scheme_impl!`] but without the `From<$name>` conversion to an oqs `Algorithm`, for
/// schemes that dispatch on the enum directly.
#[allow(unused_macros)]
macro_rules! scheme_impl_pure {
    (
        $(#[$meta:meta])*
        $name:ident,
        $(
            $(@cfg($($cfg:tt)+))?
            $(#[$variant_meta:meta])*
            $variant:ident => $display:literal ; $value:literal ; $seed_size:literal
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

        scheme_common_impl!($name, $($(@cfg($($cfg)+))? $variant => $display ; $value ; $seed_size),+);
    };
}

/// Shared (algorithm-agnostic) impls for a scheme enum: `u8` conversions, `TryFrom<u8>`,
/// `Display`, `FromStr`, and `seed_size`.
macro_rules! scheme_common_impl {
    (
        $name:ident,
        $(
            $(@cfg($($cfg:tt)+))?
            $variant:ident => $display:literal ; $value:literal ; $seed_size:literal
        ),+
        $(,)?
    ) => {
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

        impl $name {
            #[doc = concat!("Get the seed size for ", stringify!($name))]
            pub fn seed_size(&self) -> usize {
                match self {
                    $(
                        $(#[cfg($($cfg)+)])?
                        $name::$variant => $seed_size,
                    )+
                }
            }
        }

    };
}

/// Like [`scheme_impl_pure!`] but also generates the `From<$name>` conversion to an oqs
/// `Algorithm`, for the KEM schemes.
#[allow(unused_macros)]
macro_rules! scheme_impl {
    (
        $(#[$meta:meta])*
        $name:ident,
        $convert:ident,
        $(
            $(@cfg($($cfg:tt)+))?
            $(#[$variant_meta:meta])*
            $variant:ident => $algorithm:path ; $display:literal ; $value:literal ; $seed_size:literal
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

        scheme_common_impl!($name, $($(@cfg($($cfg)+))? $variant => $display ; $value ; $seed_size),+);
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
                if seed.len() != self.seed_size() {
                    return Err(Error::InvalidSeedLength(seed.len()));
                }
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
