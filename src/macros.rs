/// Implements `serde::{Serialize, Deserialize}` using strings for human-readable formats
/// and `u8` for non-human-readable formats.
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

/// Defines a scheme enum and its shared impls; schemes dispatch on the enum directly.
///
/// After the active variants, an optional `@deprecated` section lists schemes that have
/// been removed for being too weak. Deprecated schemes get no enum variant, but their
/// old wire discriminant and display string are still recognized by `TryFrom<u8>` and
/// `FromStr`, which return [`Error::DeprecatedScheme`] so data produced by an older
/// version of the library fails with a clear, actionable migration error instead of a
/// generic "invalid scheme".
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
        $(
            @deprecated
            $(
                $dep_display:literal => $dep_value:literal ; $dep_replacement:literal
            ),+
            $(,)?
        )?
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

        scheme_common_impl!(
            $name,
            $($(@cfg($($cfg)+))? $variant => $display ; $value ; $seed_size),+
            $(; deprecated $($dep_display => $dep_value ; $dep_replacement),+)?
        );
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
        $(; deprecated $($dep_display:literal => $dep_value:literal ; $dep_replacement:literal),+ )?
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
                    $($(
                        $dep_value => Err(Error::DeprecatedScheme {
                            scheme: $dep_display,
                            replacement: $dep_replacement,
                        }),
                    )+)?
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
                    $($(
                        $dep_display => Err(Error::DeprecatedScheme {
                            scheme: $dep_display,
                            replacement: $dep_replacement,
                        }),
                    )+)?
                    _ => Err(Error::InvalidSchemeStr(s.to_string())),
                }
            }
        }

        impl $name {
            #[doc = concat!("Returns the seed size for ", stringify!($name), ".")]
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
