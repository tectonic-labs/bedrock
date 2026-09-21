/// Implements `serde::{Serialize, Deserialize}` using strings for human-readable formats
/// and `u8` for non-human-readable formats.
#[cfg(any(
    feature = "bird-of-prey",
    feature = "falcon",
    feature = "frodo",
    feature = "hqc",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "mceliece",
    feature = "ml-kem",
    feature = "mayo",
    feature = "sntrup",
    feature = "xmss"
))]
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

/// Defines an unkeyed incremental hash and its algorithm-specific fixed output.
#[cfg(feature = "hashing")]
macro_rules! incremental_hash {
    ($context:ident, $digest:ident, $function:ident, $backend:ty, $length:literal,
     $description:literal, $update:expr, $finish:expr) => {
        #[doc = concat!("The ", stringify!($length), "-byte output of ", $description, ".")]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $digest([u8; $length]);

        impl $digest {
            /// Borrows the exact fixed-width digest bytes.
            pub const fn as_array(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $digest {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<[u8; $length]> for $digest {
            fn from(value: [u8; $length]) -> Self {
                Self(value)
            }
        }

        impl From<$digest> for [u8; $length] {
            fn from(value: $digest) -> Self {
                value.0
            }
        }

        impl TryFrom<&[u8]> for $digest {
            type Error = core::array::TryFromSliceError;
            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                <[u8; $length]>::try_from(value).map(Self)
            }
        }

        #[doc = concat!("Incremental ", $description, " state.")]
        #[derive(Clone, Default)]
        pub struct $context($backend);

        impl core::fmt::Debug for $context {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter
                    .debug_struct(stringify!($context))
                    .finish_non_exhaustive()
            }
        }

        impl $context {
            /// Creates an empty, unkeyed hashing context.
            pub fn new() -> Self {
                Self::default()
            }

            /// Absorbs exact bytes without framing, normalization or file I/O.
            pub fn update(&mut self, data: &[u8]) {
                ($update)(&mut self.0, data);
            }

            /// Returns a digest snapshot without consuming or resetting this context.
            pub fn fork_finish(&self) -> $digest {
                self.clone().finish()
            }

            /// Consumes this context and returns its fixed-width digest.
            pub fn finish(self) -> $digest {
                $digest(($finish)(self.0))
            }
        }

        #[doc = concat!("Computes ", $description, " over exactly `data`.")]
        pub fn $function(data: &[u8]) -> $digest {
            let mut context = $context::new();
            context.update(data);
            context.finish()
        }
    };
}

/// Checks independent answers plus streaming, forks, defaults and byte conversions.
#[cfg(all(test, feature = "hashing"))]
macro_rules! incremental_hash_tests {
    ($test:ident, $context:ident, $digest:ident, $function:ident, $length:literal, $empty:literal, $abc:literal, $multiblock:literal) => {
        #[test]
        fn $test() {
            let long: Vec<u8> = (0..=250).cycle().take(2051).collect();
            for (data, answer) in [
                (&[][..], $empty),
                (b"abc".as_slice(), $abc),
                (long.as_slice(), $multiblock),
            ] {
                let expected = $function(data);
                assert_eq!(hex::encode(expected), answer);
                for chunk_size in [
                    1, 7, 63, 64, 65, 127, 128, 135, 136, 137, 167, 168, 169, 1023, 1024, 1025,
                ] {
                    let mut context = $context::new();
                    context.update(&[]);
                    for part in data.chunks(chunk_size) {
                        context.update(part);
                    }
                    assert_eq!(context.fork_finish(), expected);
                    assert_eq!(context.fork_finish(), expected);
                    assert_eq!(context.finish(), expected);
                }
                assert_eq!(
                    $digest::try_from(expected.as_ref()).expect("exact digest length"),
                    expected
                );
                let raw: [u8; $length] = expected.into();
                assert_eq!($digest::from(raw), expected);
                assert_eq!(expected.as_array(), &raw);
                assert!($digest::try_from(&raw[..$length - 1]).is_err());
                assert!($digest::try_from([0_u8; $length + 1].as_slice()).is_err());
            }
            let mut context = $context::default();
            context.update(b"a");
            assert_eq!(context.fork_finish(), $function(b"a"));
            let mut fork = context.clone();
            context.update(b"bc");
            fork.update(b" different");
            assert_eq!(context.finish(), $function(b"abc"));
            assert_eq!(fork.finish(), $function(b"a different"));
            assert_eq!(
                format!("{:?}", $context::new()),
                concat!(stringify!($context), " { .. }")
            );
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
#[cfg(any(
    feature = "bird-of-prey",
    feature = "falcon",
    feature = "frodo",
    feature = "hqc",
    feature = "mayo",
    feature = "mceliece",
    feature = "ml-dsa",
    feature = "ml-kem",
    feature = "slh-dsa",
    feature = "sntrup"
))]
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
#[cfg(any(
    feature = "bird-of-prey",
    feature = "falcon",
    feature = "frodo",
    feature = "hqc",
    feature = "mayo",
    feature = "mceliece",
    feature = "ml-dsa",
    feature = "ml-kem",
    feature = "slh-dsa",
    feature = "sntrup"
))]
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
