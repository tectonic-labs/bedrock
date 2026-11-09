//! Tectonic's common cryptography library.
//!

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(
    feature = "bird-of-prey",
    feature = "falcon",
    feature = "frodo",
    feature = "hqc",
    feature = "hashing",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "mceliece",
    feature = "ml-kem",
    feature = "mayo",
    feature = "sntrup",
    feature = "xmss"
))]
#[macro_use]
mod macros;

#[cfg(feature = "bird-of-prey")]
pub mod bird_of_prey;
#[cfg(any(
    feature = "ecdsa-signatures",
    feature = "ed25519-signatures",
    feature = "rsa-signatures"
))]
pub mod classical_signature;
#[cfg(feature = "bird-of-prey")]
pub mod det_rng;
pub mod error;
#[cfg(feature = "falcon")]
pub mod falcon;
#[cfg(feature = "hashing")]
pub mod hashing;
#[cfg(feature = "hhd")]
// The module implements deprecated compatibility APIs; downstream uses still warn.
#[allow(deprecated)]
pub mod hhd;
#[cfg(any(
    feature = "frodo",
    feature = "hqc",
    feature = "mceliece",
    feature = "ml-kem",
    feature = "sntrup"
))]
#[cfg_attr(
    feature = "mceliece",
    expect(
        deprecated,
        reason = "implements and tests intentional McEliece legacy compatibility; downstream uses still warn"
    )
)]
pub mod kem;
#[cfg(feature = "key-agreement")]
pub mod key_agreement;
#[cfg(feature = "mayo")]
pub mod mayo;
#[cfg(feature = "ml-dsa")]
// The module implements deprecated compatibility APIs; downstream uses still warn.
#[allow(deprecated)]
pub mod ml_dsa;
#[cfg(feature = "multiformats")]
pub mod multiformats;
#[cfg(any(
    feature = "bird-of-prey",
    feature = "falcon",
    feature = "frodo",
    feature = "hqc",
    feature = "mayo",
    feature = "mceliece",
    feature = "ml-dsa",
    feature = "ml-kem",
    feature = "multiformats",
    feature = "slh-dsa",
    feature = "sntrup",
    feature = "xmss"
))]
pub mod plain;
#[cfg(feature = "random")]
pub mod random;
#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;
#[cfg(feature = "symmetric")]
pub mod symmetric;
#[cfg(feature = "xmss")]
pub mod xmss;
#[cfg(feature = "xwing")]
#[cfg_attr(
    feature = "mceliece",
    expect(
        deprecated,
        reason = "implements and tests intentional McEliece legacy compatibility; downstream uses still warn"
    )
)]
pub mod xwing;

#[cfg(all(feature = "xwing", not(any(feature = "ml-kem", feature = "mceliece"))))]
compiler_error!(
    "cannot enable `xwing` without selecting an underlying KEM; enable `ml-kem` or `mceliece`"
);

#[cfg(any(
    feature = "bird-of-prey",
    feature = "frodo",
    feature = "hqc",
    feature = "ml-dsa",
    feature = "mceliece",
    feature = "mayo",
    feature = "slh-dsa",
    feature = "sntrup",
    feature = "xmss"
))]
pub(crate) fn os_rng() -> rand_core_010::UnwrapErr<getrandom_v04::SysRng> {
    rand_core_010::UnwrapErr(getrandom_v04::SysRng)
}

#[cfg(all(
    test,
    any(
        feature = "bird-of-prey",
        feature = "falcon",
        feature = "frodo",
        feature = "hqc",
        feature = "mayo",
        feature = "mceliece",
        feature = "ml-dsa",
        feature = "ml-kem",
        feature = "slh-dsa",
        feature = "sntrup",
        feature = "xmss"
    )
))]
// Not every feature combination runs every helper.
#[allow(clippy::unwrap_used, dead_code)]
mod test_utils {
    #[cfg(feature = "multiformats")]
    use crate::multiformats::{Codec, Multikey};
    use crate::plain::{Plain, RawBytes};
    use serde::Serialize;

    /// Round-trips a value through every serialization format required by the
    /// project: Postcard, CBOR, BARE, JSON, TOML, and YAML.
    pub(crate) fn round_trip_all_formats<T>(value: &T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let bytes = postcard::to_stdvec(value).unwrap();
        assert_eq!(
            value,
            &postcard::from_bytes::<T>(&bytes).unwrap(),
            "postcard"
        );

        let cbor = serde_cbor_2::to_vec(value).unwrap();
        assert_eq!(
            value,
            &serde_cbor_2::from_slice::<T>(&cbor).unwrap(),
            "cbor"
        );

        let bare = serde_bare::to_vec(value).unwrap();
        assert_eq!(value, &serde_bare::from_slice::<T>(&bare).unwrap(), "bare");

        let json = serde_json::to_string(value).unwrap();
        assert_eq!(value, &serde_json::from_str::<T>(&json).unwrap(), "json");

        let toml_text = toml::to_string(value).unwrap();
        assert_eq!(value, &toml::from_str::<T>(&toml_text).unwrap(), "toml");

        let yaml = yaml_serde::to_string(value).unwrap();
        assert_eq!(value, &yaml_serde::from_str::<T>(&yaml).unwrap(), "yaml");
    }

    /// Encodes `value` in every format, so two values can be compared byte for byte.
    fn encodings<T: Serialize>(value: &T) -> [Vec<u8>; 6] {
        [
            postcard::to_stdvec(value).unwrap(),
            serde_cbor_2::to_vec(value).unwrap(),
            serde_bare::to_vec(value).unwrap(),
            serde_json::to_vec(value).unwrap(),
            toml::to_string(value).unwrap().into_bytes(),
            yaml_serde::to_string(value).unwrap().into_bytes(),
        ]
    }

    /// Checks that [`Plain`] writes exactly what the v0.6 derived serde wrote for a
    /// newtype around `inner`, and reads it back.
    pub(crate) fn assert_plain_compatible<T, I>(value: &T, inner: &I)
    where
        T: RawBytes + Clone + PartialEq + std::fmt::Debug,
        I: Serialize,
    {
        #[derive(Serialize)]
        struct Old<'a, I>(&'a I);

        let plain = Plain(value.clone());
        assert_eq!(encodings(&plain), encodings(&Old(inner)));
        round_trip_all_formats(&plain);
    }

    /// Checks a key's Multikey encoding: the codec, byte-identical `key-data`, both
    /// conversions, serde that is exactly the Multikey's, and trailing-byte rejection.
    #[cfg(feature = "multiformats")]
    pub(crate) fn assert_multikey<T>(value: &T, codec: Codec)
    where
        T: RawBytes
            + Serialize
            + serde::de::DeserializeOwned
            + PartialEq
            + std::fmt::Debug
            + multi_util::CodecInfo
            + for<'a> TryFrom<&'a Multikey, Error = crate::error::Error>,
        for<'a> Multikey: TryFrom<&'a T, Error = crate::error::Error>,
    {
        use multi_key::AttrId;
        use multi_util::CodecInfo;

        round_trip_all_formats(value);
        let mk = Multikey::try_from(value).unwrap();
        assert_eq!(mk.codec(), codec);
        assert_eq!(value.codec(), codec);
        assert_eq!(mk.attributes[&AttrId::KeyData].as_slice(), value.as_ref());
        if codec == Codec::Identity {
            assert_eq!(
                mk.attributes[&AttrId::AlgorithmName].as_slice(),
                value.scheme().to_string().as_bytes()
            );
        }
        assert_eq!(&T::try_from(&mk).unwrap(), value);
        assert_eq!(encodings(value), encodings(&mk));

        let mut bytes = Vec::<u8>::from(&mk);
        bytes.push(0);
        let padded = postcard::to_stdvec(&serdect::slice::HexOrBin::<false>(bytes)).unwrap();
        assert!(postcard::from_bytes::<T>(&padded).is_err());
    }

    /// Checks a signature's Multisig encoding, as [`assert_multikey`] does for keys.
    #[cfg(all(
        feature = "multiformats",
        any(
            feature = "bird-of-prey",
            feature = "falcon",
            feature = "mayo",
            feature = "ml-dsa",
            feature = "slh-dsa",
            feature = "xmss"
        )
    ))]
    pub(crate) fn assert_multisig<T>(value: &T, codec: Codec)
    where
        T: RawBytes
            + Serialize
            + serde::de::DeserializeOwned
            + PartialEq
            + std::fmt::Debug
            + multi_util::CodecInfo
            + for<'a> TryFrom<&'a crate::multiformats::Multisig, Error = crate::error::Error>,
        for<'a> crate::multiformats::Multisig: TryFrom<&'a T, Error = crate::error::Error>,
    {
        use crate::multiformats::Multisig;
        use multi_sig::AttrId;
        use multi_util::CodecInfo;

        round_trip_all_formats(value);
        let ms = Multisig::try_from(value).unwrap();
        assert_eq!(ms.codec(), codec);
        assert_eq!(value.codec(), codec);
        assert_eq!(ms.attributes[&AttrId::SigData].as_slice(), value.as_ref());
        assert_eq!(&T::try_from(&ms).unwrap(), value);
        assert_eq!(encodings(value), encodings(&ms));

        let mut bytes = Vec::<u8>::from(&ms);
        bytes.push(0);
        let padded = postcard::to_stdvec(&serdect::slice::HexOrBin::<false>(bytes)).unwrap();
        assert!(postcard::from_bytes::<T>(&padded).is_err());
    }
}
