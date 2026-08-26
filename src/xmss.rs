//! Stateful XMSS signatures for Bedrock.
//!
//! XMSS is a stateful signature scheme: every signature consumes exactly one
//! one-time leaf, and reusing a leaf reveals the secret key. This module keeps
//! the signing state serialized inside [`XmssSigningKey`] and requires callers
//! to provide durable persistence via [`XmssStateStore`].
//!
//! The critical invariant is commit-before-release: signing advances the leaf
//! index in memory, persists that advanced state through the store, and only
//! then returns the signature and updates the caller-visible signing key. If
//! persistence fails, the signature is discarded and the caller-visible key is
//! left unchanged so the consumed leaf is never released twice.
//!
//! Bedrock performs no filesystem I/O here. Callers must supply a store whose
//! [`XmssStateStore::commit`] implementation is atomic and durable; a torn or
//! non-durable write is a contract violation that can lead to leaf reuse and
//! secret-key compromise.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{deserialize_hex_or_bin, error::*, os_rng, serialize_hex_or_bin};

const OID_LEN: usize = 4;
const INDEX_LEN: usize = 4;

fn xmss_err<E: fmt::Display>(err: E) -> Error {
    Error::XmssError(err.to_string())
}

fn read_index_bytes(state: &[u8]) -> Result<u32> {
    if state.len() < OID_LEN + INDEX_LEN {
        return Err(Error::XmssError(format!(
            "XMSS signing state too short: expected at least {} bytes, got {}",
            OID_LEN + INDEX_LEN,
            state.len()
        )));
    }

    let mut index = [0_u8; INDEX_LEN];
    index.copy_from_slice(&state[OID_LEN..OID_LEN + INDEX_LEN]);
    Ok(u32::from_be_bytes(index))
}

fn validate_signing_key_bytes<P>(bytes: &[u8]) -> Result<()>
where
    P: pq_xmss::XmssParameter,
{
    pq_xmss::SigningKey::<P>::try_from(bytes)
        .map(|_| ())
        .map_err(xmss_err)
}

fn validate_verification_key_bytes<P>(bytes: &[u8]) -> Result<()>
where
    P: pq_xmss::XmssParameter,
{
    pq_xmss::VerifyingKey::<P>::try_from(bytes)
        .map(|_| ())
        .map_err(xmss_err)
}

fn validate_signature_bytes<P>(bytes: &[u8]) -> Result<()>
where
    P: pq_xmss::XmssParameter,
{
    pq_xmss::DetachedSignature::<P>::try_from(bytes)
        .map(|_| ())
        .map_err(xmss_err)
}

/// Tree height metadata for XMSS parameter sets.
///
/// Bedrock exposes signing capacity because every leaf may be used only once
/// or the secret key is revealed.
trait XmssTreeHeight: pq_xmss::XmssParameter {
    /// Full Merkle tree height `h`.
    const FULL_HEIGHT: u32;
}

macro_rules! impl_xmss_tree_height {
    ($($family:ident),+ $(,)?) => {
        $(
            impl<D: pq_xmss::XmssTreeDepth> XmssTreeHeight for pq_xmss::$family<D> {
                const FULL_HEIGHT: u32 = D::HEIGHT;
            }
        )+
    };
}

impl_xmss_tree_height!(
    XmssSha2_192,
    XmssSha2_256,
    XmssSha2_512,
    XmssShake_256,
    XmssShake_512,
    XmssShake256_192,
    XmssShake256_256,
);

/// A non-standard XMSS tree depth exposed by `pq-xmss`'s `extra-depths`
/// feature.
///
/// Heights 10, 16, and 20 are omitted because standardized concrete parameter
/// sets already cover them. Tree generation cost grows exponentially with the
/// height, so applications should choose the smallest sufficient capacity.
/// Binary serialization reserves one slot for every height from 1 through 24,
/// including the three standard heights, so future availability cannot renumber
/// existing extra-depth schemes.
#[cfg(feature = "xmss-extra-depths")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum XmssExtraDepth {
    /// Height 1 (2 signatures).
    H1 = 1,
    /// Height 2 (4 signatures).
    H2 = 2,
    /// Height 3 (8 signatures).
    H3 = 3,
    /// Height 4 (16 signatures).
    H4 = 4,
    /// Height 5 (32 signatures).
    H5 = 5,
    /// Height 6 (64 signatures).
    H6 = 6,
    /// Height 7 (128 signatures).
    H7 = 7,
    /// Height 8 (256 signatures).
    H8 = 8,
    /// Height 9 (512 signatures).
    H9 = 9,
    /// Height 11 (2,048 signatures).
    H11 = 11,
    /// Height 12 (4,096 signatures).
    H12 = 12,
    /// Height 13 (8,192 signatures).
    H13 = 13,
    /// Height 14 (16,384 signatures).
    H14 = 14,
    /// Height 15 (32,768 signatures).
    H15 = 15,
    /// Height 17 (131,072 signatures).
    H17 = 17,
    /// Height 18 (262,144 signatures).
    H18 = 18,
    /// Height 19 (524,288 signatures).
    H19 = 19,
    /// Height 21 (2,097,152 signatures).
    H21 = 21,
    /// Height 22 (4,194,304 signatures).
    H22 = 22,
    /// Height 23 (8,388,608 signatures).
    H23 = 23,
    /// Height 24 (16,777,216 signatures).
    H24 = 24,
}

#[cfg(feature = "xmss-extra-depths")]
impl XmssExtraDepth {
    /// Every available non-standard tree depth in ascending order.
    pub const ALL: [Self; 21] = [
        Self::H1,
        Self::H2,
        Self::H3,
        Self::H4,
        Self::H5,
        Self::H6,
        Self::H7,
        Self::H8,
        Self::H9,
        Self::H11,
        Self::H12,
        Self::H13,
        Self::H14,
        Self::H15,
        Self::H17,
        Self::H18,
        Self::H19,
        Self::H21,
        Self::H22,
        Self::H23,
        Self::H24,
    ];

    /// Returns the numeric Merkle tree height.
    pub const fn height(self) -> u32 {
        self as u32
    }

    /// Converts a numeric height to an available extra depth.
    pub const fn from_height(height: u32) -> Option<Self> {
        match height {
            1 => Some(Self::H1),
            2 => Some(Self::H2),
            3 => Some(Self::H3),
            4 => Some(Self::H4),
            5 => Some(Self::H5),
            6 => Some(Self::H6),
            7 => Some(Self::H7),
            8 => Some(Self::H8),
            9 => Some(Self::H9),
            11 => Some(Self::H11),
            12 => Some(Self::H12),
            13 => Some(Self::H13),
            14 => Some(Self::H14),
            15 => Some(Self::H15),
            17 => Some(Self::H17),
            18 => Some(Self::H18),
            19 => Some(Self::H19),
            21 => Some(Self::H21),
            22 => Some(Self::H22),
            23 => Some(Self::H23),
            24 => Some(Self::H24),
            _ => None,
        }
    }

    const fn wire_slot(self) -> u8 {
        self as u8 - 1
    }
}

/// A hash and output-width family for a non-standard XMSS tree depth.
#[cfg(feature = "xmss-extra-depths")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum XmssExtraDepthFamily {
    /// SHA-256 with a 256-bit output.
    Sha2_256 = 0,
    /// SHA-512 with a 512-bit output.
    Sha2_512 = 1,
    /// SHAKE128 with a 256-bit output.
    Shake128_256 = 2,
    /// SHAKE256 with a 512-bit output.
    Shake256_512 = 3,
    /// SHA-256 with a 192-bit output.
    Sha2_192 = 4,
    /// SHAKE256 with a 256-bit output.
    Shake256_256 = 5,
    /// SHAKE256 with a 192-bit output.
    Shake256_192 = 6,
}

#[cfg(feature = "xmss-extra-depths")]
impl XmssExtraDepthFamily {
    /// Every extra-depth parameter family in `pq-xmss`'s private-use OID order.
    pub const ALL: [Self; 7] = [
        Self::Sha2_256,
        Self::Sha2_512,
        Self::Shake128_256,
        Self::Shake256_512,
        Self::Sha2_192,
        Self::Shake256_256,
        Self::Shake256_192,
    ];

    const fn wire_index(self) -> u8 {
        self as u8
    }

    const fn from_wire_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Sha2_256),
            1 => Some(Self::Sha2_512),
            2 => Some(Self::Shake128_256),
            3 => Some(Self::Shake256_512),
            4 => Some(Self::Sha2_192),
            5 => Some(Self::Shake256_256),
            6 => Some(Self::Shake256_192),
            _ => None,
        }
    }

    const fn name_parts(self) -> (&'static str, u16) {
        match self {
            Self::Sha2_256 => ("SHA2", 256),
            Self::Sha2_512 => ("SHA2", 512),
            Self::Shake128_256 => ("SHAKE", 256),
            Self::Shake256_512 => ("SHAKE", 512),
            Self::Sha2_192 => ("SHA2", 192),
            Self::Shake256_256 => ("SHAKE256", 256),
            Self::Shake256_192 => ("SHAKE256", 192),
        }
    }

    const fn seed_size(self) -> usize {
        match self {
            Self::Sha2_192 | Self::Shake256_192 => 72,
            Self::Sha2_256 | Self::Shake128_256 | Self::Shake256_256 => 96,
            Self::Sha2_512 | Self::Shake256_512 => 192,
        }
    }
}

#[cfg(feature = "xmss-extra-depths")]
const XMSS_EXTRA_DEPTH_WIRE_START: u8 = 22;
#[cfg(feature = "xmss-extra-depths")]
const XMSS_EXTRA_DEPTHS_PER_FAMILY: u8 = 24;
#[cfg(feature = "xmss-extra-depths")]
const XMSS_EXTRA_DEPTH_WIRE_END: u8 = XMSS_EXTRA_DEPTH_WIRE_START
    + XMSS_EXTRA_DEPTHS_PER_FAMILY * XmssExtraDepthFamily::ALL.len() as u8
    - 1;

/// Supported XMSS parameter sets.
///
/// Each scheme has a fixed Merkle tree height and therefore a fixed maximum
/// number of signatures. Reusing a consumed leaf reveals the secret key.
/// Binary serialization retains values 1–12 for Bedrock's original schemes,
/// assigns 13–21 to the additional standard schemes, and starts the optional
/// extra-depth family blocks at 22.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum XmssScheme {
    #[default]
    /// `XMSS-SHA2_10_256`: SHA-256, tree height 10 (2^10 signatures).
    XmssSha2_10_256,
    /// `XMSS-SHA2_16_256`: SHA-256, tree height 16 (2^16 signatures).
    XmssSha2_16_256,
    /// `XMSS-SHA2_20_256`: SHA-256, tree height 20 (2^20 signatures).
    XmssSha2_20_256,
    /// `XMSS-SHA2_10_512`: SHA-512, tree height 10 (2^10 signatures).
    XmssSha2_10_512,
    /// `XMSS-SHA2_16_512`: SHA-512, tree height 16 (2^16 signatures).
    XmssSha2_16_512,
    /// `XMSS-SHA2_20_512`: SHA-512, tree height 20 (2^20 signatures).
    XmssSha2_20_512,
    /// `XMSS-SHAKE256_10_256`: SHAKE256, tree height 10 (2^10 signatures).
    XmssShake256_10_256,
    /// `XMSS-SHAKE256_16_256`: SHAKE256, tree height 16 (2^16 signatures).
    XmssShake256_16_256,
    /// `XMSS-SHAKE256_20_256`: SHAKE256, tree height 20 (2^20 signatures).
    XmssShake256_20_256,
    /// Maps to upstream `pq_xmss::XmssShake_10_512`, whose canonical RFC 8391 name
    /// is `XMSS-SHAKE_10_512`. The upstream crate exports no distinct
    /// `XmssShake256_10_512` marker type: RFC 8391 defines the SHAKE-512 family
    /// as `XMSS-SHAKE_*_512`, and the `SHAKE256_*` names from NIST SP 800-208
    /// exist only at the 256 width.
    XmssShake256_10_512,
    /// Maps to upstream `pq_xmss::XmssShake_16_512`, whose canonical RFC 8391 name
    /// is `XMSS-SHAKE_16_512`. See [`XmssScheme::XmssShake256_10_512`].
    XmssShake256_16_512,
    /// Maps to upstream `pq_xmss::XmssShake_20_512`, whose canonical RFC 8391 name
    /// is `XMSS-SHAKE_20_512`. See [`XmssScheme::XmssShake256_10_512`].
    XmssShake256_20_512,
    /// `XMSS-SHA2_10_192`: SHA-256, 192-bit output, and tree height 10.
    XmssSha2_10_192,
    /// `XMSS-SHA2_16_192`: SHA-256, 192-bit output, and tree height 16.
    XmssSha2_16_192,
    /// `XMSS-SHA2_20_192`: SHA-256, 192-bit output, and tree height 20.
    XmssSha2_20_192,
    /// `XMSS-SHAKE_10_256`: SHAKE128, 256-bit output, and tree height 10.
    XmssShake128_10_256,
    /// `XMSS-SHAKE_16_256`: SHAKE128, 256-bit output, and tree height 16.
    XmssShake128_16_256,
    /// `XMSS-SHAKE_20_256`: SHAKE128, 256-bit output, and tree height 20.
    XmssShake128_20_256,
    /// `XMSS-SHAKE256_10_192`: SHAKE256, 192-bit output, and tree height 10.
    XmssShake256_10_192,
    /// `XMSS-SHAKE256_16_192`: SHAKE256, 192-bit output, and tree height 16.
    XmssShake256_16_192,
    /// `XMSS-SHAKE256_20_192`: SHAKE256, 192-bit output, and tree height 20.
    XmssShake256_20_192,
    /// A non-standard `pq-xmss` parameter family and tree depth.
    ///
    /// The serialized key OID is private-use and interoperates only with
    /// implementations that use `pq-xmss`'s extra-depth encoding.
    #[cfg(feature = "xmss-extra-depths")]
    ExtraDepth {
        /// Hash function and output width.
        family: XmssExtraDepthFamily,
        /// Non-standard Merkle tree depth.
        depth: XmssExtraDepth,
    },
}

impl From<XmssScheme> for u8 {
    fn from(scheme: XmssScheme) -> Self {
        match scheme {
            XmssScheme::XmssSha2_10_256 => 1,
            XmssScheme::XmssSha2_16_256 => 2,
            XmssScheme::XmssSha2_20_256 => 3,
            XmssScheme::XmssSha2_10_512 => 4,
            XmssScheme::XmssSha2_16_512 => 5,
            XmssScheme::XmssSha2_20_512 => 6,
            XmssScheme::XmssShake256_10_256 => 7,
            XmssScheme::XmssShake256_16_256 => 8,
            XmssScheme::XmssShake256_20_256 => 9,
            XmssScheme::XmssShake256_10_512 => 10,
            XmssScheme::XmssShake256_16_512 => 11,
            XmssScheme::XmssShake256_20_512 => 12,
            XmssScheme::XmssSha2_10_192 => 13,
            XmssScheme::XmssSha2_16_192 => 14,
            XmssScheme::XmssSha2_20_192 => 15,
            XmssScheme::XmssShake128_10_256 => 16,
            XmssScheme::XmssShake128_16_256 => 17,
            XmssScheme::XmssShake128_20_256 => 18,
            XmssScheme::XmssShake256_10_192 => 19,
            XmssScheme::XmssShake256_16_192 => 20,
            XmssScheme::XmssShake256_20_192 => 21,
            #[cfg(feature = "xmss-extra-depths")]
            XmssScheme::ExtraDepth { family, depth } => {
                XMSS_EXTRA_DEPTH_WIRE_START
                    + family.wire_index() * XMSS_EXTRA_DEPTHS_PER_FAMILY
                    + depth.wire_slot()
            }
        }
    }
}

impl From<&XmssScheme> for u8 {
    fn from(scheme: &XmssScheme) -> Self {
        Self::from(*scheme)
    }
}

impl TryFrom<u8> for XmssScheme {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::XmssSha2_10_256),
            2 => Ok(Self::XmssSha2_16_256),
            3 => Ok(Self::XmssSha2_20_256),
            4 => Ok(Self::XmssSha2_10_512),
            5 => Ok(Self::XmssSha2_16_512),
            6 => Ok(Self::XmssSha2_20_512),
            7 => Ok(Self::XmssShake256_10_256),
            8 => Ok(Self::XmssShake256_16_256),
            9 => Ok(Self::XmssShake256_20_256),
            10 => Ok(Self::XmssShake256_10_512),
            11 => Ok(Self::XmssShake256_16_512),
            12 => Ok(Self::XmssShake256_20_512),
            13 => Ok(Self::XmssSha2_10_192),
            14 => Ok(Self::XmssSha2_16_192),
            15 => Ok(Self::XmssSha2_20_192),
            16 => Ok(Self::XmssShake128_10_256),
            17 => Ok(Self::XmssShake128_16_256),
            18 => Ok(Self::XmssShake128_20_256),
            19 => Ok(Self::XmssShake256_10_192),
            20 => Ok(Self::XmssShake256_16_192),
            21 => Ok(Self::XmssShake256_20_192),
            #[cfg(feature = "xmss-extra-depths")]
            XMSS_EXTRA_DEPTH_WIRE_START..=XMSS_EXTRA_DEPTH_WIRE_END => {
                let offset = value - XMSS_EXTRA_DEPTH_WIRE_START;
                let family =
                    XmssExtraDepthFamily::from_wire_index(offset / XMSS_EXTRA_DEPTHS_PER_FAMILY)
                        .ok_or(Error::InvalidScheme(value))?;
                let depth = XmssExtraDepth::from_height(
                    u32::from(offset % XMSS_EXTRA_DEPTHS_PER_FAMILY) + 1,
                )
                .ok_or(Error::InvalidScheme(value))?;
                Ok(Self::ExtraDepth { family, depth })
            }
            _ => Err(Error::InvalidScheme(value)),
        }
    }
}

impl fmt::Display for XmssScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XmssSha2_10_256 => f.write_str("XMSS-SHA2_10_256"),
            Self::XmssSha2_16_256 => f.write_str("XMSS-SHA2_16_256"),
            Self::XmssSha2_20_256 => f.write_str("XMSS-SHA2_20_256"),
            Self::XmssSha2_10_512 => f.write_str("XMSS-SHA2_10_512"),
            Self::XmssSha2_16_512 => f.write_str("XMSS-SHA2_16_512"),
            Self::XmssSha2_20_512 => f.write_str("XMSS-SHA2_20_512"),
            Self::XmssShake256_10_256 => f.write_str("XMSS-SHAKE256_10_256"),
            Self::XmssShake256_16_256 => f.write_str("XMSS-SHAKE256_16_256"),
            Self::XmssShake256_20_256 => f.write_str("XMSS-SHAKE256_20_256"),
            Self::XmssShake256_10_512 => f.write_str("XMSS-SHAKE_10_512"),
            Self::XmssShake256_16_512 => f.write_str("XMSS-SHAKE_16_512"),
            Self::XmssShake256_20_512 => f.write_str("XMSS-SHAKE_20_512"),
            Self::XmssSha2_10_192 => f.write_str("XMSS-SHA2_10_192"),
            Self::XmssSha2_16_192 => f.write_str("XMSS-SHA2_16_192"),
            Self::XmssSha2_20_192 => f.write_str("XMSS-SHA2_20_192"),
            Self::XmssShake128_10_256 => f.write_str("XMSS-SHAKE_10_256"),
            Self::XmssShake128_16_256 => f.write_str("XMSS-SHAKE_16_256"),
            Self::XmssShake128_20_256 => f.write_str("XMSS-SHAKE_20_256"),
            Self::XmssShake256_10_192 => f.write_str("XMSS-SHAKE256_10_192"),
            Self::XmssShake256_16_192 => f.write_str("XMSS-SHAKE256_16_192"),
            Self::XmssShake256_20_192 => f.write_str("XMSS-SHAKE256_20_192"),
            #[cfg(feature = "xmss-extra-depths")]
            Self::ExtraDepth { family, depth } => {
                let (hash, bits) = family.name_parts();
                write!(f, "XMSS-{hash}_{}_{bits}", depth.height())
            }
        }
    }
}

impl std::str::FromStr for XmssScheme {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let standard = match value {
            "XMSS-SHA2_10_256" => Some(Self::XmssSha2_10_256),
            "XMSS-SHA2_16_256" => Some(Self::XmssSha2_16_256),
            "XMSS-SHA2_20_256" => Some(Self::XmssSha2_20_256),
            "XMSS-SHA2_10_512" => Some(Self::XmssSha2_10_512),
            "XMSS-SHA2_16_512" => Some(Self::XmssSha2_16_512),
            "XMSS-SHA2_20_512" => Some(Self::XmssSha2_20_512),
            "XMSS-SHAKE256_10_256" => Some(Self::XmssShake256_10_256),
            "XMSS-SHAKE256_16_256" => Some(Self::XmssShake256_16_256),
            "XMSS-SHAKE256_20_256" => Some(Self::XmssShake256_20_256),
            "XMSS-SHAKE_10_512" => Some(Self::XmssShake256_10_512),
            "XMSS-SHAKE_16_512" => Some(Self::XmssShake256_16_512),
            "XMSS-SHAKE_20_512" => Some(Self::XmssShake256_20_512),
            "XMSS-SHA2_10_192" => Some(Self::XmssSha2_10_192),
            "XMSS-SHA2_16_192" => Some(Self::XmssSha2_16_192),
            "XMSS-SHA2_20_192" => Some(Self::XmssSha2_20_192),
            "XMSS-SHAKE_10_256" => Some(Self::XmssShake128_10_256),
            "XMSS-SHAKE_16_256" => Some(Self::XmssShake128_16_256),
            "XMSS-SHAKE_20_256" => Some(Self::XmssShake128_20_256),
            "XMSS-SHAKE256_10_192" => Some(Self::XmssShake256_10_192),
            "XMSS-SHAKE256_16_192" => Some(Self::XmssShake256_16_192),
            "XMSS-SHAKE256_20_192" => Some(Self::XmssShake256_20_192),
            _ => None,
        };
        if let Some(scheme) = standard {
            return Ok(scheme);
        }

        #[cfg(feature = "xmss-extra-depths")]
        if let Some(extra) = parse_extra_depth_scheme(value) {
            return Ok(extra);
        }

        Err(Error::InvalidSchemeStr(value.to_string()))
    }
}

#[cfg(feature = "xmss-extra-depths")]
fn parse_extra_depth_scheme(value: &str) -> Option<XmssScheme> {
    let mut parts = value.strip_prefix("XMSS-")?.split('_');
    let hash = parts.next()?;
    let height = parts.next()?.parse().ok()?;
    let bits = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }

    let depth = XmssExtraDepth::from_height(height)?;
    let family = match (hash, bits) {
        ("SHA2", 192) => XmssExtraDepthFamily::Sha2_192,
        ("SHA2", 256) => XmssExtraDepthFamily::Sha2_256,
        ("SHA2", 512) => XmssExtraDepthFamily::Sha2_512,
        ("SHAKE", 256) => XmssExtraDepthFamily::Shake128_256,
        ("SHAKE", 512) => XmssExtraDepthFamily::Shake256_512,
        ("SHAKE256", 192) => XmssExtraDepthFamily::Shake256_192,
        ("SHAKE256", 256) => XmssExtraDepthFamily::Shake256_256,
        _ => return None,
    };
    Some(XmssScheme::ExtraDepth { family, depth })
}

impl XmssScheme {
    /// Constructs one of the 147 non-standard parameter sets exposed by the
    /// `xmss-extra-depths` feature.
    #[cfg(feature = "xmss-extra-depths")]
    pub const fn extra_depth(family: XmssExtraDepthFamily, depth: XmssExtraDepth) -> Self {
        Self::ExtraDepth { family, depth }
    }

    /// Returns the extra-depth family and depth, or `None` for a standardized
    /// parameter set.
    #[cfg(feature = "xmss-extra-depths")]
    pub const fn extra_depth_params(self) -> Option<(XmssExtraDepthFamily, XmssExtraDepth)> {
        match self {
            Self::ExtraDepth { family, depth } => Some((family, depth)),
            _ => None,
        }
    }

    /// Returns the seed size for this XMSS parameter set.
    pub const fn seed_size(&self) -> usize {
        match self {
            Self::XmssSha2_10_192
            | Self::XmssSha2_16_192
            | Self::XmssSha2_20_192
            | Self::XmssShake256_10_192
            | Self::XmssShake256_16_192
            | Self::XmssShake256_20_192 => 72,
            Self::XmssSha2_10_256
            | Self::XmssSha2_16_256
            | Self::XmssSha2_20_256
            | Self::XmssShake128_10_256
            | Self::XmssShake128_16_256
            | Self::XmssShake128_20_256
            | Self::XmssShake256_10_256
            | Self::XmssShake256_16_256
            | Self::XmssShake256_20_256 => 96,
            Self::XmssSha2_10_512
            | Self::XmssSha2_16_512
            | Self::XmssSha2_20_512
            | Self::XmssShake256_10_512
            | Self::XmssShake256_16_512
            | Self::XmssShake256_20_512 => 192,
            #[cfg(feature = "xmss-extra-depths")]
            Self::ExtraDepth { family, .. } => family.seed_size(),
        }
    }
}

serde_impl!(XmssScheme);

#[cfg(feature = "xmss-extra-depths")]
macro_rules! with_extra_xmss_depth {
    ($family:ident, $depth:expr, |$P:ident| $body:block) => {{
        match $depth {
            XmssExtraDepth::H1 => {
                type $P = pq_xmss::$family<pq_xmss::H1>;
                $body
            }
            XmssExtraDepth::H2 => {
                type $P = pq_xmss::$family<pq_xmss::H2>;
                $body
            }
            XmssExtraDepth::H3 => {
                type $P = pq_xmss::$family<pq_xmss::H3>;
                $body
            }
            XmssExtraDepth::H4 => {
                type $P = pq_xmss::$family<pq_xmss::H4>;
                $body
            }
            XmssExtraDepth::H5 => {
                type $P = pq_xmss::$family<pq_xmss::H5>;
                $body
            }
            XmssExtraDepth::H6 => {
                type $P = pq_xmss::$family<pq_xmss::H6>;
                $body
            }
            XmssExtraDepth::H7 => {
                type $P = pq_xmss::$family<pq_xmss::H7>;
                $body
            }
            XmssExtraDepth::H8 => {
                type $P = pq_xmss::$family<pq_xmss::H8>;
                $body
            }
            XmssExtraDepth::H9 => {
                type $P = pq_xmss::$family<pq_xmss::H9>;
                $body
            }
            XmssExtraDepth::H11 => {
                type $P = pq_xmss::$family<pq_xmss::H11>;
                $body
            }
            XmssExtraDepth::H12 => {
                type $P = pq_xmss::$family<pq_xmss::H12>;
                $body
            }
            XmssExtraDepth::H13 => {
                type $P = pq_xmss::$family<pq_xmss::H13>;
                $body
            }
            XmssExtraDepth::H14 => {
                type $P = pq_xmss::$family<pq_xmss::H14>;
                $body
            }
            XmssExtraDepth::H15 => {
                type $P = pq_xmss::$family<pq_xmss::H15>;
                $body
            }
            XmssExtraDepth::H17 => {
                type $P = pq_xmss::$family<pq_xmss::H17>;
                $body
            }
            XmssExtraDepth::H18 => {
                type $P = pq_xmss::$family<pq_xmss::H18>;
                $body
            }
            XmssExtraDepth::H19 => {
                type $P = pq_xmss::$family<pq_xmss::H19>;
                $body
            }
            XmssExtraDepth::H21 => {
                type $P = pq_xmss::$family<pq_xmss::H21>;
                $body
            }
            XmssExtraDepth::H22 => {
                type $P = pq_xmss::$family<pq_xmss::H22>;
                $body
            }
            XmssExtraDepth::H23 => {
                type $P = pq_xmss::$family<pq_xmss::H23>;
                $body
            }
            XmssExtraDepth::H24 => {
                type $P = pq_xmss::$family<pq_xmss::H24>;
                $body
            }
        }
    }};
}

macro_rules! with_xmss_params {
    ($scheme:expr, |$P:ident| $body:block) => {{
        match $scheme {
            XmssScheme::XmssSha2_10_256 => {
                type $P = pq_xmss::XmssSha2_256<pq_xmss::H10>;
                $body
            }
            XmssScheme::XmssSha2_16_256 => {
                type $P = pq_xmss::XmssSha2_256<pq_xmss::H16>;
                $body
            }
            XmssScheme::XmssSha2_20_256 => {
                type $P = pq_xmss::XmssSha2_256<pq_xmss::H20>;
                $body
            }
            XmssScheme::XmssSha2_10_512 => {
                type $P = pq_xmss::XmssSha2_512<pq_xmss::H10>;
                $body
            }
            XmssScheme::XmssSha2_16_512 => {
                type $P = pq_xmss::XmssSha2_512<pq_xmss::H16>;
                $body
            }
            XmssScheme::XmssSha2_20_512 => {
                type $P = pq_xmss::XmssSha2_512<pq_xmss::H20>;
                $body
            }
            XmssScheme::XmssShake256_10_256 => {
                type $P = pq_xmss::XmssShake256_256<pq_xmss::H10>;
                $body
            }
            XmssScheme::XmssShake256_16_256 => {
                type $P = pq_xmss::XmssShake256_256<pq_xmss::H16>;
                $body
            }
            XmssScheme::XmssShake256_20_256 => {
                type $P = pq_xmss::XmssShake256_256<pq_xmss::H20>;
                $body
            }
            XmssScheme::XmssShake256_10_512 => {
                type $P = pq_xmss::XmssShake_512<pq_xmss::H10>;
                $body
            }
            XmssScheme::XmssShake256_16_512 => {
                type $P = pq_xmss::XmssShake_512<pq_xmss::H16>;
                $body
            }
            XmssScheme::XmssShake256_20_512 => {
                type $P = pq_xmss::XmssShake_512<pq_xmss::H20>;
                $body
            }
            XmssScheme::XmssSha2_10_192 => {
                type $P = pq_xmss::XmssSha2_192<pq_xmss::H10>;
                $body
            }
            XmssScheme::XmssSha2_16_192 => {
                type $P = pq_xmss::XmssSha2_192<pq_xmss::H16>;
                $body
            }
            XmssScheme::XmssSha2_20_192 => {
                type $P = pq_xmss::XmssSha2_192<pq_xmss::H20>;
                $body
            }
            XmssScheme::XmssShake128_10_256 => {
                type $P = pq_xmss::XmssShake_256<pq_xmss::H10>;
                $body
            }
            XmssScheme::XmssShake128_16_256 => {
                type $P = pq_xmss::XmssShake_256<pq_xmss::H16>;
                $body
            }
            XmssScheme::XmssShake128_20_256 => {
                type $P = pq_xmss::XmssShake_256<pq_xmss::H20>;
                $body
            }
            XmssScheme::XmssShake256_10_192 => {
                type $P = pq_xmss::XmssShake256_192<pq_xmss::H10>;
                $body
            }
            XmssScheme::XmssShake256_16_192 => {
                type $P = pq_xmss::XmssShake256_192<pq_xmss::H16>;
                $body
            }
            XmssScheme::XmssShake256_20_192 => {
                type $P = pq_xmss::XmssShake256_192<pq_xmss::H20>;
                $body
            }
            #[cfg(feature = "xmss-extra-depths")]
            XmssScheme::ExtraDepth { family, depth } => match family {
                XmssExtraDepthFamily::Sha2_256 => {
                    with_extra_xmss_depth!(XmssSha2_256, depth, |$P| $body)
                }
                XmssExtraDepthFamily::Sha2_512 => {
                    with_extra_xmss_depth!(XmssSha2_512, depth, |$P| $body)
                }
                XmssExtraDepthFamily::Shake128_256 => {
                    with_extra_xmss_depth!(XmssShake_256, depth, |$P| $body)
                }
                XmssExtraDepthFamily::Shake256_512 => {
                    with_extra_xmss_depth!(XmssShake_512, depth, |$P| $body)
                }
                XmssExtraDepthFamily::Sha2_192 => {
                    with_extra_xmss_depth!(XmssSha2_192, depth, |$P| $body)
                }
                XmssExtraDepthFamily::Shake256_256 => {
                    with_extra_xmss_depth!(XmssShake256_256, depth, |$P| $body)
                }
                XmssExtraDepthFamily::Shake256_192 => {
                    with_extra_xmss_depth!(XmssShake256_192, depth, |$P| $body)
                }
            },
        }
    }};
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct InnerXmss {
    scheme: XmssScheme,
    #[serde(
        serialize_with = "serialize_hex_or_bin",
        deserialize_with = "deserialize_hex_or_bin"
    )]
    value: Vec<u8>,
}

impl InnerXmss {
    fn new(scheme: XmssScheme, value: Vec<u8>) -> Self {
        Self { scheme, value }
    }
}

macro_rules! impl_xmss_wrapper {
    ($name:ident, $validate:ident, $raw_doc:literal, $from_doc:literal) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("scheme", &self.0.scheme)
                    .field("value", &"<redacted>")
                    .finish()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0.value
            }
        }

        impl From<InnerXmss> for $name {
            fn from(value: InnerXmss) -> Self {
                Self(value)
            }
        }

        impl $name {
            /// Returns the scheme recorded alongside this value.
            pub fn scheme(&self) -> XmssScheme {
                self.0.scheme
            }

            #[doc = $raw_doc]
            pub fn to_raw_bytes(&self) -> Vec<u8> {
                self.0.value.clone()
            }

            #[doc = $from_doc]
            pub fn from_raw_bytes(scheme: XmssScheme, bytes: &[u8]) -> Result<Self> {
                scheme.$validate(bytes)?;
                Ok(Self(InnerXmss::new(scheme, bytes.to_vec())))
            }
        }
    };
}

/// Durable persistence contract for XMSS signing state.
///
/// XMSS is stateful: every signature advances the secret leaf index, and
/// reusing a leaf reveals the secret key. Implementations of this trait must
/// therefore persist the serialized signing state atomically and durably.
///
/// `commit` must not return `Ok(())` until the advanced state is safely stored
/// such that it survives power loss. A torn or non-durable write is a contract
/// violation and can cause leaf reuse and secret-key compromise.
///
/// This trait intentionally does not expose cloning or export semantics beyond
/// raw state persistence. Mirroring PKCS#11 restrictions on copying sensitive
/// state, callers should treat persisted XMSS signing state as unique.
pub trait XmssStateStore {
    /// Load the most recently committed serialized signing state, if any.
    ///
    /// Returning a stale state can rewind the signing index and reveal the
    /// secret key through leaf reuse.
    fn load(&self) -> Result<Option<Vec<u8>>>;

    /// Atomically and durably persist the provided serialized signing state.
    ///
    /// Returning before the write is durable is a contract violation because a
    /// subsequent crash can cause leaf reuse and secret-key compromise.
    fn commit(&mut self, state: &[u8]) -> Result<()>;
}

/// Serialized XMSS signing key state.
///
/// This contains the full XMSS secret-key state including the current leaf
/// index. Reusing a consumed leaf reveals the secret key, so callers must
/// persist advanced state durably before releasing signatures.
#[repr(transparent)]
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct XmssSigningKey(pub(crate) InnerXmss);

impl_xmss_wrapper!(
    XmssSigningKey,
    validate_signing_key,
    "Returns a copy of the raw serialized signing state.",
    "Reconstructs a signing key from serialized bytes for a specific scheme. Callers must reject stale or rewound state because it can cause one-time leaf reuse."
);

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for XmssSigningKey {
    fn zeroize(&mut self) {
        self.0.value.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for XmssSigningKey {}

impl Drop for XmssSigningKey {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.0.value.zeroize();
        }
    }
}

/// Serialized XMSS verification key.
///
/// Verification keys are scheme-bound. Mismatching the stored scheme is always
/// rejected because byte length is not a safe discriminator.
#[repr(transparent)]
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct XmssVerificationKey(pub(crate) InnerXmss);

impl_xmss_wrapper!(
    XmssVerificationKey,
    validate_verification_key,
    "Returns a copy of the raw serialized verification key bytes.",
    "Reconstructs a verification key from serialized bytes for a scheme."
);

/// Serialized detached XMSS signature.
///
/// Signatures are scheme-bound and every valid signature corresponds to a
/// unique consumed leaf. Releasing two signatures from the same leaf reveals
/// the secret key.
#[repr(transparent)]
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct XmssSignature(pub(crate) InnerXmss);

impl_xmss_wrapper!(
    XmssSignature,
    validate_signature,
    "Returns a copy of the raw detached signature bytes.",
    "Reconstructs a detached signature from serialized bytes for a scheme."
);

impl XmssScheme {
    fn validate_signing_key(&self, bytes: &[u8]) -> Result<()> {
        with_xmss_params!(*self, |P| { validate_signing_key_bytes::<P>(bytes) })
    }

    fn validate_verification_key(&self, bytes: &[u8]) -> Result<()> {
        with_xmss_params!(*self, |P| { validate_verification_key_bytes::<P>(bytes) })
    }

    fn validate_signature(&self, bytes: &[u8]) -> Result<()> {
        with_xmss_params!(*self, |P| { validate_signature_bytes::<P>(bytes) })
    }

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

    /// Returns the XMSS Merkle tree height `h`.
    ///
    /// A key supports exactly `2^h` signatures. Reusing a consumed leaf reveals
    /// the secret key.
    pub fn tree_height(&self) -> u32 {
        with_xmss_params!(*self, |P| { <P as XmssTreeHeight>::FULL_HEIGHT })
    }

    /// Returns the maximum number of signatures for this scheme.
    ///
    /// Once this many signatures have been consumed, the key is exhausted and
    /// must never sign again or the secret key is revealed.
    pub fn max_signatures(&self) -> u64 {
        1_u64 << self.tree_height()
    }

    /// Reads the current leaf index from a serialized signing key.
    ///
    /// The stored scheme must match exactly. Short or malformed state returns
    /// an error instead of defaulting to leaf `0`, because silent rewind risks
    /// leaf reuse and secret-key compromise.
    pub fn current_index(&self, key: &XmssSigningKey) -> Result<u64> {
        self.ensure_scheme(key.0.scheme)?;
        read_index_bytes(&key.0.value).map(u64::from)
    }

    /// Returns the number of remaining signatures for a signing key.
    ///
    /// The stored scheme must match exactly. Reusing a consumed leaf reveals
    /// the secret key.
    pub fn remaining(&self, key: &XmssSigningKey) -> Result<u64> {
        Ok(self
            .max_signatures()
            .saturating_sub(self.current_index(key)?))
    }

    /// Generates a fresh keypair.
    ///
    /// The returned signing key starts at leaf `0` and has not been persisted.
    /// Callers must durably commit it before signing or a crash can reuse a
    /// leaf and reveal the secret key.
    pub fn keypair(&self) -> Result<(XmssVerificationKey, XmssSigningKey)> {
        with_xmss_params!(*self, |P| {
            let mut keypair = pq_xmss::KeyPair::<P>::generate(&mut os_rng()).map_err(xmss_err)?;
            let verification_key = XmssVerificationKey(InnerXmss::new(
                *self,
                keypair.verifying_key().as_ref().to_vec(),
            ));
            let signing_key = XmssSigningKey(InnerXmss::new(
                *self,
                keypair.signing_key().as_ref().to_vec(),
            ));
            Ok((verification_key, signing_key))
        })
    }

    /// Deterministically generates a keypair from a scheme-sized seed.
    ///
    /// The seed must be exactly [`XmssScheme::seed_size`] bytes. The returned
    /// signing key starts at leaf `0`; reusing stale persisted state can reveal
    /// the secret key through leaf reuse.
    pub fn keypair_from_seed(&self, seed: &[u8]) -> Result<(XmssVerificationKey, XmssSigningKey)> {
        if seed.len() != self.seed_size() {
            return Err(Error::InvalidSeedLength(seed.len()));
        }

        with_xmss_params!(*self, |P| {
            let mut keypair = pq_xmss::KeyPair::<P>::from_seed(seed).map_err(xmss_err)?;
            let verification_key = XmssVerificationKey(InnerXmss::new(
                *self,
                keypair.verifying_key().as_ref().to_vec(),
            ));
            let signing_key = XmssSigningKey(InnerXmss::new(
                *self,
                keypair.signing_key().as_ref().to_vec(),
            ));
            Ok((verification_key, signing_key))
        })
    }

    /// Generates a fresh keypair and durably commits its initial signing state.
    ///
    /// This refuses to overwrite existing state because rewinding a live key to
    /// leaf `0` can reveal the secret key through leaf reuse.
    pub fn keypair_with_store<S: XmssStateStore>(
        &self,
        store: &mut S,
    ) -> Result<(XmssVerificationKey, XmssSigningKey)> {
        if store.load()?.is_some() {
            return Err(Error::XmssError(
                "XMSS state store already contains a signing state".to_string(),
            ));
        }

        let (verification_key, signing_key) = self.keypair()?;
        store.commit(signing_key.as_ref())?;
        Ok((verification_key, signing_key))
    }

    /// Resumes a signing key from previously committed serialized state.
    ///
    /// Loading stale or rewound state can reveal the secret key through leaf
    /// reuse, so the store must return the latest durable state.
    pub fn resume_signing_key<S: XmssStateStore>(&self, store: &S) -> Result<XmssSigningKey> {
        let state = store
            .load()?
            .ok_or_else(|| Error::XmssError("XMSS state store is empty".to_string()))?;
        XmssSigningKey::from_raw_bytes(*self, &state)
    }

    /// Signs a message, advances the leaf index, and durably commits that
    /// advanced state before releasing the signature.
    ///
    /// Ordering matters: if persistence fails, the signature is discarded and
    /// the caller-visible signing key remains unchanged. Returning a signature
    /// before durable commit can lead to leaf reuse and secret-key compromise.
    pub fn sign<S: XmssStateStore>(
        &self,
        message: &[u8],
        signing_key: &mut XmssSigningKey,
        store: &mut S,
    ) -> Result<XmssSignature> {
        self.ensure_scheme(signing_key.0.scheme)?;

        if self.remaining(signing_key)? == 0 {
            return Err(Error::XmssKeyExhausted(LeavesCount(self.max_signatures())));
        }

        with_xmss_params!(*self, |P| {
            let mut upstream_signing_key =
                pq_xmss::SigningKey::<P>::try_from(signing_key.0.value.as_slice())
                    .map_err(xmss_err)?;
            let signature = upstream_signing_key
                .sign_detached(message)
                .map_err(xmss_err)?;
            let advanced = upstream_signing_key.as_ref().to_vec();
            let serialized_signature = signature.as_ref().to_vec();

            store.commit(&advanced)?;
            signing_key.0.value = advanced;

            Ok(XmssSignature(InnerXmss::new(*self, serialized_signature)))
        })
    }

    /// Verifies a detached XMSS signature against a message and verification
    /// key for this exact scheme.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &XmssSignature,
        verification_key: &XmssVerificationKey,
    ) -> Result<()> {
        self.ensure_scheme(signature.0.scheme)?;
        self.ensure_scheme(verification_key.0.scheme)?;

        with_xmss_params!(*self, |P| {
            let signature = pq_xmss::DetachedSignature::<P>::try_from(signature.0.value.as_slice())
                .map_err(xmss_err)?;
            let verification_key =
                pq_xmss::VerifyingKey::<P>::try_from(verification_key.0.value.as_slice())
                    .map_err(xmss_err)?;
            verification_key
                .verify_detached(&signature, message)
                .map_err(xmss_err)
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use crate::test_utils::round_trip_all_formats;
    use pq_xmss::XmssParameter;
    use std::{str::FromStr, sync::OnceLock};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct SchemeDocument {
        scheme: XmssScheme,
    }

    #[derive(Clone, Debug, Default)]
    struct MemoryStore {
        state: Option<Vec<u8>>,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self { state: None }
        }
    }

    impl XmssStateStore for MemoryStore {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            Ok(self.state.clone())
        }

        fn commit(&mut self, state: &[u8]) -> Result<()> {
            self.state = Some(state.to_vec());
            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct RecordingStore {
        state: Option<Vec<u8>>,
        commits: Vec<Vec<u8>>,
    }

    impl XmssStateStore for RecordingStore {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            Ok(self.state.clone())
        }

        fn commit(&mut self, state: &[u8]) -> Result<()> {
            let next = state.to_vec();
            self.commits.push(next.clone());
            self.state = Some(next);
            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct FailingStore {
        state: Option<Vec<u8>>,
        fail_next_commit: bool,
    }

    impl FailingStore {
        fn with_failure() -> Self {
            Self {
                state: None,
                fail_next_commit: true,
            }
        }
    }

    impl XmssStateStore for FailingStore {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            Ok(self.state.clone())
        }

        fn commit(&mut self, state: &[u8]) -> Result<()> {
            if self.fail_next_commit {
                self.fail_next_commit = false;
                return Err(Error::XmssError("simulated commit failure".to_string()));
            }

            self.state = Some(state.to_vec());
            Ok(())
        }
    }

    const STANDARD_SCHEMES: [XmssScheme; 21] = [
        XmssScheme::XmssSha2_10_256,
        XmssScheme::XmssSha2_16_256,
        XmssScheme::XmssSha2_20_256,
        XmssScheme::XmssSha2_10_512,
        XmssScheme::XmssSha2_16_512,
        XmssScheme::XmssSha2_20_512,
        XmssScheme::XmssShake256_10_256,
        XmssScheme::XmssShake256_16_256,
        XmssScheme::XmssShake256_20_256,
        XmssScheme::XmssShake256_10_512,
        XmssScheme::XmssShake256_16_512,
        XmssScheme::XmssShake256_20_512,
        XmssScheme::XmssSha2_10_192,
        XmssScheme::XmssSha2_16_192,
        XmssScheme::XmssSha2_20_192,
        XmssScheme::XmssShake128_10_256,
        XmssScheme::XmssShake128_16_256,
        XmssScheme::XmssShake128_20_256,
        XmssScheme::XmssShake256_10_192,
        XmssScheme::XmssShake256_16_192,
        XmssScheme::XmssShake256_20_192,
    ];

    fn all_schemes() -> Vec<XmssScheme> {
        let standard = STANDARD_SCHEMES.to_vec();

        #[cfg(not(feature = "xmss-extra-depths"))]
        {
            standard
        }

        #[cfg(feature = "xmss-extra-depths")]
        {
            let mut schemes = standard;
            for family in XmssExtraDepthFamily::ALL {
                for depth in XmssExtraDepth::ALL {
                    schemes.push(XmssScheme::extra_depth(family, depth));
                }
            }
            schemes
        }
    }

    const TEST_MESSAGE: &[u8] = b"bedrock xmss fixture";
    const TEST_VERIFICATION_KEY_HEX: &str = concat!(
        "000000016a96301330cf17d69bcbb3945e9c1b721816b9b584d7655da9ad2f43",
        "d2564e230cef6e57ba1651b0056292368d3002968638323151026a5f3797dc28b",
        "6cdbf36",
    );
    const TEST_SIGNING_KEY_HEX: &str = concat!(
        "0000000100000000e76f22c387a56d6a3c789580245496d893db6d914773ce68",
        "1d3745b114feb02e69e3bc2315f6813299101e0d2e23e4d18c59a918a2d7dc",
        "0b3b0628ef3390c62c6a96301330cf17d69bcbb3945e9c1b721816b9b584d76",
        "55da9ad2f43d2564e230cef6e57ba1651b0056292368d3002968638323151026",
        "a5f3797dc28b6cdbf36",
    );

    struct TestFixture {
        verification_key: XmssVerificationKey,
        initial_signing_key: XmssSigningKey,
        first_signature: XmssSignature,
        first_state: Vec<u8>,
        second_signature: XmssSignature,
        second_state: Vec<u8>,
        commits: Vec<Vec<u8>>,
    }

    /// XMSS signing computes a full authentication path. Reuse two height-10
    /// signatures and their serialized states where a fresh operation is not the
    /// behavior under test. The fixed keypair is test-only and must never be used
    /// for real signatures.
    fn test_fixture() -> &'static TestFixture {
        static SHA2_256: OnceLock<TestFixture> = OnceLock::new();

        SHA2_256.get_or_init(|| {
            let scheme = XmssScheme::XmssSha2_10_256;
            let verification_key = XmssVerificationKey::from_raw_bytes(
                scheme,
                &hex::decode(TEST_VERIFICATION_KEY_HEX).unwrap(),
            )
            .unwrap();
            let initial_signing_key =
                XmssSigningKey::from_raw_bytes(scheme, &hex::decode(TEST_SIGNING_KEY_HEX).unwrap())
                    .unwrap();
            let mut signing_key = initial_signing_key.clone();
            let mut store = RecordingStore::default();
            store.commit(signing_key.as_ref()).unwrap();
            let first_signature = scheme
                .sign(TEST_MESSAGE, &mut signing_key, &mut store)
                .unwrap();
            let first_state = signing_key.to_raw_bytes();
            let second_signature = scheme
                .sign(TEST_MESSAGE, &mut signing_key, &mut store)
                .unwrap();
            let second_state = signing_key.to_raw_bytes();

            TestFixture {
                verification_key,
                initial_signing_key,
                first_signature,
                first_state,
                second_signature,
                second_state,
                commits: store.commits,
            }
        })
    }

    fn fixture_keypair() -> (XmssVerificationKey, XmssSigningKey) {
        let fixture = test_fixture();
        (
            fixture.verification_key.clone(),
            fixture.initial_signing_key.clone(),
        )
    }

    #[test]
    fn round_trip_verify() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let fixture = test_fixture();

        scheme
            .verify(
                TEST_MESSAGE,
                &fixture.first_signature,
                &fixture.verification_key,
            )
            .unwrap();
    }

    #[test]
    fn wrong_key_fails() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let fixture = test_fixture();
        let mut wrong_key_bytes = fixture.verification_key.to_raw_bytes();
        let last = wrong_key_bytes
            .last_mut()
            .expect("XMSS verification keys are non-empty");
        *last ^= 1;
        let other_verification_key =
            XmssVerificationKey::from_raw_bytes(scheme, &wrong_key_bytes).unwrap();

        scheme
            .verify(
                TEST_MESSAGE,
                &fixture.first_signature,
                &fixture.verification_key,
            )
            .unwrap();
        assert!(
            scheme
                .verify(
                    TEST_MESSAGE,
                    &fixture.first_signature,
                    &other_verification_key,
                )
                .is_err()
        );
    }

    #[test]
    fn distinct_leaves() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let fixture = test_fixture();

        assert_eq!(read_index_bytes(&fixture.first_state).unwrap(), 1);
        assert_eq!(read_index_bytes(&fixture.second_state).unwrap(), 2);
        assert_ne!(fixture.first_signature, fixture.second_signature);
        scheme
            .verify(
                TEST_MESSAGE,
                &fixture.first_signature,
                &fixture.verification_key,
            )
            .unwrap();
        scheme
            .verify(
                TEST_MESSAGE,
                &fixture.second_signature,
                &fixture.verification_key,
            )
            .unwrap();
    }

    #[test]
    fn exhaustion() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let message = b"exhaustion";
        let (_verification_key, mut signing_key) = fixture_keypair();
        let mut exhausted_state = signing_key.to_raw_bytes();
        exhausted_state[OID_LEN..OID_LEN + INDEX_LEN]
            .copy_from_slice(&(scheme.max_signatures() as u32).to_be_bytes());
        signing_key = XmssSigningKey::from_raw_bytes(scheme, &exhausted_state).unwrap();

        assert_eq!(scheme.remaining(&signing_key).unwrap(), 0);

        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();

        let err = scheme
            .sign(message, &mut signing_key, &mut store)
            .unwrap_err();
        match err {
            Error::XmssKeyExhausted(limit) => assert_eq!(limit.0, scheme.max_signatures()),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn commit_before_release_ordering() {
        let fixture = test_fixture();

        assert_eq!(fixture.commits.len(), 3);
        assert_eq!(fixture.commits[0], fixture.initial_signing_key.as_ref());
        assert_eq!(fixture.commits[1], fixture.first_state);
        assert_eq!(fixture.commits[2], fixture.second_state);
        assert!(!fixture.first_signature.as_ref().is_empty());
    }

    #[test]
    fn failed_commit_releases_nothing() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let (verification_key, mut signing_key) = fixture_keypair();
        let initial = signing_key.to_raw_bytes();

        let mut failing_store = FailingStore::with_failure();
        failing_store.state = Some(initial.clone());

        let err = scheme
            .sign(TEST_MESSAGE, &mut signing_key, &mut failing_store)
            .unwrap_err();
        assert!(matches!(err, Error::XmssError(_)));
        assert_eq!(scheme.current_index(&signing_key).unwrap(), 0);
        assert_eq!(failing_store.state.clone().unwrap(), initial);
        scheme
            .verify(
                TEST_MESSAGE,
                &test_fixture().first_signature,
                &verification_key,
            )
            .unwrap();
    }

    #[test]
    fn keypair_with_store_refuses_to_overwrite() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let mut store = MemoryStore::new();
        store
            .commit(&[0xAA; pq_xmss::XmssSha2_10_256::SK_LEN])
            .unwrap();

        let err = scheme.keypair_with_store(&mut store).unwrap_err();
        assert!(matches!(err, Error::XmssError(_)));
    }

    #[test]
    fn resume_signing_key_does_not_rewind() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let fixture = test_fixture();
        let mut store = MemoryStore::default();
        store.commit(&fixture.first_state).unwrap();
        let resumed = scheme.resume_signing_key(&store).unwrap();

        assert_eq!(scheme.current_index(&resumed).unwrap(), 1);
        assert_eq!(resumed.to_raw_bytes(), fixture.first_state);
        assert_eq!(read_index_bytes(&fixture.second_state).unwrap(), 2);
    }

    #[test]
    fn scheme_mismatch_guards() {
        let signing_scheme = XmssScheme::XmssSha2_10_256;
        let other_scheme = XmssScheme::XmssShake256_10_256;
        let fixture = test_fixture();
        let mut signing_key = fixture.initial_signing_key.clone();
        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();

        let sign_err = other_scheme
            .sign(TEST_MESSAGE, &mut signing_key, &mut store)
            .unwrap_err();
        assert!(matches!(sign_err, Error::SchemeMismatch { .. }));

        let verify_err = other_scheme
            .verify(
                TEST_MESSAGE,
                &fixture.first_signature,
                &fixture.verification_key,
            )
            .unwrap_err();
        assert!(matches!(verify_err, Error::SchemeMismatch { .. }));
        signing_scheme
            .verify(
                TEST_MESSAGE,
                &fixture.first_signature,
                &fixture.verification_key,
            )
            .unwrap();
    }

    #[test]
    fn seed_size_matches_upstream() {
        for scheme in all_schemes() {
            let expected = with_xmss_params!(scheme, |P| { P::SEED_LEN });
            assert_eq!(scheme.seed_size(), expected);
        }
    }

    #[test]
    fn standard_wire_values_are_stable() {
        let upstream_oids = [
            1_u32, 2, 3, 4, 5, 6, 16, 17, 18, 10, 11, 12, 13, 14, 15, 7, 8, 9, 19, 20, 21,
        ];

        for (index, (scheme, expected_oid)) in
            STANDARD_SCHEMES.into_iter().zip(upstream_oids).enumerate()
        {
            let wire = index as u8 + 1;
            let oid = with_xmss_params!(scheme, |P| { P::OID });
            assert_eq!(u8::from(scheme), wire);
            assert_eq!(XmssScheme::try_from(wire).unwrap(), scheme);
            assert_eq!(oid, expected_oid);
        }
    }

    #[test]
    fn tree_height_and_max_signatures() {
        for scheme in all_schemes() {
            let height = match scheme {
                XmssScheme::XmssSha2_10_256
                | XmssScheme::XmssSha2_10_192
                | XmssScheme::XmssSha2_10_512
                | XmssScheme::XmssShake128_10_256
                | XmssScheme::XmssShake256_10_256
                | XmssScheme::XmssShake256_10_192
                | XmssScheme::XmssShake256_10_512 => 10,
                XmssScheme::XmssSha2_16_256
                | XmssScheme::XmssSha2_16_192
                | XmssScheme::XmssSha2_16_512
                | XmssScheme::XmssShake128_16_256
                | XmssScheme::XmssShake256_16_256
                | XmssScheme::XmssShake256_16_192
                | XmssScheme::XmssShake256_16_512 => 16,
                XmssScheme::XmssSha2_20_256
                | XmssScheme::XmssSha2_20_192
                | XmssScheme::XmssSha2_20_512
                | XmssScheme::XmssShake128_20_256
                | XmssScheme::XmssShake256_20_256
                | XmssScheme::XmssShake256_20_192
                | XmssScheme::XmssShake256_20_512 => 20,
                #[cfg(feature = "xmss-extra-depths")]
                XmssScheme::ExtraDepth { depth, .. } => depth.height(),
            };

            assert_eq!(scheme.tree_height(), height);
            assert_eq!(scheme.max_signatures(), 1_u64 << height);
        }
    }

    #[cfg(feature = "xmss-extra-depths")]
    #[test]
    fn extra_depth_wire_values_and_names_are_stable() {
        assert_eq!(u8::from(XmssScheme::XmssShake256_20_512), 12);
        assert_eq!(u8::from(XmssScheme::XmssSha2_10_192), 13);
        assert_eq!(u8::from(XmssScheme::XmssShake256_20_192), 21);

        let first = XmssScheme::extra_depth(XmssExtraDepthFamily::Sha2_256, XmssExtraDepth::H1);
        let last = XmssScheme::extra_depth(XmssExtraDepthFamily::Shake256_192, XmssExtraDepth::H24);

        assert_eq!(u8::from(first), 22);
        assert_eq!(u8::from(last), 189);
        assert_eq!(first.to_string(), "XMSS-SHA2_1_256");
        assert_eq!(last.to_string(), "XMSS-SHAKE256_24_192");
        assert!(matches!(
            XmssScheme::try_from(190),
            Err(Error::InvalidScheme(190))
        ));
        assert_eq!(
            XmssScheme::from_str("XMSS-SHA2_10_192").unwrap(),
            XmssScheme::XmssSha2_10_192
        );

        for family in XmssExtraDepthFamily::ALL {
            for standard_height in [10_u8, 16, 20] {
                let reserved = XMSS_EXTRA_DEPTH_WIRE_START
                    + family.wire_index() * XMSS_EXTRA_DEPTHS_PER_FAMILY
                    + standard_height
                    - 1;
                assert!(matches!(
                    XmssScheme::try_from(reserved),
                    Err(Error::InvalidScheme(value)) if value == reserved
                ));
            }

            for depth in XmssExtraDepth::ALL {
                let scheme = XmssScheme::extra_depth(family, depth);
                let oid = with_xmss_params!(scheme, |P| { P::OID.to_be_bytes() });
                assert_eq!(
                    oid,
                    [0xff, family.wire_index() + 1, 0, depth.height() as u8]
                );
            }
        }
    }

    #[cfg(feature = "xmss-extra-depths")]
    #[test]
    fn extra_depth_params_distinguish_non_standard_schemes() {
        let family = XmssExtraDepthFamily::Shake256_192;
        let depth = XmssExtraDepth::H4;

        assert_eq!(
            XmssScheme::extra_depth(family, depth).extra_depth_params(),
            Some((family, depth))
        );
        assert_eq!(XmssScheme::XmssSha2_10_192.extra_depth_params(), None);
    }

    #[cfg(feature = "xmss-extra-depths")]
    #[test]
    fn extra_depth_h1_signs_and_verifies() {
        let family = XmssExtraDepthFamily::Shake256_192;
        let scheme = XmssScheme::extra_depth(family, XmssExtraDepth::H1);
        let seed = vec![0x5a; scheme.seed_size()];
        let (verification_key, mut signing_key) = scheme.keypair_from_seed(&seed).unwrap();

        assert_eq!(&verification_key.as_ref()[..OID_LEN], &[0xff, 7, 0, 1]);

        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();
        let signature = scheme
            .sign(TEST_MESSAGE, &mut signing_key, &mut store)
            .unwrap();
        scheme
            .verify(TEST_MESSAGE, &signature, &verification_key)
            .unwrap();
        assert_eq!(scheme.current_index(&signing_key).unwrap(), 1);
    }

    #[test]
    fn serdes() {
        for scheme in all_schemes() {
            let via_u8 = XmssScheme::try_from(u8::from(scheme)).unwrap();
            let via_str = XmssScheme::from_str(&scheme.to_string()).unwrap();

            assert_eq!(via_u8, scheme);
            assert_eq!(via_str, scheme);
            round_trip_all_formats(&SchemeDocument { scheme });
        }

        let fixture = test_fixture();
        let signing_key = &fixture.initial_signing_key;
        let verification_key = &fixture.verification_key;
        let signature = &fixture.first_signature;

        round_trip_all_formats(signing_key);
        round_trip_all_formats(verification_key);
        round_trip_all_formats(signature);
    }

    #[test]
    fn short_malformed_state_errors() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let key = XmssSigningKey(InnerXmss::new(scheme, vec![0xAA; OID_LEN + INDEX_LEN - 1]));

        let err = scheme.current_index(&key).unwrap_err();
        assert!(matches!(err, Error::XmssError(_)));
    }

    #[test]
    fn resume_requires_existing_state() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let store = MemoryStore::default();

        let err = scheme.resume_signing_key(&store).unwrap_err();
        assert!(matches!(err, Error::XmssError(_)));
    }

    #[test]
    #[ignore = "full XMSS tree generation; run manually"]
    fn keypair_with_store_commits_initial_state() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let mut store = RecordingStore::default();
        let (_verification_key, signing_key) = scheme.keypair_with_store(&mut store).unwrap();

        assert_eq!(store.state.unwrap(), signing_key.to_raw_bytes());
        assert_eq!(scheme.current_index(&signing_key).unwrap(), 0);
    }

    #[test]
    fn keypair_from_seed_rejects_wrong_length() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let err = scheme
            .keypair_from_seed(&vec![0_u8; scheme.seed_size() - 1])
            .unwrap_err();
        assert!(matches!(err, Error::InvalidSeedLength(_)));
    }

    #[test]
    fn from_raw_bytes_round_trip() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let (verification_key, signing_key) = fixture_keypair();

        let signing_round_trip =
            XmssSigningKey::from_raw_bytes(scheme, &signing_key.to_raw_bytes()).unwrap();
        let verification_round_trip =
            XmssVerificationKey::from_raw_bytes(scheme, &verification_key.to_raw_bytes()).unwrap();

        assert_eq!(signing_round_trip, signing_key);
        assert_eq!(verification_round_trip, verification_key);
    }

    #[test]
    fn signature_from_raw_bytes_round_trip() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let fixture = test_fixture();

        let round_trip =
            XmssSignature::from_raw_bytes(scheme, &fixture.first_signature.to_raw_bytes()).unwrap();

        assert_eq!(round_trip, fixture.first_signature);
        scheme
            .verify(TEST_MESSAGE, &round_trip, &fixture.verification_key)
            .unwrap();
    }
}
