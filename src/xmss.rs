//! Stateful XMSS signatures for bedrock.
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
    P: xmss::XmssParameter,
{
    xmss::SigningKey::<P>::try_from(bytes)
        .map(|_| ())
        .map_err(xmss_err)
}

fn validate_verification_key_bytes<P>(bytes: &[u8]) -> Result<()>
where
    P: xmss::XmssParameter,
{
    xmss::VerifyingKey::<P>::try_from(bytes)
        .map(|_| ())
        .map_err(xmss_err)
}

fn validate_signature_bytes<P>(bytes: &[u8]) -> Result<()>
where
    P: xmss::XmssParameter,
{
    xmss::DetachedSignature::<P>::try_from(bytes)
        .map(|_| ())
        .map_err(xmss_err)
}

/// Tree height metadata for XMSS parameter sets.
///
/// The upstream `xmss` crate keeps the tree height crate-private, but bedrock
/// must expose the signing capacity because every leaf may be used only once or
/// the secret key is revealed.
trait XmssTreeHeight: xmss::XmssParameter {
    /// Full Merkle tree height `h`.
    const FULL_HEIGHT: u32;
}

impl XmssTreeHeight for xmss::XmssSha2_10_256 {
    const FULL_HEIGHT: u32 = 10;
}

impl XmssTreeHeight for xmss::XmssSha2_16_256 {
    const FULL_HEIGHT: u32 = 16;
}

impl XmssTreeHeight for xmss::XmssSha2_20_256 {
    const FULL_HEIGHT: u32 = 20;
}

impl XmssTreeHeight for xmss::XmssSha2_10_512 {
    const FULL_HEIGHT: u32 = 10;
}

impl XmssTreeHeight for xmss::XmssSha2_16_512 {
    const FULL_HEIGHT: u32 = 16;
}

impl XmssTreeHeight for xmss::XmssSha2_20_512 {
    const FULL_HEIGHT: u32 = 20;
}

impl XmssTreeHeight for xmss::XmssShake256_10_256 {
    const FULL_HEIGHT: u32 = 10;
}

impl XmssTreeHeight for xmss::XmssShake256_16_256 {
    const FULL_HEIGHT: u32 = 16;
}

impl XmssTreeHeight for xmss::XmssShake256_20_256 {
    const FULL_HEIGHT: u32 = 20;
}

impl XmssTreeHeight for xmss::XmssShake_10_512 {
    const FULL_HEIGHT: u32 = 10;
}

impl XmssTreeHeight for xmss::XmssShake_16_512 {
    const FULL_HEIGHT: u32 = 16;
}

impl XmssTreeHeight for xmss::XmssShake_20_512 {
    const FULL_HEIGHT: u32 = 20;
}

scheme_impl_pure!(
    /// Supported XMSS parameter sets.
    ///
    /// Each scheme has a fixed Merkle tree height and therefore a fixed maximum
    /// number of signatures. Reusing a consumed leaf reveals the secret key.
    XmssScheme,
    #[default]
    /// `XMSS-SHA2_10_256`: SHA-256, tree height 10 (2^10 signatures).
    XmssSha2_10_256 => "XMSS-SHA2_10_256" ; 1 ; 96,
    /// `XMSS-SHA2_16_256`: SHA-256, tree height 16 (2^16 signatures).
    XmssSha2_16_256 => "XMSS-SHA2_16_256" ; 2 ; 96,
    /// `XMSS-SHA2_20_256`: SHA-256, tree height 20 (2^20 signatures).
    XmssSha2_20_256 => "XMSS-SHA2_20_256" ; 3 ; 96,
    /// `XMSS-SHA2_10_512`: SHA-512, tree height 10 (2^10 signatures).
    XmssSha2_10_512 => "XMSS-SHA2_10_512" ; 4 ; 192,
    /// `XMSS-SHA2_16_512`: SHA-512, tree height 16 (2^16 signatures).
    XmssSha2_16_512 => "XMSS-SHA2_16_512" ; 5 ; 192,
    /// `XMSS-SHA2_20_512`: SHA-512, tree height 20 (2^20 signatures).
    XmssSha2_20_512 => "XMSS-SHA2_20_512" ; 6 ; 192,
    /// `XMSS-SHAKE256_10_256`: SHAKE256, tree height 10 (2^10 signatures).
    XmssShake256_10_256 => "XMSS-SHAKE256_10_256" ; 7 ; 96,
    /// `XMSS-SHAKE256_16_256`: SHAKE256, tree height 16 (2^16 signatures).
    XmssShake256_16_256 => "XMSS-SHAKE256_16_256" ; 8 ; 96,
    /// `XMSS-SHAKE256_20_256`: SHAKE256, tree height 20 (2^20 signatures).
    XmssShake256_20_256 => "XMSS-SHAKE256_20_256" ; 9 ; 96,
    /// Maps to upstream `xmss::XmssShake_10_512`, whose canonical RFC 8391 name
    /// is `XMSS-SHAKE_10_512`. The upstream crate exports no distinct
    /// `XmssShake256_10_512` marker type: RFC 8391 defines the SHAKE-512 family
    /// as `XMSS-SHAKE_*_512`, and the `SHAKE256_*` names from NIST SP 800-208
    /// exist only at the 256 width.
    XmssShake256_10_512 => "XMSS-SHAKE_10_512" ; 10 ; 192,
    /// Maps to upstream `xmss::XmssShake_16_512`, whose canonical RFC 8391 name
    /// is `XMSS-SHAKE_16_512`. See [`XmssScheme::XmssShake256_10_512`].
    XmssShake256_16_512 => "XMSS-SHAKE_16_512" ; 11 ; 192,
    /// Maps to upstream `xmss::XmssShake_20_512`, whose canonical RFC 8391 name
    /// is `XMSS-SHAKE_20_512`. See [`XmssScheme::XmssShake256_10_512`].
    XmssShake256_20_512 => "XMSS-SHAKE_20_512" ; 12 ; 192,
);

serde_impl!(XmssScheme);

macro_rules! with_xmss_params {
    ($scheme:expr, |$P:ident| $body:block) => {{
        match $scheme {
            XmssScheme::XmssSha2_10_256 => {
                type $P = xmss::XmssSha2_10_256;
                $body
            }
            XmssScheme::XmssSha2_16_256 => {
                type $P = xmss::XmssSha2_16_256;
                $body
            }
            XmssScheme::XmssSha2_20_256 => {
                type $P = xmss::XmssSha2_20_256;
                $body
            }
            XmssScheme::XmssSha2_10_512 => {
                type $P = xmss::XmssSha2_10_512;
                $body
            }
            XmssScheme::XmssSha2_16_512 => {
                type $P = xmss::XmssSha2_16_512;
                $body
            }
            XmssScheme::XmssSha2_20_512 => {
                type $P = xmss::XmssSha2_20_512;
                $body
            }
            XmssScheme::XmssShake256_10_256 => {
                type $P = xmss::XmssShake256_10_256;
                $body
            }
            XmssScheme::XmssShake256_16_256 => {
                type $P = xmss::XmssShake256_16_256;
                $body
            }
            XmssScheme::XmssShake256_20_256 => {
                type $P = xmss::XmssShake256_20_256;
                $body
            }
            XmssScheme::XmssShake256_10_512 => {
                type $P = xmss::XmssShake_10_512;
                $body
            }
            XmssScheme::XmssShake256_16_512 => {
                type $P = xmss::XmssShake_16_512;
                $body
            }
            XmssScheme::XmssShake256_20_512 => {
                type $P = xmss::XmssShake_20_512;
                $body
            }
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
            let mut keypair = xmss::KeyPair::<P>::generate(&mut os_rng()).map_err(xmss_err)?;
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
            let mut keypair = xmss::KeyPair::<P>::from_seed(seed).map_err(xmss_err)?;
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
                xmss::SigningKey::<P>::try_from(signing_key.0.value.as_slice())
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
            let signature = xmss::DetachedSignature::<P>::try_from(signature.0.value.as_slice())
                .map_err(xmss_err)?;
            let verification_key =
                xmss::VerifyingKey::<P>::try_from(verification_key.0.value.as_slice())
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

    use rstest::rstest;
    use std::str::FromStr;
    use xmss::XmssParameter;

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

    fn h10_schemes() -> [XmssScheme; 4] {
        [
            XmssScheme::XmssSha2_10_256,
            XmssScheme::XmssSha2_10_512,
            XmssScheme::XmssShake256_10_256,
            XmssScheme::XmssShake256_10_512,
        ]
    }

    fn all_schemes() -> [XmssScheme; 12] {
        [
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
        ]
    }

    fn scheme_seed(scheme: XmssScheme, fill: u8) -> Vec<u8> {
        vec![fill; scheme.seed_size()]
    }

    fn distinct_keypairs(
        scheme: XmssScheme,
    ) -> (
        (XmssVerificationKey, XmssSigningKey),
        (XmssVerificationKey, XmssSigningKey),
    ) {
        let first = scheme
            .keypair_from_seed(&scheme_seed(scheme, 0x11))
            .unwrap();
        let second = scheme
            .keypair_from_seed(&scheme_seed(scheme, 0x22))
            .unwrap();
        (first, second)
    }

    #[rstest]
    #[case(XmssScheme::XmssSha2_10_256)]
    #[case(XmssScheme::XmssSha2_10_512)]
    #[case(XmssScheme::XmssShake256_10_256)]
    #[case(XmssScheme::XmssShake256_10_512)]
    fn round_trip_verify(#[case] scheme: XmssScheme) {
        let message = b"bedrock xmss round trip";
        let (verification_key, mut signing_key) = scheme.keypair().unwrap();
        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();

        let signature = scheme.sign(message, &mut signing_key, &mut store).unwrap();

        scheme
            .verify(message, &signature, &verification_key)
            .unwrap();
    }

    #[rstest]
    #[case(XmssScheme::XmssSha2_10_256)]
    #[case(XmssScheme::XmssShake256_10_256)]
    fn wrong_key_fails(#[case] scheme: XmssScheme) {
        let message = b"bedrock xmss wrong key";
        let ((verification_key, mut signing_key), (other_verification_key, _)) =
            distinct_keypairs(scheme);
        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();

        let signature = scheme.sign(message, &mut signing_key, &mut store).unwrap();

        scheme
            .verify(message, &signature, &verification_key)
            .unwrap();
        assert!(scheme
            .verify(message, &signature, &other_verification_key)
            .is_err());
    }

    #[rstest]
    #[case(XmssScheme::XmssSha2_10_256)]
    #[case(XmssScheme::XmssShake256_10_256)]
    fn distinct_leaves(#[case] scheme: XmssScheme) {
        let message = b"same message, distinct leaves";
        let (verification_key, mut signing_key) = scheme.keypair().unwrap();
        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();

        assert_eq!(scheme.current_index(&signing_key).unwrap(), 0);

        let first = scheme.sign(message, &mut signing_key, &mut store).unwrap();
        assert_eq!(scheme.current_index(&signing_key).unwrap(), 1);

        let second = scheme.sign(message, &mut signing_key, &mut store).unwrap();
        assert_eq!(scheme.current_index(&signing_key).unwrap(), 2);

        assert_ne!(first, second);
        scheme.verify(message, &first, &verification_key).unwrap();
        scheme.verify(message, &second, &verification_key).unwrap();
    }

    #[test]
    fn exhaustion() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let message = b"exhaustion";
        let (_verification_key, mut signing_key) = scheme
            .keypair_from_seed(&scheme_seed(scheme, 0x33))
            .unwrap();
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
        let scheme = XmssScheme::XmssSha2_10_256;
        let message = b"ordering";
        let (_verification_key, mut signing_key) = scheme
            .keypair_from_seed(&scheme_seed(scheme, 0x44))
            .unwrap();
        let initial = signing_key.to_raw_bytes();
        let mut store = RecordingStore::default();
        store.commit(&initial).unwrap();

        let signature = scheme.sign(message, &mut signing_key, &mut store).unwrap();
        let committed = store.state.clone().unwrap();

        assert_eq!(store.commits.len(), 2);
        assert_eq!(read_index_bytes(&committed).unwrap(), 1);
        assert_eq!(committed, signing_key.to_raw_bytes());
        assert_eq!(scheme.current_index(&signing_key).unwrap(), 1);
        assert!(!signature.as_ref().is_empty());
    }

    #[test]
    fn failed_commit_releases_nothing() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let message = b"commit failure";
        let (verification_key, mut signing_key) = scheme
            .keypair_from_seed(&scheme_seed(scheme, 0x55))
            .unwrap();
        let initial = signing_key.to_raw_bytes();

        let mut failing_store = FailingStore::with_failure();
        failing_store.state = Some(initial.clone());

        let err = scheme
            .sign(message, &mut signing_key, &mut failing_store)
            .unwrap_err();
        assert!(matches!(err, Error::XmssError(_)));
        assert_eq!(scheme.current_index(&signing_key).unwrap(), 0);
        assert_eq!(failing_store.state.clone().unwrap(), initial);

        let signature = scheme
            .sign(message, &mut signing_key, &mut failing_store)
            .unwrap();
        assert_eq!(scheme.current_index(&signing_key).unwrap(), 1);
        scheme
            .verify(message, &signature, &verification_key)
            .unwrap();
    }

    #[test]
    fn keypair_with_store_refuses_to_overwrite() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let mut store = MemoryStore::new();
        store
            .commit(&[0xAA; xmss::XmssSha2_10_256::SK_LEN])
            .unwrap();

        let err = scheme.keypair_with_store(&mut store).unwrap_err();
        assert!(matches!(err, Error::XmssError(_)));
    }

    #[test]
    fn resume_signing_key_does_not_rewind() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let message = b"resume";
        let (verification_key, mut signing_key) = scheme
            .keypair_from_seed(&scheme_seed(scheme, 0x66))
            .unwrap();
        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();

        let first = scheme.sign(message, &mut signing_key, &mut store).unwrap();
        let resumed = scheme.resume_signing_key(&store).unwrap();

        assert_eq!(scheme.current_index(&resumed).unwrap(), 1);

        let mut resumed = resumed;
        let second = scheme.sign(message, &mut resumed, &mut store).unwrap();

        assert_ne!(first, second);
        scheme.verify(message, &first, &verification_key).unwrap();
        scheme.verify(message, &second, &verification_key).unwrap();
        assert_eq!(scheme.current_index(&resumed).unwrap(), 2);
    }

    #[test]
    fn scheme_mismatch_guards() {
        let signing_scheme = XmssScheme::XmssSha2_10_256;
        let other_scheme = XmssScheme::XmssShake256_10_256;
        let message = b"scheme mismatch";
        let (verification_key, mut signing_key) = signing_scheme
            .keypair_from_seed(&scheme_seed(signing_scheme, 0x77))
            .unwrap();
        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();

        let signature = signing_scheme
            .sign(message, &mut signing_key, &mut store)
            .unwrap();

        let sign_err = other_scheme
            .sign(message, &mut signing_key, &mut store)
            .unwrap_err();
        assert!(matches!(sign_err, Error::SchemeMismatch { .. }));

        let verify_err = other_scheme
            .verify(message, &signature, &verification_key)
            .unwrap_err();
        assert!(matches!(verify_err, Error::SchemeMismatch { .. }));
    }

    #[test]
    fn seed_size_matches_upstream() {
        for scheme in all_schemes() {
            let expected = with_xmss_params!(scheme, |P| { P::SEED_LEN });
            assert_eq!(scheme.seed_size(), expected);
        }
    }

    #[test]
    fn tree_height_and_max_signatures() {
        for scheme in all_schemes() {
            let (height, expected_signatures) = match scheme {
                XmssScheme::XmssSha2_10_256
                | XmssScheme::XmssSha2_10_512
                | XmssScheme::XmssShake256_10_256
                | XmssScheme::XmssShake256_10_512 => (10, 1_u64 << 10),
                XmssScheme::XmssSha2_16_256
                | XmssScheme::XmssSha2_16_512
                | XmssScheme::XmssShake256_16_256
                | XmssScheme::XmssShake256_16_512 => (16, 1_u64 << 16),
                XmssScheme::XmssSha2_20_256
                | XmssScheme::XmssSha2_20_512
                | XmssScheme::XmssShake256_20_256
                | XmssScheme::XmssShake256_20_512 => (20, 1_u64 << 20),
            };

            assert_eq!(scheme.tree_height(), height);
            assert_eq!(scheme.max_signatures(), expected_signatures);
        }
    }

    #[test]
    fn serdes() {
        for scheme in all_schemes() {
            let via_u8 = XmssScheme::try_from(u8::from(scheme)).unwrap();
            let via_str = XmssScheme::from_str(&scheme.to_string()).unwrap();
            let json = serde_json::to_string(&scheme).unwrap();
            let json_round_trip: XmssScheme = serde_json::from_str(&json).unwrap();
            let postcard = postcard::to_stdvec(&scheme).unwrap();
            let postcard_round_trip: XmssScheme = postcard::from_bytes(&postcard).unwrap();

            assert_eq!(via_u8, scheme);
            assert_eq!(via_str, scheme);
            assert_eq!(json_round_trip, scheme);
            assert_eq!(postcard_round_trip, scheme);
        }

        let scheme = XmssScheme::XmssSha2_10_256;
        let message = b"serde";
        let (verification_key, mut signing_key) = scheme
            .keypair_from_seed(&scheme_seed(scheme, 0x88))
            .unwrap();
        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();
        let signature = scheme.sign(message, &mut signing_key, &mut store).unwrap();

        let signing_json = serde_json::to_string(&signing_key).unwrap();
        let signing_key_round_trip: XmssSigningKey = serde_json::from_str(&signing_json).unwrap();
        assert_eq!(signing_key_round_trip, signing_key);

        let signing_postcard = postcard::to_stdvec(&signing_key).unwrap();
        let signing_key_postcard: XmssSigningKey = postcard::from_bytes(&signing_postcard).unwrap();
        assert_eq!(signing_key_postcard, signing_key);

        let verification_json = serde_json::to_string(&verification_key).unwrap();
        let verification_key_round_trip: XmssVerificationKey =
            serde_json::from_str(&verification_json).unwrap();
        assert_eq!(verification_key_round_trip, verification_key);

        let verification_postcard = postcard::to_stdvec(&verification_key).unwrap();
        let verification_key_postcard: XmssVerificationKey =
            postcard::from_bytes(&verification_postcard).unwrap();
        assert_eq!(verification_key_postcard, verification_key);

        let signature_json = serde_json::to_string(&signature).unwrap();
        let signature_round_trip: XmssSignature = serde_json::from_str(&signature_json).unwrap();
        assert_eq!(signature_round_trip, signature);

        let signature_postcard = postcard::to_stdvec(&signature).unwrap();
        let signature_postcard_round_trip: XmssSignature =
            postcard::from_bytes(&signature_postcard).unwrap();
        assert_eq!(signature_postcard_round_trip, signature);
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
    fn keypair_with_store_commits_initial_state() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let mut store = RecordingStore::default();

        let (_verification_key, signing_key) = scheme.keypair_with_store(&mut store).unwrap();

        assert_eq!(store.commits.len(), 1);
        assert_eq!(store.state.unwrap(), signing_key.to_raw_bytes());
        assert_eq!(scheme.current_index(&signing_key).unwrap(), 0);
    }

    #[test]
    fn from_raw_bytes_round_trip() {
        for scheme in h10_schemes() {
            let (verification_key, signing_key) = scheme
                .keypair_from_seed(&scheme_seed(scheme, 0x99))
                .unwrap();

            let signing_round_trip =
                XmssSigningKey::from_raw_bytes(scheme, &signing_key.to_raw_bytes()).unwrap();
            let verification_round_trip =
                XmssVerificationKey::from_raw_bytes(scheme, &verification_key.to_raw_bytes())
                    .unwrap();

            assert_eq!(signing_round_trip, signing_key);
            assert_eq!(verification_round_trip, verification_key);
        }
    }

    #[test]
    fn signature_from_raw_bytes_round_trip() {
        let scheme = XmssScheme::XmssSha2_10_256;
        let message = b"signature bytes";
        let (verification_key, mut signing_key) = scheme
            .keypair_from_seed(&scheme_seed(scheme, 0xAB))
            .unwrap();
        let mut store = MemoryStore::default();
        store.commit(signing_key.as_ref()).unwrap();
        let signature = scheme.sign(message, &mut signing_key, &mut store).unwrap();

        let round_trip = XmssSignature::from_raw_bytes(scheme, &signature.to_raw_bytes()).unwrap();

        assert_eq!(round_trip, signature);
        scheme
            .verify(message, &round_trip, &verification_key)
            .unwrap();
    }
}
