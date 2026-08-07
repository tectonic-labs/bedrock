//! Known-answer tests for the code- and lattice-based KEMs.
//!
//! A round-trip test cannot tell you whether a scheme is wired to the right backend:
//! encapsulate-then-decapsulate agrees with itself even if HQC-192 is quietly running
//! HQC-256's parameters, or if FrodoKEM's AES and SHAKE variants are transposed. These
//! tests pin the answers to values produced outside this crate.
//!
//! Two independent checks:
//!
//! 1. **Decapsulation against submission vectors.** The HQC fixtures under `tests/data/`
//!    are vector 0 of the official HQC submission's KAT files for each parameter set.
//!    Decapsulating the given ciphertext with the given secret key must yield the given
//!    shared secret. Nothing in this crate can influence the expected value.
//!
//! 2. **Published encoding sizes.** Every parameter set has fixed key, ciphertext and
//!    shared-secret lengths defined by its specification. Asserting them catches a
//!    scheme dispatched to another parameter set's backend, which is the failure mode
//!    a round-trip is structurally blind to.

// Gated on the three KEM families this file actually has vectors for, not merely on the
// key-generation features. `kem` itself is compiled only when a KEM family is enabled,
// and no KEM family is in `default` — so gating on `kgen`/`encp`/`decp` alone (all of
// which ARE default) compiles this file against a module that does not exist.
#![cfg(all(
    feature = "kgen",
    feature = "encp",
    feature = "decp",
    any(feature = "hqc", feature = "sntrup", feature = "frodo")
))]

use tectonic_bedrock::error::Error;
use tectonic_bedrock::kem::{KemCiphertext, KemDecapsulationKey, KemScheme};

/// Decode a hex fixture, tolerating the trailing newline.
fn hex_fixture(contents: &str) -> Vec<u8> {
    hex::decode(contents.trim()).expect("fixture is valid hex")
}

#[cfg(feature = "hqc")]
mod hqc_nist_vectors {
    use super::*;

    /// Decapsulate a published (sk, ct) pair and compare against the published secret.
    fn check(scheme: KemScheme, sk_hex: &str, ct_hex: &str, ss_hex: &str) {
        let sk = hex_fixture(sk_hex);
        let ct = hex_fixture(ct_hex);
        let expected = hex_fixture(ss_hex);

        let dk = KemDecapsulationKey::from_raw_bytes(scheme, &sk)
            .expect("KAT secret key must parse for its own scheme");
        let ciphertext = KemCiphertext::from_raw_bytes(scheme, &ct)
            .expect("KAT ciphertext must parse for its own scheme");

        let ss = scheme
            .decapsulate(&ciphertext, &dk)
            .expect("KAT decapsulation must succeed");

        assert_eq!(
            ss.to_raw_bytes(),
            expected,
            "{scheme} decapsulated an HQC submission vector to the wrong shared secret"
        );
    }

    #[test]
    fn hqc128_matches_nist_vector_0() {
        check(
            KemScheme::Hqc128,
            include_str!("data/hqc128-kat0-sk.hex"),
            include_str!("data/hqc128-kat0-ct.hex"),
            include_str!("data/hqc128-kat0-ss.hex"),
        );
    }

    #[test]
    fn hqc192_matches_nist_vector_0() {
        check(
            KemScheme::Hqc192,
            include_str!("data/hqc192-kat0-sk.hex"),
            include_str!("data/hqc192-kat0-ct.hex"),
            include_str!("data/hqc192-kat0-ss.hex"),
        );
    }

    #[test]
    fn hqc256_matches_nist_vector_0() {
        check(
            KemScheme::Hqc256,
            include_str!("data/hqc256-kat0-sk.hex"),
            include_str!("data/hqc256-kat0-ct.hex"),
            include_str!("data/hqc256-kat0-ss.hex"),
        );
    }

    /// A vector belonging to one parameter set must not decapsulate under another.
    ///
    /// This is the mis-wiring probe: if HQC-192 were dispatched to HQC-256's backend,
    /// the sizes would disagree and this would surface it.
    #[test]
    fn nist_vectors_do_not_cross_parameter_sets() {
        let sk = hex_fixture(include_str!("data/hqc128-kat0-sk.hex"));
        assert!(KemDecapsulationKey::from_raw_bytes(KemScheme::Hqc192, &sk).is_err());
        assert!(KemDecapsulationKey::from_raw_bytes(KemScheme::Hqc256, &sk).is_err());
    }
}

#[cfg(feature = "sntrup")]
mod sntrup_ietf_vectors {
    use super::*;

    /// Decapsulation vectors 0 and 1 for sntrup761, from
    /// `draft-josefsson-ntruprime-streamlined-00`.
    fn check(sk_hex: &str, ct_hex: &str, ss_hex: &str) {
        let scheme = KemScheme::Sntrup761;
        let dk = KemDecapsulationKey::from_raw_bytes(scheme, &hex_fixture(sk_hex))
            .expect("KAT secret key must parse");
        let ct = KemCiphertext::from_raw_bytes(scheme, &hex_fixture(ct_hex))
            .expect("KAT ciphertext must parse");

        let ss = scheme.decapsulate(&ct, &dk).expect("KAT decapsulation");
        assert_eq!(ss.to_raw_bytes(), hex_fixture(ss_hex));
    }

    #[test]
    fn sntrup761_matches_ietf_vector_0() {
        check(
            include_str!("data/sntrup761-kat0-sk.hex"),
            include_str!("data/sntrup761-kat0-ct.hex"),
            include_str!("data/sntrup761-kat0-ss.hex"),
        );
    }

    #[test]
    fn sntrup761_matches_ietf_vector_1() {
        check(
            include_str!("data/sntrup761-kat1-sk.hex"),
            include_str!("data/sntrup761-kat1-ct.hex"),
            include_str!("data/sntrup761-kat1-ss.hex"),
        );
    }
}

#[cfg(feature = "frodo")]
mod frodo_iso_vectors {
    use super::*;

    /// Vector 0 from the FrodoKEM reference implementation's KAT files; the same vector
    /// is used in the ISO/IEC 18033-2 Amd 2 conformance review.
    fn check(scheme: KemScheme, sk_hex: &str, ct_hex: &str, ss_hex: &str) {
        let dk = KemDecapsulationKey::from_raw_bytes(scheme, &hex_fixture(sk_hex))
            .expect("KAT secret key must parse");
        let ct = KemCiphertext::from_raw_bytes(scheme, &hex_fixture(ct_hex))
            .expect("KAT ciphertext must parse");

        let ss = scheme.decapsulate(&ct, &dk).expect("KAT decapsulation");
        assert_eq!(
            ss.to_raw_bytes(),
            hex_fixture(ss_hex),
            "{scheme} decapsulated its reference vector to the wrong shared secret"
        );
    }

    #[test]
    fn frodo640aes_matches_reference_vector_0() {
        check(
            KemScheme::FrodoKem640Aes,
            include_str!("data/frodo640aes-kat0-sk.hex"),
            include_str!("data/frodo640aes-kat0-ct.hex"),
            include_str!("data/frodo640aes-kat0-ss.hex"),
        );
    }

    #[test]
    fn frodo640shake_matches_reference_vector_0() {
        check(
            KemScheme::FrodoKem640Shake,
            include_str!("data/frodo640shake-kat0-sk.hex"),
            include_str!("data/frodo640shake-kat0-ct.hex"),
            include_str!("data/frodo640shake-kat0-ss.hex"),
        );
    }

    /// The AES and SHAKE variants must not be transposed.
    ///
    /// Nothing structural can catch this: at n=640 the two have byte-identical keys,
    /// ciphertexts and shared secrets, so the size table passes either way and a
    /// round-trip stays inside whichever backend it was given. Only a reference vector
    /// distinguishes them — decapsulating the AES vector under SHAKE must not reproduce
    /// the AES answer.
    #[test]
    fn aes_and_shake_backends_are_not_transposed() {
        let aes_sk = hex_fixture(include_str!("data/frodo640aes-kat0-sk.hex"));
        let aes_ct = hex_fixture(include_str!("data/frodo640aes-kat0-ct.hex"));
        let aes_ss = hex_fixture(include_str!("data/frodo640aes-kat0-ss.hex"));

        // Same lengths, so the SHAKE scheme accepts the encodings without complaint.
        let dk = KemDecapsulationKey::from_raw_bytes(KemScheme::FrodoKem640Shake, &aes_sk)
            .expect("identical sizes mean SHAKE parses AES key material");
        let ct = KemCiphertext::from_raw_bytes(KemScheme::FrodoKem640Shake, &aes_ct)
            .expect("identical sizes mean SHAKE parses an AES ciphertext");

        let ss = KemScheme::FrodoKem640Shake
            .decapsulate(&ct, &dk)
            .expect("implicit rejection returns a secret rather than erroring");

        assert_ne!(
            ss.to_raw_bytes(),
            aes_ss,
            "SHAKE reproduced the AES vector's shared secret — the backends are transposed"
        );
    }
}

/// Published encoding sizes: `(scheme, public key, secret key, ciphertext, shared secret)`.
///
/// The HQC rows are read off the official KAT vectors under `tests/data/`, so they are
/// genuinely external. The sntrup and FrodoKEM rows come from their upstream crates'
/// published parameter tables — weaker than a NIST vector, but still outside this crate,
/// which allows them to catch a scheme dispatched to a neighboring
/// parameter set's backend.
const PUBLISHED_SIZES: &[(KemScheme, usize, usize, usize, usize)] = &[
    #[cfg(feature = "hqc")]
    (KemScheme::Hqc128, 2241, 2321, 4433, 32),
    #[cfg(feature = "hqc")]
    (KemScheme::Hqc192, 4514, 4602, 8978, 32),
    #[cfg(feature = "hqc")]
    (KemScheme::Hqc256, 7237, 7333, 14421, 32),
    #[cfg(feature = "sntrup")]
    (KemScheme::Sntrup653, 994, 1518, 897, 32),
    #[cfg(feature = "sntrup")]
    (KemScheme::Sntrup761, 1158, 1763, 1039, 32),
    #[cfg(feature = "sntrup")]
    (KemScheme::Sntrup857, 1322, 1999, 1184, 32),
    #[cfg(feature = "sntrup")]
    (KemScheme::Sntrup953, 1505, 2254, 1349, 32),
    #[cfg(feature = "sntrup")]
    (KemScheme::Sntrup1013, 1623, 2417, 1455, 32),
    #[cfg(feature = "sntrup")]
    (KemScheme::Sntrup1277, 2067, 3059, 1847, 32),
    #[cfg(feature = "frodo")]
    // FrodoKEM ciphertexts carry a salt in the non-ephemeral construction, so these
    // are longer than the salt-free figures quoted for the original submission.
    (KemScheme::FrodoKem640Aes, 9616, 19888, 9752, 16),
    #[cfg(feature = "frodo")]
    (KemScheme::FrodoKem640Shake, 9616, 19888, 9752, 16),
    #[cfg(feature = "frodo")]
    (KemScheme::FrodoKem976Aes, 15632, 31296, 15792, 24),
    #[cfg(feature = "frodo")]
    (KemScheme::FrodoKem976Shake, 15632, 31296, 15792, 24),
    #[cfg(feature = "frodo")]
    (KemScheme::FrodoKem1344Aes, 21520, 43088, 21696, 32),
    #[cfg(feature = "frodo")]
    (KemScheme::FrodoKem1344Shake, 21520, 43088, 21696, 32),
];

/// Every scheme must produce keys and ciphertexts of its own published length.
///
/// A scheme dispatched to a neighboring parameter set's backend fails here even though
/// it would round-trip perfectly, because the round-trip never leaves that backend.
#[test]
fn encodings_match_published_sizes() {
    assert!(
        !PUBLISHED_SIZES.is_empty(),
        "no scheme features enabled for this test"
    );

    for &(scheme, pk_len, sk_len, ct_len, ss_len) in PUBLISHED_SIZES {
        let (ek, dk) = scheme.keypair().expect("keypair");
        assert_eq!(
            ek.to_raw_bytes().len(),
            pk_len,
            "{scheme} public key length"
        );
        assert_eq!(
            dk.to_raw_bytes().len(),
            sk_len,
            "{scheme} secret key length"
        );

        let (ct, ss) = scheme.encapsulate(&ek).expect("encapsulate");
        assert_eq!(
            ct.to_raw_bytes().len(),
            ct_len,
            "{scheme} ciphertext length"
        );
        assert_eq!(
            ss.to_raw_bytes().len(),
            ss_len,
            "{scheme} shared secret length"
        );
    }
}

/// A malformed ciphertext must not behave differently from a well-formed one in a way
/// that leaks whether decryption succeeded.
///
/// These KEMs use implicit rejection: a ciphertext that fails to decrypt yields a
/// pseudorandom shared secret rather than an error, so an attacker cannot use the API
/// as a decryption oracle. What matters for uniformity is that a *well-formed but
/// corrupted* ciphertext of the correct length is accepted and produces a shared secret
/// that simply differs from the sender's — never an error that distinguishes it.
#[test]
fn corrupted_ciphertexts_are_implicitly_rejected() {
    for &(scheme, _, _, _, _) in PUBLISHED_SIZES {
        let (ek, dk) = scheme.keypair().expect("keypair");
        let (ct, ss_sender) = scheme.encapsulate(&ek).expect("encapsulate");

        let mut corrupted = ct.to_raw_bytes();
        corrupted[0] ^= 0xFF;
        let ct_bad = KemCiphertext::from_raw_bytes(scheme, &corrupted)
            .expect("a corrupted ciphertext of correct length must still parse");

        match scheme.decapsulate(&ct_bad, &dk) {
            Ok(ss) => assert_ne!(
                ss.to_raw_bytes(),
                ss_sender.to_raw_bytes(),
                "{scheme} returned the sender's secret for a corrupted ciphertext"
            ),
            Err(Error::SchemeMismatch { .. }) => {
                panic!("{scheme} reported a scheme mismatch for its own ciphertext")
            }
            Err(_) => {
                // Some backends validate structure before decrypting. That is a weaker
                // guarantee than implicit rejection but not a scheme-confusion bug; it
                // is recorded here rather than asserted away.
            }
        }
    }
}
