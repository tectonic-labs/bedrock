//! NIST ACVP known-answer tests for ML-DSA with a FIPS 204 context string.
//!
//! The vectors are a pinned subset of `usnistgov/ACVP-Server`; see
//! `tests/data/ml-dsa-acvp-README.md` for provenance, the NIST notice and the selection rule.
#![cfg(feature = "ml-dsa")]

use serde::Deserialize;
use tectonic_bedrock::ml_dsa::{MlDsaContext, MlDsaScheme};

#[cfg(feature = "vrfy")]
use tectonic_bedrock::ml_dsa::{MlDsaSignature, MlDsaVerificationKey};

#[cfg(feature = "sign")]
use tectonic_bedrock::ml_dsa::MlDsaSigningKey;

/// Maps an ACVP `parameterSet` name (identical to Bedrock's scheme name) to the scheme.
fn scheme(name: &str) -> MlDsaScheme {
    name.parse().unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[derive(Deserialize)]
struct File<T> {
    cases: Vec<T>,
}

#[cfg(feature = "vrfy")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerCase {
    tc_id: u32,
    parameter_set: String,
    test_passed: bool,
    reason: String,
    context: String,
    message: String,
    pk: String,
    signature: String,
}

#[cfg(feature = "sign")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenCase {
    tc_id: u32,
    parameter_set: String,
    context: String,
    message: String,
    sk: String,
    signature: String,
}

/// `verify_with_context` must agree with ACVP's `testPassed` for every case.
///
/// Tampered signatures may be rejected already at decoding (`from_raw_bytes`); that counts as a
/// rejection, which is what ACVP expects for `testPassed: false`.
#[cfg(feature = "vrfy")]
#[test]
fn sig_ver_matches_acvp() {
    let file: File<SigVerCase> =
        serde_json::from_str(include_str!("data/ml-dsa-acvp-sigver.json")).unwrap();
    assert!(!file.cases.is_empty());
    for case in file.cases {
        let scheme = scheme(&case.parameter_set);
        let label = format!(
            "{} tcId {} ({})",
            case.parameter_set, case.tc_id, case.reason
        );
        let pk = MlDsaVerificationKey::from_raw_bytes(scheme, &unhex(&case.pk)).unwrap();
        let context = unhex(&case.context);
        let context = MlDsaContext::try_from(context.as_slice()).unwrap();
        let accepted = MlDsaSignature::from_raw_bytes(scheme, &unhex(&case.signature))
            .and_then(|sig| scheme.verify_with_context(&unhex(&case.message), context, &sig, &pk))
            .is_ok();
        assert_eq!(accepted, case.test_passed, "{label}");
    }
}

/// Deterministic `sign_with_context` must reproduce ACVP's expected signature bytes exactly.
#[cfg(feature = "sign")]
#[test]
fn sig_gen_deterministic_matches_acvp() {
    let file: File<SigGenCase> =
        serde_json::from_str(include_str!("data/ml-dsa-acvp-siggen.json")).unwrap();
    assert!(!file.cases.is_empty());
    for case in file.cases {
        let scheme = scheme(&case.parameter_set);
        let label = format!("{} tcId {}", case.parameter_set, case.tc_id);
        let sk = MlDsaSigningKey::from_raw_bytes(scheme, &unhex(&case.sk)).unwrap();
        let context = unhex(&case.context);
        let context = MlDsaContext::try_from(context.as_slice()).unwrap();
        let sig = scheme
            .sign_with_context(&unhex(&case.message), context, &sk)
            .unwrap();
        assert_eq!(sig.to_raw_bytes(), unhex(&case.signature), "{label}");
    }
}
