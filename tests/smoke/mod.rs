//! Test bodies for the wasm smoke tests, shared by the Node and the browser crates.
//!
//! On `wasm32-unknown-unknown` every RNG-backed API reaches the operating system through
//! `getrandom`, which needs its JavaScript backend there (`crypto.getRandomValues` through
//! `wasm-bindgen`). That backend is only wired up at build time, so these tests run the
//! real thing: they generate keys, sign and verify, all of which draw entropy.
//!
//! The crates that use this module decide where the tests run: `tests/wasm_smoke.rs` in
//! Node, `tests/wasm_smoke_browser.rs` in a browser. Both compile to nothing on other
//! targets, so a native `cargo test` ignores them.

use tectonic_bedrock::ml_dsa::MlDsaScheme;
use wasm_bindgen_test::wasm_bindgen_test;

const MESSAGE: &[u8] = b"bedrock wasm smoke test";

/// Key generation, signing and verification all work, and a modified message is rejected.
#[wasm_bindgen_test]
fn ml_dsa_sign_verify_roundtrip() {
    let scheme = MlDsaScheme::Dsa65;
    let (verification_key, signing_key) = scheme.keypair().expect("key generation");
    let signature = scheme.sign(MESSAGE, &signing_key).expect("signing");

    scheme
        .verify(MESSAGE, &signature, &verification_key)
        .expect("verifying the signed message");

    let rejected = scheme.verify(b"a different message", &signature, &verification_key);
    assert!(rejected.is_err(), "a modified message must not verify");
}

/// Two key generations return different keys, so the backend feeds fresh entropy
/// rather than a constant or an all-zero buffer.
#[wasm_bindgen_test]
fn keygen_draws_fresh_entropy() {
    let scheme = MlDsaScheme::Dsa65;
    let (first, _) = scheme.keypair().expect("first key generation");
    let (second, _) = scheme.keypair().expect("second key generation");

    assert_ne!(
        first.to_raw_bytes(),
        second.to_raw_bytes(),
        "two key generations produced the same verification key"
    );
}
