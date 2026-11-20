//! Runtime smoke test for the `wasm` feature, run in a browser.
//!
//! Same tests as `tests/wasm_smoke.rs`, but the module is loaded with the web
//! `wasm-bindgen` glue instead of the Node glue, which is how the crate is consumed in a
//! browser client. Without `wasm_bindgen_test_configure!` the runner refuses to run these
//! tests in a browser and skips them, which would pass while testing nothing.
//!
//! CI: `wasm-pack test --headless --chrome -- --test wasm_smoke_browser --features wasm`.

#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

mod smoke;
