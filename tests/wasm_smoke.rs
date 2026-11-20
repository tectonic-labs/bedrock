//! Runtime smoke test for the `wasm` feature, run in Node.
//!
//! The tests live in `tests/smoke/mod.rs`; this crate decides where they run. Node is the
//! quick one: its `globalThis.crypto.getRandomValues` is the same Web Crypto API a browser
//! provides. See `tests/wasm_smoke_browser.rs` for the browser run.
//!
//! CI: `wasm-pack test --node -- --test wasm_smoke --features wasm`.

#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

mod smoke;
