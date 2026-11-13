# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## v0.8.0

### Changed

- **Breaking:** keys now serialize as a Multikey and signatures as a Multisig, through the
  new default `multiformats` feature. This covers ML-DSA, FN-DSA/ETHFALCON, MAYO, SLH-DSA,
  Bird-of-Prey, XMSS, and the KEM encapsulation and decapsulation keys. Data written by
  earlier releases does not decode with the new default; read it with `plain::Plain` (or
  `#[serde(with = "tectonic_bedrock::plain")]`) and write it back to migrate.
- **Breaking:** without `multiformats`, those keys and signatures have no serde impls.
  The feature never switches the format, so another crate enabling it cannot change what
  your build writes.
- `plain` deserialization of XMSS signing keys checks the length and parameter set instead of
  rebuilding the key's tree, so untrusted input cannot force minutes of hashing.
- **Breaking:** the minimum supported Rust version is now 1.99, the multi-* crates' minimum.
- **Breaking:** `Error` has a new `Multiformat` variant (with `multiformats`).
- KEM ciphertexts and shared secrets, and X-Wing keys and ciphertexts, keep their
  `{scheme, value}` serde shape: there is no multiformat type for them.

### Added

- Added FIPS 204 context-string support to ML-DSA: `MlDsaScheme::sign_with_context`,
  `MlDsaScheme::sign_randomized_with_context` (feature `sign`) and
  `MlDsaScheme::verify_with_context` (feature `vrfy`), taking an `MlDsaContext`. Its
  `TryFrom<&[u8]>` refuses a context longer than 255 bytes with `Error::MlDsaError`, so
  signing and verifying never see one. `sign`, `sign_randomized` and `verify` delegate
  with an empty context, so their behavior and output bytes are unchanged.
- `TryFrom` conversions between every key and `Multikey`, and every signature and
  `Multisig`, plus `CodecInfo`. Schemes with a matching standard multicodec use it; the
  rest use the `identity` codec with `algorithm-name` and `key-type` (keys) or `scheme`
  (signatures). Decoding rejects other codecs, extra or missing attributes, comments,
  multisig messages, and trailing bytes.
- `TryFrom` conversions between the `hashing` digests and `Multihash`.
- The `plain` module: `RawBytes`, the `Plain` wrapper, and `serialize`/`deserialize`
  functions for the pre-0.8 `{scheme, value}` shape. `to_raw_bytes`, `from_raw_bytes` and
  `AsRef<[u8]>` are unchanged.
- `#[serde(with = "tectonic_bedrock::multiformats")]`, the counterpart of the `plain`
  functions, so one struct can keep some fields in each encoding. The sealed
  `multiformats::Multiformat` trait marks the types it accepts.
- Dependencies `multi-codec` 2, `multi-hash` 4, `multi-key` 3.1, `multi-sig` 3,
  `multi-trait` 1.1 and `multi-util` 2, optional behind `multiformats`, with
  `default-features = false` so they bring in no signature or KEM implementation. They do
  add `ssh-key` 0.7.0-rc.11 (required by multi-key), `rand` 0.10 and `serde_cbor_2`.
  `multiformats` also adds `strum` and turns on `zeroize`.

### Known issues

- Serializing a secret key to a human-readable format leaves unzeroized copies on the heap
  inside multi-key and multi-util. Binary formats and `plain` are not affected.

## v0.6.0

### Added

- Added the opt-in `hashing` feature with one-shot functions, incremental contexts,
  and typed digests for SHA-512, SHA3-256/384, SHAKE128-256/SHAKE256-512,
  BLAKE2s-256/BLAKE2b-512, and BLAKE3-256.
- Hash contexts support chunked updates, consuming finalization, and non-consuming
  prefix digests. File I/O and protocol framing remain caller responsibilities;
  existing SHA-256/SHA-384 APIs in `symmetric` are unchanged.
- Added independent hash vectors, chunk-boundary coverage, and hashing-only CI
  checks on the MSRV and stable Rust.

### Deprecated

- All five Classic McEliece KEM variants and McEliece-based X-Wing now emit Rust
  deprecation warnings on direct use, following
  [recent key-recovery research](https://eprint.iacr.org/2026/1984).
  Legacy operations, names, wire IDs, serialization, and feature-dependent defaults
  remain unchanged. Parsing and deserialization still accept these schemes without
  runtime warnings. Select ML-KEM-768/1024 or their X25519 hybrids for new deployments.

## v0.5.3

### Added

- Added independent `ecdsa-signatures`, `ed25519-signatures`, and
  `rsa-signatures` feature flags for conventional signature operations.

### Changed

- Replaced crate-local byte serialization wrappers with direct `serdect`
  adapters and limited `hex` to test-only formatting and vector decoding.
- Retained `classical-signatures` as a compatibility umbrella while allowing
  downstream consumers to omit the RSA implementation affected by
  RUSTSEC-2023-0071.

## v0.5.2 - 2026-09-01

### Added

- Added the optional `symmetric` feature with transport-neutral AES-GCM,
  ChaCha20-Poly1305, SHA-2, HMAC/HKDF, AES block, and ChaCha20 stream
  primitives for protocol adapters such as bedrock-tls.
- Added optional `random` and `key-agreement` features for operating-system
  CSPRNG access and ephemeral X25519, P-256, and P-384 agreement.
- Added the optional `classical-signatures` feature with transport-neutral RSA,
  P-256 ECDSA, P-384 ECDSA, and Ed25519 verification, signing, public-key
  encoding, and PKCS#8/PKCS#1/SEC1 private-key loading.

## v0.5.1 - 2026-08-31

### Fixed

- Updated ML-DSA seeded and randomized key generation for the `ml-dsa` 0.1.1
  API used by the published package.

## v0.5.0 - 2026-08-25

### Added

- Added the nine standardized XMSS parameter sets that Bedrock did not previously
  expose, using `pq-xmss` 0.2.0 to bring standard single-tree coverage to all 21
  combinations.
- Added the optional `xmss-extra-depths` feature, exposing all 147 non-standard
  `pq-xmss` parameter sets across seven hash/output families and tree heights 1–9,
  11–15, 17–19, and 21–24. Existing XMSS wire discriminants 1–12 remain unchanged,
  the additional standard schemes use 13–21, and extra-depth schemes use a stable
  24-slot-per-family layout from 22–189 with standard-depth slots reserved. Extra-depth
  keys retain `pq-xmss`'s private-use OIDs.

### Changed

- Migrated the crate to the Rust 2024 edition while retaining Rust 1.95 as the MSRV.
- Replaced the `xmss` backend with `pq-xmss` 0.2.0 for faster XMSS operations and
  lower memory usage while preserving existing XMSS scheme names and wire discriminants.
- Marked `XmssScheme` as non-exhaustive so optional or future parameter-set additions
  do not break downstream exhaustive matches.
- Updated `sntrup` to 0.4.0 for its SIMD-backed performance improvements and
  zeroization of secret temporaries; this raises the effective MSRV to Rust 1.95.
- Updated `rand` and `rand_chacha` to 0.10; moved the hash and MAC stack to
  Digest 0.11-compatible releases (`hmac` 0.13, `sha2` 0.11, `sha3` 0.12, and
  `shake` 0.1); and updated `curve25519-dalek` to 5.0 and `x25519-dalek` to 3.0.
  FN-DSA's `rand_core` 0.6 compatibility boundary remains until its public RNG
  traits migrate; newer backends use `rand_core` 0.10.

## v0.4.0 - 2026-08-07

### Added

- Falcon and ETHFALCON signing and verification benchmarks.
- HHD key derivation for HQC-128, HQC-192, and HQC-256. The parameter sets use
  independent BIP-85 child indices `10'`/`11'`/`12'` and SLIP-0010 domain separators,
  then pass the complete 32-byte child key to `hqc-kem` as deterministic key-generation
  input. This release also adds the KEM-aware HHD wallet constructors and
  `derive_hqc128_keypair`, `derive_hqc192_keypair`, and `derive_hqc256_keypair`.

### Changed

- Replaced the Classic McEliece backend with `pq-mceliece`, added the ISO-standardized
  460896, 6688128, 6960119, and 8192128 parameter sets, and made 460896 the default when
  Classic McEliece is the only enabled KEM family. ClassicMcEliece-348864 remains
  available for legacy interoperability.
- Kept all-feature CI within its five-minute budget by limiting expensive XMSS
  cryptographic behavior tests to `XMSS-SHA2_10_256` and reusing a fixed test-only
  key plus two safely cached signatures and serialized states. Full-tree key
  generation remains available as an ignored manual smoke test. Heights 16/20 and
  the remaining hash/width variants retain dispatch, size, serialization, name, and
  wire-contract coverage without building full Merkle trees.
- Updated the transitive `keccak` dependency used by Falcon compatibility tests from
  the yanked 0.1.5 release to 0.1.6.

## v0.3.0 - 2026-07-28

### Added

- Hierarchical deterministic (HD) wallet key derivation for MAYO-1, MAYO-2, and MAYO-3.
  This release adds the
  `SignatureScheme::Mayo1/Mayo2/Mayo3` and `SignatureSeed::Mayo1/Mayo2/Mayo3` variants,
  the `HHDWallet::derive_mayo1_keypair` / `derive_mayo2_keypair` / `derive_mayo3_keypair`
  methods, and BIP-85 child indices `7'`/`8'`/`9'`. The 32-byte SLIP-0010 child key is
  truncated (never expanded) to each parameter set's key-generation seed size—24 bytes for
  MAYO-1 and MAYO-2; 32 bytes for MAYO-3. MAYO-5 is intentionally not supported in HHD
  because its 40-byte seed cannot be sourced from a 32-byte SLIP-0010 child key without
  expansion.

### Removed

- **BREAKING:** Removed ML-KEM-512 (NIST Level 1), now considered too weak to offer.
  This drops the `KemScheme::MlKem512` and `XwingScheme::X25519MlKem512` variants.
  Defaults move to ML-KEM-768 and ML-DSA-65. Serde discriminants and BIP-85 child
  indices of the surviving schemes are unchanged, so existing serialized keys and
  derivation paths for stronger schemes remain valid.

### Deprecated

- The removed schemes' wire discriminants (`1`) and name strings (`"ML-KEM-512"`,
  `"X25519-ML-KEM-512"`) are reserved and now map to a new
  `Error::DeprecatedScheme { scheme, replacement }` on `TryFrom<u8>` / `FromStr` (and
  therefore on deserialization), so data produced by an older version fails with a clear
  migration error instead of a generic `InvalidScheme`. The discriminants are never
  reassigned to other schemes.
- ML-DSA-44 remains available for compatibility, but its public APIs are deprecated in
  favor of ML-DSA-65 or a stronger parameter set.

## v0.2.0 - 2026-01-04

- Initial release.
- Renamed HHD domain separators by removing the `-v1` suffix from signature-specific
  separator strings (#20).
