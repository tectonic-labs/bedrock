# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
