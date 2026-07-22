# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- HD wallet (HHD) key derivation for MAYO-1, MAYO-2, and MAYO-3. Adds the
  `SignatureScheme::Mayo1/Mayo2/Mayo3` and `SignatureSeed::Mayo1/Mayo2/Mayo3` variants,
  the `HHDWallet::derive_mayo1_keypair` / `derive_mayo2_keypair` / `derive_mayo3_keypair`
  methods, and BIP-85 child indices `7'`/`8'`/`9'`. The 32-byte SLIP-0010 child key is
  truncated (never expanded) to each parameter set's keygen seed size — 24 bytes for
  MAYO-1/2, 32 bytes for MAYO-3. MAYO-5 is intentionally not supported in HHD because its
  40-byte seed cannot be sourced from a 32-byte SLIP-0010 child key without expansion.

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

- Initial Release
- Renamed HHD domain separators by removing `-v1` suffix from signature specific separator strings (#20)
