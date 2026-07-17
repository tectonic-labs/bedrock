# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
