# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Restored ML-DSA-44 (NIST Level 2). This reinstates the `MlDsaScheme::Dsa44` variant, the
  `SignatureScheme::MlDsa44` / `SignatureSeed::MlDsa44` HD-wallet variants, the
  `HHDWallet::derive_mldsa44_keypair` method, and all `ML_DSA_44_*` constants, restoring
  wire discriminant `1` and BIP-85 child index `4` for ML-DSA-44. `MlDsaScheme::Dsa65`
  remains the default.

### Removed

- **BREAKING:** Removed ML-KEM-512 (NIST Level 1), now considered too weak to offer. This
  drops the `KemScheme::MlKem512` and `XwingScheme::X25519MlKem512` variants. The default
  moves to ML-KEM-768. Serde discriminants and BIP-85 child indices of the surviving
  schemes are unchanged, so existing serialized keys and derivation paths for stronger
  schemes remain valid.

### Deprecated

- The removed schemes' wire discriminants (`1`) and name strings (`"ML-KEM-512"`,
  `"X25519-ML-KEM-512"`) are reserved and now map to a new
  `Error::DeprecatedScheme { scheme, replacement }` on `TryFrom<u8>` / `FromStr` (and
  therefore on deserialization), so data produced by an older version fails with a clear
  migration error instead of a generic `InvalidScheme`. The discriminants are never
  reassigned to other schemes.

## v0.2.0 - 2026-01-04

- Initial Release
- Renamed HHD domain separators by removing `-v1` suffix from signature specific separator strings (#20)
