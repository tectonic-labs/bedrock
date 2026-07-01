# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Removed

- **BREAKING:** Removed ML-KEM-512 (NIST Level 1) and ML-DSA-44 (NIST Level 2),
  now considered too weak to offer. This drops the `KemScheme::MlKem512`,
  `MlDsaScheme::Dsa44`, and `XwingScheme::X25519MlKem512` variants, the
  `SignatureScheme::MlDsa44` / `SignatureSeed::MlDsa44` HD-wallet variants, the
  `HHDWallet::derive_mldsa44_keypair` method, and all `ML_DSA_44_*` constants.
  Defaults move to ML-KEM-768 and ML-DSA-65. Serde discriminants and BIP-85 child
  indices of the surviving schemes are unchanged, so existing serialized keys and
  derivation paths for stronger schemes remain valid.

## v0.2.0 - 2026-01-04

- Initial Release
- Renamed HHD domain separators by removing `-v1` suffix from signature specific separator strings (#20)
