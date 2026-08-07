# Bedrock

Tectonic's common cryptography library.

Bedrock provides post-quantum cryptographic primitives, including digital signatures and
key-encapsulation mechanisms (KEMs). The library supports NIST-standardized algorithms
(ML-DSA and ML-KEM) as well as other post-quantum schemes (Falcon/FN-DSA and Classic
McEliece).

## Features

- **ML-DSA (FIPS 204)**: Module-Lattice-Based Digital Signature Algorithm
- **Falcon/FN-DSA**: Fast Fourier lattice-based compact signatures
- **MAYO**: Multivariate oil-and-vinegar signatures with compact public keys
- **ML-KEM (FIPS 203)**: Module-lattice-based key-encapsulation mechanism
- **Classic McEliece**: Code-based key-encapsulation mechanism
- **ETHFALCON**: Ethereum-compatible Falcon variant with Keccak-256 XOF
- **X-Wing**: Hybrid KEM combining X25519 with ML-KEM or Classic McEliece
- **HQC**: Code-based key-encapsulation mechanism over quasi-cyclic codes,
  [selected by NIST for standardization](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post_Quantum_Cryptography-Standardization)
- **Streamlined NTRU Prime**: Lattice-based KEM avoiding ring structure, all six sizes
- **FrodoKEM**: Conservative plain-LWE key-encapsulation mechanism
- **XMSS (RFC 8391 / SP 800-208)**: Stateful hash-based signatures
- **Bird-of-Prey-2**: Hybrid signatures combining Ed25519 with ML-DSA or FN-DSA

## Supported Algorithms

### ML-DSA (Digital Signatures)

Three security levels following NIST standards:

- **ML-DSA-44** (NIST Level 2) - Deprecated; use ML-DSA-65 or higher
- **ML-DSA-65** (NIST Level 3) - Default
- **ML-DSA-87** (NIST Level 5)

### Falcon/FN-DSA (Digital Signatures)

Two security levels plus Ethereum variant:

- **FN-DSA-512** (NIST Level 1) - Default
- **FN-DSA-1024** (NIST Level 5)
- **ETHFALCON** (Ethereum-compatible Falcon-512 with Keccak-256)

### MAYO (Digital Signatures)

MAYO provides multivariate oil-and-vinegar signatures with compact public keys through
the `mayo` feature. It offers four parameter sets at three NIST security levels:

- **MAYO-1** (NIST Level 1) - Default
- **MAYO-2** (NIST Level 1) - Smallest signatures
- **MAYO-3** (NIST Level 3)
- **MAYO-5** (NIST Level 5)

HHD key derivation is supported for MAYO-1, MAYO-2, and MAYO-3. The 32-byte
SLIP-0010 child key is truncated to the parameter set's key-generation seed size (24 bytes
for MAYO-1 and MAYO-2; 32 bytes for MAYO-3). MAYO-5 is not offered in HHD because its
40-byte seed would require expanding, rather than truncating, the child key.

### ML-KEM (Key Encapsulation)

Two security levels following NIST standards:

- **ML-KEM-768** (NIST Level 3) - Default when the `ml-kem` feature is enabled
- **ML-KEM-1024** (NIST Level 5)

### Classic McEliece (Key Encapsulation)

- **ClassicMcEliece-348864** (legacy NIST Level 1; not part of ISO)
- **ClassicMcEliece-460896** (NIST Level 3) - Default when only `mceliece` is enabled
- **ClassicMcEliece-6688128** (NIST Level 5)
- **ClassicMcEliece-6960119** (NIST Level 5)
- **ClassicMcEliece-8192128** (NIST Level 5)

The four larger sizes are ISO standardized; 348864 remains available for legacy
interoperability. Every size supports deterministic key generation from a 32-byte seed.

### X-Wing (Hybrid Key Encapsulation)

Hybrid KEM combining X25519 with post-quantum KEMs:

- **X25519-ML-KEM-768** (X25519 + ML-KEM-768) - Default
- **X25519-ML-KEM-1024** (X25519 + ML-KEM-1024)
- **X25519-ClassicMcEliece348864** (X25519 + Classic McEliece)

### HQC (Key Encapsulation)

Code-based KEM selected by NIST for standardization, using quasi-cyclic codes with a
concatenated Reed-Solomon/Reed-Muller construction under a Fujisaki-Okamoto transform.
Its final FIPS publication is forthcoming. HQC complements ML-KEM with larger ciphertexts
and a security assumption that does not rest on structured lattices. Enable it with the
`hqc` feature.

- **HQC-128** (NIST Level 1)
- **HQC-192** (NIST Level 3) - Default when `hqc` is the only KEM enabled
- **HQC-256** (NIST Level 5)

Seed-derived key generation is supported with a 32-byte seed. Decapsulation is pinned to
the official HQC submission's known-answer test vectors in `tests/kat_kem.rs`.

All three parameter sets also support HHD key derivation when the `hhd` and `hqc`
features are enabled. HQC-128/192/256 use distinct BIP-85 child indices `10'`/`11'`/`12'`
and SLIP-0010 domain separators. The complete 32-byte SLIP-0010 child key is passed to
HQC deterministic key generation without truncation or expansion.

### Streamlined NTRU Prime (Key Encapsulation)

Streamlined NTRU Prime is a lattice-based KEM designed to avoid the ring structure used by
ring-LWE schemes. Enable it through the `sntrup` feature. All six parameter sets are
offered:

- **sntrup653** (NIST Level 1) - lowest margin in the family
- **sntrup761** (NIST Level 2) - the set OpenSSH deploys in `sntrup761x25519-sha512`
- **sntrup857** (NIST Level 3)
- **sntrup953** (NIST Level 4)
- **sntrup1013** (NIST Level 5)
- **sntrup1277** (NIST Level 5)

Every set generates keys deterministically from a 32-byte seed, so all six support
seed-derived generation.

### FrodoKEM (Key Encapsulation)

FrodoKEM is a conservative KEM built on plain LWE with no ring or module structure. Enable
it through the `frodo` feature. Six parameter sets are available:

- **FrodoKEM-640-AES** / **FrodoKEM-640-SHAKE** (NIST Level 1)
- **FrodoKEM-976-AES** / **FrodoKEM-976-SHAKE** (NIST Level 3)
- **FrodoKEM-1344-AES** / **FrodoKEM-1344-SHAKE** (NIST Level 5)

The AES and SHAKE variants of a given `n` differ only in how the matrix **A** is derived
and have identical key, ciphertext, and shared-secret lengths. They are
therefore distinguished exclusively by the scheme stored alongside the key material —
never by encoding length.

**FrodoKEM does not support seed-derived key generation.** Its key seed is 48, 72, or 96
bytes depending on parameter set, above the 32-byte ceiling a single SLIP-0010 child key
can supply without expansion. `keypair_from_seed` returns
`Error::DeterministicKeygenUnsupported` for any input, including an empty seed. Use
`KemScheme::supports_seeded_keygen()` to test for this rather than inspecting `seed_size`,
which is zero for these schemes and would otherwise be ambiguous.

### XMSS (Stateful Hash-Based Signatures)

XMSS provides hash-based signatures under **RFC 8391** and **SP 800-208** through the
`xmss` feature. It supports twelve parameter sets: SHA-2 and SHAKE256, each at tree heights
10, 16, and 20 and with 256- or 512-bit output.

**XMSS is stateful.** Every signature consumes one one-time-signature leaf, and releasing
two signatures under the same leaf index reveals the secret key. Because Bedrock performs
no I/O, state persistence is the caller's responsibility: implement the `XmssStateStore`
trait. The signer commits advanced state through the store *before* releasing a signature,
so a failed commit yields no signature. Exhausting the tree returns
`Error::XmssKeyExhausted` rather than wrapping around.

### Bird-of-Prey-2 (Hybrid Signatures)

Bird-of-Prey-2 provides strong-unforgeability-preserving hybrid signatures that combine
Ed25519—treated as a Fiat-Shamir identification scheme with unique responses—with a
post-quantum signature. It follows ePrint 2025/1844 and Section 4 of
`draft-prabel-cfrg-suf-hybrid-sigs`. Enable it through the `bird-of-prey` feature.

- **Ed25519-ML-DSA-65**
- **Ed25519-FN-DSA-512**

The Ed25519 commitment `R` is recovered during verification rather than transmitted, so the
classical half of the signature is a single 32-byte scalar instead of a full 64-byte EdDSA
signature. The classical component is serialized first in both keys and signatures.

Because the combiner hashes the post-quantum signature into its Fiat-Shamir challenge, that
signature must be a deterministic function of key and message — otherwise a repeated
message would pair a fixed classical nonce with two different challenges and leak the
classical secret key. The FN-DSA branch is therefore driven by an RFC 6979 HMAC-SHA-512
DRBG (`det_rng`); the ML-DSA branch uses Bedrock's already-deterministic signer directly.

No cross-implementation test vectors exist for BoP-2 yet, so byte-level interoperability
with other implementations is not claimed.

### Excluded Schemes

The weakest ML-KEM parameter set is intentionally **not** offered. ML-DSA-44 remains
available for compatibility, but is deprecated and should not be used for new deployments:

| Scheme | NIST Level | Status | Notes |
|--------|-----------|--------|-------|
| **ML-KEM-512** | Level 1 | Removed | Use ML-KEM-768 (the new `KemScheme` default) or higher. |
| **ML-DSA-44** | Level 2 | Deprecated | Available for compatibility; use ML-DSA-65 (the `MlDsaScheme` default) or higher. |
| **X25519-ML-KEM-512** | — | Removed | Hybrid built on ML-KEM-512; use X25519-ML-KEM-768 or higher. |

Removing the KEMs dropped the `KemScheme::MlKem512` and
`XwingScheme::X25519MlKem512` variants. See the [CHANGELOG](./CHANGELOG.md) for the
full breaking-change entry. ML-DSA-44's APIs remain available with deprecation warnings.

The serde discriminants and BIP-85 child indices of the surviving schemes are unchanged,
so existing serialized keys and derivation paths for the stronger schemes remain valid.

**Deprecation path for existing data.** The wire discriminants (`1`) and name strings
(`"ML-KEM-512"`, `"X25519-ML-KEM-512"`) of the removed schemes stay
**reserved**: deserializing or parsing data produced by an older version of the library
returns a specific `Error::DeprecatedScheme { scheme, replacement }` — naming the removed
scheme and its recommended replacement — rather than a generic `InvalidScheme`. This gives
anything that may already have used these schemes a clear, actionable migration error
instead of a silent or confusing failure. The discriminants are never reassigned to other
schemes.

> **Note:** ClassicMcEliece-348864 remains available for legacy interoperability; new
> applications should select one of the ISO-standardized sizes.

## API Reference

### ML-DSA Methods

#### `MlDsaScheme`

**Key Generation:**

- `keypair() -> Result<(MlDsaVerificationKey, MlDsaSigningKey)>`
  Generates a new ML-DSA signing and verification keypair (requires the `kgen` feature).

**Signing:**

- `sign(message: &[u8], signing_key: &MlDsaSigningKey) -> Result<MlDsaSignature>`
  Signs a message with the specified signing key (requires the `sign` feature).

**Verification:**

- `verify(message: &[u8], signature: &MlDsaSignature, verification_key: &MlDsaVerificationKey) -> Result<()>`
  Verifies a signature (requires the `vrfy` feature).

#### `MlDsaSigningKey`, `MlDsaVerificationKey`, `MlDsaSignature`

Common methods for all types:

- `scheme() -> MlDsaScheme` - Returns the scheme used by this key or signature.
- `to_raw_bytes() -> Vec<u8>` - Converts the value to its raw byte representation.
- `from_raw_bytes(scheme: MlDsaScheme, bytes: &[u8]) -> Result<Self>` - Constructs a value from raw bytes.
- `as_ref() -> &[u8]` - Returns a byte-slice reference.

### Falcon/FN-DSA Methods

#### `FalconScheme`

**Key Generation:**

- `keypair() -> Result<(FalconVerificationKey, FalconSigningKey)>`
  Generates a new Falcon signing and verification keypair (requires the `kgen` feature).
- `keypair_from_seed(seed: &[u8]) -> Result<(FalconVerificationKey, FalconSigningKey)>`
  Generates a keypair from a 32- to 64-byte seed (requires the `kgen` feature).

**Signing:**

- `sign(message: &[u8], signing_key: &FalconSigningKey) -> Result<FalconSignature>`
  Signs a message with the specified signing key (requires the `sign` feature).

**Verification:**

- `verify(message: &[u8], signature: &FalconSignature, verification_key: &FalconVerificationKey) -> Result<()>`
  Verifies a signature (requires the `vrfy` feature).

#### `FalconSigningKey`, `FalconVerificationKey`, `FalconSignature`

Common methods for all types:

- `scheme() -> FalconScheme` - Returns the scheme used by this key or signature.
- `to_raw_bytes() -> Vec<u8>` - Converts the value to its raw byte representation.
- `from_raw_bytes(scheme: FalconScheme, bytes: &[u8]) -> Result<Self>` - Constructs a value from raw bytes.
- `as_ref() -> &[u8]` - Returns a byte-slice reference.

#### `FalconSigningKey` (ETHFALCON-specific)

When `eth_falcon` feature is enabled:

- `into_ethereum(self) -> Result<Self>` - Converts an FN-DSA-512 signing key to the ETHFALCON scheme.
- `into_dsa512(self) -> Result<Self>` - Converts an ETHFALCON signing key to the FN-DSA-512 scheme.

#### ETHFALCON Conversions

When `eth_falcon` feature is enabled:

- `EthFalconVerifyingKey::try_from(FalconVerificationKey) -> Result<EthFalconVerifyingKey>`
  Converts a Falcon public key to the ETHFALCON Solidity format (`abi.encodePacked`, NTT form, 1,024 bytes).
- `EthFalconSignature::try_from(FalconSignature) -> Result<EthFalconSignature>`
  Converts a Falcon signature to the ETHFALCON Solidity format (`abi.encodePacked`, 1,024 bytes).

### KEM Methods

#### `KemScheme`

**Key Generation:**

- `keypair() -> Result<(KemEncapsulationKey, KemDecapsulationKey)>`
  Generates a new encapsulation and decapsulation keypair (requires the `kgen` feature).
- `keypair_from_seed(seed: &[u8]) -> Result<(KemEncapsulationKey, KemDecapsulationKey)>`
  Generates a keypair from a seed (requires the `kgen` feature).

**Encapsulation:**

- `encapsulate(encapsulation_key: &KemEncapsulationKey) -> Result<(KemCiphertext, KemSharedSecret)>`
  Encapsulates to the provided public key (requires the `encp` feature).

**Decapsulation:**

- `decapsulate(ciphertext: &KemCiphertext, decapsulation_key: &KemDecapsulationKey) -> Result<KemSharedSecret>`
  Decapsulates the provided ciphertext (requires the `decp` feature).

#### `KemEncapsulationKey`, `KemDecapsulationKey`, `KemCiphertext`, `KemSharedSecret`

Common methods for all types:

- `scheme() -> KemScheme` - Returns the scheme used by this key, ciphertext, or secret.
- `to_raw_bytes() -> Vec<u8>` - Converts the value to its raw byte representation.
- `from_raw_bytes(scheme: KemScheme, bytes: &[u8]) -> Result<Self>` - Constructs a value from raw bytes.
- `as_ref() -> &[u8]` - Returns a byte-slice reference.

### X-Wing Methods

#### `XwingScheme`

**Key Generation:**

- `keypair() -> Result<(EncapsulationKey, DecapsulationKey)>`
  Generates a new X-Wing encapsulation and decapsulation keypair (requires the `xwing` feature).
- `keypair_from_seed(seed: &[u8]) -> Result<(EncapsulationKey, DecapsulationKey)>`
  Generates a keypair from a seed (requires the `xwing` feature).

#### `EncapsulationKey`

- `encapsulate() -> Result<(Ciphertext, SharedSecret)>`
  Creates a ciphertext and shared secret for the encapsulation key holder.
- `to_raw_bytes() -> Vec<u8>` - Converts the value to its raw byte representation.
- `from_raw_bytes(scheme: XwingScheme, bytes: &[u8]) -> Result<Self>` - Constructs a value from raw bytes.

#### `DecapsulationKey`

- `decapsulate(ciphertext: &Ciphertext) -> Result<SharedSecret>`
  Decapsulates the ciphertext to recover the shared secret.
- `to_seed() -> Vec<u8>` - Returns the seed bytes.
- `from_seed(scheme: XwingScheme, bytes: &[u8]) -> Self` - Constructs a key from seed bytes.
- `expand() -> Result<ExpandedDecapsulationKey>` - Expands the seed into full key material.

#### `ExpandedDecapsulationKey`

- `decapsulate(ciphertext: &Ciphertext) -> Result<SharedSecret>` - Decapsulates using the expanded key.
- `encapsulation_key() -> EncapsulationKey` - Returns the associated encapsulation key.

#### `Ciphertext`

- `to_raw_bytes() -> Vec<u8>` - Converts the value to its raw byte representation.
- `from_raw_bytes(scheme: XwingScheme, bytes: &[u8]) -> Result<Self>` - Constructs a value from raw bytes.

### Serialization

All key types, signatures, ciphertexts, and shared secrets implement `serde::Serialize`
and `serde::Deserialize`:

- **Human-readable formats** (JSON, for example): Serialized as hex strings.
- **Binary formats** (postcard and CBOR, for example): Serialized as compact byte arrays.

Schemes implement the `Display` and `FromStr` traits for string parsing:

- `to_string()` - Converts a scheme to its string representation (for example, "ML-DSA-65").
- `from_str(s: &str) -> Result<Self>` or `parse()` - Parses a scheme from a string.
- Conversion to and from `u8` provides compact storage.

## Examples

### ML-DSA Digital Signatures

```rust
use tectonic_bedrock::ml_dsa::MlDsaScheme;

// Generate a keypair
let scheme = MlDsaScheme::Dsa65;
let (verification_key, signing_key) = scheme.keypair()?;

// Sign a message
let message = b"Hello, world!";
let signature = scheme.sign(message, &signing_key)?;

// Verify the signature
scheme.verify(message, &signature, &verification_key)?;

// Serialize keys
let vk_json = serde_json::to_string(&verification_key)?;
let vk_binary = postcard::to_stdvec(&verification_key)?;
```

### Falcon/FN-DSA Digital Signatures

```rust
use tectonic_bedrock::falcon::FalconScheme;

// Generate a keypair with deterministic seed
let scheme = FalconScheme::Dsa512;
let seed = [1u8; 48];
let (verification_key, signing_key) = scheme.keypair_from_seed(&seed)?;

// Sign and verify
let message = b"Sign this message";
let signature = scheme.sign(message, &signing_key)?;
scheme.verify(message, &signature, &verification_key)?;
```

### ETHFALCON (Ethereum-compatible)

```rust
use tectonic_bedrock::falcon::{EthFalconSignature, EthFalconVerifyingKey, FalconScheme};

// Generate ETHFALCON keypair
let scheme = FalconScheme::Ethereum;
let (verification_key, signing_key) = scheme.keypair()?;

// Sign with ETHFALCON
let message = b"Transaction data";
let signature = scheme.sign(message, &signing_key)?;

// Verify
scheme.verify(message, &signature, &verification_key)?;

// Convert to Solidity-compatible formats
let eth_vk: EthFalconVerifyingKey = verification_key.try_into()?;
let eth_sig: EthFalconSignature = signature.try_into()?;

// Convert between schemes
let signing_key_512 = signing_key.into_dsa512()?;
```

### ML-KEM Key Encapsulation

```rust
use tectonic_bedrock::kem::KemScheme;

// Generate a keypair
let scheme = KemScheme::MlKem768;
let (encapsulation_key, decapsulation_key) = scheme.keypair()?;

// Encapsulate to create shared secret
let (ciphertext, shared_secret_sender) = scheme.encapsulate(&encapsulation_key)?;

// Decapsulate to recover shared secret
let shared_secret_receiver = scheme.decapsulate(&ciphertext, &decapsulation_key)?;

assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref());
```

### Classic McEliece

```rust
use tectonic_bedrock::kem::KemScheme;

// Use Classic McEliece for code-based KEM
let scheme = KemScheme::ClassicMcEliece6960119;
let (ek, dk) = scheme.keypair()?;
let (ct, ss) = scheme.encapsulate(&ek)?;
let ss2 = scheme.decapsulate(&ct, &dk)?;
assert_eq!(ss.as_ref(), ss2.as_ref());
```

### HQC HHD Key Derivation

```rust
use tectonic_bedrock::{
    hhd::{HHDWallet, Mnemonic},
    kem::KemScheme,
};

let mnemonic = Mnemonic::from_phrase(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)?;
let wallet = HHDWallet::new_from_mnemonic_with_kem_schemes(
    mnemonic,
    Vec::new(),
    vec![KemScheme::Hqc128, KemScheme::Hqc192, KemScheme::Hqc256],
    None,
)?;

let (encapsulation_key, decapsulation_key) = wallet.derive_hqc192_keypair(0)?;
let (ciphertext, sender_secret) = KemScheme::Hqc192.encapsulate(&encapsulation_key)?;
let receiver_secret = KemScheme::Hqc192.decapsulate(&ciphertext, &decapsulation_key)?;
assert_eq!(sender_secret.as_ref(), receiver_secret.as_ref());
```

### X-Wing Hybrid KEM

```rust
use tectonic_bedrock::xwing::XwingScheme;

// Generate X-Wing keypair (combines X25519 with ML-KEM-768)
let scheme = XwingScheme::X25519MlKem768;
let (encapsulation_key, decapsulation_key) = scheme.keypair()?;

// Encapsulate to create shared secret
let (ciphertext, shared_secret_sender) = encapsulation_key.encapsulate()?;

// Decapsulate to recover shared secret
let shared_secret_receiver = decapsulation_key.decapsulate(&ciphertext)?;

assert_eq!(shared_secret_sender, shared_secret_receiver);
```

## Feature Flags

Control which algorithms and operations are enabled:

### Algorithm Features

- `ml-dsa` - Enable ML-DSA signature schemes (default)
- `slh-dsa` - Enable SLH-DSA signature schemes (default)
- `mayo` - Enable MAYO signature schemes (default)
- `falcon` - Enable Falcon/FN-DSA signature schemes (default)
- `eth_falcon` - Enable ETHFALCON Ethereum-compatible variant (default, requires `falcon`)
- `ml-kem` - Enable ML-KEM key encapsulation
- `mceliece` - Enable Classic McEliece key encapsulation
- `frodo` - Enable FrodoKEM key encapsulation
- `hqc` - Enable HQC key encapsulation and, with `hhd`, HQC HD derivation
- `sntrup` - Enable Streamlined NTRU Prime key encapsulation
- `xmss` - Enable XMSS stateful signatures
- `bird-of-prey` - Enable Bird-of-Prey-2 hybrid signatures
- `xwing` - Enable X-Wing hybrid KEM (requires `ml-kem` or `mceliece`)
- `hhd` - Enable hierarchical deterministic wallet support (default)

### Operation Features

- `kgen` - Enable key generation (default)
- `sign` - Enable signing operations (default)
- `vrfy` - Enable verification operations (default)
- `encp` - Enable encapsulation operations (default)
- `decp` - Enable decapsulation operations (default)

### Default Features

Bedrock is designed to allow selective features to minimize the dependency list.
The default feature set is:

```toml
default = ["eth_falcon", "falcon", "ml-dsa", "slh-dsa", "mayo", "decp", "encp", "kgen", "sign", "vrfy", "hhd"]
```

### Minimal Configuration Examples

Verification only (no key generation or signing):

```toml
tectonic-bedrock = { version = "0.4", default-features = false, features = ["ml-dsa", "vrfy"] }
```

ML-KEM only:

```toml
tectonic-bedrock = { version = "0.4", default-features = false, features = ["ml-kem", "kgen", "encp", "decp"] }
```

X-Wing hybrid KEM only:

```toml
tectonic-bedrock = { version = "0.4", default-features = false, features = ["ml-kem", "xwing", "kgen", "encp", "decp"] }
```

## Error Handling

All fallible operations return `Result<T, tectonic_bedrock::error::Error>`. The `Error`
enum includes, among others:

- `McElieceError(String)` - Errors from the Classic McEliece KEM.
- `InvalidScheme(u8)` / `InvalidSchemeStr(String)` - Invalid scheme identifiers.
- `InvalidSeedLength(usize)` - A seed length that does not match the selected scheme.
- `InvalidLength(usize)` - Invalid data length.
- `FnDsaError(String)` - ETHFALCON-specific errors.

## Security Considerations

- All post-quantum algorithms are designed to resist attacks by classical and quantum
  computers.
- ML-DSA and ML-KEM are standardized by NIST in FIPS 204 and FIPS 203, respectively.
- Falcon provides smaller signatures than ML-DSA at comparable security levels.
- ETHFALCON enables post-quantum signatures in Ethereum smart contracts.
- Classic McEliece offers conservative code-based security.
- Use deterministic key generation (`keypair_from_seed`) only when necessary.
- Protect private keys and seeds with appropriate key-management practices.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual-licensed
as above without any additional terms or conditions.

## References

- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [ETHFALCON Specification](https://github.com/zknoxhq/ETHFALCON)
- [X-Wing (IETF Draft)](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [pq-mceliece](https://github.com/mikelodder7/pq-mceliece)
