# Bedrock

Tectonic's common cryptography library

Bedrock provides post-quantum cryptographic primitives including digital signatures and key encapsulation mechanisms (KEMs). The library supports NIST-standardized algorithms (ML-DSA, ML-KEM) as well as other post-quantum schemes (Falcon/FN-DSA, Classic McEliece).

## Features

- **ML-DSA (FIPS 204)**: Module-Lattice-Based Digital Signature Algorithm
- **Falcon/FN-DSA**: Fast Fourier Lattice-based Compact Signatures
- **ML-KEM (FIPS 203)**: Module-Lattice-Based Key-Encapsulation Mechanism
- **Classic McEliece**: Code-based Key Encapsulation Mechanism
- **ETHFALCON**: Ethereum-compatible Falcon variant with Keccak-256 XOF

## Supported Algorithms

### ML-DSA (Digital Signatures)

Three security levels following NIST standards:

- **ML-DSA-44** (NIST Level 2) - Default
- **ML-DSA-65** (NIST Level 3)
- **ML-DSA-87** (NIST Level 5)

### Falcon/FN-DSA (Digital Signatures)

Two security levels plus Ethereum variant:

- **FN-DSA-512** (NIST Level 1) - Default
- **FN-DSA-1024** (NIST Level 5)
- **ETHFALCON** (Ethereum-compatible Falcon-512 with Keccak-256)

### ML-KEM (Key Encapsulation)

Three security levels following NIST standards:

- **ML-KEM-512** (NIST Level 1) - Default when `ml-kem` feature enabled
- **ML-KEM-768** (NIST Level 3)
- **ML-KEM-1024** (NIST Level 5)

### Classic McEliece (Key Encapsulation)

- **ClassicMcEliece-348864** (NIST Level 1) - Default when only `mceliece` feature enabled

## API Reference

### ML-DSA Methods

#### `MlDsaScheme`

**Key Generation:**
- `keypair() -> Result<(MlDsaVerificationKey, MlDsaSigningKey)>`
  Generate a new ML-DSA signing and verification key pair (requires `kgen` feature)

**Signing:**
- `sign(message: &[u8], signing_key: &MlDsaSigningKey) -> Result<MlDsaSignature>`
  Sign a message with the specified signing key (requires `sign` feature)

**Verification:**
- `verify(message: &[u8], signature: &MlDsaSignature, verification_key: &MlDsaVerificationKey) -> Result<()>`
  Verify a signature (requires `vrfy` feature)

#### `MlDsaSigningKey`, `MlDsaVerificationKey`, `MlDsaSignature`

Common methods for all types:
- `scheme() -> MlDsaScheme` - Get the scheme used by this key/signature
- `to_raw_bytes() -> Vec<u8>` - Convert to raw byte representation
- `from_raw_bytes(scheme: MlDsaScheme, bytes: &[u8]) -> Result<Self>` - Create from raw bytes
- `as_ref() -> &[u8]` - Get byte slice reference

### Falcon/FN-DSA Methods

#### `FalconScheme`

**Key Generation:**
- `keypair() -> Result<(FalconVerificationKey, FalconSigningKey)>`
  Generate a new Falcon signing and verification key pair (requires `kgen` feature)
- `keypair_from_seed(seed: &[u8]) -> Result<(FalconVerificationKey, FalconSigningKey)>`
  Generate a key pair from a seed (32-64 bytes, requires `kgen` feature)

**Signing:**
- `sign(message: &[u8], signing_key: &FalconSigningKey) -> Result<FalconSignature>`
  Sign a message with the specified signing key (requires `sign` feature)

**Verification:**
- `verify(message: &[u8], signature: &FalconSignature, verification_key: &FalconVerificationKey) -> Result<()>`
  Verify a signature (requires `vrfy` feature)

#### `FalconSigningKey`, `FalconVerificationKey`, `FalconSignature`

Common methods for all types:
- `scheme() -> FalconScheme` - Get the scheme used by this key/signature
- `to_raw_bytes() -> Vec<u8>` - Convert to raw byte representation
- `from_raw_bytes(scheme: FalconScheme, bytes: &[u8]) -> Result<Self>` - Create from raw bytes
- `as_ref() -> &[u8]` - Get byte slice reference

#### `FalconSigningKey` (ETHFALCON-specific)

When `eth_falcon` feature is enabled:
- `into_ethereum(self) -> Result<Self>` - Convert FN-DSA-512 signing key to ETHFALCON scheme
- `into_dsa512(self) -> Result<Self>` - Convert ETHFALCON signing key to FN-DSA-512 scheme

#### ETHFALCON Conversions

When `eth_falcon` feature is enabled:
- `EthFalconVerifyingKey::try_from(FalconVerificationKey) -> Result<EthFalconVerifyingKey>`
  Convert Falcon public key to ETHFALCON Solidity format (abi.encodePacked, NTT form, 1024 bytes)
- `EthFalconSignature::try_from(FalconSignature) -> Result<EthFalconSignature>`
  Convert Falcon signature to ETHFALCON Solidity format (abi.encodePacked, 1024 bytes)

### KEM Methods

#### `KemScheme`

**Key Generation:**
- `keypair() -> Result<(KemEncapsulationKey, KemDecapsulationKey)>`
  Generate a new encapsulation/decapsulation key pair (requires `kgen` feature)
- `keypair_from_seed(seed: &[u8]) -> Result<(KemEncapsulationKey, KemDecapsulationKey)>`
  Generate a key pair from a seed (requires `kgen` feature)

**Encapsulation:**
- `encapsulate(encapsulation_key: &KemEncapsulationKey) -> Result<(KemCiphertext, KemSharedSecret)>`
  Encapsulate to the provided public key (requires `encp` feature)

**Decapsulation:**
- `decapsulate(ciphertext: &KemCiphertext, decapsulation_key: &KemDecapsulationKey) -> Result<KemSharedSecret>`
  Decapsulate the provided ciphertext (requires `decp` feature)

#### `KemEncapsulationKey`, `KemDecapsulationKey`, `KemCiphertext`, `KemSharedSecret`

Common methods for all types:
- `scheme() -> KemScheme` - Get the scheme used by this key/ciphertext/secret
- `to_raw_bytes() -> Vec<u8>` - Convert to raw byte representation
- `from_raw_bytes(scheme: KemScheme, bytes: &[u8]) -> Result<Self>` - Create from raw bytes
- `as_ref() -> &[u8]` - Get byte slice reference

### Serialization

All key types, signatures, ciphertexts, and shared secrets implement `serde::Serialize` and `serde::Deserialize`:
- **Human-readable formats** (JSON, etc.): Serialized as hex strings and human-readable
- **Binary formats** (postcard, bincode, etc.): Serialized as compact byte arrays

Schemes implement the [`Display`] and [`FromStr`] traits for string parsing:
- `to_string()` - Convert scheme to string representation (e.g., "ML-DSA-44")
- `from_str(s: &str) -> Result<Self>` or `parse()` - Parse scheme from string
- Conversion to/from `u8` for compact storage

## Examples

### ML-DSA Digital Signatures

```rust
use bedrock::ml_dsa::MlDsaScheme;

// Generate a keypair
let scheme = MlDsaScheme::Dsa44;
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
use bedrock::falcon::FalconScheme;

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
use bedrock::falcon::{FalconScheme, EthFalconVerifyingKey, EthFalconSignature};

// Generate ETHFALCON keypair
let scheme = FalconScheme::Ethereum;
let (verification_key, signing_key) = scheme.keypair()?;

// Sign with ETHFALCON
let message = b"Transaction data";
let signature = scheme.sign(message, &signing_key)?;

// Convert to Solidity-compatible formats
let eth_vk: EthFalconVerifyingKey = verification_key.try_into()?;
let eth_sig: EthFalconSignature = signature.try_into()?;

// Verify
scheme.verify(message, &signature, &verification_key)?;

// Convert between schemes
let signing_key_512 = signing_key.into_dsa512()?;
```

### ML-KEM Key Encapsulation

```rust
use bedrock::kem::KemScheme;

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
use bedrock::kem::KemScheme;

// Use Classic McEliece for code-based KEM
let scheme = KemScheme::ClassicMcEliece348864;
let (ek, dk) = scheme.keypair()?;
let (ct, ss) = scheme.encapsulate(&ek)?;
let ss2 = scheme.decapsulate(&ct, &dk)?;
assert_eq!(ss.as_ref(), ss2.as_ref());
```

## Feature Flags

Control which algorithms and operations are enabled:

### Algorithm Features
- `ml-dsa` - Enable ML-DSA signature schemes (default)
- `falcon` - Enable Falcon/FN-DSA signature schemes (default)
- `eth_falcon` - Enable ETHFALCON Ethereum-compatible variant (default, requires `falcon`)
- `ml-kem` - Enable ML-KEM key encapsulation (default)
- `mceliece` - Enable Classic McEliece key encapsulation (default)

### Operation Features
- `kgen` - Enable key generation (default)
- `sign` - Enable signing operations (default)
- `vrfy` - Enable verification operations (default)
- `encp` - Enable encapsulation operations (default)
- `decp` - Enable decapsulation operations (default)

### Features

Bedrock is designed to allow selective features to minimize the dependency list.
The default is

```toml
default = ["eth_falcon", "falcon", "mceliece", "ml-dsa", "ml-kem", "decp", "encp", "kgen", "sign", "vrfy"]
```

### Minimal Configuration Examples

Verification only (no key generation or signing):
```toml
bedrock = { version = "0.1", default-features = false, features = ["ml-dsa", "vrfy"] }
```

ML-KEM only:
```toml
bedrock = { version = "0.1", default-features = false, features = ["ml-kem", "kgen", "encp", "decp"] }
```

## Error Handling

All fallible operations return `Result<T, bedrock::error::Error>`. The `Error` enum includes:

- `OqsError(String)` - Errors from the underlying OQS library
- `InvalidScheme(u8)` / `InvalidSchemeStr(String)` - Invalid scheme identifiers
- `InvalidSeedLength(usize)` - Seed length out of valid range (32-64 bytes)
- `InvalidLength(usize)` - Invalid data length
- `FnDsaError(String)` - ETHFALCON-specific errors

## Security Considerations

- All algorithms are quantum-resistant
- ML-DSA and ML-KEM are NIST-standardized (FIPS 204, FIPS 203)
- Falcon provides smaller signatures than ML-DSA with similar security
- ETHFALCON enables post-quantum signatures in Ethereum smart contracts
- Classic McEliece offers conservative code-based security
- Use deterministic key generation (`keypair_from_seed`) only when necessary
- Protect private keys and seeds with appropriate key management practices

## License

See repository for license information.

## References

- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [ETHFALCON Specification](https://github.com/zknoxhq/ETHFALCON)
- [liboqs](https://github.com/open-quantum-safe/liboqs)