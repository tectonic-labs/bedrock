# Hybrid Hierarchical Deterministic (HD) Wallet Library

This library provides a framework for managing hybrid hierarchical deterministic ([HD wallets](https://en.bitcoin.it/wiki/Deterministic_wallet)) that support multiple signature schemes from a single [BIP-39 mnemonic seed phrase](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). It enables seamless coexistence of both classical ([ECDSA secp256k1](https://en.bitcoin.it/wiki/Secp256k1)) and post-quantum ([Falcon-512](https://falcon-sign.info/)) signature schemes within a unified wallet structure. The post-quantum Falcon-512 primitive leverages [Tectonic's Bedrock repository](https://github.com/tectonic-labs/bedrock), which is based on the [OQS C implementation](https://github.com/open-quantum-safe/liboqs).

## Features

- **Multi-Scheme Support**: Derive keys for multiple signature schemes (ECDSA secp256k1, Falcon-512)  
- **Single Mnemonic**: Use one BIP-39 mnemonic to derive all scheme-specific seeds  
- **BIP-85 Derivation**: Derive scheme-specific seeds using the BIP-85 standard  
- **BIP-32 & SLIP-0010**: Supports both BIP-32 (ECDSA) and SLIP-0010 (Falcon) HD key derivation  
- **Deterministic**: All keys are deterministically derived from the master seed  
- **Cryptographic Separation**: Each signature scheme uses independent derivation paths  

## Quick Start

### Creating and Using a Hybrid HD Wallet with ECDSA and Falcon

```rust
use bedrock::hhd::{HHDWallet, SignatureScheme};

// Create a new wallet with both ECDSA and Falcon support
let wallet = HHDWallet::new(
    vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
    None, // Optional BIP-39 passphrase
).unwrap();

// Derive a keypair for ECDSA at address index 0
let ecdsa_keypair = wallet.derive_keypair_for_scheme(
    SignatureScheme::EcdsaSecp256k1,
    0,
).unwrap();

// Sign and verify with ECDSA
let message = b"Hello, world!";
let ecdsa_signature = wallet.sign_with_scheme( // Only available with "sign" feature flag
    SignatureScheme::EcdsaSecp256k1,
    0,
    message,
).unwrap();
let verified = wallet.verify_with_scheme( // Only available with "vrfy" feature flag
    SignatureScheme::EcdsaSecp256k1,
    0,
    message,
    &ecdsa_signature,
).unwrap();
assert!(verified);

// Derive a keypair for Falcon at address index 0
let falcon_keypair = wallet.derive_keypair_for_scheme(
    SignatureScheme::Falcon512,
    0,
).unwrap();

// Sign and verify with Falcon
let falcon_signature = wallet.sign_with_scheme( // Only available with "sign" feature flag
    SignatureScheme::Falcon512,
    0,
    message,
).unwrap();
let falcon_verified = wallet.verify_with_scheme( // Only available with "vrfy" feature flag
    SignatureScheme::Falcon512,
    0,
    message,
    &falcon_signature,
).unwrap();
assert!(falcon_verified);
```

### Importing a Wallet from an Existing Mnemonic Phrase

```rust
use bedrock::hhd::{HHDWallet, SignatureScheme, Mnemonic};

// Your BIP-39 phrase (for example, a 24-word phrase)
let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

// You can optionally provide a BIP-39 passphrase
let password = Some("my secret password");

// Import the wallet with both ECDSA and Falcon enabled
let wallet = HHDWallet::new_from_mnemonic(
    mnemonic,
    vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
    password,
).unwrap();

// Use wallet.derive_keypair_for_scheme, sign_with_scheme, etc. as above.
```

### Signing and Verifying with All Schemes

Example only available through `"sing"` and `"vrfy"` features.

```rust
use bedrock::hhd::{HHDWallet, SignatureScheme};

// Create a wallet with both ECDSA and Falcon support
let wallet = HHDWallet::new(
    vec![SignatureScheme::EcdsaSecp256k1, SignatureScheme::Falcon512],
    None,
).unwrap();

let message = b"Hello, world!";

// Sign with all schemes at the same address index
let signatures = wallet.sign_with_all_schemes(0, message).unwrap();

// Verify all signatures
let verified = wallet.verify_with_all_schemes(0, message, &signatures).unwrap();
assert!(verified);
```

## Architecture

The hybrid HD wallet architecture enables multiple signature schemes to coexist within a single wallet structure while maintaining cryptographic separation.

### Overview

The wallet follows a hierarchical derivation model:

1. **Master Mnemonic** (BIP-39): A single 24-word mnemonic phrase serves as the root entropy source for the entire wallet
2. **Scheme-Specific Seeds** (BIP-85): Each signature scheme receives its own 64-byte seed derived from the master mnemonic
3. **Keypairs** (BIP-32/SLIP-0010): Individual keypairs are derived from scheme seeds using address indices

This design ensures that:
- All keys are deterministically derived from a single mnemonic, allowing them to be restored from the mnemonic alone
- Different signature schemes use cryptographically independent seeds

### Derivation Paths

#### BIP-85 Scheme Seed Derivation

Each signature scheme gets its own unique seed through BIP-85 derivation from the master mnemonic. Two different paths are used for each signature type:

- **ECDSA secp256k1**: `m/83696968'/83286642'/1'`
- **Falcon-512**: `m/83696968'/83286642'/2'`

The base path `m/83696968'` is the standard BIP-85 path, `/83286642'` stands for Tectonic in a T9 keypad, and the final component (`1'` or `2'`) identifies the signature scheme. This ensures that even though both schemes share the same mnemonic, they operate on cryptographically independent seeds.

#### Key Derivation Paths

Once a scheme-specific seed is obtained, individual keypairs are derived using address indices.

**ECDSA secp256k1** (BIP-32, BIP-44):
- Domain separator: `Bitcoin seed`
- Base path: `m/44'/60'/0'/0`
- Full path: `m/44'/60'/0'/0/{address_index}`
- Standard: BIP-32 (non-hardened address index)
- Example for address index 0: `m/44'/60'/0'/0/0`

**Falcon-512** (SLIP-0010, hardened):
- Domain separator: `Falcon-512-v1 seed`
- Base path: `m/44'/60'/0'/0'`
- Full path: `m/44'/60'/0'/0'/{address_index}'`
- Standard: SLIP-0010 (all components hardened)
- Example for address index 0: `m/44'/60'/0'/0'/0'`

### Key Differences

| Signature | ECDSA secp256k1 | Falcon-512 |
|--------|----------------|------------|
| **BIP-85 Index** | `1'` | `2'` |
| **HD Standard** | BIP-32 | SLIP-0010 |
| **Domain Separator** | `Bitcoin seed`| `Falcon-512-v1 seed` |
| **Address Index** | Non-hardened | Hardened |


For more detailed implementation information, see the [ARCHITECTURE.md](https://github.com/tectonic-labs/bedrock/blob/main/src/hhd/ARCHITECTURE.md) document.

## Modules

- [`bip85`](hybrid-hd-wallet/src/bip85.rs): BIP-85 implementation for deriving scheme-specific seeds  
- [`keys`](hybrid-hd-wallet/src/keys/): Keypair wrappers for ECDSA and Falcon-512  
- [`mnemonic`](hybrid-hd-wallet/src/mnemonic.rs): BIP-39 mnemonic phrase handling  
- [`signatures`](hybrid-hd-wallet/src/signatures.rs): Signature scheme definitions and constants  
- [`slip10`](hybrid-hd-wallet/src/slip10.rs): SLIP-0010 implementation for Falcon-512 key derivation  

## Standards Used

- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki): Mnemonic code for generating deterministic keys  
- [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki): Hierarchical Deterministic Wallets  
- [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki): Multi-Account Hierarchy for Deterministic Wallets  
- [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki): Deterministic Entropy From BIP32 Keychains  
- [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md): Universal private key derivation from master private key
