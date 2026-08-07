# Hybrid HD Wallet Specification: ECDSA and Post-Quantum Schemes

Tectonic PQ Wallet supports hybrid signature workflows that combine conventional and
post-quantum signatures. It provides Web3 users with deterministic wallet management based
on familiar, battle-tested standards.

This document specifies the derivation process for Tectonic's hybrid hierarchical
deterministic (HD) wallet. The wallet deterministically generates and manages keypair
hierarchies for the following schemes:

1. ECDSA secp256k1 signatures;
2. Falcon-512 signatures [1];
3. ML-DSA-44, ML-DSA-65, and ML-DSA-87 signatures [2] (ML-DSA-44 is deprecated);
4. MAYO-1, MAYO-2, and MAYO-3 signatures;
5. HQC-128, HQC-192, and HQC-256 key encapsulation.

The design allows a single BIP-39 mnemonic to derive independent key hierarchies for
multiple schemes without requiring separate mnemonics.

## General overview

Wallets with incompatible derivation mechanisms can produce different keys from the same
input. Tectonic PQ Wallet therefore reuses established standards wherever possible. It
uses [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
[BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki),
[BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), and
[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki), and extends
[SLIP-0010](https://slips.readthedocs.io/en/latest/slip-0010/) to post-quantum schemes.

In summary, BIP-39 generates a master seed from a mnemonic, and BIP-85 generates an
independent child seed for each configured scheme. BIP-85 uses BIP-32 hardened child key
derivation (CKD) with the path `m/83696968'/{app_no}'/{index}'`. The ECDSA branch
(`index = 1`) can use hardened or non-hardened BIP-32 derivation. Falcon (`index = 2`),
ML-DSA (`index = 4, 5, 6`), MAYO (`index = 7, 8, 9`), and HQC
(`index = 10, 11, 12`) use hardened SLIP-0010 derivation.

In other words, we have the following flow:

1. BIP-39 generates the master seed.
2. BIP-85 generates scheme-specific child seeds using
   `m/83696968'/{app_no}'/{index}'`:
   - ECDSA (`index = 1`) follows BIP-32/BIP-44 with hardened or non-hardened key
     derivation.
   - Falcon (`index = 2`) follows SLIP-0010 adapted to Falcon signatures.
   - ML-DSA-44 (`index = 4`) is deprecated and follows SLIP-0010 adapted to ML-DSA-44.
   - ML-DSA-65 (`index = 5`) follows SLIP-0010 adapted to ML-DSA-65.
   - ML-DSA-87 (`index = 6`) follows SLIP-0010 adapted to ML-DSA-87.
   - MAYO-1 (`index = 7`) follows SLIP-0010 and truncates the 32-byte child key to the
     24-byte key-generation seed.
   - MAYO-2 (`index = 8`) follows SLIP-0010 and truncates the 32-byte child key to the
     24-byte key-generation seed.
   - MAYO-3 (`index = 9`) follows SLIP-0010 and uses the full 32-byte child key. MAYO-5
     is not supported because its 40-byte seed would require expansion.
   - HQC-128/192/256 (`index = 10, 11, 12`) use the full 32-byte SLIP-0010 child key for
     deterministic KEM key generation.

```
     RBG (256 bits)
      │
      │
      V
Initial seed (256-bit security)
      │
      │ BIP-39
      │
      V
   Mnemonic (24 words)
      │
      │ PBKDF2
      │
      V
 Master Seed (512 bits; 256-bit security)
      │
      │ HMAC-SHA-512("Bitcoin seed", master_seed)
      │
      V
Master root key (512 bits; 256-bit security)
      │
      ├─> CKD(master_root_key, info = ecdsa_path) = (sk, ch)
      │       │
      │       └─> HMAC-SHA-512("bip-entropy-from-k", sk) = child_master_seed
      │              │
      │              └─> [ECDSA]    BIP-32 with child_master_seed
      │                                         and
      │                        "Bitcoin seed" as the domain separator
      │
      └─> CKD(master_root_key, info = falcon_path) = (sk, ch)
              │
              └─> HMAC-SHA-512("bip-entropy-from-k", sk) = child_master_seed
                     │
                     └─> [Falcon-512]   SLIP-0010 with child_master_seed
                                                     and
                                 "Falcon-512 seed" as the domain separator
```

Let's go over each step.

## Master Seed Generation

To provide a standard wallet-creation experience, Tectonic uses BIP-39 to generate a
24-word mnemonic from which it derives a master seed. The following diagram summarizes
the process:

```
                                  BIP-39           PBKDF2
RBG (256 bits) ---> Initial seed ------> Mnemonic ------> Master seed
                  (256-bit security)     (24 words)      (256-bit security)
```

For a more visual description of the steps, see this
[BIP-39 mnemonic overview](https://learnmeabitcoin.com/technical/keys/hd-wallets/mnemonic-seed/#generate-entropy).

### Security notes

A conservative parameter choice permits only 24-word mnemonics, for two reasons:

1. Falcon and ML-DSA key generation require a seed with 256 bits of entropy.
2. Grover's algorithm halves the effective strength of generic hash preimage searches.

The following sections explain these considerations.

#### NIST compliance

FIPS 204 permits seeded ML-DSA key generation using an approved random bit generator
(RBG) [2]. Although the first FN-DSA draft has not yet been published, similar guidance is
expected if deterministic key generation is specified. The Falcon key-generation seed
provides 256 bits of entropy.

The process must therefore ensure that the generated master seed is equivalent to output
from an RBG with 256 bits of entropy. The following argument supports that guarantee:

- RBG strength: 256 bits
- SHA-256 strength: 256 bits
- PBKDF2 strength: min(entropy of password, PRF strength)
  - The mnemonic provides 256 bits of entropy.
  - SHA-512 is used as the PRF.
  - Therefore, PBKDF2 provides 256 bits of strength.

#### Grover degradation

The symmetric operations used by BIP-39 are believed to resist quantum attacks, although
Grover's algorithm reduces their effective security strength. As a rule of thumb,
maintaining 128 bits of security against generic quantum search requires 256 bits of
classical security.

## Child Seed Generation

After generating the Tectonic PQ Wallet master seed, BIP-85 derives a separate child seed
for each configured scheme.

As specified by BIP-85, derivation follows a fully hardened path from the BIP-32 master
root key. BIP-32 creates that root key by applying HMAC-SHA-512 with `"Bitcoin seed"` as
the key and the master seed as the message. At the end of the path, BIP-85 applies an
additional HMAC-SHA-512 entropy-derivation step to produce the final child seed.

```
Master seed (512 bits; 256-bit security)
      │
      │ HMAC-SHA-512("Bitcoin seed", master_seed)
      │
      V
Master root key (512 bits; 256-bit security)
      │
      ├─> CKD(master_root_key, info = ecdsa_path) = (sk, ch)
      │       │
      │       └─> HMAC-SHA-512("bip-entropy-from-k", sk) = child_master_seed
      │
      └─> CKD(master_root_key, info = falcon_path) = (sk, ch)
              │
              └─> HMAC-SHA-512("bip-entropy-from-k", sk) = child_master_seed
```

The next sections review BIP-32 hardened derivation and specify the path conventions for
the ECDSA, Falcon, ML-DSA, MAYO, and HQC branches.

### Child derivation procedure

The original [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
standard defines the child key derivation (CKD) function. Given a raw parent key
$k_{par}$, a raw parent chain code $c_{par}$, and an index $i$ represented as a 32-bit
integer, the hardened function
$\mathsf{CKD_{priv}}((k_{par}, c_{par}), i) → (k_i, c_i)$ is defined as follows:

1. Check whether $i ≥ 2^{31}$, which indicates a hardened child; return an error
   otherwise.
2. Let $I = \mathsf{HMAC-SHA-512}(\mathsf{key} = c_{par},\, \mathsf{data} = \texttt{0x00} || k_{par} || i)$.
3. Split $I$ into two 32-byte sequences, $I_L$ and $I_R$.
4. Return $(k_i, c_i) = (I_L, I_R)$.

To support a hierarchical keychain, define CKD over a path $L$ (an ordered list of
indices) as recursive applications of $\mathsf{CKD}_i$ to each element of $L$. For
example, for $L = [l_1, l_2, l_3]$,
$\mathsf{CKD}((k_{par}, c_{par}), L) → k$ is:

$$\mathsf{CKD_{priv}}(\mathsf{CKD_{priv}}(\mathsf{CKD_{priv}}((k_{par}, c_{par}), l_1), l_2), l_3) = k,$$

where $k$ is a 256-bit key.

#### Security notes

Using this process to generate child seeds requires two security properties:

1. CKD preserves the original entropy.
2. Key separation ensures that the generated keys are independent, so compromising one
   key does not weaken the others.

##### Key generation process security

The chained CKD process follows the structure of the HMAC-based Key Derivation Function
(HKDF-SHA512) specified in the original
[[K10]](https://eprint.iacr.org/2010/264.pdf) paper and in
[RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869). HKDF uses an
extract-and-expand approach based on initial secret key material (SKM). The extraction
phase uses the SKM to generate a pseudorandom key (PRK), which is passed to an expansion
function to generate new key material.

The CKD procedure can be viewed as omitting the extraction phase and using the master seed
directly as the PRK for expansion. As noted in
[[K10]](https://eprint.iacr.org/2010/264.pdf), Section D, Point 1, a master seed that is
already a uniformly random string of the HMAC key length can be used directly as the HMAC
key. The hierarchical derivation path extends this process by computing several chained
HMAC operations.

This argument bases CKD security on the HKDF analysis in
[[K10]](https://eprint.iacr.org/2010/264.pdf) and
[RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).

##### Key separation

Child-seed derivation must ensure that material leaked from one branch does not affect
another branch. This key-separation principle follows the key derivation function (KDF)
guidance in
[NIST SP 800-108](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf).
Given the relationship to HKDF described in the
[previous subsection](#key-generation-process-security), the CKD process provides branch
separation.

### Derivation path convention

BIP-85 derives a private key from the BIP-32 master root key using a fully hardened path.

The derivation path follows the convention:

```
m/83696968'/{app_no}'/{index}'
```

Here, `{app_no}` identifies the application and `{index}` identifies the scheme.

Tectonic's post-quantum wallet application number is `app_no = 83286642`, which spells
"Tectonic" on a T9 keypad. The scheme indices are `1` for `ecdsa-secp256k1`, `2` for
`falcon-512`, `4` for deprecated `ml-dsa-44`, `5` for `ml-dsa-65`, `6` for `ml-dsa-87`,
`7` for `mayo-1`, `8` for `mayo-2`, `9` for `mayo-3`, and `10`, `11`, and `12` for
HQC-128, HQC-192, and HQC-256, respectively. Index `3` is reserved for future analysis.
MAYO-5 is intentionally omitted because its 40-byte key-generation seed cannot be
sourced from a 32-byte SLIP-0010 child key without expansion.

The hardened derivation path does not use an ECC-specific construction because $k_{par}$
is passed as raw bytes in the HMAC data field. The process can therefore be applied to
generic derivation mechanisms.

### Child master seed derivation

The CKD output $k$ is passed to `HMAC-SHA-512("bip-entropy-from-k", k)`, which produces the
child master seed for deriving an ECDSA or post-quantum keypair.

## HD keychain

The entropy produced by the BIP-85 procedure becomes the seed for each scheme's keychain.

The ECDSA branch can follow traditional BIP-32 hierarchical derivation with either
hardened or non-hardened paths. Falcon, ML-DSA, MAYO, and HQC follow the hardened path
proposed in [SLIP-0010](https://slips.readthedocs.io/en/latest/slip-0010/) for universal
key derivation. Each scheme uses a distinct domain separator, including `"HQC-128 seed"`,
`"HQC-192 seed"`, and `"HQC-256 seed"`. ML-DSA-44 is retained only for compatibility and
is deprecated. For MAYO, the 32-byte SLIP-0010 child key is truncated to the parameter
set's key-generation seed size: 24 bytes for MAYO-1/2 and 32 bytes for MAYO-3. MAYO-5 is
not supported because deriving its 40-byte seed would require expansion rather than
truncation. HQC uses all 32 child-key bytes directly for each parameter set.

The original Falcon and ML-DSA proposals do not provide an out-of-the-box key
rerandomization technique, so they cannot use a non-hardened derivation path.

```
└─> HMAC-SHA-512("bip-entropy-from-k", k) = child_master_seed
        │
        └─> [ECDSA]    BIP-32 with child_master_seed
                                    and
                    "Bitcoin seed" as the domain separator


└─> HMAC-SHA-512("bip-entropy-from-k", k) = child_master_seed
        │
        └─> [Falcon-512]   SLIP-0010 with child_master_seed
                                       and
                   "Falcon-512 seed" as the domain separator
```

### Alternative approach

As an alternative, a child master seed could be used as BIP-39 input to generate a
mnemonic for each branch. This approach also separates the branches and lets a user export
one branch to another wallet by using its corresponding seed phrase.

## Existing designs

The design combines ideas from two existing proposals:

- [Quantus Network QIP-0002](https://github.com/Quantus-Network/improvement-proposals/blob/main/qip-0002.md)
  describes an HD solution for post-quantum signatures. It uses `"Bitcoin seed"` to derive
  the master root key but does not follow SLIP-0010. Tectonic follows SLIP-0010 and uses a
  new domain-separation string. QIP-0002 also does not provide a hybrid scheme, whereas
  Tectonic derives separate conventional and post-quantum chains.
- [Project 11](https://blog.projecteleven.com/posts/generating-post-quantum-keypairs-from-a-single-24word-seed-phrase)
  describes generating different post-quantum key types from a single 24-word seed phrase.
  It does not combine conventional and post-quantum signatures. It uses BIP-85 to generate
  separate branches but does not propose BIP-32/SLIP-0010 derivation within each branch.

## References

1. [Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU](https://falcon-sign.info/)
2. [FIPS 204, Section 3.6.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
