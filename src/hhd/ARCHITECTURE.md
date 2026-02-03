# Hybrid HD Wallet Specification: ECDSA + Post-Quantum Signature

Tectonic PQ Wallet supports an hybrid signature verification mechanism between non-post-quantum and post-quantum signatures while aiming to provide web3 users with a deterministic mechanism for their wallet management. This deterministic mechanism should follow battle-tested standards that users have familiarity with. 

This document specifies a derivation process for Tectonic hybrid hierarchical deterministic (HD) wallet that is capable to deterministically generate and manage keypair tree hierarchies for the following signature types:

1. ECDSA secp256k1 signature;
2. Falcon-512 signature [1];
3. ML-DSA-44 signature [2];
3. ML-DSA-65 signature [2];
3. ML-DSA-87 signature [2];

The design chosen for Tectonic wallet allows a single BIP-39 mnemonic to deterministically derive key hierarchies for multiple signatures without requireing independent mnemonic seeds. Note that, although we currently aim to support only two signatures, the mechanism can be generalized to any number of signature schemes.

## General overview

We all know the hurdles of using wallets with incompatible derivation mechanisms. This steems from the fact that there is a variety of paths to achieve the same goal which leads to different outcomes. Tectonic PQ Wallet philosophy focus on using as much already developed standards as possible to design a successfull path for meaningful adoption. That being said, the Tectonic PQ Wallet uses the following standards [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki), [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) and extends [SLIP0010](https://slips.readthedocs.io/en/latest/slip-0010/) to PQ signatures. 

In summary, the process to generate a hierarchy of keypairs for both ECDSA, Falcon and ML-DSA signatures is as follows. The BIP-39 standard is used to generate a master seed from a BIP-39 mnemonic. Then, the BIP-85 standard is used to generate two child seeds to feed the hierarchical structure of ECDSA and PQ signatures. The BIP-85 standard uses the BIP-32 standard with hardened child key derivation (CKD) to produce those child seeds with the path given by `m/83696968'/{app_no}'/{index}'`. Then, the ECDSA branch (`index=1`) can follow the desired BIP-32 mechanism (hardened or non-hardened) for its hierarchical derivation, Falcon branch (`index=2`) and ML-DSA branches (`index=4,5,6`) follows a SLIP0010 approach. 

In other words, we have the following flow:

1. BIP 39 for Master Seed generation.
2. BIP 85 to generate two child seeds using the path `m/83696968'/{app_no}'/{index}'`:
    - ECDSA branch (`index=1`): follows the BIP-32/44 standards with hardened/non-hardened key derivation.
    - Falcon branch (`index=2`): follows the SLIP0010 standard adapted to Falcon signatures.
    - ML-DSA-44 branch (`index=4`): follows the SLIP0010 standard adapted to ML-DSA-44 signatures.
    - ML-DSA-65 branch (`index=5`): follows the SLIP0010 standard adapted to ML-DSA-65 signatures.
    - ML-DSA-87 branch (`index=6`): follows the SLIP0010 standard adapted to ML-DSA-87 signatures.


```
     RBG (256 bits) 
      │          
      │
      V
  Init Seed (256-bits security)
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
      │ HMAC-SHA512("Bitcoin seed", master_seed)
      │
      V      
Master root key (512 bits; 256-bit security)
      │
      ├─> CKD(master_root_key, info = ecdsa_path) = (sk, ch)
      │       │
      │       └─> HMAC-SHA512("bip-entropy-from-k", sk) = child_master_seed
      │              │
      │              └─> [ECDSA]    BIP-32 with child_master_seed 
      |                                         and 
      |                        "Bitcoin seed" as the domain separator  
      │
      └─> CKD(master_root_key, info = falcon_path) = (sk, ch)
              │
              └─> HMAC-SHA512("bip-entropy-from-k", sk) = child_master_seed
                     │
                     └─> [Falcon-512]   SLIP0010 with child_master_seed   
                                                     and   
                                 "Falcon-512 seed" as the domain separator 
```

Let's go over each step.



## Master Seed Generation

In order to provide a standard UX for wallet creation, we focus ourselves on the BIP-39 standard to generate a mnemonic wordlist of 24 words, from which a master seed can be derived. We use the exact same master seed derivation mechanism as presented in BIP-39. The following diagram reviews the steps to generate a master seed:

```
                                  BIP-39           PBKDF2
RBG (256 bits) --->   Init Seed   ------> Mnemonic ------> Master Seed
                   (256-bits sec)        (24 words)       (256-bits sec) 
```

For a more visual description of all steps involved we refer to this [material](https://learnmeabitcoin.com/technical/keys/hd-wallets/mnemonic-seed/#generate-entropy).

### Security notes

A conservative choice of parameters allows only mnemonic with at least 24 words. The reason being twofold:
1. Falcon and ML-DSA key generation requires a seed with 256 bits of entropy;
2. Grover's algorithm degrades hash-based strength by half.

We extend the points next.

#### NIST compliance

NIST siganture approves seeded ML-DSA key generation using an approved random bit generator (RBG) [2]. Although Falcon first draft has not been proposed yet, a similar guideline is expected to apply in case a deterministic key generation is specified. Similar to ML-DSA [2] and as specified in [3], the seed for Falcon key generation procedure requires a minimum of 256 security bits. 

Therefore, one has to guarantee that the master seed generated in this process can indeed be considered equivalent to a RBG with 256 bits of entropy. The following argument supports that guarantee:

- RBG strength: 256 bits
- SHA256 strength: 256 bits
- PBKDF2 strength: min(entropy of password, PRF strength)
    - Entropy of mnemonic passed is 256 bits
    - SHA512 is used as PRF
    - From the above, one can conclude that PBKDF2 strength is 256 bits. 

#### Grover degradation

From a quantum-threat perspective, all operations involved in BIP-39 are quantum-resistant. It is important to note though that they come with some parameter degradation due to Grover's algorithm and its impact on hash-based cryptography. As a general rule of thumb, if we want to keep the minimum 128-bit security, we need at least 256-bit security in the classical world.


## Child Seeds Generation

After having the master seed of the Tectonic PQ Wallet, we need to derive two child seeds corresponding to both signature types. In order to achieve this, we follow the BIP-85 standard.

As described in its specification, BIP-85 uses a fully hardened derivation path (CKD) from the BIP-32 master root key, which, according to the BIP-32 standard, is the HMAC with the string "Bitcoin seed" as key and the master seed as the message. At the end of the chain, BIP-85 additionally applies an entropy derivation function (HMAC-SHA512) to generate the final child seed. The process is summarized below.

```
Master Seed (512 bits; 256-bit security)
      │ 
      │ HMAC-SHA512("Bitcoin seed", master_seed)
      │
      V      
Master root key (512 bits; 256-bit security)
      │
      ├─> CKD(master_root_key, info = ecdsa_path) = (sk, ch)
      │       │
      │       └─> HMAC-SHA512("bip-entropy-from-k", sk) = child_master_seed
      │
      └─> CKD(master_root_key, info = falcon_path) = (sk, ch)
              │
              └─> HMAC-SHA512("bip-entropy-from-k", sk) = child_master_seed 
```

We start by recalling the hardened derivation function used in BIP-32 and then specify the derivation path convention used in Tectonic PQ Wallet for both ECDSA (`ecdsa_path`), Falcon (`falcon_path`) and ML-DSA sigantures.

### Child derivation procedure

We start by recalling the child key derivation function (CKD) defined in the original [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) standard. Given raw parent key $k_{par}$, raw parent chaincode $c_{par}$ and index $i$ in 32 bit representation, the hardened function $\mathsf{CKD_{priv}}((k_{par}, c_{par}), i) → (k_i, c_i)$ is defined as follows:

1. Check whether $i ≥ 2^{31}$ (whether the child is a hardened key), output error otherwise.
2. Let $I = \mathsf{HMAC-SHA512}(\mathsf{key} = c_{par},\, \mathsf{data} = \texttt{0x00} || k_{par} || i)$. 
3. Split $I$ into two 32-byte sequences, $I_L$ and $I_R$.
4. Output: $(k_i, c_i) = (I_L, I_R)$

In order to support a hierarchic keychain, we define the child key derivation procedure (CKD) on path L (a list of oredered indexes) as the recursive call of $\mathsf{CKD}_i$ function on the elements of L. As an example, for $L = [l_1, l_2, l_3]$, $\mathsf{CKD}((k_{par}, c_{par}), L) → k$ is given by:

$$\mathsf{CKD_{priv}}(\mathsf{CKD_{priv}}(\mathsf{CKD_{priv}}((k_{par}, c_{par}), l_1), l_2), l_3) = k,$$

where $k$ is a 512 bit key.

#### Security notes

In order to use the above process in the generation of the child seeds we need to guarantee two security properties:

1. The CDK process preserves the original entropy;
2. Key separation: this guarantees that the newly generated keys are independent from each other, meaning that compomise of one key does not degrade the security of the other keys.

##### Key generation process security

The above CDK chained process follows the spirit of HMAC-based Key Derivation Function (HKDF-SHA512) specified in the original [[K10]](https://eprint.iacr.org/2010/264.pdf) paper and in [RFC5869](https://datatracker.ietf.org/doc/html/rfc5869). The HKDF scheme follows an extract-and-expand approach based on some initial secret key material (SKM). The extraction phase uses SKM to generate a pseudo random key (PRK) that is then passed to an expansion function to generate new key material. 

We can think of CDK procedure lacking an extraction phase and using the master seed directly as the PRK in the expansion phase. Indeed, as noted in ([[K10]](https://eprint.iacr.org/2010/264.pdf), Section D, Point 1), since the master seed is already a random string of the length of the HMAC key, one can simply use the master seed as the key to HMAC and jump over the extraction phase. Moreover, the HKDF security property allows the extraction phase to compute HMAC only once during extraction phase. This process is indeed extend in CKD due to the hierarchical nature of the derivation path as CKD computes not only one HMAC but several chained HMACs.

The above argument shows that CDK security relies on the security of HKDF analysed in [[K10]](https://eprint.iacr.org/2010/264.pdf) paper and in [RFC5869].

##### Key separation

For the derivation of the child seeds it is important to guarantee that any material leaked in one branch does not affect the security of the other branch. This key separation principle is guaranteed by the key derivation function (KDF) mechanisms defined in [NIST SP 800-108](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf). Since HKDF is a valid KDF specified in the document, and CDK mechanism breaks down to HKDF (check [previous subsection argument](#key-generation-process-security)), we can conclude that the CDK process achieves the key separation principle.


### Derivation path convention

In BIP-85 a private key can be derived from the BIP-32 master root key using a fully hardened derivation path. 

The derivation path follows the convention:

`
m/83696968'/{app_no}'/{index}', where {app_no} is the path for the application, and {index} is the index.
`

Tectonic's post-quantum wallet app number is `app_no = 83286642`, standing for Tectonic written in a T9 keyboard. `ecdsa-secp258k1` signature is given `index=1`, `falcon-512` signature is given `index=2`, `ml-dsa-44` signature is given `index=4`, `ml-dsa-65` signature is given `index=5`, `ml-dsa-87` signature is given `index=6`. `index=3` is reserved for future analysis.

We recall that the harneded derivation path does not use an ECC specific construction as the kpar is passed as raw bytes to the HMAC in the Data field. Therefore, this process can be applied to a generic derivation mechanism.

### Child master seed derivation

The output of CKD denoted by k is then passed to `HMAC-SHA512("bip-entropy-from-k", k)` which is our child master seed for the derivation of the either ECDSA or PQ keypairs. 


## HD keychain

The entropy derived from BIP-85 procedure described above for the two branches can then be used as the seed for the generation of two keychains.

The ECDSA branch can follow the traditional BIP-32 hierarchical derivation with either hardened or non-hardened derivation paths. The Falcon branch and the ML-DSA branches follow a hardened derivation path proposed in [SLIP0010](https://slips.readthedocs.io/en/latest/slip-0010/) for universal key derivation. We adopt a similar approach to ed25519 signature with the domain separator strings `"Falcon-512 seed"`, `"ML-DSA-44 seed"`, `"ML-DSA-65 seed"` and `"ML-DSA-87 seed"`, used in the master key generation step. 

We note that Falcon and ML-DSA original proposals do not provide a out-of-the-box rerandomization key technique, which does not allow for a non-hardened derivation path.

```
└─> HMAC-SHA512("bip-entropy-from-k", k) = child_master_seed
        │
        └─> [ECDSA]    BIP-32 with child_master_seed 
                                    and 
                    "Bitcoin seed" as the domain separator  


└─> HMAC-SHA512("bip-entropy-from-k", k) = child_master_seed
        │
        └─> [Falcon-512]   SLIP0010 with child_master_seed   
                                       and   
                   "Falcon-512 seed" as the domain separator 
```


### Alternative approach

For convenience, we might consider the case where the child master seed is used as the original seed in BIP-39 to generate a mnemonic child seed for each branch. This also creates independence and allows the user to export just one of them to some other wallet by using the corresponding seed phrase.


# Existing desings

The above design for an hybrid PQ-wallet merges the proposals of two existing solutions:

- Quantus Network: presents [QIP0002](https://github.com/Quantus-Network/improvement-proposals/blob/main/qip-0002.md), an HD solution for PQ signatures.
    - Difference 1: 
        - They use "Bitcoin seed" as the string to derive the master key root and are not following SLIP0010.
        - We follow SLIP0010 and addopt a new string.
    - Difference 2:
        - They are not using an hybrid scheme
        - We have an HD mechanism that leads to two different chains, allowing for an hybrid solution.
- Project 11: presents a [blogpost](https://blog.projecteleven.com/posts/generating-post-quantum-keypairs-from-a-single-24word-seed-phrase) that allows generating different post-quantum signature types:
    - Difference 1:
        - They do not support a hybrid approach with non-post-quantum and post-quantum signatures.
    - Difference 2:
        - They use BIP-85 to generate to different branches but do not propose to follow BIP-32/SLIP0010 standard for each branch.


# References
[1] NIST original proposal: https://falcon-sign.info/
[2] [FIPS 204 section 3.6.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)