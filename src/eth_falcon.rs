//! ETHFALCON (Falcon-512 with Keccak-256 XOF) - Post-quantum signatures compatible with Solidity
//! Implements the ETHFALCON variant as specified in the
//! [ZKnox ETHFALCON repository](https://github.com/zknoxhq/ETHFALCON).

use crate::error::*;

#[cfg(any(feature = "kgen", feature = "sign"))]
/// A Signing key for the ETHFALCON signing scheme
pub type EthFalconSigningKey = [u8; fn_dsa_comm::sign_key_size(fn_dsa_comm::FN_DSA_LOGN_512)];

#[cfg(any(feature = "kgen", feature = "vrfy"))]
/// A Verifying key for the ETHFALCON signing scheme
pub type EthFalconVerifyingKey = [u8; fn_dsa_comm::vrfy_key_size(fn_dsa_comm::FN_DSA_LOGN_512)];

/// The required salt length for ETHFALCON signatures
pub const SALT_LEN: usize = 40;

#[cfg(feature = "sign")]
/// Sign a message using ETHFALCON
///
/// Uses Keccak-256 XOF for hash-to-point instead of SHAKE256.
///
/// # Arguments
/// * `message` - Message to sign (raw bytes)
/// * `salt` - 40-byte random salt
/// * `private_key` - Private key bytes (encoded SigningKey)
///
/// # Returns
/// * `Ok(signature_bytes)` - Signature in ETHFALCON format
pub fn sign(message: &[u8], salt: &[u8; SALT_LEN], private_key: &[u8]) -> Result<Vec<u8>> {
    use zeroize::Zeroize;

    let mut private_key = <[u8; 1281]>::try_from(private_key)
        .map_err(|_| Error::FnDsaError("Invalid private key length".to_string()))?;
    let mut signature = [0u8; 666];
    fn_dsa_sign::eth_falcon::sign(&private_key, message, salt, &mut signature)
        .map_err(|e| Error::FnDsaError(e.to_string()))?;
    private_key.zeroize();
    fn_dsa_signature_to_eth_falcon_signature(&signature)
}

#[cfg(feature = "vrfy")]
/// Verify an ETHFALCON signature
///
/// This is the core Rust API that accepts raw byte slices.
/// All inputs are Solidity abi.encodePacked(uint256[32]) format (1024 bytes each).
///
/// # Arguments
/// * `message` - The message bytes (any length)
/// * `salt` - 40-byte random salt from signature
/// * `s2_packed` - Signature s2 in abi.encodePacked format (1024 bytes)
/// * `pk_ntt_packed` - Public key h in NTT form, abi.encodePacked format (1024 bytes)
///
/// # Returns
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err` if inputs are malformed
pub fn verify(
    message: &[u8],
    salt: &[u8; SALT_LEN],
    signature: &[u8; fn_dsa_comm::eth_falcon::SIGNATURE_ABI_PACKED_LENGTH],
    public_key: &[u8; fn_dsa_comm::eth_falcon::PUBKEY_NTT_PACKED_LENGTH],
) -> Result<bool> {
    fn_dsa_vrfy::eth_falcon::verify(message, salt, signature, public_key)
        .map_err(|e| Error::FnDsaError(e.to_string()))
}

/// Convert Falcon public key to ETHFALCON Solidity format (abi.encodePacked, NTT form)
///
/// # Arguments
/// * `pubkey` - Standard Falcon public key (897 bytes)
///
/// # Returns
/// * 1024-byte abi.encodePacked(uint256[32]) format
pub fn fn_dsa_pubkey_to_eth_falcon_pubkey(pubkey: &[u8]) -> Result<Vec<u8>> {
    Ok(fn_dsa_comm::eth_falcon::decode_pubkey_to_ntt_packed(pubkey)
        .map_err(|e| Error::FnDsaError(e.to_string()))?
        .to_vec())
}

/// Convert Falcon signature to ETHFALCON Solidity format (abi.encodePacked)
///
/// # Arguments
/// * `signature` - Standard Falcon signature bytes
///
/// # Returns
/// * 1024-byte abi.encodePacked(uint256[32]) format
pub fn fn_dsa_signature_to_eth_falcon_signature(signature: &[u8]) -> Result<Vec<u8>> {
    Ok(
        fn_dsa_comm::eth_falcon::decode_signature_to_packed(signature)
            .map_err(|e| Error::FnDsaError(e.to_string()))?
            .to_vec(),
    )
}

#[cfg(feature = "kgen")]
mod key_gen;

#[cfg(feature = "kgen")]
pub use key_gen::*;
