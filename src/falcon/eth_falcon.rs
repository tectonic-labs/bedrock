//! ETHFALCON (Falcon-512 with Keccak-256 XOF) - Post-quantum signatures compatible with Solidity
//! Implements the ETHFALCON variant as specified in the
//! [ZKnox ETHFALCON repository](https://github.com/zknoxhq/ETHFALCON).

use super::{FalconScheme, FalconSignature, FalconSigningKey, FalconVerificationKey, InnerFalcon};
use crate::error::*;

/// An NTT packed verifying key for the ETHFALCON signing scheme
pub type EthFalconVerifyingKey = [u8; fn_dsa_comm::eth_falcon::PUBKEY_NTT_PACKED_LENGTH];

/// A solidity abi packed ETH FALCON signature
pub type EthFalconSignature = [u8; fn_dsa_comm::eth_falcon::SIGNATURE_ABI_PACKED_LENGTH];

impl TryFrom<FalconVerificationKey> for EthFalconVerifyingKey {
    type Error = Error;

    fn try_from(public_key: FalconVerificationKey) -> Result<Self> {
        Self::try_from(&public_key)
    }
}

impl TryFrom<&FalconVerificationKey> for EthFalconVerifyingKey {
    type Error = Error;

    /// Convert Falcon public key to ETHFALCON Solidity format (abi.encodePacked, NTT form)
    ///
    /// # Arguments
    /// * `pubkey` - Standard Falcon public key (897 bytes)
    ///
    /// # Returns
    /// * 1024-byte abi.encodePacked(uint256\[32\]) format
    fn try_from(public_key: &FalconVerificationKey) -> Result<Self> {
        if public_key.0.scheme == FalconScheme::Ethereum {
            fn_dsa_comm::eth_falcon::decode_pubkey_to_ntt_packed(public_key.0.value.as_ref())
                .map_err(|e| Error::FnDsaError(e.to_string()))
        } else {
            Err(Error::InvalidSchemeStr(
                "Only ETHFALCON public key is supported".to_string(),
            ))
        }
    }
}

impl TryFrom<FalconSignature> for EthFalconSignature {
    type Error = Error;

    /// Convert Falcon signature to ETHFALCON Solidity format (abi.encodePacked)
    ///
    /// # Arguments
    /// * `signature` - Standard Falcon signature bytes
    ///
    /// # Returns
    /// * 1024-byte abi.encodePacked(uint256\[32\]) format
    fn try_from(signature: FalconSignature) -> Result<Self> {
        Self::try_from(&signature)
    }
}

impl TryFrom<&FalconSignature> for EthFalconSignature {
    type Error = Error;

    fn try_from(signature: &FalconSignature) -> Result<Self> {
        if signature.0.scheme == FalconScheme::Ethereum {
            fn_dsa_comm::eth_falcon::decode_signature_to_packed(signature.0.value.as_ref())
                .map_err(|e| Error::FnDsaError(e.to_string()))
        } else {
            Err(Error::InvalidSchemeStr(
                "Only ETHFALCON signature is supported".to_string(),
            ))
        }
    }
}

impl FalconScheme {
    #[cfg(feature = "sign")]
    /// Sign a message
    pub fn sign(&self, message: &[u8], signing_key: &FalconSigningKey) -> Result<FalconSignature> {
        match self {
            Self::Ethereum => {
                use fn_dsa_sign::{
                    eth_falcon::{generate_salt, EthFalconSigningKey},
                    signature_size, SigningKey, SigningKeyStandard, FN_DSA_LOGN_512,
                };

                let mut sk = SigningKeyStandard::decode(signing_key.0.value.as_ref())
                    .ok_or_else(|| Error::FnDsaError("Invalid signing key".to_string()))?;
                let salt = generate_salt();
                let mut sig = [0u8; signature_size(FN_DSA_LOGN_512)];
                sk.sign_eth(message, &salt, &mut sig);
                Ok(InnerFalcon {
                    scheme: *self,
                    value: sig.to_vec(),
                }
                .into())
            }
            _ => self.sign_inner(message, signing_key),
        }
    }

    #[cfg(feature = "vrfy")]
    /// Verify a signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &FalconSignature,
        verification_key: &FalconVerificationKey,
    ) -> Result<()> {
        match self {
            Self::Ethereum => {
                use fn_dsa_comm::eth_falcon::{decode_signature_to_packed, SALT_LEN};
                use fn_dsa_vrfy::eth_falcon::EthFalconVerifyingKey as Efvk;

                let pk = EthFalconVerifyingKey::try_from(verification_key)?;
                let pk = Efvk::decode(&pk);

                let mut salt = [0u8; SALT_LEN];
                salt.copy_from_slice(&signature.0.value[1..SALT_LEN + 1]);

                let sig = decode_signature_to_packed(&signature.0.value)
                    .map_err(|e| Error::FnDsaError(e.to_string()))?;

                if pk.verify(message, &salt, &sig) {
                    Ok(())
                } else {
                    Err(Error::FnDsaError("Invalid signature".to_string()))
                }
            }
            _ => self.verify_inner(message, signature, verification_key),
        }
    }
}

impl FalconSigningKey {
    /// Change the signing scheme to [`FalconScheme::Ethereum`] if allowed
    pub fn into_ethereum(self) -> Result<Self> {
        self.convert(FalconScheme::Dsa512, FalconScheme::Ethereum)
    }

    /// Change the signing scheme to [`FalconScheme::Dsa512`] if allowed
    pub fn into_dsa512(self) -> Result<Self> {
        self.convert(FalconScheme::Ethereum, FalconScheme::Dsa512)
    }

    fn convert(self, from: FalconScheme, to: FalconScheme) -> Result<Self> {
        if self.0.scheme == from {
            Ok(InnerFalcon {
                scheme: to,
                value: self.0.value,
            }
            .into())
        } else {
            Err(Error::InvalidSchemeStr(format!(
                "Unsupported scheme change from {} to {}",
                self.0.scheme, to,
            )))
        }
    }
}
