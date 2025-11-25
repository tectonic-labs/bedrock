//! ETHFALCON (Falcon-512 with Keccak-256 XOF) - Post-quantum signatures compatible with Solidity
//! Implements the ETHFALCON variant as specified in the
//! [ZKnox ETHFALCON repository](https://github.com/zknoxhq/ETHFALCON).

/// An NTT packed verifying key for the ETHFALCON signing scheme
pub type EthFalconVerifyingKey = [u8; fn_dsa_comm::eth_falcon::PUBKEY_NTT_PACKED_LENGTH];

/// A solidity abi packed ETH FALCON signature
pub type EthFalconSignature = [u8; fn_dsa_comm::eth_falcon::SIGNATURE_ABI_PACKED_LENGTH];
