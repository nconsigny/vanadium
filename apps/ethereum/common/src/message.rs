//! Request and Response message types for the Ethereum V-App protocol.
//!
//! These enums define the full set of messages exchanged between
//! the client and V-App. Messages are serialized with postcard.
//!
//! # Security Model
//!
//! All requests come from the untrusted host. The V-App must:
//! 1. Validate all fields after deserialization
//! 2. Never trust metadata without signature verification
//! 3. Fail closed on any parsing/validation error

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::types::{
    AppConfiguration, Bip32Path, DomainInfo, EthAddress, Hash256, MethodInfo, NftInfo, Signature,
    TokenInfo,
};

/// Request messages from client to V-App.
///
/// Each variant corresponds to a command in the wire protocol.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Request {
    // === Configuration Commands ===
    /// Get application configuration and version.
    GetAppConfiguration,

    /// Get a random challenge for replay protection.
    GetChallenge,

    /// Exit the V-App (for testing only).
    Exit,

    // === Transaction Signing ===
    /// Sign a legacy or EIP-2718 typed transaction.
    ///
    /// For large transactions, this may be sent in chunks.
    SignTransaction {
        /// BIP32 derivation path for signing key.
        path: Bip32Path,
        /// RLP-encoded transaction data.
        tx_data: Vec<u8>,
    },

    /// Sign a transaction with clear signing (full metadata display).
    ClearSignTransaction {
        /// BIP32 derivation path for signing key.
        path: Bip32Path,
        /// RLP-encoded transaction data.
        tx_data: Vec<u8>,
        /// Additional context for clear signing.
        context: Vec<u8>,
    },

    // === Message Signing ===
    /// Sign an EIP-191 personal message.
    SignPersonalMessage {
        /// BIP32 derivation path for signing key.
        path: Bip32Path,
        /// Message to sign (will be prefixed per EIP-191).
        message: Vec<u8>,
    },

    /// Sign pre-hashed EIP-712 typed data.
    ///
    /// Requires blind signing to be enabled.
    SignEip712Hashed {
        /// BIP32 derivation path for signing key.
        path: Bip32Path,
        /// EIP-712 domain separator hash.
        domain_hash: Hash256,
        /// EIP-712 message hash.
        message_hash: Hash256,
    },

    /// Sign full EIP-712 typed data with parsing.
    SignEip712Message {
        /// BIP32 derivation path for signing key.
        path: Bip32Path,
        /// JSON-encoded typed data.
        typed_data: Vec<u8>,
    },

    // === Metadata Provision ===
    /// Provide verified ERC-20 token information.
    ProvideErc20TokenInfo {
        /// Token information.
        info: TokenInfo,
        /// CAL signature over the info.
        signature: Vec<u8>,
    },

    /// Provide verified NFT collection information.
    ProvideNftInfo {
        /// NFT collection information.
        info: NftInfo,
        /// CAL signature over the info.
        signature: Vec<u8>,
    },

    /// Provide verified domain name resolution.
    ProvideDomainName {
        /// Domain resolution information.
        info: DomainInfo,
        /// Signature from domain authority.
        signature: Vec<u8>,
    },

    /// Provide verified contract method information.
    LoadContractMethodInfo {
        /// Method information.
        info: MethodInfo,
        /// CAL signature over the info.
        signature: Vec<u8>,
    },

    /// Set context for subsequent metadata lookups.
    ByContractAddressAndChain {
        /// Chain ID for context.
        chain_id: u64,
        /// Contract address for context.
        address: EthAddress,
    },

    // === Eth2 Staking (Placeholder) ===
    /// Get BLS public key for validator (not implemented).
    Eth2GetPublicKey {
        /// BIP32 derivation path (EIP-2334).
        path: Bip32Path,
    },

    /// Set withdrawal index (not implemented).
    Eth2SetWithdrawalIndex {
        /// Withdrawal credential index.
        index: u32,
    },
}

/// Response messages from V-App to client.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Error response with error code.
    Error(Error),

    /// App configuration and version.
    AppConfiguration(AppConfiguration),

    /// Random challenge bytes.
    Challenge([u8; 32]),

    /// ECDSA signature (v, r, s).
    Signature(Signature),

    /// BLS public key (48 bytes, for Eth2).
    /// Note: Using Vec instead of [u8; 48] for serde compatibility.
    BlsPublicKey(Vec<u8>),

    /// Boolean result for metadata provision.
    Accepted(bool),

    /// Context bound confirmation.
    ContextBound(bool),

    /// Success with no data.
    Success,
}

impl Response {
    /// Creates an error response.
    pub fn error(e: Error) -> Self {
        Response::Error(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = Request::GetAppConfiguration;
        // Ensure it can be serialized (postcard requires alloc feature)
        let _ = core::mem::size_of_val(&request);
    }

    #[test]
    fn test_response_error() {
        let response = Response::error(Error::RejectedByUser);
        assert!(matches!(response, Response::Error(Error::RejectedByUser)));
    }
}
