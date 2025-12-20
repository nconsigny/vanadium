//! Core types for the Ethereum V-App.
//!
//! These types are shared between V-App and client, serialized via postcard.
//! All validation happens in the V-App after deserialization.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Maximum BIP32 derivation path depth.
pub const MAX_BIP32_PATH_DEPTH: usize = 10;

/// Ethereum address (20 bytes).
pub type EthAddress = [u8; 20];

/// Keccak256 hash (32 bytes).
pub type Hash256 = [u8; 32];

/// Function selector (4 bytes).
pub type Selector = [u8; 4];

/// BIP32 derivation path.
///
/// The path is stored as a vector of u32 values where hardened indices
/// have the 0x80000000 bit set. Maximum depth is 10 elements.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct Bip32Path(pub Vec<u32>);

impl Bip32Path {
    /// Creates a new empty path.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Creates a path from a slice.
    pub fn from_slice(path: &[u32]) -> Self {
        Self(path.to_vec())
    }

    /// Returns the path length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the path is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the path as a slice.
    pub fn as_slice(&self) -> &[u32] {
        &self.0
    }

    /// Validates the path for Ethereum (BIP44 m/44'/60'/account'/change/index).
    ///
    /// Returns true if the path follows standard Ethereum derivation.
    pub fn is_valid_ethereum_path(&self) -> bool {
        if self.0.len() < 3 || self.0.len() > MAX_BIP32_PATH_DEPTH {
            return false;
        }

        // Check purpose: must be 44' (hardened)
        if self.0[0] != 0x8000002C {
            return false;
        }

        // Check coin type: must be 60' (Ethereum) - hardened
        if self.0[1] != 0x8000003C {
            return false;
        }

        // Account index must be hardened
        if self.0[2] & 0x80000000 == 0 {
            return false;
        }

        // Change and address index should not be hardened (if present)
        for &idx in &self.0[3..] {
            if idx & 0x80000000 != 0 {
                return false;
            }
        }

        true
    }
}

/// ECDSA signature components (v, r, s).
///
/// For transactions, v follows EIP-155: v = chain_id * 2 + 35 + recovery_id
/// For messages, v = 27 + recovery_id
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Recovery identifier (27/28 for legacy, EIP-155 for transactions).
    pub v: u8,
    /// R component (32 bytes, big-endian).
    pub r: [u8; 32],
    /// S component (32 bytes, big-endian, low-S normalized).
    pub s: [u8; 32],
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            v: 0,
            r: [0u8; 32],
            s: [0u8; 32],
        }
    }
}

/// App configuration returned by GET_APP_CONFIGURATION.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AppConfiguration {
    /// Major version.
    pub version_major: u8,
    /// Minor version.
    pub version_minor: u8,
    /// Patch version.
    pub version_patch: u8,
    /// Whether blind signing is enabled.
    pub blind_signing_enabled: bool,
    /// Whether EIP-712 filtering is enabled.
    pub eip712_filtering_enabled: bool,
}

impl Default for AppConfiguration {
    fn default() -> Self {
        Self {
            version_major: 0,
            version_minor: 1,
            version_patch: 0,
            blind_signing_enabled: false,
            eip712_filtering_enabled: true,
        }
    }
}

/// ERC-20 token information for display purposes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    /// Chain ID where the token is deployed.
    pub chain_id: u64,
    /// Token contract address.
    pub address: EthAddress,
    /// Token ticker symbol (e.g., "USDC").
    pub ticker: String,
    /// Token decimals (e.g., 6 for USDC, 18 for most tokens).
    pub decimals: u8,
}

/// NFT collection information for display purposes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NftInfo {
    /// Chain ID where the NFT is deployed.
    pub chain_id: u64,
    /// NFT contract address.
    pub address: EthAddress,
    /// Collection name.
    pub name: String,
}

/// Domain name resolution information.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DomainInfo {
    /// Resolved address.
    pub address: EthAddress,
    /// Domain name (e.g., "vitalik.eth").
    pub domain: String,
}

/// Contract method information for clear signing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MethodInfo {
    /// Chain ID.
    pub chain_id: u64,
    /// Contract address.
    pub address: EthAddress,
    /// Function selector (4 bytes).
    pub selector: Selector,
    /// Method name (e.g., "transfer").
    pub name: String,
    /// ABI-encoded parameter definitions.
    pub abi: Vec<u8>,
}

/// Transaction type for EIP-2718 typed transactions.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransactionType {
    /// Legacy transaction (pre-EIP-2718).
    Legacy = 0x00,
    /// EIP-2930 access list transaction.
    AccessList = 0x01,
    /// EIP-1559 fee market transaction.
    FeeMarket = 0x02,
}

impl TryFrom<u8> for TransactionType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(TransactionType::Legacy),
            0x01 => Ok(TransactionType::AccessList),
            0x02 => Ok(TransactionType::FeeMarket),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip32_path_validation() {
        // Valid standard Ethereum path: m/44'/60'/0'/0/0
        let valid = Bip32Path::from_slice(&[0x8000002C, 0x8000003C, 0x80000000, 0, 0]);
        assert!(valid.is_valid_ethereum_path());

        // Invalid: wrong purpose
        let invalid_purpose = Bip32Path::from_slice(&[0x80000031, 0x8000003C, 0x80000000]);
        assert!(!invalid_purpose.is_valid_ethereum_path());

        // Invalid: wrong coin type
        let invalid_coin = Bip32Path::from_slice(&[0x8000002C, 0x80000000, 0x80000000]);
        assert!(!invalid_coin.is_valid_ethereum_path());

        // Invalid: too short
        let too_short = Bip32Path::from_slice(&[0x8000002C, 0x8000003C]);
        assert!(!too_short.is_valid_ethereum_path());
    }
}
