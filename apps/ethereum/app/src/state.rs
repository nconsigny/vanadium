//! Session state management for the Ethereum V-App.
//!
//! This module manages per-session state including:
//! - Verified metadata cache (tokens, domains, methods)
//! - Command state machine
//! - Pending transaction context
//!
//! # Security
//!
//! - All cached metadata must be verified before storage
//! - State is cleared on app exit
//! - No persistent state beyond device seed

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use common::types::{DomainInfo, EthAddress, MethodInfo, NftInfo, Selector, TokenInfo};

/// Maximum number of cached token entries.
pub const MAX_TOKEN_CACHE: usize = 50;
/// Maximum number of cached domain entries.
pub const MAX_DOMAIN_CACHE: usize = 20;
/// Maximum number of cached method entries.
pub const MAX_METHOD_CACHE: usize = 20;

/// V-App session state.
///
/// This state is maintained for the duration of the V-App execution.
/// All metadata in this state has been verified against CAL signatures.
#[derive(Default)]
pub struct SessionState {
    /// Cached verified ERC-20 token info.
    pub token_cache: Vec<TokenInfo>,
    /// Cached verified NFT collection info.
    pub nft_cache: Vec<NftInfo>,
    /// Cached verified domain name resolutions.
    pub domain_cache: Vec<DomainInfo>,
    /// Cached verified contract method info.
    pub method_cache: Vec<MethodInfo>,
    /// Current context chain ID (set by ByContractAddressAndChain).
    pub context_chain_id: Option<u64>,
    /// Current context address (set by ByContractAddressAndChain).
    pub context_address: Option<EthAddress>,
    /// App configuration: blind signing enabled.
    pub blind_signing_enabled: bool,
}

impl SessionState {
    /// Creates a new empty session state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Caches verified token info.
    ///
    /// Uses simple FIFO eviction when cache is full.
    /// Caller must verify the token info before caching.
    pub fn cache_token(&mut self, info: TokenInfo) {
        // Check if already cached (update in place)
        for cached in &mut self.token_cache {
            if cached.chain_id == info.chain_id && cached.address == info.address {
                *cached = info;
                return;
            }
        }

        // Add new entry, evicting oldest if full
        if self.token_cache.len() >= MAX_TOKEN_CACHE {
            self.token_cache.remove(0);
        }
        self.token_cache.push(info);
    }

    /// Looks up cached token info.
    pub fn lookup_token(&self, chain_id: u64, address: &EthAddress) -> Option<&TokenInfo> {
        self.token_cache
            .iter()
            .find(|t| t.chain_id == chain_id && &t.address == address)
    }

    /// Caches verified NFT info.
    pub fn cache_nft(&mut self, info: NftInfo) {
        for cached in &mut self.nft_cache {
            if cached.chain_id == info.chain_id && cached.address == info.address {
                *cached = info;
                return;
            }
        }

        if self.nft_cache.len() >= MAX_TOKEN_CACHE {
            self.nft_cache.remove(0);
        }
        self.nft_cache.push(info);
    }

    /// Looks up cached NFT info.
    pub fn lookup_nft(&self, chain_id: u64, address: &EthAddress) -> Option<&NftInfo> {
        self.nft_cache
            .iter()
            .find(|n| n.chain_id == chain_id && &n.address == address)
    }

    /// Caches verified domain info.
    pub fn cache_domain(&mut self, info: DomainInfo) {
        for cached in &mut self.domain_cache {
            if cached.address == info.address {
                *cached = info;
                return;
            }
        }

        if self.domain_cache.len() >= MAX_DOMAIN_CACHE {
            self.domain_cache.remove(0);
        }
        self.domain_cache.push(info);
    }

    /// Looks up cached domain info.
    pub fn lookup_domain(&self, address: &EthAddress) -> Option<&DomainInfo> {
        self.domain_cache.iter().find(|d| &d.address == address)
    }

    /// Caches verified method info.
    pub fn cache_method(&mut self, info: MethodInfo) {
        for cached in &mut self.method_cache {
            if cached.chain_id == info.chain_id
                && cached.address == info.address
                && cached.selector == info.selector
            {
                *cached = info;
                return;
            }
        }

        if self.method_cache.len() >= MAX_METHOD_CACHE {
            self.method_cache.remove(0);
        }
        self.method_cache.push(info);
    }

    /// Looks up cached method info.
    pub fn lookup_method(
        &self,
        chain_id: u64,
        address: &EthAddress,
        selector: &Selector,
    ) -> Option<&MethodInfo> {
        self.method_cache.iter().find(|m| {
            m.chain_id == chain_id && &m.address == address && &m.selector == selector
        })
    }

    /// Sets the current context for metadata lookups.
    pub fn set_context(&mut self, chain_id: u64, address: EthAddress) {
        self.context_chain_id = Some(chain_id);
        self.context_address = Some(address);
    }

    /// Clears the current context.
    pub fn clear_context(&mut self) {
        self.context_chain_id = None;
        self.context_address = None;
    }

    /// Returns the current context if set.
    pub fn get_context(&self) -> Option<(u64, &EthAddress)> {
        match (&self.context_chain_id, &self.context_address) {
            (Some(chain_id), Some(address)) => Some((*chain_id, address)),
            _ => None,
        }
    }
}

/// Formats an Ethereum address for display.
///
/// Returns the address in checksummed format (EIP-55).
pub fn format_address(address: &EthAddress) -> String {
    // For minimal implementation, return hex without checksum
    // Full implementation would use Keccak256 for EIP-55 checksum
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for byte in address {
        use core::fmt::Write;
        let _ = write!(result, "{:02x}", byte);
    }
    result
}

/// Formats an amount with decimals for display.
///
/// # Arguments
/// * `value` - Raw token value (big-endian bytes)
/// * `decimals` - Number of decimal places
/// * `ticker` - Token ticker symbol
pub fn format_amount(value: &[u8], _decimals: u8, ticker: &str) -> String {
    // Convert bytes to decimal string
    // For minimal implementation, show raw hex
    let mut result = String::from("0x");
    for byte in value {
        use core::fmt::Write;
        let _ = write!(result, "{:02x}", byte);
    }
    result.push(' ');
    result.push_str(ticker);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_token_cache() {
        let mut state = SessionState::new();

        let token = TokenInfo {
            chain_id: 1,
            address: [0u8; 20],
            ticker: String::from("TEST"),
            decimals: 18,
        };

        state.cache_token(token.clone());
        assert!(state.lookup_token(1, &[0u8; 20]).is_some());
        assert!(state.lookup_token(2, &[0u8; 20]).is_none());
    }

    #[test]
    fn test_format_address() {
        let address = [0u8; 20];
        let formatted = format_address(&address);
        assert_eq!(formatted, "0x0000000000000000000000000000000000000000");
    }
}
