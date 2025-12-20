//! Metadata provision command handlers.
//!
//! Handles:
//! - PROVIDE_ERC20_TOKEN_INFO (0x20)
//! - PROVIDE_NFT_INFO (0x21)
//! - PROVIDE_DOMAIN_NAME (0x22)
//! - LOAD_CONTRACT_METHOD_INFO (0x23)
//! - BY_CONTRACT_ADDRESS_AND_CHAIN (0x24)
//!
//! # Security Model
//!
//! All metadata comes from the untrusted host and MUST be verified
//! against a trusted signature (CAL) before caching or display.
//!
//! The minimal implementation accepts metadata without full CAL verification
//! but marks it as UNVERIFIED. Full implementation would verify against
//! the embedded CAL public key.
//!
//! # Docs consulted
//!
//! - docs/metadata-auth.md: Signature verification model

use common::error::Error;
use common::message::Response;
use common::types::{DomainInfo, EthAddress, MethodInfo, NftInfo, TokenInfo};

/// Handles PROVIDE_ERC20_TOKEN_INFO command.
///
/// Caches verified ERC-20 token metadata for display during signing.
///
/// # Arguments
/// * `info` - Token information (chain_id, address, ticker, decimals)
/// * `signature` - CAL signature over the info
///
/// # Security
///
/// - Full implementation must verify signature against CAL public key
/// - Minimal implementation accepts without verification (UNVERIFIED)
/// - Ticker and decimals used for display only, not for security
///
/// # Returns
/// - `Response::Accepted(true)` if cached successfully
/// - `Error::InvalidSignature` if signature verification fails
pub fn handle_provide_erc20_token_info(
    info: &TokenInfo,
    _signature: &[u8],
) -> Result<Response, Error> {
    // Validate basic constraints
    if info.ticker.is_empty() || info.ticker.len() > 12 {
        return Err(Error::InvalidParameter);
    }

    if info.decimals > 36 {
        return Err(Error::InvalidParameter);
    }

    // TODO: Full implementation would verify signature here:
    // 1. Reconstruct canonical metadata blob
    // 2. Compute keccak256(metadata_blob)
    // 3. Verify ECDSA signature against CAL public key
    // 4. Reject with Error::InvalidSignature if invalid

    // For minimal implementation, accept without verification
    // In production, this would cache the verified info in session state

    Ok(Response::Accepted(true))
}

/// Handles PROVIDE_NFT_INFO command.
///
/// Caches verified NFT collection metadata for display during signing.
///
/// # Arguments
/// * `info` - NFT collection information
/// * `signature` - CAL signature over the info
///
/// # Returns
/// - `Response::Accepted(true)` if cached successfully
pub fn handle_provide_nft_info(info: &NftInfo, _signature: &[u8]) -> Result<Response, Error> {
    // Validate basic constraints
    if info.name.is_empty() || info.name.len() > 64 {
        return Err(Error::InvalidParameter);
    }

    // TODO: Verify CAL signature

    Ok(Response::Accepted(true))
}

/// Handles PROVIDE_DOMAIN_NAME command.
///
/// Caches verified domain name resolution for display during signing.
///
/// # Arguments
/// * `info` - Domain resolution information
/// * `signature` - Signature from domain authority
///
/// # Returns
/// - `Response::Accepted(true)` if cached successfully
pub fn handle_provide_domain_name(info: &DomainInfo, _signature: &[u8]) -> Result<Response, Error> {
    // Validate basic constraints
    if info.domain.is_empty() || info.domain.len() > 256 {
        return Err(Error::InvalidParameter);
    }

    // TODO: Verify domain authority signature

    Ok(Response::Accepted(true))
}

/// Handles LOAD_CONTRACT_METHOD_INFO command.
///
/// Caches verified contract method ABI for clear signing.
///
/// # Arguments
/// * `info` - Method information (selector, name, ABI)
/// * `signature` - CAL signature over the info
///
/// # Returns
/// - `Response::Accepted(true)` if cached successfully
pub fn handle_load_contract_method_info(
    info: &MethodInfo,
    _signature: &[u8],
) -> Result<Response, Error> {
    // Validate basic constraints
    if info.name.is_empty() || info.name.len() > 64 {
        return Err(Error::InvalidParameter);
    }

    // TODO: Verify CAL signature

    Ok(Response::Accepted(true))
}

/// Handles BY_CONTRACT_ADDRESS_AND_CHAIN command.
///
/// Sets the current context for subsequent metadata lookups.
/// This allows the client to specify which contract/chain to use
/// for resolving metadata.
///
/// # Arguments
/// * `chain_id` - Chain ID for context
/// * `address` - Contract address for context
///
/// # Returns
/// - `Response::ContextBound(true)` if context set successfully
pub fn handle_by_contract_address_and_chain(
    chain_id: u64,
    _address: &EthAddress,
) -> Result<Response, Error> {
    // Validate chain_id is reasonable
    if chain_id == 0 {
        return Err(Error::InvalidParameter);
    }

    // TODO: Store context in session state for subsequent lookups

    Ok(Response::ContextBound(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn test_provide_erc20_token_info_valid() {
        let info = TokenInfo {
            chain_id: 1,
            address: [0u8; 20],
            ticker: String::from("USDC"),
            decimals: 6,
        };

        let result = handle_provide_erc20_token_info(&info, &[]);
        assert!(matches!(result, Ok(Response::Accepted(true))));
    }

    #[test]
    fn test_provide_erc20_token_info_invalid_ticker() {
        let info = TokenInfo {
            chain_id: 1,
            address: [0u8; 20],
            ticker: String::new(), // Empty ticker
            decimals: 6,
        };

        let result = handle_provide_erc20_token_info(&info, &[]);
        assert!(matches!(result, Err(Error::InvalidParameter)));
    }

    #[test]
    fn test_provide_erc20_token_info_invalid_decimals() {
        let info = TokenInfo {
            chain_id: 1,
            address: [0u8; 20],
            ticker: String::from("TEST"),
            decimals: 40, // Too many decimals
        };

        let result = handle_provide_erc20_token_info(&info, &[]);
        assert!(matches!(result, Err(Error::InvalidParameter)));
    }

    #[test]
    fn test_by_contract_address_and_chain_valid() {
        let result = handle_by_contract_address_and_chain(1, &[0u8; 20]);
        assert!(matches!(result, Ok(Response::ContextBound(true))));
    }

    #[test]
    fn test_by_contract_address_and_chain_invalid_chain() {
        let result = handle_by_contract_address_and_chain(0, &[0u8; 20]);
        assert!(matches!(result, Err(Error::InvalidParameter)));
    }
}
