//! EIP-7730 Clear Signing Display Rules.
//!
//! This module implements parsing and application of EIP-7730 display rules
//! for clear signing of smart contract transactions. It bridges the ABI decoder
//! with human-readable display formatting.
//!
//! # EIP-7730 Overview
//!
//! EIP-7730 defines a JSON schema for mapping smart contract function calls
//! to human-readable display formats. Key concepts:
//!
//! - **Format**: Display configuration for a specific function selector
//! - **Field**: Mapping from ABI parameter to display label and format
//! - **Intent**: Human-readable description of the function's purpose
//!
//! # Security
//!
//! - Display rules come from the HOST and are UNTRUSTED
//! - Rules must be verified against a trusted registry (CAL) before use
//! - Until verified, transactions should be shown as "unverified" or rejected
//!
//! # Example JSON Structure (AAVE format)
//!
//! ```json
//! {
//!   "intent": "Repay loan",
//!   "fields": [
//!     {"path": "asset", "label": "Asset", "format": "addressName"},
//!     {"path": "amount", "label": "Amount", "format": "tokenAmount", "params": {"tokenPath": "asset"}},
//!     {"path": "onBehalfOf", "label": "For", "format": "addressName"}
//!   ]
//! }
//! ```
//!
//! # Docs consulted
//!
//! - EIP-7730 specification
//! - https://github.com/LedgerHQ/clear-signing-erc7730-registry
//! - docs/security.md: Trust boundaries

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::abi::{AbiValue, DecodedCall};

/// Maximum number of fields in a display format.
const MAX_FIELDS: usize = 16;

/// Maximum label length in characters.
const MAX_LABEL_LEN: usize = 32;

/// Maximum intent description length.
const MAX_INTENT_LEN: usize = 64;

/// Errors during display rule application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {
    /// Field path not found in decoded call.
    FieldNotFound,
    /// Format type not supported.
    UnsupportedFormat,
    /// Value type doesn't match expected format.
    TypeMismatch,
    /// Token not found in metadata cache.
    TokenNotFound,
    /// Address not found in metadata cache.
    AddressNotFound,
    /// Display rules not verified.
    Unverified,
    /// Too many fields in format.
    TooManyFields,
    /// Label too long.
    LabelTooLong,
}

/// Display format types for ABI values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayFormat {
    /// Raw value display (hex for bytes, decimal for integers).
    Raw,
    /// Token amount with decimals and symbol (e.g., "1.5 ETH").
    TokenAmount {
        /// Path to the token address parameter for decimal lookup.
        token_path: Option<String>,
    },
    /// Address with ENS name if available.
    AddressName,
    /// Enum value mapped to human-readable string.
    Enum {
        /// Mapping from numeric value to display string.
        values: Vec<(u64, String)>,
    },
    /// Nested calldata (for multicall patterns).
    Calldata,
    /// Date/time display (Unix timestamp).
    DateTime,
    /// Percentage with basis points.
    Percentage,
    /// Boolean as "Yes"/"No" or custom labels.
    Boolean {
        true_label: Option<String>,
        false_label: Option<String>,
    },
}

/// A single field display rule.
#[derive(Debug, Clone)]
pub struct DisplayField {
    /// Parameter path (e.g., "asset", "amount", "params.deadline").
    pub path: String,
    /// User-facing label.
    pub label: String,
    /// Display format.
    pub format: DisplayFormat,
}

/// Complete display format for a function.
#[derive(Debug, Clone)]
pub struct FunctionDisplay {
    /// Function selector (4 bytes).
    pub selector: [u8; 4],
    /// Human-readable intent description.
    pub intent: String,
    /// Field display rules in order.
    pub fields: Vec<DisplayField>,
    /// Whether this format has been verified against trusted registry.
    pub verified: bool,
}

/// Formatted value ready for display.
#[derive(Debug, Clone)]
pub struct FormattedValue {
    /// Display label.
    pub label: String,
    /// Formatted value string.
    pub value: String,
}

/// Context for formatting (provides token info, address names, etc.).
pub trait DisplayContext {
    /// Get token symbol and decimals by address.
    fn get_token_info(&self, address: &[u8; 20]) -> Option<(&str, u8)>;

    /// Get human-readable name for an address (ENS, contract name, etc.).
    fn get_address_name(&self, address: &[u8; 20]) -> Option<&str>;
}

/// Formats a decoded call for display using the provided rules.
///
/// # Arguments
/// * `call` - Decoded ABI call
/// * `display` - Display format rules
/// * `param_types` - Parameter types matching the call
/// * `param_names` - Parameter names for path lookup
/// * `ctx` - Context for token/address lookup
///
/// # Returns
/// List of formatted values for display, or error.
///
/// # Security
///
/// If `display.verified` is false, callers MUST show an "unverified" warning.
pub fn format_call<C: DisplayContext>(
    call: &DecodedCall,
    display: &FunctionDisplay,
    param_names: &[&str],
    ctx: &C,
) -> Result<Vec<FormattedValue>, DisplayError> {
    if display.fields.len() > MAX_FIELDS {
        return Err(DisplayError::TooManyFields);
    }

    let mut result = Vec::with_capacity(display.fields.len());

    for field in &display.fields {
        if field.label.len() > MAX_LABEL_LEN {
            return Err(DisplayError::LabelTooLong);
        }

        // Find the parameter by path
        let value = find_value_by_path(&call.params, param_names, &field.path)?;

        // Format based on display type
        let formatted = format_value(value, &field.format, &call.params, param_names, ctx)?;

        result.push(FormattedValue {
            label: field.label.clone(),
            value: formatted,
        });
    }

    Ok(result)
}

/// Finds a value in the decoded params by path.
fn find_value_by_path<'a>(
    params: &'a [AbiValue],
    names: &[&str],
    path: &str,
) -> Result<&'a AbiValue, DisplayError> {
    // Simple path: just parameter name
    // TODO: Support nested paths like "params.deadline"
    for (i, name) in names.iter().enumerate() {
        if *name == path {
            return params.get(i).ok_or(DisplayError::FieldNotFound);
        }
    }
    Err(DisplayError::FieldNotFound)
}

/// Formats a single ABI value according to the display format.
fn format_value<C: DisplayContext>(
    value: &AbiValue,
    format: &DisplayFormat,
    all_params: &[AbiValue],
    param_names: &[&str],
    ctx: &C,
) -> Result<String, DisplayError> {
    match format {
        DisplayFormat::Raw => format_raw(value),

        DisplayFormat::TokenAmount { token_path } => {
            // Get token address from path or use native ETH
            let (symbol, decimals) = if let Some(path) = token_path {
                let token_addr = find_value_by_path(all_params, param_names, path)?;
                let addr = token_addr.as_address().ok_or(DisplayError::TypeMismatch)?;
                ctx.get_token_info(addr).ok_or(DisplayError::TokenNotFound)?
            } else {
                // Default to ETH
                ("ETH", 18)
            };

            let amount_bytes = value.as_uint_bytes().ok_or(DisplayError::TypeMismatch)?;
            Ok(format_token_amount(amount_bytes, decimals, symbol))
        }

        DisplayFormat::AddressName => {
            let addr = value.as_address().ok_or(DisplayError::TypeMismatch)?;
            if let Some(name) = ctx.get_address_name(addr) {
                Ok(name.into())
            } else {
                Ok(format_address(addr))
            }
        }

        DisplayFormat::Enum { values } => {
            let uint_bytes = value.as_uint_bytes().ok_or(DisplayError::TypeMismatch)?;
            let num = bytes_to_u64(uint_bytes);
            for (val, label) in values {
                if *val == num {
                    return Ok(label.clone());
                }
            }
            // Fallback to numeric
            Ok(alloc::format!("{}", num))
        }

        DisplayFormat::Boolean {
            true_label,
            false_label,
        } => {
            let b = value.as_bool().ok_or(DisplayError::TypeMismatch)?;
            if b {
                Ok(true_label.clone().unwrap_or_else(|| "Yes".into()))
            } else {
                Ok(false_label.clone().unwrap_or_else(|| "No".into()))
            }
        }

        DisplayFormat::DateTime => {
            let uint_bytes = value.as_uint_bytes().ok_or(DisplayError::TypeMismatch)?;
            let timestamp = bytes_to_u64(uint_bytes);
            // Simple timestamp display - could be enhanced with date formatting
            Ok(alloc::format!("Unix: {}", timestamp))
        }

        DisplayFormat::Percentage => {
            let uint_bytes = value.as_uint_bytes().ok_or(DisplayError::TypeMismatch)?;
            let bps = bytes_to_u64(uint_bytes);
            // Assuming basis points (1/100 of a percent)
            let whole = bps / 100;
            let frac = bps % 100;
            Ok(alloc::format!("{}.{:02}%", whole, frac))
        }

        DisplayFormat::Calldata => {
            // For nested calldata, just show length
            let bytes = value.as_bytes().ok_or(DisplayError::TypeMismatch)?;
            Ok(alloc::format!("{} bytes calldata", bytes.len()))
        }
    }
}

/// Formats raw ABI value.
fn format_raw(value: &AbiValue) -> Result<String, DisplayError> {
    match value {
        AbiValue::Uint(bytes) => {
            // For small values, show decimal; for large, show hex
            if bytes.len() <= 8 {
                Ok(alloc::format!("{}", bytes_to_u64(bytes)))
            } else {
                Ok(alloc::format!("0x{}", hex::encode(bytes)))
            }
        }
        AbiValue::Int(bytes) => {
            // Signed integer - show as hex for simplicity
            Ok(alloc::format!("0x{}", hex::encode(bytes)))
        }
        AbiValue::Address(addr) => Ok(format_address(addr)),
        AbiValue::Bool(b) => Ok(if *b { "true" } else { "false" }.into()),
        AbiValue::FixedBytes(b) | AbiValue::Bytes(b) => {
            if b.len() <= 32 {
                Ok(alloc::format!("0x{}", hex::encode(b)))
            } else {
                Ok(alloc::format!("0x{}... ({} bytes)", hex::encode(&b[..8]), b.len()))
            }
        }
        AbiValue::String(s) => Ok(s.clone()),
        AbiValue::Array(arr) => Ok(alloc::format!("[{} items]", arr.len())),
        AbiValue::Tuple(items) => Ok(alloc::format!("({} fields)", items.len())),
    }
}

/// Formats an address as checksummed hex.
fn format_address(addr: &[u8; 20]) -> String {
    // Use EIP-55 checksum
    crate::utils::format_address_checksummed(addr)
}

/// Formats a token amount with decimals and symbol.
fn format_token_amount(amount_bytes: &[u8], decimals: u8, symbol: &str) -> String {
    // Handle big-endian uint256: value is in the LOW bytes (last 16 bytes).
    // For values that fit in u128, the high bytes (first 16) should be zero.
    let len = amount_bytes.len();

    // Check if we have a 32-byte uint256
    if len == 32 {
        // Check if high bytes are zero (value fits in u128)
        let high_zero = amount_bytes[..16].iter().all(|&b| b == 0);

        let amount: u128 = if high_zero {
            // Read from low bytes (last 16 bytes)
            let mut n: u128 = 0;
            for &byte in &amount_bytes[16..] {
                n = (n << 8) | (byte as u128);
            }
            n
        } else {
            // Value exceeds u128, show hex representation
            let hex_str = alloc::format!("0x{}", hex::encode(amount_bytes));
            return alloc::format!("{} {}", hex_str, symbol);
        };

        let decimal_str = format_u128_with_decimals_internal(amount, decimals);
        return alloc::format!("{} {}", decimal_str, symbol);
    }

    // For non-32-byte arrays (e.g., uint160 = 20 bytes), values are big-endian
    // with significant bytes at the END (right-aligned).
    // We need to check if the value fits in u128 and read from the end.
    if len <= 16 {
        // Fits entirely in u128 - read all bytes
        let mut amount: u128 = 0;
        for &byte in amount_bytes {
            amount = (amount << 8) | (byte as u128);
        }
        let decimal_str = format_u128_with_decimals_internal(amount, decimals);
        return alloc::format!("{} {}", decimal_str, symbol);
    }

    // len > 16: Check if high bytes are zero (value fits in u128)
    let high_len = len - 16;
    let high_zero = amount_bytes[..high_len].iter().all(|&b| b == 0);

    if high_zero {
        // Read from low bytes (last 16 bytes)
        let mut amount: u128 = 0;
        for &byte in &amount_bytes[high_len..] {
            amount = (amount << 8) | (byte as u128);
        }
        let decimal_str = format_u128_with_decimals_internal(amount, decimals);
        alloc::format!("{} {}", decimal_str, symbol)
    } else {
        // Value exceeds u128, show hex representation
        let hex_str = alloc::format!("0x{}", hex::encode(amount_bytes));
        alloc::format!("{} {}", hex_str, symbol)
    }
}

/// Formats a u128 value with decimal places.
fn format_u128_with_decimals_internal(value: u128, decimals: u8) -> String {
    if decimals == 0 {
        return alloc::format!("{}", value);
    }

    let divisor = 10u128.pow(decimals as u32);
    let whole = value / divisor;
    let frac = value % divisor;

    if frac == 0 {
        alloc::format!("{}", whole)
    } else {
        // Format fractional part with leading zeros, then trim trailing zeros
        let frac_str = alloc::format!("{:0>width$}", frac, width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        alloc::format!("{}.{}", whole, trimmed)
    }
}

/// Converts big-endian bytes to u64.
fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for byte in bytes.iter().take(8) {
        result = (result << 8) | (*byte as u64);
    }
    result
}

// ============================================================================
// Common Protocol Display Formats
// ============================================================================

/// Creates display format for standard ERC-20 transfer.
pub fn erc20_transfer_format() -> FunctionDisplay {
    FunctionDisplay {
        selector: [0xa9, 0x05, 0x9c, 0xbb], // transfer(address,uint256)
        intent: "Transfer tokens".into(),
        fields: vec![
            DisplayField {
                path: "to".into(),
                label: "To".into(),
                format: DisplayFormat::AddressName,
            },
            DisplayField {
                path: "amount".into(),
                label: "Amount".into(),
                format: DisplayFormat::TokenAmount { token_path: None },
            },
        ],
        verified: false, // Must be verified against registry
    }
}

/// Creates display format for standard ERC-20 approve.
pub fn erc20_approve_format() -> FunctionDisplay {
    FunctionDisplay {
        selector: [0x09, 0x5e, 0xa7, 0xb3], // approve(address,uint256)
        intent: "Approve spending".into(),
        fields: vec![
            DisplayField {
                path: "spender".into(),
                label: "Spender".into(),
                format: DisplayFormat::AddressName,
            },
            DisplayField {
                path: "amount".into(),
                label: "Amount".into(),
                format: DisplayFormat::TokenAmount { token_path: None },
            },
        ],
        verified: false,
    }
}

/// AAVE V3 repay function display format.
pub fn aave_v3_repay_format() -> FunctionDisplay {
    FunctionDisplay {
        selector: crate::parsing::abi::compute_selector(
            "repay(address,uint256,uint256,address)",
        ),
        intent: "Repay AAVE loan".into(),
        fields: vec![
            DisplayField {
                path: "asset".into(),
                label: "Asset".into(),
                format: DisplayFormat::AddressName,
            },
            DisplayField {
                path: "amount".into(),
                label: "Amount".into(),
                format: DisplayFormat::TokenAmount {
                    token_path: Some("asset".into()),
                },
            },
            DisplayField {
                path: "interestRateMode".into(),
                label: "Rate Mode".into(),
                format: DisplayFormat::Enum {
                    values: vec![
                        (1, "Stable".into()),
                        (2, "Variable".into()),
                    ],
                },
            },
            DisplayField {
                path: "onBehalfOf".into(),
                label: "For".into(),
                format: DisplayFormat::AddressName,
            },
        ],
        verified: false,
    }
}

/// AAVE V3 supply function display format.
pub fn aave_v3_supply_format() -> FunctionDisplay {
    FunctionDisplay {
        selector: crate::parsing::abi::compute_selector(
            "supply(address,uint256,address,uint16)",
        ),
        intent: "Supply to AAVE".into(),
        fields: vec![
            DisplayField {
                path: "asset".into(),
                label: "Asset".into(),
                format: DisplayFormat::AddressName,
            },
            DisplayField {
                path: "amount".into(),
                label: "Amount".into(),
                format: DisplayFormat::TokenAmount {
                    token_path: Some("asset".into()),
                },
            },
            DisplayField {
                path: "onBehalfOf".into(),
                label: "For".into(),
                format: DisplayFormat::AddressName,
            },
        ],
        verified: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockContext;

    impl DisplayContext for MockContext {
        fn get_token_info(&self, address: &[u8; 20]) -> Option<(&str, u8)> {
            // USDC address (mainnet)
            if address == &hex_literal::hex!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") {
                Some(("USDC", 6))
            } else {
                None
            }
        }

        fn get_address_name(&self, address: &[u8; 20]) -> Option<&str> {
            if address == &hex_literal::hex!("1234567890123456789012345678901234567890") {
                Some("Test Contract")
            } else {
                None
            }
        }
    }

    #[test]
    fn test_format_raw_uint() {
        let value = AbiValue::Uint(vec![0x00, 0x00, 0x00, 0x64]); // 100
        let result = format_raw(&value).unwrap();
        assert_eq!(result, "100");
    }

    #[test]
    fn test_format_raw_address() {
        let addr = hex_literal::hex!("1234567890123456789012345678901234567890");
        let value = AbiValue::Address(addr);
        let result = format_raw(&value).unwrap();
        assert!(result.starts_with("0x"));
        assert_eq!(result.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_format_percentage() {
        let value = AbiValue::Uint(vec![0x00, 0x00, 0x01, 0xF4]); // 500 bps = 5.00%
        let result = format_value(
            &value,
            &DisplayFormat::Percentage,
            &[],
            &[],
            &MockContext,
        )
        .unwrap();
        assert_eq!(result, "5.00%");
    }

    #[test]
    fn test_format_enum() {
        let value = AbiValue::Uint(vec![0x02]); // Variable rate
        let format = DisplayFormat::Enum {
            values: vec![(1, "Stable".into()), (2, "Variable".into())],
        };
        let result = format_value(&value, &format, &[], &[], &MockContext).unwrap();
        assert_eq!(result, "Variable");
    }

    #[test]
    fn test_erc20_transfer_format() {
        let format = erc20_transfer_format();
        assert_eq!(format.selector, [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(format.fields.len(), 2);
        assert!(!format.verified);
    }

    #[test]
    fn test_aave_repay_format() {
        let format = aave_v3_repay_format();
        assert_eq!(format.fields.len(), 4);
        assert_eq!(format.intent, "Repay AAVE loan");
    }

    #[test]
    fn test_format_token_amount_uint256() {
        // Test that uint256 values are correctly read from low bytes (big-endian)
        // Value: 1_000_000 (1 USDC with 6 decimals)
        let mut amount_bytes = [0u8; 32];
        // 1_000_000 = 0x0F_42_40 in big-endian at the end of the 32 bytes
        amount_bytes[29] = 0x0F;
        amount_bytes[30] = 0x42;
        amount_bytes[31] = 0x40;

        let result = format_token_amount(&amount_bytes, 6, "USDC");
        assert_eq!(result, "1 USDC");
    }

    #[test]
    fn test_format_token_amount_uint256_larger() {
        // Test a larger value: 1.5 ETH = 1_500_000_000_000_000_000 wei
        let mut amount_bytes = [0u8; 32];
        // 1_500_000_000_000_000_000 = 0x14D1_120D_7B16_0000 in big-endian
        let value: u64 = 1_500_000_000_000_000_000;
        let value_bytes = value.to_be_bytes();
        amount_bytes[24..32].copy_from_slice(&value_bytes);

        let result = format_token_amount(&amount_bytes, 18, "ETH");
        assert_eq!(result, "1.5 ETH");
    }

    #[test]
    fn test_format_token_amount_short_bytes() {
        // Test with shorter byte arrays (not full uint256)
        let amount_bytes = [0x0F, 0x42, 0x40]; // 1_000_000
        let result = format_token_amount(&amount_bytes, 6, "USDC");
        assert_eq!(result, "1 USDC");
    }

    #[test]
    fn test_format_token_amount_overflow_shows_hex() {
        // Test that values exceeding u128 show hex representation
        let mut amount_bytes = [0u8; 32];
        amount_bytes[0] = 0x01; // Non-zero in high bytes = exceeds u128
        amount_bytes[31] = 0x01;

        let result = format_token_amount(&amount_bytes, 18, "ETH");
        assert!(result.starts_with("0x"), "Expected hex for overflow value: {}", result);
        assert!(result.ends_with(" ETH"), "Expected ETH suffix: {}", result);
    }

    #[test]
    fn test_format_token_amount_uint160() {
        // Test uint160 (20 bytes) - the bug case where value bytes are at the END
        // Value: 1_000_000 in a 20-byte big-endian array
        // The first 17 bytes are zeros, value 0x0F4240 is in the last 3 bytes
        let mut amount_bytes = [0u8; 20];
        amount_bytes[17] = 0x0F;
        amount_bytes[18] = 0x42;
        amount_bytes[19] = 0x40;

        let result = format_token_amount(&amount_bytes, 6, "USDC");
        assert_eq!(result, "1 USDC", "uint160 value should be read from end, not beginning");
    }

    #[test]
    fn test_format_token_amount_uint200() {
        // Test uint200 (25 bytes) - another case with > 16 bytes
        // Value: 1.5 ETH = 1_500_000_000_000_000_000 wei
        let mut amount_bytes = [0u8; 25];
        let value: u64 = 1_500_000_000_000_000_000;
        let value_bytes = value.to_be_bytes();
        // Place value at the end (bytes 17-24)
        amount_bytes[17..25].copy_from_slice(&value_bytes);

        let result = format_token_amount(&amount_bytes, 18, "ETH");
        assert_eq!(result, "1.5 ETH", "uint200 value should be read from end");
    }

    #[test]
    fn test_format_token_amount_uint160_overflow() {
        // Test uint160 with a value exceeding u128
        // 160 bits > 128 bits, so we can have values that exceed u128
        let mut amount_bytes = [0u8; 20];
        // Set a non-zero byte in the first 4 bytes (indices 0-3)
        // which would be in the "high" portion for a 20-byte value
        amount_bytes[0] = 0x01;
        amount_bytes[19] = 0x01;

        let result = format_token_amount(&amount_bytes, 18, "ETH");
        assert!(result.starts_with("0x"), "uint160 overflow should show hex: {}", result);
        assert!(result.ends_with(" ETH"), "Expected ETH suffix: {}", result);
    }
}
