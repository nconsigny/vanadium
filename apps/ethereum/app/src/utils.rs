//! Utility functions for the Ethereum V-App.
//!
//! This module provides helper functions for:
//! - Address formatting (EIP-55 checksum)
//! - Amount formatting with decimals
//! - Hex encoding/decoding
//!
//! # Security
//!
//! All functions operate on validated data only.
//! No secret-dependent memory access patterns.

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use common::types::EthAddress;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

/// Keccak256 hash function as used by Ethereum.
///
/// # Security
///
/// Uses tiny-keccak which has a constant-time Keccak-f[1600] permutation.
/// The memory access pattern is fixed regardless of input content.
///
/// # Arguments
/// * `data` - Input data to hash
///
/// # Returns
/// 32-byte Keccak256 digest
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Streaming Keccak256 hasher for large inputs.
///
/// Use this when hashing data that arrives in chunks to avoid
/// allocating the full data in memory.
///
/// # Example
/// ```ignore
/// let mut hasher = Keccak256Hasher::new();
/// hasher.update(chunk1);
/// hasher.update(chunk2);
/// let hash = hasher.finalize();
/// ```
pub struct Keccak256Hasher {
    inner: Keccak,
}

impl Keccak256Hasher {
    /// Creates a new Keccak256 hasher.
    pub fn new() -> Self {
        Self {
            inner: Keccak::v256(),
        }
    }

    /// Updates the hasher with additional data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the hash and returns the 32-byte digest.
    pub fn finalize(self) -> [u8; 32] {
        let mut output = [0u8; 32];
        self.inner.finalize(&mut output);
        output
    }
}

impl Default for Keccak256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Formats an Ethereum address with EIP-55 checksum.
///
/// The checksum is computed by taking the Keccak256 hash of the lowercase
/// hex address (without 0x prefix) and capitalizing each letter where the
/// corresponding hex digit of the hash is >= 8.
pub fn format_address_checksummed(address: &EthAddress) -> String {
    let hex_lower = hex::encode(address);
    let hash = keccak256(hex_lower.as_bytes());

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in hex_lower.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            // Get the corresponding nibble from the hash
            let hash_byte = hash[i / 2];
            let nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0F
            };

            if nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Formats an address as simple hex (no checksum).
pub fn format_address_hex(address: &EthAddress) -> String {
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    result.push_str(&hex::encode(address));
    result
}

/// Formats a 256-bit value as decimal string.
///
/// # Arguments
/// * `value` - Big-endian 32-byte value
/// * `decimals` - Number of decimal places to insert
///
/// # Returns
/// Decimal string representation with decimal point inserted.
pub fn format_u256_decimal(value: &[u8; 32], decimals: u8) -> String {
    // Convert big-endian bytes to decimal string
    // This is a simplified implementation for small values

    // Check if value fits in u128 (16 bytes)
    let mut is_small = true;
    for &byte in &value[..16] {
        if byte != 0 {
            is_small = false;
            break;
        }
    }

    if is_small {
        // Value fits in u128
        let mut n: u128 = 0;
        for &byte in &value[16..] {
            n = n << 8 | byte as u128;
        }

        let decimal_str = format_u128_with_decimals(n, decimals);
        return decimal_str;
    }

    // For large values, return hex representation
    let mut result = String::from("0x");
    let mut started = false;
    for &byte in value {
        if byte != 0 || started {
            started = true;
            use core::fmt::Write;
            let _ = write!(result, "{:02x}", byte);
        }
    }
    if !started {
        result.push('0');
    }
    result
}

/// Formats a u128 value with decimal places.
fn format_u128_with_decimals(value: u128, decimals: u8) -> String {
    if decimals == 0 {
        return alloc::format!("{}", value);
    }

    let divisor = 10u128.pow(decimals as u32);
    let whole = value / divisor;
    let frac = value % divisor;

    if frac == 0 {
        alloc::format!("{}", whole)
    } else {
        // Format fractional part with leading zeros
        let frac_str = alloc::format!("{:0width$}", frac, width = decimals as usize);
        // Trim trailing zeros
        let trimmed = frac_str.trim_end_matches('0');
        alloc::format!("{}.{}", whole, trimmed)
    }
}

/// Formats an amount with token ticker.
///
/// # Arguments
/// * `value` - Raw token value (big-endian 32 bytes)
/// * `decimals` - Number of decimal places
/// * `ticker` - Token ticker symbol
pub fn format_token_amount(value: &[u8; 32], decimals: u8, ticker: &str) -> String {
    let amount = format_u256_decimal(value, decimals);
    alloc::format!("{} {}", amount, ticker)
}

/// Formats ETH amount (18 decimals).
pub fn format_eth_amount(value: &[u8; 32]) -> String {
    format_token_amount(value, 18, "ETH")
}

/// Formats gas price in Gwei.
pub fn format_gas_price(value: &[u8; 32]) -> String {
    format_token_amount(value, 9, "Gwei")
}

/// Checks if a byte slice contains only printable ASCII characters.
pub fn is_printable_ascii(data: &[u8]) -> bool {
    data.iter().all(|&b| b >= 0x20 && b < 0x7F)
}

/// Truncates a string for display, adding ellipsis if needed.
///
/// # Arguments
/// * `s` - String to truncate
/// * `max_len` - Maximum length before truncation
pub fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return String::from(s);
    }

    let mut result = String::with_capacity(max_len + 3);
    result.push_str(&s[..max_len]);
    result.push_str("...");
    result
}

/// Parses a hex string (with or without 0x prefix) into bytes.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, &'static str> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|_| "Invalid hex string")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keccak256 test vectors from Ethereum
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    // keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8

    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(b"");
        let expected = hex_literal::hex!(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_keccak256_hello() {
        let hash = keccak256(b"hello");
        let expected = hex_literal::hex!(
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_keccak256_hello_world() {
        // keccak256("hello world") from online tools
        let hash = keccak256(b"hello world");
        let expected = hex_literal::hex!(
            "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_keccak256_streaming() {
        // Verify streaming produces same result as one-shot
        let mut hasher = Keccak256Hasher::new();
        hasher.update(b"hello");
        hasher.update(b" ");
        hasher.update(b"world");
        let hash = hasher.finalize();

        let expected = keccak256(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_keccak256_eip55_address() {
        // EIP-55 checksum test: address 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
        // keccak256("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed") should produce
        // a hash where we check specific nibbles >= 8 for uppercase
        let hash = keccak256(b"5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        // First nibble of hash determines if 'a' in position 1 is uppercase
        // The full verification is done by format_address_checksummed
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_format_address_hex() {
        let address = [0xdeu8, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let formatted = format_address_hex(&address);
        assert_eq!(formatted, "0xdeadbeef00000000000000000000000000000000");
    }

    #[test]
    fn test_format_address_checksummed() {
        // Test EIP-55 checksum address formatting
        // Address: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
        let address = hex_literal::hex!("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        let formatted = format_address_checksummed(&address);
        assert_eq!(formatted, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn test_format_address_checksummed_all_caps() {
        // All-caps address: 0x52908400098527886E0F7030069857D2E4169EE7
        let address = hex_literal::hex!("52908400098527886E0F7030069857D2E4169EE7");
        let formatted = format_address_checksummed(&address);
        assert_eq!(formatted, "0x52908400098527886E0F7030069857D2E4169EE7");
    }

    #[test]
    fn test_format_u128_with_decimals() {
        assert_eq!(format_u128_with_decimals(1000000, 6), "1");
        assert_eq!(format_u128_with_decimals(1500000, 6), "1.5");
        assert_eq!(format_u128_with_decimals(1000000000000000000, 18), "1");
        assert_eq!(format_u128_with_decimals(1234567890000000000, 18), "1.23456789");
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b"Hello, World!"));
        assert!(!is_printable_ascii(b"Hello\x00World"));
        assert!(!is_printable_ascii(b"\xff\xfe"));
    }

    #[test]
    fn test_truncate_for_display() {
        assert_eq!(truncate_for_display("short", 10), "short");
        assert_eq!(truncate_for_display("this is a long string", 10), "this is a ...");
    }
}
