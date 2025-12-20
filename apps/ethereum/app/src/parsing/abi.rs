//! ABI decoding for Ethereum contract calldata.
//!
//! This module provides parsing for Solidity ABI-encoded function calls,
//! supporting clear signing display of decoded parameters.
//!
//! # Security
//!
//! All parsing operates on untrusted input. The parser:
//! - Validates all offsets and lengths before access
//! - Uses bounded iteration to prevent DoS
//! - Fails closed on any malformed data
//!
//! # Supported Types
//!
//! - Elementary: uint8-uint256, int8-int256, address, bool, bytes1-bytes32
//! - Dynamic: bytes, string
//! - Arrays: T[] (dynamic), T[N] (fixed)
//! - Tuples: (T1, T2, ...) for struct encoding
//!
//! # Docs consulted
//!
//! - Solidity ABI Specification
//! - docs/security.md: Memory access patterns

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// Maximum number of parameters in a function (prevent DoS).
const MAX_PARAMS: usize = 32;

/// Maximum recursion depth for nested types.
const MAX_DEPTH: usize = 8;

/// Maximum dynamic data size (1MB).
const MAX_DYNAMIC_SIZE: usize = 1024 * 1024;

/// ABI decoding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiError {
    /// Input data too short.
    DataTooShort,
    /// Invalid selector.
    InvalidSelector,
    /// Invalid offset value.
    InvalidOffset,
    /// Invalid length value.
    InvalidLength,
    /// Unknown type signature.
    UnknownType,
    /// Too many parameters.
    TooManyParams,
    /// Nesting too deep.
    NestingTooDeep,
    /// Invalid UTF-8 in string.
    InvalidUtf8,
    /// Dynamic data too large.
    DataTooLarge,
}

/// Solidity ABI type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiType {
    /// Unsigned integer (bits: 8-256, must be multiple of 8).
    Uint(u16),
    /// Signed integer (bits: 8-256, must be multiple of 8).
    Int(u16),
    /// Address (20 bytes).
    Address,
    /// Boolean.
    Bool,
    /// Fixed-size bytes (1-32).
    FixedBytes(u8),
    /// Dynamic bytes.
    Bytes,
    /// Dynamic string.
    String,
    /// Fixed-size array.
    FixedArray(Box<AbiType>, usize),
    /// Dynamic-size array.
    DynamicArray(Box<AbiType>),
    /// Tuple (struct).
    Tuple(Vec<AbiType>),
}

impl AbiType {
    /// Returns true if this type is dynamic (requires offset indirection).
    pub fn is_dynamic(&self) -> bool {
        match self {
            AbiType::Bytes | AbiType::String | AbiType::DynamicArray(_) => true,
            AbiType::FixedArray(inner, _) => inner.is_dynamic(),
            AbiType::Tuple(types) => types.iter().any(|t| t.is_dynamic()),
            _ => false,
        }
    }

    /// Returns the head size in bytes (32 for all elementary types).
    pub fn head_size(&self) -> usize {
        match self {
            AbiType::Uint(_)
            | AbiType::Int(_)
            | AbiType::Address
            | AbiType::Bool
            | AbiType::FixedBytes(_) => 32,
            AbiType::Bytes | AbiType::String | AbiType::DynamicArray(_) => 32, // offset
            AbiType::FixedArray(inner, len) => {
                if inner.is_dynamic() {
                    32 // offset
                } else {
                    inner.head_size() * len
                }
            }
            AbiType::Tuple(types) => {
                if types.iter().any(|t| t.is_dynamic()) {
                    32 // offset
                } else {
                    types.iter().map(|t| t.head_size()).sum()
                }
            }
        }
    }
}

/// Decoded ABI value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiValue {
    /// Unsigned integer (up to 256 bits, stored as big-endian bytes).
    Uint(Vec<u8>),
    /// Signed integer (up to 256 bits, stored as big-endian bytes).
    Int(Vec<u8>),
    /// Address (20 bytes).
    Address([u8; 20]),
    /// Boolean.
    Bool(bool),
    /// Fixed-size bytes.
    FixedBytes(Vec<u8>),
    /// Dynamic bytes.
    Bytes(Vec<u8>),
    /// String.
    String(String),
    /// Array of values.
    Array(Vec<AbiValue>),
    /// Tuple of values.
    Tuple(Vec<AbiValue>),
}

impl AbiValue {
    /// Returns this value as an address if it is one.
    pub fn as_address(&self) -> Option<&[u8; 20]> {
        match self {
            AbiValue::Address(addr) => Some(addr),
            _ => None,
        }
    }

    /// Returns this value as a u256 bytes if it's a uint.
    pub fn as_uint_bytes(&self) -> Option<&[u8]> {
        match self {
            AbiValue::Uint(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Returns this value as a string if it is one.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            AbiValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns this value as bytes if it is dynamic bytes.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            AbiValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns this value as a bool if it is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            AbiValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Function parameter with name and type.
#[derive(Debug, Clone)]
pub struct AbiParam {
    /// Parameter name.
    pub name: String,
    /// Parameter type.
    pub param_type: AbiType,
}

/// Decoded function call.
#[derive(Debug, Clone)]
pub struct DecodedCall {
    /// Function selector (4 bytes).
    pub selector: [u8; 4],
    /// Decoded parameter values (in order).
    pub params: Vec<AbiValue>,
}

/// ABI decoder for contract calldata.
pub struct AbiDecoder;

impl AbiDecoder {
    /// Decodes function calldata given the parameter types.
    ///
    /// # Arguments
    /// * `data` - Full calldata including 4-byte selector
    /// * `param_types` - Expected parameter types in order
    ///
    /// # Returns
    /// Decoded call with selector and parameter values.
    pub fn decode(data: &[u8], param_types: &[AbiType]) -> Result<DecodedCall, AbiError> {
        if data.len() < 4 {
            return Err(AbiError::DataTooShort);
        }

        if param_types.len() > MAX_PARAMS {
            return Err(AbiError::TooManyParams);
        }

        let mut selector = [0u8; 4];
        selector.copy_from_slice(&data[..4]);

        let params = Self::decode_params(&data[4..], param_types, 0)?;

        Ok(DecodedCall { selector, params })
    }

    /// Decodes parameters from calldata (without selector).
    fn decode_params(
        data: &[u8],
        types: &[AbiType],
        depth: usize,
    ) -> Result<Vec<AbiValue>, AbiError> {
        if depth > MAX_DEPTH {
            return Err(AbiError::NestingTooDeep);
        }

        let mut values = Vec::with_capacity(types.len());
        let mut offset = 0;

        for param_type in types {
            let value = Self::decode_value(data, &mut offset, param_type, depth)?;
            values.push(value);
        }

        Ok(values)
    }

    /// Decodes a single value at the given offset.
    fn decode_value(
        data: &[u8],
        offset: &mut usize,
        param_type: &AbiType,
        depth: usize,
    ) -> Result<AbiValue, AbiError> {
        if depth > MAX_DEPTH {
            return Err(AbiError::NestingTooDeep);
        }

        match param_type {
            AbiType::Uint(bits) => {
                let bytes = Self::read_word(data, offset)?;
                let byte_len = (*bits as usize + 7) / 8;
                // Extract relevant bytes (right-aligned in 32-byte word)
                let start = 32 - byte_len;
                Ok(AbiValue::Uint(bytes[start..].to_vec()))
            }

            AbiType::Int(bits) => {
                let bytes = Self::read_word(data, offset)?;
                let byte_len = (*bits as usize + 7) / 8;
                let start = 32 - byte_len;
                Ok(AbiValue::Int(bytes[start..].to_vec()))
            }

            AbiType::Address => {
                let bytes = Self::read_word(data, offset)?;
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&bytes[12..32]);
                Ok(AbiValue::Address(addr))
            }

            AbiType::Bool => {
                let bytes = Self::read_word(data, offset)?;
                let value = bytes[31] != 0;
                Ok(AbiValue::Bool(value))
            }

            AbiType::FixedBytes(len) => {
                let bytes = Self::read_word(data, offset)?;
                Ok(AbiValue::FixedBytes(bytes[..*len as usize].to_vec()))
            }

            AbiType::Bytes => {
                let data_offset = Self::read_offset(data, offset)?;
                let bytes = Self::read_dynamic_bytes(data, data_offset)?;
                Ok(AbiValue::Bytes(bytes))
            }

            AbiType::String => {
                let data_offset = Self::read_offset(data, offset)?;
                let bytes = Self::read_dynamic_bytes(data, data_offset)?;
                let s = core::str::from_utf8(&bytes).map_err(|_| AbiError::InvalidUtf8)?;
                Ok(AbiValue::String(s.into()))
            }

            AbiType::DynamicArray(inner) => {
                let data_offset = Self::read_offset(data, offset)?;
                let values = Self::decode_dynamic_array(data, data_offset, inner, depth + 1)?;
                Ok(AbiValue::Array(values))
            }

            AbiType::FixedArray(inner, len) => {
                if inner.is_dynamic() {
                    let data_offset = Self::read_offset(data, offset)?;
                    let values = Self::decode_fixed_array(data, data_offset, inner, *len, depth + 1)?;
                    Ok(AbiValue::Array(values))
                } else {
                    let mut values = Vec::with_capacity(*len);
                    for _ in 0..*len {
                        let value = Self::decode_value(data, offset, inner, depth + 1)?;
                        values.push(value);
                    }
                    Ok(AbiValue::Array(values))
                }
            }

            AbiType::Tuple(types) => {
                if types.iter().any(|t| t.is_dynamic()) {
                    let data_offset = Self::read_offset(data, offset)?;
                    let values = Self::decode_params(&data[data_offset..], types, depth + 1)?;
                    Ok(AbiValue::Tuple(values))
                } else {
                    let values = Self::decode_params(&data[*offset..], types, depth + 1)?;
                    *offset += types.iter().map(|t| t.head_size()).sum::<usize>();
                    Ok(AbiValue::Tuple(values))
                }
            }
        }
    }

    /// Reads a 32-byte word from data.
    fn read_word(data: &[u8], offset: &mut usize) -> Result<[u8; 32], AbiError> {
        if *offset + 32 > data.len() {
            return Err(AbiError::DataTooShort);
        }
        let mut word = [0u8; 32];
        word.copy_from_slice(&data[*offset..*offset + 32]);
        *offset += 32;
        Ok(word)
    }

    /// Reads an offset value from a 32-byte word.
    fn read_offset(data: &[u8], offset: &mut usize) -> Result<usize, AbiError> {
        let word = Self::read_word(data, offset)?;
        // Offset is stored as big-endian in last 8 bytes (really just 4 bytes practically)
        let value = u64::from_be_bytes(word[24..32].try_into().unwrap());
        if value > data.len() as u64 {
            return Err(AbiError::InvalidOffset);
        }
        Ok(value as usize)
    }

    /// Reads dynamic bytes from data at the given offset.
    fn read_dynamic_bytes(data: &[u8], offset: usize) -> Result<Vec<u8>, AbiError> {
        if offset + 32 > data.len() {
            return Err(AbiError::DataTooShort);
        }

        // First word is length
        let len_word: [u8; 32] = data[offset..offset + 32].try_into().unwrap();
        let len = u64::from_be_bytes(len_word[24..32].try_into().unwrap()) as usize;

        if len > MAX_DYNAMIC_SIZE {
            return Err(AbiError::DataTooLarge);
        }

        let data_start = offset + 32;
        if data_start + len > data.len() {
            return Err(AbiError::DataTooShort);
        }

        Ok(data[data_start..data_start + len].to_vec())
    }

    /// Decodes a dynamic array.
    fn decode_dynamic_array(
        data: &[u8],
        offset: usize,
        inner: &AbiType,
        depth: usize,
    ) -> Result<Vec<AbiValue>, AbiError> {
        if offset + 32 > data.len() {
            return Err(AbiError::DataTooShort);
        }

        // First word is length
        let len_word: [u8; 32] = data[offset..offset + 32].try_into().unwrap();
        let len = u64::from_be_bytes(len_word[24..32].try_into().unwrap()) as usize;

        if len > MAX_PARAMS {
            return Err(AbiError::TooManyParams);
        }

        let element_data = &data[offset + 32..];
        let mut values = Vec::with_capacity(len);
        let mut elem_offset = 0;

        for _ in 0..len {
            let value = Self::decode_value(element_data, &mut elem_offset, inner, depth)?;
            values.push(value);
        }

        Ok(values)
    }

    /// Decodes a fixed-size array.
    fn decode_fixed_array(
        data: &[u8],
        offset: usize,
        inner: &AbiType,
        len: usize,
        depth: usize,
    ) -> Result<Vec<AbiValue>, AbiError> {
        let element_data = &data[offset..];
        let mut values = Vec::with_capacity(len);
        let mut elem_offset = 0;

        for _ in 0..len {
            let value = Self::decode_value(element_data, &mut elem_offset, inner, depth)?;
            values.push(value);
        }

        Ok(values)
    }
}

/// Computes the function selector from a function signature.
///
/// The selector is the first 4 bytes of keccak256(signature).
///
/// # Arguments
/// * `signature` - Function signature (e.g., "transfer(address,uint256)")
pub fn compute_selector(signature: &str) -> [u8; 4] {
    use crate::utils::keccak256;
    let hash = keccak256(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_selector() {
        // transfer(address,uint256) => 0xa9059cbb
        let selector = compute_selector("transfer(address,uint256)");
        assert_eq!(selector, [0xa9, 0x05, 0x9c, 0xbb]);

        // approve(address,uint256) => 0x095ea7b3
        let selector = compute_selector("approve(address,uint256)");
        assert_eq!(selector, [0x09, 0x5e, 0xa7, 0xb3]);

        // balanceOf(address) => 0x70a08231
        let selector = compute_selector("balanceOf(address)");
        assert_eq!(selector, [0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn test_decode_simple_transfer() {
        // transfer(address,uint256) call
        // Selector: a9059cbb
        // Address: 0x1234...5678 (padded to 32 bytes)
        // Amount: 1000000 (padded to 32 bytes)
        let data = hex_literal::hex!(
            "a9059cbb"
            "000000000000000000000000123456789abcdef0123456789abcdef012345678"
            "00000000000000000000000000000000000000000000000000000000000f4240"
        );

        let types = vec![AbiType::Address, AbiType::Uint(256)];
        let decoded = AbiDecoder::decode(&data, &types).unwrap();

        assert_eq!(decoded.selector, [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(decoded.params.len(), 2);

        // Check address
        let addr = decoded.params[0].as_address().unwrap();
        assert_eq!(
            addr,
            &hex_literal::hex!("123456789abcdef0123456789abcdef012345678")
        );

        // Check amount (1000000 = 0xf4240)
        let amount = decoded.params[1].as_uint_bytes().unwrap();
        assert_eq!(amount, &hex_literal::hex!("00000000000000000000000000000000000000000000000000000000000f4240"));
    }

    #[test]
    fn test_decode_bool() {
        // Some function with a bool parameter
        let data = hex_literal::hex!(
            "12345678"
            "0000000000000000000000000000000000000000000000000000000000000001"
        );

        let types = vec![AbiType::Bool];
        let decoded = AbiDecoder::decode(&data, &types).unwrap();

        assert!(decoded.params[0].as_bool().unwrap());
    }

    #[test]
    fn test_abi_type_is_dynamic() {
        assert!(!AbiType::Uint(256).is_dynamic());
        assert!(!AbiType::Address.is_dynamic());
        assert!(!AbiType::Bool.is_dynamic());
        assert!(!AbiType::FixedBytes(32).is_dynamic());

        assert!(AbiType::Bytes.is_dynamic());
        assert!(AbiType::String.is_dynamic());
        assert!(AbiType::DynamicArray(Box::new(AbiType::Uint(256))).is_dynamic());

        // Fixed array of static type is not dynamic
        assert!(!AbiType::FixedArray(Box::new(AbiType::Uint(256)), 3).is_dynamic());
        // Fixed array of dynamic type is dynamic
        assert!(AbiType::FixedArray(Box::new(AbiType::String), 3).is_dynamic());
    }
}
