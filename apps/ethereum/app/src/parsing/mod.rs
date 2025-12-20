//! Transaction and RLP parsing for the Ethereum V-App.
//!
//! This module provides:
//! - RLP decoding for Ethereum data structures
//! - Transaction parsing (legacy and EIP-2718 typed)
//! - ABI decoding for contract calldata
//! - EIP-7730 clear signing display rules
//!
//! # Security
//!
//! All parsing happens in the V-App on untrusted input.
//! Parsers must:
//! - Validate all length fields before access
//! - Fail closed on any malformed data
//! - Avoid unbounded allocations
//!
//! # Docs consulted
//!
//! - docs/security.md: Memory access pattern leakage
//! - Ethereum Yellow Paper: RLP specification
//! - Solidity ABI Specification
//! - EIP-7730 Clear Signing Specification

pub mod abi;
pub mod eip7730;
pub mod rlp;
pub mod transaction;

// Re-exports for external use (allow dead code for public API items)
#[allow(unused_imports)]
pub use abi::{AbiDecoder, AbiError, AbiType, AbiValue, DecodedCall};
#[allow(unused_imports)]
pub use eip7730::{DisplayContext, DisplayError, DisplayField, DisplayFormat, FunctionDisplay};
#[allow(unused_imports)]
pub use rlp::{RlpError, RlpItem};
pub use transaction::{ParsedTransaction, TransactionParser};
