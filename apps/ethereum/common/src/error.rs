//! Error types for the Ethereum V-App.
//!
//! These error codes are returned in the response frame and propagated
//! to the client. Error messages are kept minimal to avoid leaking
//! security-relevant information.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Error codes for the Ethereum V-App.
///
/// Each variant maps to a specific error code in the wire protocol.
/// Error messages are intentionally terse to avoid information leakage.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Error {
    /// User rejected the operation on the device.
    RejectedByUser = 0x01,
    /// Unknown or unsupported command.
    InvalidCommand = 0x02,
    /// Invalid parameter in the request.
    InvalidParameter = 0x03,
    /// Malformed data in the request payload.
    InvalidData = 0x04,
    /// Signature verification failed.
    InvalidSignature = 0x05,
    /// Security policy violation.
    SecurityViolation = 0x06,
    /// Operation not supported.
    UnsupportedOperation = 0x07,
    /// Internal error in the V-App.
    InternalError = 0x08,
    /// Operation timed out.
    Timeout = 0x09,
    /// Blind signing is disabled but required.
    BlindSigningDisabled = 0x0A,
    /// Required metadata not found in cache.
    MetadataNotFound = 0x0B,
    /// Invalid BIP32/44 derivation path.
    InvalidDerivationPath = 0x0C,
    /// Key derivation failed.
    KeyDerivationFailed = 0x0D,
    /// Signing operation failed.
    SigningFailed = 0x0E,
    /// Invalid transaction format.
    InvalidTransaction = 0x0F,
    /// Invalid RLP encoding.
    InvalidRlp = 0x10,
    /// Invalid message format.
    InvalidMessage = 0x11,
    /// Invalid EIP-712 typed data.
    InvalidTypedData = 0x12,
    /// Invalid state machine transition.
    InvalidState = 0x13,
    /// Chunked transfer error.
    ChunkError = 0x14,
    /// Buffer overflow or size limit exceeded.
    BufferOverflow = 0x15,
}

impl Error {
    /// Returns the error code as a u8.
    pub fn code(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally terse messages to avoid information leakage
        match self {
            Error::RejectedByUser => write!(f, "Rejected by user"),
            Error::InvalidCommand => write!(f, "Invalid command"),
            Error::InvalidParameter => write!(f, "Invalid parameter"),
            Error::InvalidData => write!(f, "Invalid data"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::SecurityViolation => write!(f, "Security violation"),
            Error::UnsupportedOperation => write!(f, "Unsupported operation"),
            Error::InternalError => write!(f, "Internal error"),
            Error::Timeout => write!(f, "Timeout"),
            Error::BlindSigningDisabled => write!(f, "Blind signing disabled"),
            Error::MetadataNotFound => write!(f, "Metadata not found"),
            Error::InvalidDerivationPath => write!(f, "Invalid derivation path"),
            Error::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Error::SigningFailed => write!(f, "Signing failed"),
            Error::InvalidTransaction => write!(f, "Invalid transaction"),
            Error::InvalidRlp => write!(f, "Invalid RLP"),
            Error::InvalidMessage => write!(f, "Invalid message"),
            Error::InvalidTypedData => write!(f, "Invalid typed data"),
            Error::InvalidState => write!(f, "Invalid state"),
            Error::ChunkError => write!(f, "Chunk error"),
            Error::BufferOverflow => write!(f, "Buffer overflow"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(Error::RejectedByUser.code(), 0x01);
        assert_eq!(Error::InvalidCommand.code(), 0x02);
        assert_eq!(Error::BufferOverflow.code(), 0x15);
    }
}
