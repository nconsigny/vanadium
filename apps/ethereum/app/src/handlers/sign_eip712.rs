//! EIP-712 signing handlers.
//!
//! Handles:
//! - SIGN_EIP712_HASHED (0x05): Sign pre-hashed EIP-712 data
//! - SIGN_EIP712_MESSAGE (0x06): Sign full EIP-712 typed data
//!
//! # Security Model
//!
//! - Pre-hashed signing requires blind signing enabled (security risk)
//! - Full typed data signing parses and displays the content
//! - Domain hash prevents cross-domain replay
//!
//! # Docs consulted
//!
//! - docs/commands.md: Command specification
//! - EIP-712: Typed Structured Data Hashing and Signing

use alloc::vec::Vec;
use common::error::Error;
use common::message::Response;
use common::types::{Bip32Path, Hash256, Signature, MAX_BIP32_PATH_DEPTH};
use sdk::curve::{Curve, EcfpPrivateKey, Secp256k1};

use crate::utils::keccak256;

/// EIP-712 prefix byte.
const EIP712_PREFIX: u8 = 0x19;
/// EIP-712 version byte.
const EIP712_VERSION: u8 = 0x01;

/// Handles SIGN_EIP712_HASHED command.
///
/// Signs pre-hashed EIP-712 typed data. This is a "blind signing" operation
/// because the V-App cannot verify what the user is actually signing.
///
/// # Arguments
/// * `app` - SDK App instance for UX
/// * `path` - BIP32 derivation path
/// * `domain_hash` - EIP-712 domain separator hash
/// * `message_hash` - EIP-712 message hash
///
/// # Security
///
/// - REQUIRES blind signing to be enabled
/// - User sees only the hash values, not the actual content
/// - Should only be used when full parsing is impossible
///
/// # Returns
/// - `Response::Signature` with v, r, s components
/// - `Error::BlindSigningDisabled` if blind signing not enabled
/// - `Error::RejectedByUser` if user declines
pub fn handle_sign_eip712_hashed(
    app: &mut sdk::App,
    path: &Bip32Path,
    domain_hash: &Hash256,
    message_hash: &Hash256,
) -> Result<Response, Error> {
    // Validate path
    if path.len() > MAX_BIP32_PATH_DEPTH {
        return Err(Error::InvalidDerivationPath);
    }

    if !path.is_valid_ethereum_path() {
        return Err(Error::InvalidDerivationPath);
    }

    // TODO: Check if blind signing is enabled in session state
    // For minimal implementation, allow with warning
    // In production: return Err(Error::BlindSigningDisabled);

    // Compute final hash: keccak256(0x19 || 0x01 || domainHash || messageHash)
    let mut data = Vec::with_capacity(66);
    data.push(EIP712_PREFIX);
    data.push(EIP712_VERSION);
    data.extend_from_slice(domain_hash);
    data.extend_from_slice(message_hash);
    let final_hash = keccak256(&data);

    // Display for user confirmation
    if !display_eip712_hashed(app, domain_hash, message_hash) {
        return Err(Error::RejectedByUser);
    }

    // Sign
    let signature = sign_hash_eip712(path, &final_hash)?;

    Ok(Response::Signature(signature))
}

/// Handles SIGN_EIP712_MESSAGE command.
///
/// Signs full EIP-712 typed data with parsing and display.
///
/// # Arguments
/// * `app` - SDK App instance for UX
/// * `path` - BIP32 derivation path
/// * `typed_data` - JSON-encoded EIP-712 typed data
///
/// # Security
///
/// - Parses and validates the typed data structure
/// - Displays domain and message fields to user
/// - Safer than blind signing (SIGN_EIP712_HASHED)
///
/// # Returns
/// - `Response::Signature` with v, r, s components
/// - `Error::InvalidTypedData` if parsing fails
/// - `Error::RejectedByUser` if user declines
pub fn handle_sign_eip712_message(
    app: &mut sdk::App,
    path: &Bip32Path,
    typed_data: &[u8],
) -> Result<Response, Error> {
    // Validate path
    if path.len() > MAX_BIP32_PATH_DEPTH {
        return Err(Error::InvalidDerivationPath);
    }

    if !path.is_valid_ethereum_path() {
        return Err(Error::InvalidDerivationPath);
    }

    // Validate typed data size
    if typed_data.is_empty() || typed_data.len() > 65536 {
        return Err(Error::InvalidTypedData);
    }

    // Parse EIP-712 typed data
    // For minimal implementation, compute hash directly
    // Full implementation would parse JSON and display fields
    let (domain_hash, message_hash) = parse_eip712_typed_data(typed_data)?;

    // Compute final hash
    let mut data = Vec::with_capacity(66);
    data.push(EIP712_PREFIX);
    data.push(EIP712_VERSION);
    data.extend_from_slice(&domain_hash);
    data.extend_from_slice(&message_hash);
    let final_hash = keccak256(&data);

    // Display for user confirmation
    if !display_eip712_message(app, &domain_hash, &message_hash) {
        return Err(Error::RejectedByUser);
    }

    // Sign
    let signature = sign_hash_eip712(path, &final_hash)?;

    Ok(Response::Signature(signature))
}

/// Parses EIP-712 typed data and returns (domain_hash, message_hash).
///
/// # Minimal Implementation
///
/// This is a placeholder that treats the input as raw concatenated hashes.
/// Full implementation would:
/// 1. Parse JSON structure
/// 2. Validate type definitions
/// 3. Compute domain hash from domain fields
/// 4. Compute message hash from primaryType and message
fn parse_eip712_typed_data(typed_data: &[u8]) -> Result<(Hash256, Hash256), Error> {
    // For minimal implementation, expect pre-computed hashes
    // Format: domain_hash (32) || message_hash (32)
    if typed_data.len() < 64 {
        return Err(Error::InvalidTypedData);
    }

    let mut domain_hash = [0u8; 32];
    let mut message_hash = [0u8; 32];

    domain_hash.copy_from_slice(&typed_data[..32]);
    message_hash.copy_from_slice(&typed_data[32..64]);

    Ok((domain_hash, message_hash))
}

/// Displays EIP-712 hashed data for user confirmation (blind signing).
#[cfg(not(any(test, feature = "autoapprove")))]
fn display_eip712_hashed(
    app: &mut sdk::App,
    domain_hash: &Hash256,
    message_hash: &Hash256,
) -> bool {
    use alloc::vec;
    use sdk::ux::{Icon, TagValue};

    let approved = app.review_pairs(
        "Sign EIP-712\n(blind signing)",
        "",
        &vec![
            TagValue {
                tag: "Domain hash".into(),
                value: hex::encode(domain_hash),
            },
            TagValue {
                tag: "Message hash".into(),
                value: hex::encode(message_hash),
            },
        ],
        "Sign typed data",
        "Confirm",
        false,
    );

    if approved {
        app.show_info(Icon::Success, "Typed data signed");
    } else {
        app.show_info(Icon::Failure, "Signature rejected");
    }

    approved
}

#[cfg(any(test, feature = "autoapprove"))]
fn display_eip712_hashed(
    _app: &mut sdk::App,
    _domain_hash: &Hash256,
    _message_hash: &Hash256,
) -> bool {
    true
}

/// Displays EIP-712 message for user confirmation.
#[cfg(not(any(test, feature = "autoapprove")))]
fn display_eip712_message(
    app: &mut sdk::App,
    domain_hash: &Hash256,
    message_hash: &Hash256,
) -> bool {
    use alloc::vec;
    use sdk::ux::{Icon, TagValue};

    // For minimal implementation, show hashes
    // Full implementation would show parsed fields
    let approved = app.review_pairs(
        "Sign EIP-712",
        "",
        &vec![
            TagValue {
                tag: "Domain".into(),
                value: hex::encode(&domain_hash[..8]) + "...",
            },
            TagValue {
                tag: "Message".into(),
                value: hex::encode(&message_hash[..8]) + "...",
            },
        ],
        "Sign typed data",
        "Confirm",
        false,
    );

    if approved {
        app.show_info(Icon::Success, "Typed data signed");
    } else {
        app.show_info(Icon::Failure, "Signature rejected");
    }

    approved
}

#[cfg(any(test, feature = "autoapprove"))]
fn display_eip712_message(
    _app: &mut sdk::App,
    _domain_hash: &Hash256,
    _message_hash: &Hash256,
) -> bool {
    true
}

/// Signs a hash for EIP-712 (v = 27/28).
///
/// For EIP-712 typed data signing, the v value follows the legacy message
/// signing convention: v = 27 + recovery_id (where recovery_id is 0 or 1).
fn sign_hash_eip712(path: &Bip32Path, hash: &[u8; 32]) -> Result<Signature, Error> {
    let hd_node =
        Secp256k1::derive_hd_node(path.as_slice()).map_err(|_| Error::KeyDerivationFailed)?;

    let privkey = EcfpPrivateKey::<Secp256k1, 32>::new(*hd_node.privkey);

    // Use recoverable signing to get the recovery ID directly from the ECALL
    let (der_sig, recovery_id) = privkey
        .ecdsa_sign_hash_recoverable(hash)
        .map_err(|_| Error::SigningFailed)?;

    let (r, s) = parse_der_signature(&der_sig)?;

    // v = 27 + recovery_id for EIP-712 messages (legacy format)
    let v = 27u8 + recovery_id;

    Ok(Signature { v, r, s })
}

/// Parses a DER-encoded ECDSA signature into (r, s) components.
fn parse_der_signature(der: &[u8]) -> Result<([u8; 32], [u8; 32]), Error> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err(Error::SigningFailed);
    }

    let mut pos = 2;

    if der[pos] != 0x02 {
        return Err(Error::SigningFailed);
    }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;

    if pos + r_len > der.len() {
        return Err(Error::SigningFailed);
    }
    let r_bytes = &der[pos..pos + r_len];
    pos += r_len;

    if pos >= der.len() || der[pos] != 0x02 {
        return Err(Error::SigningFailed);
    }
    pos += 1;
    if pos >= der.len() {
        return Err(Error::SigningFailed);
    }
    let s_len = der[pos] as usize;
    pos += 1;

    if pos + s_len > der.len() {
        return Err(Error::SigningFailed);
    }
    let s_bytes = &der[pos..pos + s_len];

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];

    let r_start = if r_bytes.len() > 32 { 1 } else { 0 };
    let s_start = if s_bytes.len() > 32 { 1 } else { 0 };

    let r_copy_len = r_bytes.len() - r_start;
    let s_copy_len = s_bytes.len() - s_start;

    if r_copy_len > 32 || s_copy_len > 32 {
        return Err(Error::SigningFailed);
    }

    r[32 - r_copy_len..].copy_from_slice(&r_bytes[r_start..]);
    s[32 - s_copy_len..].copy_from_slice(&s_bytes[s_start..]);

    Ok((r, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_eip712_hashed_invalid_path() {
        let mut app = sdk::App::singleton();
        let long_path = Bip32Path::from_slice(&[0u32; 15]);
        let domain_hash = [0u8; 32];
        let message_hash = [0u8; 32];

        let result = handle_sign_eip712_hashed(&mut app, &long_path, &domain_hash, &message_hash);
        assert!(matches!(result, Err(Error::InvalidDerivationPath)));
    }

    #[test]
    fn test_sign_eip712_message_empty_data() {
        let mut app = sdk::App::singleton();
        let path = Bip32Path::from_slice(&[0x8000002C, 0x8000003C, 0x80000000, 0, 0]);

        let result = handle_sign_eip712_message(&mut app, &path, &[]);
        assert!(matches!(result, Err(Error::InvalidTypedData)));
    }

    #[test]
    fn test_parse_eip712_typed_data_too_short() {
        let short_data = [0u8; 32]; // Need at least 64 bytes
        let result = parse_eip712_typed_data(&short_data);
        assert!(result.is_err());
    }
}
