//! Personal message signing handler.
//!
//! Handles:
//! - SIGN_PERSONAL_MESSAGE (0x04): Sign EIP-191 personal message
//!
//! # Security Model
//!
//! - Messages are prefixed with "\x19Ethereum Signed Message:\n{len}"
//! - This prevents signing arbitrary transaction hashes
//! - User sees the message content on secure display
//! - Non-printable messages shown as hex with warning
//!
//! # Docs consulted
//!
//! - docs/commands.md: Command specification
//! - EIP-191: Signed Data Standard

use alloc::vec::Vec;
use common::error::Error;
use common::message::Response;
use common::types::{Bip32Path, Signature, MAX_BIP32_PATH_DEPTH};
use sdk::curve::{Curve, EcfpPrivateKey, Secp256k1};

use crate::utils::keccak256;
#[cfg(not(any(test, feature = "autoapprove")))]
use crate::utils::{is_printable_ascii, truncate_for_display};

/// Maximum message size (64KB).
const MAX_MESSAGE_SIZE: usize = 65536;

/// EIP-191 message prefix.
const EIP191_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";

/// Handles SIGN_PERSONAL_MESSAGE command.
///
/// Signs an EIP-191 personal message with the key derived from the given path.
///
/// # Arguments
/// * `app` - SDK App instance for UX
/// * `path` - BIP32 derivation path
/// * `message` - Message bytes to sign
///
/// # Security Invariants
///
/// - INV-3: User sees what they sign (message displayed)
/// - INV-5: Signature is low-S normalized
/// - INV-6: Path must be valid Ethereum derivation
///
/// # Returns
/// - `Response::Signature` with v, r, s components
/// - `Error::InvalidDerivationPath` if path invalid
/// - `Error::RejectedByUser` if user declines
/// - `Error::SigningFailed` if signing fails
pub fn handle_sign_personal_message(
    app: &mut sdk::App,
    path: &Bip32Path,
    message: &[u8],
) -> Result<Response, Error> {
    // Validate path
    if path.len() > MAX_BIP32_PATH_DEPTH {
        return Err(Error::InvalidDerivationPath);
    }

    if !path.is_valid_ethereum_path() {
        return Err(Error::InvalidDerivationPath);
    }

    // Validate message size
    if message.is_empty() || message.len() > MAX_MESSAGE_SIZE {
        return Err(Error::InvalidMessage);
    }

    // Build EIP-191 prefixed message
    let prefixed_message = build_eip191_message(message);

    // Hash the prefixed message
    let msg_hash = keccak256(&prefixed_message);

    // Display message for user confirmation
    if !display_personal_message(app, message) {
        return Err(Error::RejectedByUser);
    }

    // Derive key and sign
    let signature = sign_hash(path, &msg_hash)?;

    Ok(Response::Signature(signature))
}

/// Builds an EIP-191 prefixed message.
///
/// Format: "\x19Ethereum Signed Message:\n{len}{message}"
fn build_eip191_message(message: &[u8]) -> Vec<u8> {
    let len_str = alloc::format!("{}", message.len());
    let mut prefixed = Vec::with_capacity(EIP191_PREFIX.len() + len_str.len() + message.len());
    prefixed.extend_from_slice(EIP191_PREFIX);
    prefixed.extend_from_slice(len_str.as_bytes());
    prefixed.extend_from_slice(message);
    prefixed
}

/// Displays a personal message for user confirmation.
///
/// # Display rules
/// - Printable ASCII: show as text
/// - Non-printable: show as hex with warning
/// - Long messages: truncate with "..."
#[cfg(not(any(test, feature = "autoapprove")))]
fn display_personal_message(app: &mut sdk::App, message: &[u8]) -> bool {
    use alloc::vec;
    use sdk::ux::{Icon, TagValue};

    let (message_display, is_hex) = if is_printable_ascii(message) {
        // Display as text
        let text = core::str::from_utf8(message).unwrap_or("<invalid UTF-8>");
        (truncate_for_display(text, 200), false)
    } else {
        // Display as hex
        let hex = hex::encode(message);
        (truncate_for_display(&hex, 200), true)
    };

    let intro_text = if is_hex {
        "Sign message\n(hex data)"
    } else {
        "Sign message"
    };

    let approved = app.review_pairs(
        intro_text,
        "",
        &vec![
            TagValue {
                tag: "Message".into(),
                value: message_display,
            },
            TagValue {
                tag: "Length".into(),
                value: alloc::format!("{} bytes", message.len()),
            },
        ],
        "Sign message",
        "Confirm",
        false,
    );

    if approved {
        app.show_info(Icon::Success, "Message signed");
    } else {
        app.show_info(Icon::Failure, "Signature rejected");
    }

    approved
}

#[cfg(any(test, feature = "autoapprove"))]
fn display_personal_message(_app: &mut sdk::App, _message: &[u8]) -> bool {
    true
}

/// Signs a 32-byte hash with the key derived from the given path.
///
/// # Security
///
/// - Uses SDK's side-channel protected ECDSA
/// - Signature is low-S normalized (handled by SDK)
/// - v value is 27 or 28 (legacy format for messages)
fn sign_hash(path: &Bip32Path, hash: &[u8; 32]) -> Result<Signature, Error> {
    // Derive key using SDK ECALL
    let hd_node =
        Secp256k1::derive_hd_node(path.as_slice()).map_err(|_| Error::KeyDerivationFailed)?;

    let privkey = EcfpPrivateKey::<Secp256k1, 32>::new(*hd_node.privkey);

    // Use recoverable signing to get the recovery ID directly from the ECALL
    let (der_sig, recovery_id) = privkey
        .ecdsa_sign_hash_recoverable(hash)
        .map_err(|_| Error::SigningFailed)?;

    // Parse DER signature into (r, s)
    let (r, s) = parse_der_signature(&der_sig)?;

    // v = 27 + recovery_id for personal messages (legacy format)
    let v = 27u8 + recovery_id;

    Ok(Signature { v, r, s })
}

/// Parses a DER-encoded ECDSA signature into (r, s) components.
///
/// DER format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
fn parse_der_signature(der: &[u8]) -> Result<([u8; 32], [u8; 32]), Error> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err(Error::SigningFailed);
    }

    let mut pos = 2; // Skip 0x30 and length byte

    // Parse R
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

    // Parse S
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

    // Convert to 32-byte arrays (right-aligned, zero-padded)
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];

    // Handle potential leading zero byte in DER encoding
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
    fn test_build_eip191_message() {
        let message = b"Hello, World!";
        let prefixed = build_eip191_message(message);

        let expected_prefix = b"\x19Ethereum Signed Message:\n13";
        assert!(prefixed.starts_with(expected_prefix));
        assert!(prefixed.ends_with(b"Hello, World!"));
    }

    #[test]
    fn test_build_eip191_message_empty() {
        // Empty message should still work
        let prefixed = build_eip191_message(b"");
        let expected = b"\x19Ethereum Signed Message:\n0";
        assert_eq!(&prefixed[..], expected);
    }

    #[test]
    fn test_sign_personal_message_invalid_path() {
        let mut app = sdk::App::singleton();

        // Path too long
        let long_path = Bip32Path::from_slice(&[0u32; 15]);
        let result = handle_sign_personal_message(&mut app, &long_path, b"test");
        assert!(matches!(result, Err(Error::InvalidDerivationPath)));
    }

    #[test]
    fn test_sign_personal_message_empty_message() {
        let mut app = sdk::App::singleton();
        let path = Bip32Path::from_slice(&[0x8000002C, 0x8000003C, 0x80000000, 0, 0]);

        let result = handle_sign_personal_message(&mut app, &path, &[]);
        assert!(matches!(result, Err(Error::InvalidMessage)));
    }
}
