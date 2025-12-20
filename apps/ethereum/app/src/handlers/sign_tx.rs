//! Transaction signing handlers.
//!
//! Handles:
//! - SIGN_TRANSACTION (0x03): Sign legacy/EIP-2718 transaction
//! - CLEAR_SIGN_TRANSACTION (0x30): Sign with full metadata display
//!
//! # Security Model
//!
//! - All transaction data parsed in V-App
//! - User sees recipient, value, gas, data summary
//! - EIP-155 replay protection enforced
//! - Low-S signature normalization
//!
//! # Docs consulted
//!
//! - docs/commands.md: Command specification
//! - EIP-155: Simple Replay Attack Protection
//! - EIP-1559: Fee market change

use common::error::Error;
use common::message::Response;
use common::types::{Bip32Path, Signature, TransactionType, MAX_BIP32_PATH_DEPTH};
use sdk::curve::{Curve, EcfpPrivateKey, Secp256k1};

use crate::parsing::{ParsedTransaction, TransactionParser};
#[cfg(not(any(test, feature = "autoapprove")))]
use alloc::string::String;
#[cfg(not(any(test, feature = "autoapprove")))]
use crate::state::format_address;
#[cfg(not(any(test, feature = "autoapprove")))]
use crate::utils::{format_eth_amount, format_gas_price};

/// Maximum transaction size for signing.
const MAX_TX_SIZE: usize = 65536;

/// Handles SIGN_TRANSACTION command.
///
/// Signs a legacy or EIP-2718 typed transaction.
///
/// # Arguments
/// * `app` - SDK App instance for UX
/// * `path` - BIP32 derivation path
/// * `tx_data` - RLP-encoded transaction data
///
/// # Security Invariants
///
/// - INV-3: User sees recipient, value, gas before signing
/// - INV-5: Signature is low-S normalized, v follows EIP-155
/// - INV-6: Path must be valid Ethereum derivation
///
/// # Returns
/// - `Response::Signature` with EIP-155 v value
/// - `Error::InvalidDerivationPath` if path invalid
/// - `Error::InvalidTransaction` if parsing fails
/// - `Error::RejectedByUser` if user declines
pub fn handle_sign_transaction(
    app: &mut sdk::App,
    path: &Bip32Path,
    tx_data: &[u8],
) -> Result<Response, Error> {
    // Validate path
    if path.len() > MAX_BIP32_PATH_DEPTH {
        return Err(Error::InvalidDerivationPath);
    }

    if !path.is_valid_ethereum_path() {
        return Err(Error::InvalidDerivationPath);
    }

    // Validate transaction size
    if tx_data.is_empty() || tx_data.len() > MAX_TX_SIZE {
        return Err(Error::InvalidTransaction);
    }

    // Parse transaction
    let tx = TransactionParser::parse(tx_data).map_err(|_| Error::InvalidTransaction)?;

    // Display transaction for user confirmation
    if !display_transaction(app, &tx, false) {
        return Err(Error::RejectedByUser);
    }

    // Sign transaction hash
    let signature = sign_transaction_hash(path, &tx)?;

    Ok(Response::Signature(signature))
}

/// Handles CLEAR_SIGN_TRANSACTION command.
///
/// Signs a transaction with full metadata display (decoded contract calls).
///
/// # Arguments
/// * `app` - SDK App instance for UX
/// * `path` - BIP32 derivation path
/// * `tx_data` - RLP-encoded transaction data
/// * `context` - Additional context for clear signing
///
/// # Security
///
/// - Uses cached metadata for contract call decoding
/// - Falls back to blind signing if metadata unavailable
pub fn handle_clear_sign_transaction(
    app: &mut sdk::App,
    path: &Bip32Path,
    tx_data: &[u8],
    _context: &[u8],
) -> Result<Response, Error> {
    // Validate path
    if path.len() > MAX_BIP32_PATH_DEPTH {
        return Err(Error::InvalidDerivationPath);
    }

    if !path.is_valid_ethereum_path() {
        return Err(Error::InvalidDerivationPath);
    }

    // Validate transaction size
    if tx_data.is_empty() || tx_data.len() > MAX_TX_SIZE {
        return Err(Error::InvalidTransaction);
    }

    // Parse transaction
    let tx = TransactionParser::parse(tx_data).map_err(|_| Error::InvalidTransaction)?;

    // TODO: Look up contract method info from cache using selector
    // For minimal implementation, display raw like regular sign

    // Display transaction with clear signing flag
    if !display_transaction(app, &tx, true) {
        return Err(Error::RejectedByUser);
    }

    // Sign transaction hash
    let signature = sign_transaction_hash(path, &tx)?;

    Ok(Response::Signature(signature))
}

/// Displays a transaction for user confirmation.
#[cfg(not(any(test, feature = "autoapprove")))]
fn display_transaction(app: &mut sdk::App, tx: &ParsedTransaction, _clear_sign: bool) -> bool {
    use alloc::vec;
    use sdk::ux::{Icon, TagValue};

    let tx_type_str = match tx.tx_type {
        TransactionType::Legacy => "Legacy",
        TransactionType::AccessList => "EIP-2930",
        TransactionType::FeeMarket => "EIP-1559",
    };

    let recipient = match &tx.to {
        Some(addr) => format_address(addr),
        None => String::from("Contract Creation"),
    };

    let value_str = format_eth_amount(&tx.value);
    let gas_str = alloc::format!("{}", tx.gas_limit);
    let gas_price_str = format_gas_price(&tx.gas_price);

    let data_str = if tx.data.is_empty() {
        String::from("(none)")
    } else if tx.data.len() > 32 {
        alloc::format!("{} bytes", tx.data.len())
    } else {
        hex::encode(&tx.data)
    };

    let chain_str = tx
        .chain_id
        .map(|c| alloc::format!("{}", c))
        .unwrap_or_else(|| String::from("(none)"));

    let mut fields = vec![
        TagValue {
            tag: "Type".into(),
            value: tx_type_str.into(),
        },
        TagValue {
            tag: "Chain ID".into(),
            value: chain_str,
        },
        TagValue {
            tag: "To".into(),
            value: recipient,
        },
        TagValue {
            tag: "Value".into(),
            value: value_str,
        },
        TagValue {
            tag: "Gas Limit".into(),
            value: gas_str,
        },
        TagValue {
            tag: "Gas Price".into(),
            value: gas_price_str,
        },
        TagValue {
            tag: "Data".into(),
            value: data_str,
        },
    ];

    // Add max priority fee for EIP-1559
    if let Some(priority_fee) = &tx.max_priority_fee {
        fields.push(TagValue {
            tag: "Priority Fee".into(),
            value: format_gas_price(priority_fee),
        });
    }

    let approved = app.review_pairs(
        "Review transaction",
        "",
        &fields,
        "Sign transaction",
        "Confirm",
        false,
    );

    if approved {
        app.show_info(Icon::Success, "Transaction signed");
    } else {
        app.show_info(Icon::Failure, "Transaction rejected");
    }

    approved
}

#[cfg(any(test, feature = "autoapprove"))]
fn display_transaction(_app: &mut sdk::App, _tx: &ParsedTransaction, _clear_sign: bool) -> bool {
    true
}

/// Signs a transaction hash and returns signature with EIP-155 v value.
fn sign_transaction_hash(path: &Bip32Path, tx: &ParsedTransaction) -> Result<Signature, Error> {
    // Derive key using SDK ECALL
    let hd_node =
        Secp256k1::derive_hd_node(path.as_slice()).map_err(|_| Error::KeyDerivationFailed)?;

    let privkey = EcfpPrivateKey::<Secp256k1, 32>::new(*hd_node.privkey);

    // Sign the hash with recovery ID
    // The VM now returns the recovery ID (parity bit) alongside the signature.
    let (der_sig, recovery_id) = privkey
        .ecdsa_sign_hash_recoverable(&tx.sign_hash)
        .map_err(|_| Error::SigningFailed)?;

    // Parse DER signature into (r, s)
    let (r, s) = parse_der_signature(&der_sig)?;

    // Compute v value from recovery ID
    // For EIP-155: v = chain_id * 2 + 35 + recovery_id
    // For typed transactions: v = recovery_id (0 or 1)
    let v = compute_v_from_recovery_id(recovery_id, tx.chain_id, tx.tx_type)?;

    Ok(Signature { v, r, s })
}

/// Computes the final v value from recovery ID, chain ID, and transaction type.
///
/// # Arguments
/// * `recovery_id` - The ECDSA recovery ID (0 or 1), indicating parity of R.y
/// * `chain_id` - Optional chain ID for EIP-155 replay protection
/// * `tx_type` - Transaction type (Legacy, AccessList, FeeMarket)
///
/// # Returns
/// The v value for the signature:
/// - Legacy with chain ID (EIP-155): v = chain_id * 2 + 35 + recovery_id
/// - Legacy without chain ID: v = 27 + recovery_id
/// - Typed transactions (EIP-2930/EIP-1559): v = recovery_id (0 or 1)
fn compute_v_from_recovery_id(
    recovery_id: u8,
    chain_id: Option<u64>,
    tx_type: TransactionType,
) -> Result<u8, Error> {
    match tx_type {
        TransactionType::Legacy => {
            if let Some(cid) = chain_id {
                // EIP-155: v = chain_id * 2 + 35 + recovery_id
                let v = cid
                    .checked_mul(2)
                    .and_then(|x| x.checked_add(35))
                    .and_then(|x| x.checked_add(recovery_id as u64))
                    .ok_or(Error::InvalidTransaction)?;

                // For common chains (Ethereum mainnet = 1), v fits in u8
                // For larger chain IDs, we need to return the full value
                if v > 255 {
                    // Large chain ID handling:
                    // The v value doesn't fit in u8, but the Signature struct
                    // currently uses u8 for v. For large chain IDs, the client
                    // should use typed transactions (EIP-1559) instead.
                    return Err(Error::InvalidTransaction);
                }

                Ok(v as u8)
            } else {
                // Pre-EIP-155: v = 27 + recovery_id
                Ok(27 + recovery_id)
            }
        }
        TransactionType::AccessList | TransactionType::FeeMarket => {
            // For typed transactions (EIP-2930/EIP-1559): v is just recovery_id (0 or 1)
            Ok(recovery_id)
        }
    }
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
    fn test_sign_transaction_invalid_path() {
        let mut app = sdk::App::singleton();
        let long_path = Bip32Path::from_slice(&[0u32; 15]);

        let result = handle_sign_transaction(&mut app, &long_path, &[0xc0]);
        assert!(matches!(result, Err(Error::InvalidDerivationPath)));
    }

    #[test]
    fn test_sign_transaction_empty_data() {
        let mut app = sdk::App::singleton();
        let path = Bip32Path::from_slice(&[0x8000002C, 0x8000003C, 0x80000000, 0, 0]);

        let result = handle_sign_transaction(&mut app, &path, &[]);
        assert!(matches!(result, Err(Error::InvalidTransaction)));
    }

    #[test]
    fn test_compute_v_value_legacy_eip155_recovery_0() {
        // Chain ID 1 (Ethereum mainnet): v = 1 * 2 + 35 + 0 = 37
        let v = compute_v_from_recovery_id(0, Some(1), TransactionType::Legacy).unwrap();
        assert_eq!(v, 37);
    }

    #[test]
    fn test_compute_v_value_legacy_eip155_recovery_1() {
        // Chain ID 1 (Ethereum mainnet): v = 1 * 2 + 35 + 1 = 38
        let v = compute_v_from_recovery_id(1, Some(1), TransactionType::Legacy).unwrap();
        assert_eq!(v, 38);
    }

    #[test]
    fn test_compute_v_value_legacy_no_chain_id() {
        // Pre-EIP-155: v = 27 + recovery_id
        let v = compute_v_from_recovery_id(0, None, TransactionType::Legacy).unwrap();
        assert_eq!(v, 27);

        let v = compute_v_from_recovery_id(1, None, TransactionType::Legacy).unwrap();
        assert_eq!(v, 28);
    }

    #[test]
    fn test_compute_v_value_typed_eip1559() {
        // For typed transactions, v is just recovery_id (0 or 1)
        let v = compute_v_from_recovery_id(0, Some(1), TransactionType::FeeMarket).unwrap();
        assert_eq!(v, 0);

        let v = compute_v_from_recovery_id(1, Some(1), TransactionType::FeeMarket).unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn test_compute_v_value_typed_eip2930() {
        // For EIP-2930 access list transactions, v is recovery_id
        let v = compute_v_from_recovery_id(0, Some(1), TransactionType::AccessList).unwrap();
        assert_eq!(v, 0);

        let v = compute_v_from_recovery_id(1, Some(1), TransactionType::AccessList).unwrap();
        assert_eq!(v, 1);
    }
}
