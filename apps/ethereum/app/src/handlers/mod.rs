//! Command handlers for the Ethereum V-App.
//!
//! Each handler implements a specific command from the wire protocol.
//! All handlers must:
//! 1. Validate input parameters
//! 2. Enforce security invariants
//! 3. Return appropriate errors on failure
//! 4. Never sign ambiguous data
//!
//! # Docs consulted
//!
//! - docs/security.md: Memory access pattern leakage
//! - docs/ecalls.md: ECALL interface for crypto
//! - apps/bitcoin: Handler pattern

mod config;
mod metadata;
mod sign_eip712;
mod sign_message;
mod sign_tx;

pub use config::{handle_get_app_configuration, handle_get_challenge};
pub use metadata::{
    handle_by_contract_address_and_chain, handle_load_contract_method_info,
    handle_provide_domain_name, handle_provide_erc20_token_info, handle_provide_nft_info,
};
pub use sign_eip712::{handle_sign_eip712_hashed, handle_sign_eip712_message};
pub use sign_message::handle_sign_personal_message;
pub use sign_tx::{handle_clear_sign_transaction, handle_sign_transaction};
