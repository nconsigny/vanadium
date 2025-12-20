//! Ethereum V-App for Vanadium.
//!
//! This V-App provides secure transaction and message signing for Ethereum
//! and EVM-compatible chains within the Vanadium VM on Ledger Secure Elements.
//!
//! # Security Model
//!
//! - Host is fully compromised; treat all input as adversarial
//! - All parsing and validation happens in V-App
//! - Cryptographic operations use SDK primitives (side-channel protected)
//! - User sees exactly what they sign on the secure display
//! - Fail closed on any ambiguity
//!
//! # Docs consulted
//!
//! - docs/security.md: Memory access pattern leakage, outsourced memory security
//! - docs/ecalls.md: ECALL interface for crypto operations
//! - apps/bitcoin/app/src/main.rs: V-App structure pattern

#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;

mod handlers;
mod parsing;
mod state;
mod utils;

use alloc::vec::Vec;

use common::error::Error;
use common::message::{Request, Response};
use sdk::{App, AppBuilder};

// Bootstrap the V-App entry point
sdk::bootstrap!();

/// Handle a single request from the client.
///
/// # Security
///
/// This function is the main dispatch point for all client requests.
/// Each handler must:
/// 1. Validate all input parameters
/// 2. Maintain state machine invariants
/// 3. Return appropriate error on any validation failure
fn handle_request(app: &mut App, request: &Request) -> Result<Response, Error> {
    match request {
        // Configuration commands
        Request::GetAppConfiguration => handlers::handle_get_app_configuration(),
        Request::GetChallenge => handlers::handle_get_challenge(),
        Request::Exit => sdk::exit(0),

        // Transaction signing
        Request::SignTransaction { path, tx_data } => {
            handlers::handle_sign_transaction(app, path, tx_data)
        }
        Request::ClearSignTransaction {
            path,
            tx_data,
            context,
        } => handlers::handle_clear_sign_transaction(app, path, tx_data, context),

        // Message signing
        Request::SignPersonalMessage { path, message } => {
            handlers::handle_sign_personal_message(app, path, message)
        }
        Request::SignEip712Hashed {
            path,
            domain_hash,
            message_hash,
        } => handlers::handle_sign_eip712_hashed(app, path, domain_hash, message_hash),
        Request::SignEip712Message { path, typed_data } => {
            handlers::handle_sign_eip712_message(app, path, typed_data)
        }

        // Metadata provision
        Request::ProvideErc20TokenInfo { info, signature } => {
            handlers::handle_provide_erc20_token_info(info, signature)
        }
        Request::ProvideNftInfo { info, signature } => {
            handlers::handle_provide_nft_info(info, signature)
        }
        Request::ProvideDomainName { info, signature } => {
            handlers::handle_provide_domain_name(info, signature)
        }
        Request::LoadContractMethodInfo { info, signature } => {
            handlers::handle_load_contract_method_info(info, signature)
        }
        Request::ByContractAddressAndChain { chain_id, address } => {
            handlers::handle_by_contract_address_and_chain(*chain_id, address)
        }

        // Eth2 staking (not implemented in minimal version)
        Request::Eth2GetPublicKey { .. } => Err(Error::UnsupportedOperation),
        Request::Eth2SetWithdrawalIndex { .. } => Err(Error::UnsupportedOperation),
    }
}

/// Process a raw message from the client.
///
/// # Security
///
/// This function handles postcard deserialization of untrusted input.
/// On any deserialization failure, it returns an InvalidData error.
fn process_message(app: &mut App, request: &[u8]) -> Vec<u8> {
    // Deserialize the request; fail closed on any error
    let Ok(request) = postcard::from_bytes(request) else {
        return postcard::to_allocvec(&Response::Error(Error::InvalidData))
            .unwrap_or_else(|_| Vec::new());
    };

    // Handle the request
    let response = handle_request(app, &request).unwrap_or_else(Response::error);

    // Serialize the response
    postcard::to_allocvec(&response).unwrap_or_else(|_| {
        // If serialization fails, return a minimal error
        postcard::to_allocvec(&Response::Error(Error::InternalError)).unwrap_or_else(|_| Vec::new())
    })
}

/// V-App entry point.
pub fn main() {
    AppBuilder::new("Ethereum", env!("CARGO_PKG_VERSION"), process_message)
        .description("Ethereum signing app")
        .developer("Ledger")
        .run();
}
