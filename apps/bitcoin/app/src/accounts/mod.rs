use alloc::string::{String, ToString};

mod bip388;
mod conversions;

pub use bip388::{
    DescriptorTemplate, KeyInformation, KeyOrigin, KeyPlaceholder, TapTree, WalletPolicy,
};
use bitcoin::{params::Params, Address};

use crate::script::ToScript;

/// A generic trait for "accounts", parameterized by the type of coordinates.
///
/// Each implementer will define how to turn its coordinates into an address.
///
pub trait AccountType<C> {
    fn get_address(&self, coords: &C) -> Result<String, &'static str>;
}

#[derive(Debug, Clone)]
pub enum Account {
    WalletPolicy(WalletPolicy),
    // In the future, more account types will be here.
}

/// A single enum to hold all possible coordinate types.
/// Currently, there’s only `WalletPolicyCoordinates`.
#[derive(Debug, Clone, Copy)]
pub enum Coordinates {
    WalletPolicy(WalletPolicyCoordinates),
    // In the future, more coordinate types will be here.
}

/// Coordinates for the `WalletPolicy` account type
#[derive(Debug, Clone, Copy)]
pub struct WalletPolicyCoordinates {
    pub is_change: bool,
    pub address_index: u32,
}

// Implement the generic trait for `WalletPolicy` with its corresponding coordinates.
impl AccountType<WalletPolicyCoordinates> for WalletPolicy {
    fn get_address(&self, coords: &WalletPolicyCoordinates) -> Result<String, &'static str> {
        let script = self
            .to_script(coords.is_change, coords.address_index)
            .map_err(|_| "Failed to derive script")?;
        Address::from_script(&script, Params::TESTNET4)
            .map(|address| address.to_string())
            .map_err(|_| "Failed to derive address")
    }
}
