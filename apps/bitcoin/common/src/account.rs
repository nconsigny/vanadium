use alloc::string::{String, ToString};

pub use crate::bip388::{
    DescriptorTemplate, KeyInformation, KeyPlaceholder, TapTree, WalletPolicy,
};
use bitcoin::{params::Params, Address};

use crate::script::ToScript;

/// A generic trait for "accounts", parameterized by the type of coordinates.
///
/// Each implementer will define how to turn its coordinates into an address.
///
pub trait Account {
    type Coordinates;

    fn get_address(&self, coords: &Self::Coordinates) -> Result<String, &'static str>;
}

/// Coordinates for the `WalletPolicy` account type
#[derive(Debug, Clone, Copy)]
pub struct WalletPolicyCoordinates {
    pub is_change: bool,
    pub address_index: u32,
}

// Implement the generic trait for `WalletPolicy` with its corresponding coordinates.
impl Account for WalletPolicy {
    type Coordinates = WalletPolicyCoordinates;
    fn get_address(&self, coords: &WalletPolicyCoordinates) -> Result<String, &'static str> {
        let script = self
            .to_script(coords.is_change, coords.address_index)
            .map_err(|_| "Failed to derive script")?;
        Address::from_script(&script, Params::TESTNET4)
            .map(|address| address.to_string())
            .map_err(|_| "Failed to derive address")
    }
}
