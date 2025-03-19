use alloc::string::{String, ToString};

// re-export, as we use this both as a message and as an internal data type
pub use crate::message::WalletPolicyCoordinates;

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
