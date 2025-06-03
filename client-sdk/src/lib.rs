mod apdu;
mod hash;

pub mod elf;
pub mod memory;

#[cfg(feature = "transport")]
pub mod comm;
#[cfg(feature = "transport")]
pub mod transport;
#[cfg(feature = "transport")]
pub mod vanadium_client;

pub use common::manifest;

// re-export if using the cargo_toml feature
#[cfg(feature = "cargo_toml")]
pub use cargo_toml;
