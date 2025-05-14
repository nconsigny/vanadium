mod apdu;
pub mod comm;
pub mod elf;
pub mod transport;
pub mod vanadium_client;

pub use common::manifest;

// re-export if using the cargo_toml feature
#[cfg(feature = "cargo_toml")]
pub use cargo_toml;
