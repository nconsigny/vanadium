//! Ethereum V-App Client Library.
//!
//! This library provides a high-level interface for communicating with
//! the Ethereum V-App running in the Vanadium VM.
//!
//! # Example
//!
//! ```no_run
//! use vnd_ethereum_client::EthereumClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create client connected to native app
//!     let mut client = EthereumClient::new(transport).await;
//!
//!     // Get app configuration
//!     let config = client.get_app_configuration().await.unwrap();
//!     println!("Version: {}.{}.{}", config.version_major, config.version_minor, config.version_patch);
//! }
//! ```

mod client;

pub use client::{EthereumClient, EthereumClientError};
