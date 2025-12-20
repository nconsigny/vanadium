//! Common types and definitions for the Ethereum V-App.
//!
//! This crate provides shared types used by both the V-App (riscv/no_std)
//! and the client (native/std). All types are designed to be serializable
//! with postcard for wire protocol communication.
//!
//! # Security Note
//!
//! This crate is part of the trust boundary. Types defined here are used
//! for parsing untrusted input from the host. All validation must happen
//! in the V-App after deserialization.

#![no_std]

extern crate alloc;

pub mod commands;
pub mod error;
pub mod message;
pub mod types;

pub use commands::Command;
pub use error::Error;
