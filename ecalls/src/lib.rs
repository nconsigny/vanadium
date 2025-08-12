#![no_std]

// We make this module empty if not riscv32, otherwise rust-analyzer complains as it cannot
// compile RISC-V assembly on non-RISC-V targets.

#[cfg(target_arch = "riscv32")]
mod ecalls_impl;

#[cfg(target_arch = "riscv32")]
pub use ecalls_impl::*;
