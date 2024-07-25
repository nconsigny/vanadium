
#[cfg(target_arch = "riscv32")]
use crate::ecalls_riscv as ecalls_module;

#[cfg(not(target_arch = "riscv32"))]
use crate::ecalls_native as ecalls_module;


pub use ecalls_module::*;