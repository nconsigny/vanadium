#![feature(asm_const)]

#![cfg_attr(target_arch = "riscv32", no_main, no_std)]

pub mod ux;

mod ecalls;
mod ecall_constants;

#[cfg(target_arch = "riscv32")]
mod ecalls_riscv;

#[cfg(not(target_arch = "riscv32"))]
mod ecalls_native;


pub fn fatal(msg: &str) {
    // TODO: placeholder
    let _ = msg;
}

#[cfg(test)]
mod tests {
    
}
