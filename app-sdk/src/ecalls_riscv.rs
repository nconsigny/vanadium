use core::arch::asm;

use crate::ecall_constants::*;

pub fn ecall_ux_idle() {
    unsafe {
        asm!(
            "li a7, {0}",
            "ecall",
            const ECALL_UX_IDLE
        );
    }
}
