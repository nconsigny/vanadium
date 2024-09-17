use core::arch::asm;

use crate::ecalls::EcallsInterface;
use common::ecall_constants::*;

macro_rules! ecall0v {
    // ECALL with no arguments and no return value
    ($fn_name:ident, $syscall_number:expr) => {
        fn $fn_name() {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                );
            }
        }
    };
}
macro_rules! ecall0 {
    // ECALL with no arguments and returning a value
    ($fn_name:ident, $syscall_number:expr, $ret_type:ty) => {
        fn $fn_name() -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}
macro_rules! ecall1v {
    // ECALL with 1 argument and no return value
    ($fn_name:ident, $syscall_number:expr, ($arg1:ident: $arg1_type:ty)) => {
        fn $fn_name($arg1: $arg1_type) {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1             // First argument in a0
                );
            }
        }
    };
}
macro_rules! ecall1 {
    // ECALL with 1 argument and returning a value
    ($fn_name:ident, $syscall_number:expr, ($arg1:ident: $arg1_type:ty), $ret_type:ty) => {
        fn $fn_name($arg1: $arg1_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}
macro_rules! ecall2v {
    // ECALL with 2 arguments and no return value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty)) => {
        fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type) {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2             // Second argument in a1
                );
            }
        }
    };
}
macro_rules! ecall2 {
    // ECALL with 2 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty), $ret_type:ty) => {
        fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}
macro_rules! ecall3v {
    // ECALL with 3 arguments and no return value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty)) => {
        fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type) {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3             // Third argument in a2
                );
            }
        }
    };
}
macro_rules! ecall3 {
    // ECALL with 3 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty), $ret_type:ty) => {
        fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}

pub struct Ecall;

impl EcallsInterface for Ecall {
    ecall0v!(ux_idle, ECALL_UX_IDLE);

    fn exit(status: i32) -> ! {
        unsafe {
            asm!(
                "ecall",
                in("t0") ECALL_EXIT,
                in("a0") status,
                options(noreturn)
            );
        }
    }

    // fatal() and exit() are diverging, therefore we can't use the macro
    fn fatal(msg: *const u8, size: usize) -> ! {
        unsafe {
            asm!(
                "ecall",
                in("t0") ECALL_FATAL,
                in("a0") msg,
                in("a1") size,
                options(noreturn)
            );
        }
    }

    ecall2v!(xsend, ECALL_XSEND, (buffer: *const u8), (size: usize));
    ecall2!(xrecv, ECALL_XRECV, (buffer: *mut u8), (size: usize), usize);
}
