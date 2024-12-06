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
macro_rules! ecall2v_pub {
    // ECALL with 2 arguments and no return value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty)) => {
        pub fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type) {
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
macro_rules! ecall3_pub {
    // ECALL with 3 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty), $ret_type:ty) => {
        pub fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type) -> $ret_type {
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

macro_rules! ecall4v {
    // ECALL with 4 arguments and no return value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty)) => {
        fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type) {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4             // Fourth argument in a3
                );
            }
        }
    };
}
macro_rules! ecall4 {
    // ECALL with 4 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty), $ret_type:ty) => {
        fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4,            // Fourth argument in a3
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}
macro_rules! ecall4_pub {
    // ECALL with 4 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty), $ret_type:ty) => {
        pub fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4,            // Fourth argument in a3
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}

macro_rules! ecall5 {
    // ECALL with 5 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty),
     ($arg5:ident: $arg5_type:ty), $ret_type:ty) => {
        fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type, $arg5: $arg5_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4,            // Third argument in a3
                    in("a4") $arg5,            // Third argument in a4
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}

macro_rules! ecall6 {
    // ECALL with 6 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty),
     ($arg5:ident: $arg5_type:ty),
     ($arg6:ident: $arg6_type:ty), $ret_type:ty) => {
        fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type, $arg5: $arg5_type, $arg6: $arg6_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4,            // Third argument in a3
                    in("a4") $arg5,            // Third argument in a4
                    in("a5") $arg6,            // Third argument in a5
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

    ecall5!(bn_modm, ECALL_MODM, (r: *mut u8), (n: *const u8), (len: usize), (m: *const u8), (len_m: usize), u32);
    ecall5!(bn_addm, ECALL_ADDM, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize), u32);
    ecall5!(bn_subm, ECALL_SUBM, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize), u32);
    ecall5!(bn_multm, ECALL_MULTM, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize), u32);
    ecall6!(bn_powm, ECALL_POWM, (r: *mut u8), (a: *const u8), (e: *const u8), (len_e: usize), (m: *const u8), (len: usize), u32);

    ecall5!(derive_hd_node, ECALL_DERIVE_HD_NODE, (curve: u32), (path: *const u32), (path_len: usize), (privkey: *mut u8), (chain_code: *mut u8), u32);
    ecall1!(get_master_fingerprint, ECALL_GET_MASTER_FINGERPRINT, (curve: u32), u32);
}

// The following ecalls are specific to this target
impl Ecall {
    ecall2v_pub!(hash_init, ECALL_HASH_INIT, (hash_id: u32), (ctx: *mut u8));
    ecall4_pub!(hash_update, ECALL_HASH_UPDATE, (hash_id: u32), (ctx: *mut u8), (data: *const u8), (len: usize), u32);
    ecall3_pub!(hash_final, ECALL_HASH_DIGEST, (hash_id: u32), (ctx: *mut u8), (digest: *const u8), u32);
}
