#[cfg(target_arch = "riscv32")]
use crate::ecalls_riscv as ecalls_module;

#[cfg(not(target_arch = "riscv32"))]
use crate::ecalls_native as ecalls_module;

pub(crate) trait EcallsInterface {
    /// Shows the idle screen of the V-App
    fn ux_idle();

    /// Exits the V-App with the given status code
    fn exit(status: i32) -> !;

    /// Prints a fatal error message and exits the V-App
    fn fatal(msg: *const u8, size: usize) -> !;

    /// Sends a buffer to the host
    fn xsend(buffer: *const u8, size: usize);

    /// Receives a buffer of at most `max_size` bytes from the host
    fn xrecv(buffer: *mut u8, max_size: usize) -> usize;

    /// Computes the reminder of dividing `n` by `m`, storing the result in `r`.
    /// `r` and `n` are of length `len`; `m` is of length `len_m`.
    /// `len` must be at least as big as `len_m`.
    fn bn_modm(r: *mut u8, n: *const u8, len: usize, m: *const u8, len_m: usize) -> bool;

    /// Adds two big numbers `a` and `b` modulo `m`
    fn bn_addm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> bool;

    /// Subtracts two big numbers `a` and `b` modulo `m`
    fn bn_subm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> bool;

    /// Multiplies two big numbers `a` and `b` modulo `m`
    fn bn_multm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> bool;

    /// Computes `a` to the power of `e` modulo `m`
    fn bn_powm(
        r: *mut u8,
        a: *const u8,
        e: *const u8,
        len_e: usize,
        m: *const u8,
        len: usize,
    ) -> bool;
}

pub(crate) use ecalls_module::*;
