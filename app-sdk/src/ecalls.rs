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
}

pub(crate) use ecalls_module::*;
