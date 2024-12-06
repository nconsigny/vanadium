#[cfg(target_arch = "riscv32")]
use crate::ecalls_riscv as ecalls_module;

#[cfg(not(target_arch = "riscv32"))]
use crate::ecalls_native as ecalls_module;

/// Trait defining the interface for all the ecalls.
pub(crate) trait EcallsInterface {
    /// Displays the idle screen of the V-App.
    fn ux_idle();

    /// Exits the V-App with the specified status code.
    ///
    /// # Parameters
    /// - `status`: The exit status code.
    ///
    /// # Returns
    /// This function does not return.
    fn exit(status: i32) -> !;

    /// Prints a fatal error message and exits the V-App.
    ///
    /// # Parameters
    /// - `msg`: Pointer to the error message, that must be a valid UTF-8 string.
    /// - `size`: Size of the error message.
    ///
    /// # Returns
    /// This function does not return.
    fn fatal(msg: *const u8, size: usize) -> !;

    /// Sends a buffer to the host.
    ///
    /// # Parameters
    /// - `buffer`: Pointer to the buffer to send.
    /// - `size`: Size of the buffer.
    fn xsend(buffer: *const u8, size: usize);

    /// Receives a buffer from the host.
    ///
    /// # Parameters
    /// - `buffer`: Pointer to the buffer to store received data.
    /// - `max_size`: Maximum size of the buffer.
    ///
    /// # Returns
    /// The number of bytes received.
    fn xrecv(buffer: *mut u8, max_size: usize) -> usize;

    /// Computes the remainder of dividing `n` by `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `n`: Pointer to the dividend buffer.
    /// - `len`: Length of `r` and `n`.
    /// - `m`: Pointer to the divisor buffer.
    /// - `len_m`: Length of `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    fn bn_modm(r: *mut u8, n: *const u8, len: usize, m: *const u8, len_m: usize) -> u32;

    /// Adds two big numbers `a` and `b` modulo `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `a`: Pointer to the first addend buffer.
    /// - `b`: Pointer to the second addend buffer.
    /// - `m`: Pointer to the modulus buffer.
    /// - `len`: Length of `r`, `a`, `b`, and `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    fn bn_addm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32;

    /// Subtracts two big numbers `a` and `b` modulo `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `a`: Pointer to the minuend buffer.
    /// - `b`: Pointer to the subtrahend buffer.
    /// - `m`: Pointer to the modulus buffer.
    /// - `len`: Length of `r`, `a`, `b`, and `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    fn bn_subm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32;

    /// Multiplies two big numbers `a` and `b` modulo `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `a`: Pointer to the first factor buffer.
    /// - `b`: Pointer to the second factor buffer.
    /// - `m`: Pointer to the modulus buffer.
    /// - `len`: Length of `r`, `a`, `b`, and `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    fn bn_multm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32;

    /// Computes `a` to the power of `e` modulo `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `a`: Pointer to the base buffer.
    /// - `e`: Pointer to the exponent buffer.
    /// - `len_e`: Length of `e`.
    /// - `m`: Pointer to the modulus buffer.
    /// - `len`: Length of `r`, `a`, and `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    fn bn_powm(
        r: *mut u8,
        a: *const u8,
        e: *const u8,
        len_e: usize,
        m: *const u8,
        len: usize,
    ) -> u32;

    /// Derives a hierarchical deterministic (HD) node, made of the private key and the corresponding chain code.
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
    /// - `path`: Pointer to the derivation path array.
    /// - `path_len`: Length of the derivation path array.
    /// - `privkey`: Pointer to the buffer to store the derived private key.
    /// - `chain_code`: Pointer to the buffer to store the derived chain code.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Panics
    /// This function panics if the curve is not supported.
    fn derive_hd_node(
        curve: u32,
        path: *const u32,
        path_len: usize,
        privkey: *mut u8,
        chain_code: *mut u8,
    ) -> u32;

    /// Retrieves the fingerprint for master public key for the specified curve.
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
    ///
    /// # Returns
    /// The master fingerprint as a 32-bit unsigned integer, computed as the first 32 bits of `ripemd160(sha256(pk))`,
    /// where `pk` is the public key in compressed form.
    ///
    /// # Panics
    /// This function panics if the curve is not supported.
    fn get_master_fingerprint(curve: u32) -> u32;
}

pub(crate) use ecalls_module::*;
