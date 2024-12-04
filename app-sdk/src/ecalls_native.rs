use std::io;
use std::io::Write;

use crate::ecalls::EcallsInterface;
use common::ecall_constants::MAX_BIGNUMBER_SIZE;
use num_bigint::BigUint;
use num_traits::Zero;

unsafe fn to_bigint(bytes: *const u8, len: usize) -> BigUint {
    let bytes = std::slice::from_raw_parts(bytes, len);
    BigUint::from_bytes_be(bytes)
}

unsafe fn copy_result(r: *mut u8, result_bytes: &[u8], len: usize) -> () {
    if result_bytes.len() < len {
        std::ptr::write_bytes(r, 0, len - result_bytes.len());
    }
    std::ptr::copy_nonoverlapping(
        result_bytes.as_ptr(),
        r.add(len - result_bytes.len()),
        result_bytes.len(),
    );
}

pub struct Ecall;

impl EcallsInterface for Ecall {
    fn ux_idle() {}

    fn exit(status: i32) -> ! {
        std::process::exit(status);
    }

    fn fatal(msg: *const u8, size: usize) -> ! {
        // print the message as a panic
        let slice = unsafe { std::slice::from_raw_parts(msg, size) };
        let msg = std::str::from_utf8(slice).unwrap();
        panic!("{}", msg);
    }

    fn xsend(buffer: *const u8, size: usize) {
        let slice = unsafe { std::slice::from_raw_parts(buffer, size) };
        for byte in slice {
            print!("{:02x}", byte);
        }
        print!("\n");
        io::stdout().flush().expect("Failed to flush stdout");
    }

    fn xrecv(buffer: *mut u8, max_size: usize) -> usize {
        // Request a hex string from the user; repeat until the input is valid
        // and at most max_size bytes long
        let (n_bytes_to_copy, bytes) = loop {
            let mut input = String::new();
            io::stdout().flush().expect("Failed to flush stdout");
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read line");

            let input = input.trim();

            let Ok(bytes) = hex::decode(input) else {
                println!(
                    "Input too large, max size is {} bytes, please try again.",
                    max_size
                );
                continue;
            };
            if bytes.len() <= max_size {
                break (bytes.len(), bytes);
            }
            println!("Input too large, please try again.");
        };

        // copy to the destination buffer
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, n_bytes_to_copy);
        }

        return n_bytes_to_copy;
    }

    fn bn_modm(r: *mut u8, n: *const u8, len: usize, m: *const u8, len_m: usize) -> u32 {
        if len > MAX_BIGNUMBER_SIZE || len_m > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        if len_m > len_m {
            return 0;
        }

        let n = unsafe { to_bigint(n, len) };
        let m = unsafe { to_bigint(m, len_m) };

        if m.is_zero() {
            return 0;
        }

        let result = n % &m;
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }

    fn bn_addm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
        if len > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        let a = unsafe { to_bigint(a, len) };
        let b = unsafe { to_bigint(b, len) };
        let m = unsafe { to_bigint(m, len) };

        if a >= m || b >= m {
            return 0;
        }

        if m.is_zero() {
            return 0;
        }

        let result = (a + b) % &m;
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }

    fn bn_subm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
        if len > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        let a = unsafe { to_bigint(a, len) };
        let b = unsafe { to_bigint(b, len) };
        let m = unsafe { to_bigint(m, len) };

        if a >= m || b >= m {
            return 0;
        }

        if m.is_zero() {
            return 0;
        }

        // the `+ &m` is to avoid negative numbers, since BigUints must be non-negative
        let result = ((a + &m) - b) % &m;
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }

    fn bn_multm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
        if len > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        let a = unsafe { to_bigint(a, len) };
        let b = unsafe { to_bigint(b, len) };
        let m = unsafe { to_bigint(m, len) };

        if a >= m || b >= m {
            return 0;
        }

        if m.is_zero() {
            return 0;
        }

        let result = (a * b) % &m;
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }

    fn bn_powm(
        r: *mut u8,
        a: *const u8,
        e: *const u8,
        len_e: usize,
        m: *const u8,
        len: usize,
    ) -> u32 {
        if len > MAX_BIGNUMBER_SIZE || len_e > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        let a = unsafe { to_bigint(a, len) };
        let e = unsafe { to_bigint(e, len_e) };
        let m = unsafe { to_bigint(m, len) };

        if a >= m {
            return 0;
        }

        if m.is_zero() {
            return 0;
        }

        let result = a.modpow(&e, &m);
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }
}
