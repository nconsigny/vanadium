#![feature(start)]
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(target_arch = "riscv32")]
use sdk::fatal;

extern crate alloc;

mod commands;
mod handlers;

use commands::Command;
use handlers::*;

use alloc::vec;

// Temporary to force the creation of a data section
#[used]
#[no_mangle]
pub static mut APP_NAME: [u8; 32] = *b"Test\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn my_panic(info: &core::panic::PanicInfo) -> ! {
    let message = if let Some(location) = info.location() {
        alloc::format!(
            "Panic occurred in file '{}' at line {}: {}",
            location.file(),
            location.line(),
            info.message()
        )
    } else {
        alloc::format!("Panic occurred: {}", info.message())
    };
    fatal(&message); // does not return
}

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub fn _start(_argc: isize, _argv: *const *const u8) -> isize {
    main(_argc, _argv)
}

#[start]
pub fn main(_: isize, _: *const *const u8) -> isize {
    sdk::rust_init_heap();

    // TODO: remove
    unsafe {
        core::ptr::read_volatile(&APP_NAME);
    }

    // TODO: remove
    // test code to make sure that vector allocations are emitted
    let x = vec![1, 2, 3];
    unsafe {
        core::ptr::read_volatile(&x);
    }

    sdk::ux::ux_idle();
    loop {
        let msg = sdk::xrecv(256);
        // let buffer = comm::receive_message().unwrap(); // TODO: what to do on error?

        // sdk::ux::app_loading_start("Handling request...\x00");

        if msg.len() == 0 {
            sdk::exit(0);
        }

        let Ok(command) = Command::try_from(msg[0]) else {
            panic!("Unknown command");
        };

        let response = match command {
            Command::Reverse => {
                let mut data = msg[1..].to_vec();
                data.reverse();
                data
            }
            Command::AddNumbers => {
                // sum all the numbers from 0 to n
                if msg.len() != 5 {
                    panic!("Invalid input");
                }
                let n = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
                let mut result: u64 = 0;
                for i in 0..=n {
                    result += i as u64;
                }
                result.to_be_bytes().to_vec()
            }
            Command::Base58Encode => handle_base58_encode(&msg[1..]),
            Command::Sha256 => handle_sha256(&msg[1..]),
            Command::CountPrimes => handle_count_primes(&msg[1..]),
            Command::Panic => {
                let panic_msg = core::str::from_utf8(&msg[1..]).unwrap();
                panic!("{}", panic_msg);
            }
        };

        sdk::xsend(&response);
    }
}
