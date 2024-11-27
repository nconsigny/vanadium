#![feature(start)]
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(target_arch = "riscv32")]
use sdk::fatal;

use sdk::hash::Hasher;

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use common::{Command, HashId};

// Temporary to force the creation of a data section
#[used]
#[no_mangle]
pub static mut APP_NAME: [u8; 32] = *b"Sadik\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

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

    sdk::ux::ux_idle();
    loop {
        let msg = match sdk::comm::receive_message() {
            Ok(msg) => msg,
            Err(e) => {
                let error_string = e.to_string();
                panic!("Error receiving message: {}", error_string);
            }
        };

        let command: Command = postcard::from_bytes(&msg).expect("Deserialization failed");

        let response: Vec<u8> = match command {
            Command::Hash { hash_id, msg } => {
                let hash_id = HashId::try_from(hash_id).expect("Invalid hash ID");
                match hash_id {
                    HashId::Ripemd160 => {
                        let mut digest: [u8; 20] = [0u8; 20];
                        let mut hasher = sdk::hash::Ripemd160::new();
                        hasher.update(&msg);
                        hasher.digest(&mut digest);
                        digest.to_vec()
                    }
                    HashId::Sha256 => {
                        let mut hasher = sdk::hash::Sha256::new();
                        hasher.update(&msg);
                        let mut digest = [0u8; 32];
                        hasher.digest(&mut digest);
                        digest.to_vec()
                    }
                    HashId::Sha512 => {
                        let mut hasher = sdk::hash::Sha512::new();
                        hasher.update(&msg);
                        let mut digest = [0u8; 64];
                        hasher.digest(&mut digest);
                        digest.to_vec()
                    }
                }
            }
        };

        sdk::comm::send_message(&response);
    }
}
