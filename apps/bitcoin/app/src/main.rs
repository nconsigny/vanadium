#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(target_arch = "riscv32")]
use sdk::fatal;

extern crate alloc;

mod constants;
mod handlers;
mod merkle;

use handlers::*;

use alloc::{boxed::Box, string::ToString};

use common::message::{Request, Response};

// Temporary to force the creation of a data section
#[used]
#[no_mangle]
pub static mut APP_NAME: [u8; 32] = *b"Bitcoin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

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
pub fn _start() {
    sdk::rust_init_heap();
    main()
}

fn handle_request(request: &Request) -> Result<Response, &'static str> {
    match request {
        Request::GetVersion => todo!(),
        Request::Exit => sdk::exit(0),
        Request::GetMasterFingerprint => handle_get_master_fingerprint(),
        Request::GetExtendedPubkey { path, display } => handle_get_extended_pubkey(path, *display),
        Request::RegisterAccount(_account) => todo!(),
        Request::GetAddress {
            name,
            account,
            hmac,
            coordinates,
            display,
        } => {
            // hmac should be empty or a 32 byte vector; if not, give an error, otherwise convert to Option<[u8; 32]>
            let hmac = match hmac.len() {
                0 => None,
                32 => Some(hmac.as_slice().try_into().unwrap()),
                _ => return Err("Invalid HMAC length"),
            };

            handle_get_address(name.as_deref(), account, hmac, coordinates, *display)
        }
        Request::SignPsbt { psbt: _ } => todo!(),
    }
}

fn process_message() -> Result<Response, Box<dyn core::error::Error>> {
    let req_msg = sdk::comm::receive_message()?;
    let request: Request = postcard::from_bytes(&req_msg)?;
    let response = handle_request(&request)?;
    Ok(response)
}

pub fn main() {
    sdk::ux::ux_idle();
    loop {
        let response = match process_message() {
            Ok(response) => response,
            Err(e) => Response::Error(e.to_string()),
        };
        let resp_msg = postcard::to_allocvec(&response).unwrap();
        sdk::comm::send_message(&resp_msg);
    }
}
