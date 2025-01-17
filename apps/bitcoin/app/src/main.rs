#![feature(start)]
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use alloc::borrow::Cow;

#[cfg(target_arch = "riscv32")]
use sdk::fatal;

extern crate alloc;
extern crate quick_protobuf;

mod accounts;
mod constants;
mod handlers;
mod merkle;
mod script;
mod taproot;

use handlers::*;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use common::message::{
    mod_Request::OneOfrequest, mod_Response::OneOfresponse, Request, Response, ResponseError,
};
use quick_protobuf::{BytesReader, BytesWriter, MessageRead, MessageWrite, Writer};

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
pub fn _start(_argc: isize, _argv: *const *const u8) -> isize {
    main(_argc, _argv)
}

fn handle_req_<'a>(buffer: &'a [u8]) -> Result<Response<'a>, &'static str> {
    let mut reader = BytesReader::from_bytes(buffer);
    let request: Request =
        Request::from_reader(&mut reader, buffer).map_err(|_| "Failed to parse request")?; // TODO: proper error handling

    let response = match request.request {
        OneOfrequest::get_version(_) => OneOfresponse::get_version(todo!()),
        OneOfrequest::exit(_) => {
            sdk::exit(0);
        }
        OneOfrequest::get_master_fingerprint(_) => {
            OneOfresponse::get_master_fingerprint(handle_get_master_fingerprint()?)
        }
        OneOfrequest::get_extended_pubkey(req) => {
            OneOfresponse::get_extended_pubkey(handle_get_extended_pubkey(&req)?)
        }
        OneOfrequest::register_account(_req) => OneOfresponse::register_account(todo!()),
        OneOfrequest::get_address(req) => OneOfresponse::get_address(handle_get_address(&req)?),
        OneOfrequest::sign_psbt(_req) => OneOfresponse::sign_psbt(todo!()),
        OneOfrequest::None => OneOfresponse::error(ResponseError {
            error_msg: Cow::Borrowed("Invalid command"),
        }),
    };

    Ok(Response { response })
}

fn handle_req(buffer: &[u8]) -> Vec<u8> {
    let error_msg: String;

    let response = match handle_req_(buffer) {
        Ok(response) => response,
        Err(error) => {
            error_msg = error.to_string();
            Response {
                response: OneOfresponse::error(ResponseError {
                    error_msg: Cow::Borrowed(&error_msg),
                }),
            }
        }
    };

    let mut out = vec![0; response.get_size()];
    let mut writer = Writer::new(BytesWriter::new(&mut out));
    response.write_message(&mut writer).unwrap();

    out.to_vec()
}

#[start]
pub fn main(_: isize, _: *const *const u8) -> isize {
    sdk::rust_init_heap();

    sdk::ux::ux_idle();
    loop {
        let req = match sdk::comm::receive_message() {
            Ok(req) => req,
            Err(e) => {
                let error_string = e.to_string();
                let r = Response {
                    response: OneOfresponse::error(ResponseError {
                        error_msg: Cow::Borrowed(&error_string),
                    }),
                };
                let mut out = vec![0; r.get_size()];
                let mut writer = Writer::new(BytesWriter::new(&mut out));
                r.write_message(&mut writer).unwrap();

                out.to_vec()
            }
        };
        let result = handle_req(&req);
        sdk::comm::send_message(&result);
    }
}
