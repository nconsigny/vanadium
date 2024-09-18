#![feature(start)]
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(target_arch = "riscv32")]
use sdk::fatal;

extern crate alloc;

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
        if msg.len() == 1 {
            panic!("Oh no, how can I reverse a single byte?");
        }

        // reverse the message
        let mut reversed = msg.clone();
        reversed.reverse();
        sdk::xsend(&reversed);

        // let result = handle_req(&buffer, &mut state);

        // sdk::ux::app_loading_stop();
        // sdk::ux::ux_idle();

        // comm::send_message(&result).unwrap(); // TODO: what to do on error?
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
