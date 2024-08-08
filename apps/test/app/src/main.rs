#![feature(start)]
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(target_arch = "riscv32")]
use sdk::fatal;


// Temporary to force the creation of a data section
#[used]
#[no_mangle]
pub static mut APP_NAME: [u8; 32] = *b"Test\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";


#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    fatal("panic");
    loop {}
}

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub fn _start(_argc: isize, _argv: *const *const u8) -> isize {
    main(_argc, _argv)
}

#[start]
pub fn main(_: isize, _: *const *const u8) -> isize {
    // TODO: remove
    unsafe {
        core::ptr::read_volatile(&APP_NAME);
    }

    sdk::ux::ux_idle();
    loop {
        // let buffer = comm::receive_message().unwrap(); // TODO: what to do on error?

        // sdk::ux::app_loading_start("Handling request...\x00");

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
