#![feature(start)]
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(target_arch = "riscv32")]
use sdk::fatal;

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
    // TODO: implement a main boilerplate
    loop {}
}
