#![feature(asm_const)]

#![cfg_attr(target_arch = "riscv32", no_main, no_std)]

pub mod ux;

mod ecalls;
mod ecall_constants;

#[cfg(target_arch = "riscv32")]
mod ecalls_riscv;

#[cfg(not(target_arch = "riscv32"))]
mod ecalls_native;

use embedded_alloc::Heap;

#[cfg(not(target_arch = "riscv32"))]
use ctor;

const HEAP_SIZE: usize = 65536;
static mut HEAP_ALLOC: [u8; HEAP_SIZE] = [0; HEAP_SIZE];


#[global_allocator]
static HEAP: Heap = Heap::empty();

fn init_heap() {
    unsafe {
        HEAP.init(HEAP_ALLOC.as_ptr() as usize, HEAP_SIZE);
    }
}

// On native targets, we use the ctor crate to call the initializer automatically at startup
#[cfg(not(target_arch = "riscv32"))]
#[ctor::ctor]
fn init_head_wrapper() {
    init_heap();
}

// embedded-alloc requires an implementation of critical_section::Impl
use critical_section::RawRestoreState;

struct CriticalSection;
critical_section::set_impl!(CriticalSection);

/// Default empty implementation as we don't have concurrency.
unsafe impl critical_section::Impl for CriticalSection {
    unsafe fn acquire() -> RawRestoreState {}
    unsafe fn release(_restore_state: RawRestoreState) {}
}

// Allocator initialization for riscv32 targets
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub extern "C" fn rust_init_heap() {
    init_heap();
}

// On native targets, the initializer is called automatically using ctor above
#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn rust_init_heap() {
    // the initializer is called automatically on native targets
}

pub fn fatal(msg: &str) {
    // TODO: placeholder
    let _ = msg;
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
