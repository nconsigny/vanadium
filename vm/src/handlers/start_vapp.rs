
use core::cell::RefCell;

use alloc::rc::Rc;
use ledger_device_sdk::io;

use common::manifest::Manifest;
use common::vm::{Cpu, MemorySegment};

use crate::{println, AppSW};
use super::lib::outsourced_mem::OutsourcedMemory;


pub fn handler_start_vapp(comm: &mut io::Comm) -> Result<(), AppSW> {
    let data_raw = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    let (manifest, hmac) = postcard::take_from_bytes::<Manifest>(data_raw)
        .map_err(|_| AppSW::IncorrectData)?;


    if hmac.len() != 32 {
        return Err(AppSW::IncorrectData);
    }

    // TODO: actually check the HMAC (and use a constant-time comparison)
    if hmac != [0x42u8; 32] {
        return Err(AppSW::SignatureFail);
    }
    
    println!("Running app with Manifest: {:?}", manifest);
    println!("hmac: {:?}", hmac);

    
    let comm = Rc::new(RefCell::new(comm));

    let code_seg = MemorySegment::<OutsourcedMemory>::new(
        manifest.code_start,
        manifest.code_end - manifest.code_start,
        OutsourcedMemory::new(comm.clone(), true)
    ).unwrap();

    let data_seg = MemorySegment::<OutsourcedMemory>::new(
        manifest.data_start,
        manifest.data_end - manifest.data_start,
        OutsourcedMemory::new(comm.clone(), false)
    ).unwrap();

    let stack_seg = MemorySegment::<OutsourcedMemory>::new(
        manifest.stack_start,
        manifest.stack_end - manifest.stack_start,
        OutsourcedMemory::new(comm.clone(), false)
    ).unwrap();

    let mut cpu = Cpu::new(
        manifest.entrypoint,
        code_seg,
        data_seg,
        stack_seg
    );
    
    // x2 is the stack pointer, that grows backwards from the end of the stack
    // we make sure it's aligned to a multiple of 4
    cpu.regs[2] = (manifest.stack_end - 4) & 0xfffffff0u32;

    assert!(cpu.pc % 4 == 0, "Unaligned entrypoint");

    loop {
        let instr = cpu.fetch_instruction();

        println!("{:08x?}: {:08x?}", cpu.pc, instr);

        cpu.execute(instr);
    }
}
