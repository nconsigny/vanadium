
use core::cell::RefCell;

use common::vm::{Cpu, MemorySegment, Page, PagedMemory};
use crate::{println, AppSW, Instruction};

use alloc::rc::Rc;
use ledger_device_sdk::io;

use common::manifest::Manifest;
use common::constants::PAGE_SIZE;
use common::client_commands::ClientCommandCode;

// TODO: temporary implementation that stores a single page, and without page integrity checks
struct OutsourcedMemory<'c> {
    comm: Rc<RefCell<&'c mut io::Comm>>,
    idx: Option<u32>,
    page: Page,
    is_readonly: bool
}

impl<'c> OutsourcedMemory<'c> {
    fn new(comm: Rc<RefCell<&'c mut io::Comm>>, is_readonly: bool) -> Self {
        Self {
            comm,
            idx: None,
            page: Page { data: [0; PAGE_SIZE] },
            is_readonly
        }
    }

    fn commit_page(&mut self) -> Result<(), &'static str> {
        let Some(idx) = self.idx else {
            panic!("No page to commit");
        };

        let mut comm = self.comm.borrow_mut();

        // First message: communicate the page to commit
        // TODO: should add a byte to identify in which segment does the page belong
        comm.append(&[ClientCommandCode::CommitPage as u8]);
        comm.append(&idx.to_be_bytes());
        comm.reply(AppSW::InterruptedExecution);

        let Instruction::Continue(p1, p2) = comm.next_command() else {
            return Err("INS not supported"); // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err("Wrong P1/P2");
        }

        // Second message  message: communicate the page content
        comm.append(&[ClientCommandCode::CommitPageContent as u8]);
        comm.append(&self.page.data);

        let Instruction::Continue(p1, p2) = comm.next_command() else {
            return Err("INS not supported"); // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err("Wrong P1/P2");
        }

        Ok(())
    }
}

impl<'c> PagedMemory for OutsourcedMemory<'c> {
    type PageRef<'a> = &'a mut Page where Self: 'a;

    fn get_page<'a>(&'a mut self, page_index: u32) -> Result<Self::PageRef<'a>, &'static str> {
        if let Some(idx) = &mut self.idx {
            if *idx == page_index {
                return Ok(&mut self.page);
            } else {
                if !self.is_readonly {
                    self.commit_page()?;
                }
            }
        }

        let mut comm = self.comm.borrow_mut();
        comm.append(&[ClientCommandCode::GetPage as u8]);
        comm.append(&page_index.to_be_bytes());
        comm.reply(AppSW::InterruptedExecution);

        let Instruction::Continue(p1, p2) = comm.next_command() else {
            return Err("INS not supported"); // expected "Continue"
        };

        if p2 != 0 {
            return Err("Wrong P2");
        }

        let fetched_data = comm.get_data().map_err(|_| "Wrong APDU length")?;
        if fetched_data.len() != PAGE_SIZE - 1 {
            return Err("Wrong APDU length");
        }
        // overwrite page content
        self.page.data[0..PAGE_SIZE - 1].copy_from_slice(fetched_data);
        self.page.data[PAGE_SIZE - 1] = p1;

        // update index
        self.idx = Some(page_index);

        Ok(&mut self.page)
    }
}


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
