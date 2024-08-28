use core::ops::{Deref, DerefMut};

use alloc::vec::Vec;
use crate::constants::PAGE_SIZE;

#[derive(Clone)]
pub struct Page { pub data: [u8; PAGE_SIZE] }

#[inline(always)]
fn page_start(address: u32) -> u32 {
    address & !((PAGE_SIZE as u32) - 1)
}

// A generic trait representing pages of memory
pub trait PagedMemory {
    type PageRef<'a>: Deref<Target = Page> + DerefMut<Target = Page> + 'a where Self: 'a;

    fn get_page<'a>(&'a mut self, page_index: u32) -> Result<Self::PageRef<'a>, &'static str>;
}

pub struct VecMemory {
    pages: Vec<Page>
}

impl PagedMemory for VecMemory {
    type PageRef<'a> = &'a mut Page where Self: 'a;

    fn get_page<'a>(&'a mut self, page_index: u32) -> Result<Self::PageRef<'a>, &'static str> {
        self.pages.get_mut(page_index as usize).ok_or("Page not found")
    }
}


impl VecMemory {
    pub fn new(n_pages: usize) -> VecMemory {
        let mut pages = Vec::with_capacity(n_pages);
        for _ in 0..n_pages {
            pages.push(Page { data: [0; PAGE_SIZE] });
        }
        VecMemory { pages }
    }
}


pub struct MemorySegment<M: PagedMemory> {
    start_address: u32,
    size: u32,
    paged_memory: M,
}

impl<M: PagedMemory> MemorySegment<M> {
    pub fn new(start_address: u32, size: u32, paged_memory: M) -> Result<Self, &'static str> {
        if start_address.checked_add(size).is_none() {
            return Err("start_address + size does not fit in a u32");
        }

        Ok(Self {
            start_address,
            size,
            paged_memory,
        })
    }

    #[inline]
    pub fn read_u8(&mut self, address: u32) -> Result<u8, &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 1 {
            return Err("Address out of bounds");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = (relative_address / (PAGE_SIZE as u32)) as u32;
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let page = self.paged_memory.get_page(page_index)?;

        Ok(page.data[offset])
    }

    #[inline]
    pub fn read_u16(&mut self, address: u32) -> Result<u16, &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 2 {
            return Err("Address out of bounds");
        }

        if address % 2 != 0 {
            return Err("Unaligned address");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = (relative_address / (PAGE_SIZE as u32)) as u32;
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let page = self.paged_memory.get_page(page_index)?;

        let value = u16::from_le_bytes([
            page.data[offset],
            page.data[offset + 1],
        ]);

        Ok(value)
    }

    #[inline]
    pub fn read_u32(&mut self, address: u32) -> Result<u32, &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 4 {
            return Err("Address out of bounds");
        }

        if address % 4 != 0 {
            return Err("Unaligned address");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = (relative_address / (PAGE_SIZE as u32)) as u32;
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let page = self.paged_memory.get_page(page_index)?;

        let value = u32::from_le_bytes([
            page.data[offset],
            page.data[offset + 1],
            page.data[offset + 2],
            page.data[offset + 3],
        ]);

        Ok(value)
    }

    #[inline]
    pub fn write_u8(&mut self, address: u32, value: u8) -> Result<(), &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 1 {
            return Err("Address out of bounds");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = (relative_address / (PAGE_SIZE as u32)) as u32;
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let mut page = self.paged_memory.get_page(page_index)?;

        page.data[offset] = value;

        Ok(())
    }

    #[inline]
    pub fn write_u16(&mut self, address: u32, value: u16) -> Result<(), &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 2 {
            return Err("Address out of bounds");
        }

        if address % 2 != 0 {
            return Err("Unaligned address");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = (relative_address / (PAGE_SIZE as u32)) as u32;
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let mut page = self.paged_memory.get_page(page_index)?;

        page.data[offset] = value as u8;
        page.data[offset + 1] = (value >> 8) as u8;

        Ok(())
    }

    #[inline]
    pub fn write_u32(&mut self, address: u32, value: u32) -> Result<(), &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 4 {
            return Err("Address out of bounds");
        }

        if address % 4 != 0 {
            return Err("Unaligned address");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = (relative_address / (PAGE_SIZE as u32)) as u32;
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let mut page = self.paged_memory.get_page(page_index)?;

        page.data[offset] = value as u8;
        page.data[offset + 1] = (value >> 8) as u8;
        page.data[offset + 2] = (value >> 16) as u8;
        page.data[offset + 3] = (value >> 24) as u8;

        Ok(())
    }
}


pub struct Cpu<M: PagedMemory> {
    pub pc: u32,
    pub regs: [u32; 32],
    pub code_seg: MemorySegment<M>,
    pub data_seg: MemorySegment<M>,
    pub stack_seg: MemorySegment<M>
}

impl<M: PagedMemory> Cpu<M> {
    pub fn new(entrypoint: u32, code_seg: MemorySegment<M>, data_seg: MemorySegment<M>, stack_seg: MemorySegment<M>) -> Cpu<M> {
        Cpu {
            pc: entrypoint,
            regs: [0; 32],
            code_seg,
            data_seg,
            stack_seg
        }
    }

    #[inline(always)]
    pub fn fetch_instruction(&mut self) -> u32 {
        if let Ok(inst) = self.code_seg.read_u32(self.pc) {
            inst
        } else {
            panic!("Failed to fetch page")
        }
    }

    #[inline(always)]
    pub fn execute(&mut self, inst: u32) {

        // TODO: for now, treat everything as a NOP
        // This is a placeholder for actual instruction decoding and execution logic
        // match inst {
        //     0x00 => self.regs[0] = 0, // Example: NOP
        //     _ => panic!("Unknown instruction"),
        // }

        self.pc += 4;
        self.regs[0] = 0;
    }
}
