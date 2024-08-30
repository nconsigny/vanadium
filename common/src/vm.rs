//! This module provides traits to represent memory segments that are split into pages, and a
//! simple CPU model that can execute instructions from these memory segments.

use core::ops::{Deref, DerefMut};

use crate::constants::PAGE_SIZE;
use alloc::vec::Vec;

/// Represents a single page of memory.
#[derive(Clone, Debug)]
pub struct Page {
    pub data: [u8; PAGE_SIZE],
}

/// Calculates the start address of the page containing the given address.
#[inline(always)]
fn page_start(address: u32) -> u32 {
    address & !((PAGE_SIZE as u32) - 1)
}

/// A generic trait representing a memory that is split into pages.
/// This allows abstracting over different ways of storing pages.
pub trait PagedMemory {
    type PageRef<'a>: Deref<Target = Page> + DerefMut<Target = Page> + 'a
    where
        Self: 'a;

    /// Retrieves a mutable reference to the page at the given index.
    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, &'static str>;
}

/// A simple implementation of `PagedMemory` using a vector of pages.
#[derive(Clone, Debug)]
pub struct VecMemory {
    pages: Vec<Page>,
}

impl PagedMemory for VecMemory {
    type PageRef<'a> = &'a mut Page where Self: 'a;

    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, &'static str> {
        self.pages
            .get_mut(page_index as usize)
            .ok_or("Page not found")
    }
}

impl VecMemory {
    /// Creates a new `VecMemory` with the specified number of pages.
    pub fn new(n_pages: usize) -> VecMemory {
        let mut pages = Vec::with_capacity(n_pages);
        for _ in 0..n_pages {
            pages.push(Page {
                data: [0; PAGE_SIZE],
            });
        }
        VecMemory { pages }
    }
}

/// Represents a contiguous region of memory, implemented via a paged memory.
pub struct MemorySegment<M: PagedMemory> {
    start_address: u32,
    size: u32,
    paged_memory: M,
}

impl<M: PagedMemory> MemorySegment<M> {
    /// Creates a new `MemorySegment`.
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

    /// Reads a byte from the specified address.
    #[inline]
    pub fn read_u8(&mut self, address: u32) -> Result<u8, &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 1 {
            return Err("Address out of bounds");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let page = self.paged_memory.get_page(page_index)?;

        Ok(page.data[offset])
    }

    /// Reads a 16-bit value from the specified address.
    #[inline]
    pub fn read_u16(&mut self, address: u32) -> Result<u16, &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 2 {
            return Err("Address out of bounds");
        }

        if address % 2 != 0 {
            return Err("Unaligned address");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let page = self.paged_memory.get_page(page_index)?;

        let value = u16::from_le_bytes([page.data[offset], page.data[offset + 1]]);

        Ok(value)
    }

    /// Reads a 32-bit value from the specified address.
    #[inline]
    pub fn read_u32(&mut self, address: u32) -> Result<u32, &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 4 {
            return Err("Address out of bounds");
        }

        if address % 4 != 0 {
            return Err("Unaligned address");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
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

    /// Writes a byte to the specified address.
    #[inline]
    pub fn write_u8(&mut self, address: u32, value: u8) -> Result<(), &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 1 {
            return Err("Address out of bounds");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let mut page = self.paged_memory.get_page(page_index)?;

        page.data[offset] = value;

        Ok(())
    }

    /// Writes a 16-bit value to the specified address.
    #[inline]
    pub fn write_u16(&mut self, address: u32, value: u16) -> Result<(), &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 2 {
            return Err("Address out of bounds");
        }

        if address % 2 != 0 {
            return Err("Unaligned address");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let mut page = self.paged_memory.get_page(page_index)?;

        page.data[offset] = value as u8;
        page.data[offset + 1] = (value >> 8) as u8;

        Ok(())
    }

    /// Writes a 32-bit value to the specified address.
    #[inline]
    pub fn write_u32(&mut self, address: u32, value: u32) -> Result<(), &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 4 {
            return Err("Address out of bounds");
        }

        if address % 4 != 0 {
            return Err("Unaligned address");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let mut page = self.paged_memory.get_page(page_index)?;

        page.data[offset] = value as u8;
        page.data[offset + 1] = (value >> 8) as u8;
        page.data[offset + 2] = (value >> 16) as u8;
        page.data[offset + 3] = (value >> 24) as u8;

        Ok(())
    }
}

/// Represents the state of the Risc-V CPU, with registers and three memory segments
/// for code, data and stack.
pub struct Cpu<M: PagedMemory> {
    pub pc: u32,
    pub regs: [u32; 32],
    pub code_seg: MemorySegment<M>,
    pub data_seg: MemorySegment<M>,
    pub stack_seg: MemorySegment<M>,
}

impl<M: PagedMemory> Cpu<M> {
    /// Creates a new `Cpu` instance.
    pub fn new(
        entrypoint: u32,
        code_seg: MemorySegment<M>,
        data_seg: MemorySegment<M>,
        stack_seg: MemorySegment<M>,
    ) -> Cpu<M> {
        Cpu {
            pc: entrypoint,
            regs: [0; 32],
            code_seg,
            data_seg,
            stack_seg,
        }
    }

    #[inline(always)]
    /// Fetches the next instruction to be executed.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec_memory_new() {
        let n_pages = 5;
        let vec_memory = VecMemory::new(n_pages);

        assert_eq!(vec_memory.pages.len(), n_pages);
        for page in vec_memory.pages.iter() {
            assert_eq!(page.data, [0; PAGE_SIZE]);
        }
    }

    #[test]
    fn test_vec_memory_get_page() {
        let n_pages = 3;
        let mut vec_memory = VecMemory::new(n_pages);

        // Test valid page access
        for i in 0..n_pages {
            let page = vec_memory.get_page(i as u32).expect("Page should exist");
            assert_eq!(page.data, [0; PAGE_SIZE]);
        }

        // Test out-of-bounds page access
        assert!(vec_memory.get_page(n_pages as u32).is_err());
    }

    #[test]
    fn test_vec_memory_modify_page() {
        let n_pages = 3;
        let mut vec_memory = VecMemory::new(n_pages);

        // Modify a page and verify the change
        let page_index = 1;
        {
            let page = vec_memory.get_page(page_index).expect("Page should exist");
            page.data[42] = 42;
        }

        let page = vec_memory.get_page(page_index).expect("Page should exist");
        assert_eq!(page.data[42], 42);
    }
}
