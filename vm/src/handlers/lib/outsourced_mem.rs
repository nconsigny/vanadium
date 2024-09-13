use core::cell::RefCell;

use alloc::{rc::Rc, vec, vec::Vec};
use common::vm::{Page, PagedMemory};
use ledger_device_sdk::io;

use common::client_commands::{
    CommitPageContentMessage, CommitPageMessage, GetPageMessage, Message, SectionKind,
};
use common::constants::PAGE_SIZE;

use crate::{println, AppSW, Instruction};

#[derive(Clone, Debug)]
struct CachedPage {
    idx: u32,           // Page index
    page: Page,         // Page data
    usage_counter: u32, // For LRU tracking
    valid: bool,        // Indicates if the slot contains a valid page
}

impl Default for CachedPage {
    fn default() -> Self {
        Self {
            idx: 0,
            page: Page {
                data: [0; PAGE_SIZE],
            },
            usage_counter: 0,
            valid: false,
        }
    }
}

pub struct OutsourcedMemory<'c> {
    comm: Rc<RefCell<&'c mut io::Comm>>,
    pages: Vec<CachedPage>,
    is_readonly: bool,
    section_kind: SectionKind,
    usage_counter: u32,
}

impl<'c> OutsourcedMemory<'c> {
    pub fn new(
        comm: Rc<RefCell<&'c mut io::Comm>>,
        max_pages: usize,
        is_readonly: bool,
        section_kind: SectionKind,
    ) -> Self {
        let pages = vec![CachedPage::default(); max_pages];
        Self {
            comm,
            pages,
            is_readonly,
            section_kind,
            usage_counter: 0,
        }
    }

    fn commit_page_at(&mut self, index: usize) -> Result<(), &'static str> {
        let page = &self.pages[index];
        assert!(page.valid, "Trying to commit an invalid page");

        println!("Committing page {}, locally at index {}", page.idx, index); // TODO: remove

        let mut comm = self.comm.borrow_mut();
        CommitPageMessage::new(self.section_kind, page.idx).serialize_to_comm(&mut comm);
        comm.reply(AppSW::InterruptedExecution);

        let Instruction::Continue(p1, p2) = comm.next_command() else {
            return Err("INS not supported"); // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err("Wrong P1/P2");
        }

        // Second message: communicate the page content
        CommitPageContentMessage::new(page.page.data.to_vec()).serialize_to_comm(&mut comm);
        comm.reply(AppSW::InterruptedExecution);

        let Instruction::Continue(p1, p2) = comm.next_command() else {
            return Err("INS not supported"); // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err("Wrong P1/P2");
        }

        Ok(())
    }

    fn load_page(&mut self, page_index: u32) -> Result<Page, &'static str> {
        println!("Loading page at index {}", page_index); // TODO: remove

        let mut comm = self.comm.borrow_mut();
        GetPageMessage::new(self.section_kind, page_index).serialize_to_comm(&mut comm);
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

        let mut data = [0u8; PAGE_SIZE];
        data[0..PAGE_SIZE - 1].copy_from_slice(&fetched_data);
        data[PAGE_SIZE - 1] = p1;

        Ok(Page { data })
    }
}

impl<'c> PagedMemory for OutsourcedMemory<'c> {
    type PageRef<'a> = &'a mut Page where Self: 'a;

    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, &'static str> {
        // Increment the global usage counter
        self.usage_counter = self.usage_counter.wrapping_add(1);

        // Search for the page in cache
        for i in 0..self.pages.len() {
            if self.pages[i].valid && self.pages[i].idx == page_index {
                // Update usage_counter for LRU
                self.pages[i].usage_counter = self.usage_counter;

                // Return mutable reference to the page
                return Ok(&mut self.pages[i].page);
            }
        }

        // Page not found in cache
        // Find a free slot
        let mut slot: Option<usize> = None;
        for i in 0..self.pages.len() {
            if !self.pages[i].valid {
                slot = Some(i);
                break;
            }
        }

        // If no free slot, evict the least recently used page
        if slot.is_none() {
            let mut oldest_usage = u32::MAX;
            let mut evict_index = 0;
            for i in 0..self.pages.len() {
                if self.pages[i].usage_counter < oldest_usage {
                    oldest_usage = self.pages[i].usage_counter;
                    evict_index = i;
                }
            }

            // Commit the page if this memory is not readonly
            if !self.is_readonly {
                self.commit_page_at(evict_index)?;
            }

            // Invalidate the evicted page
            self.pages[evict_index].valid = false;
            slot = Some(evict_index);
        }

        let slot = slot.unwrap();

        // Load the page into the slot
        let page_data = self.load_page(page_index)?;
        self.pages[slot] = CachedPage {
            idx: page_index,
            page: page_data,
            usage_counter: self.usage_counter,
            valid: true,
        };

        // Return mutable reference to the page
        Ok(&mut self.pages[slot].page)
    }
}
