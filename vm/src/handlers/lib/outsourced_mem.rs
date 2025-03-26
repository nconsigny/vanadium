use core::cell::RefCell;

use alloc::{rc::Rc, vec, vec::Vec};
use common::vm::{Page, PagedMemory};
use ledger_device_sdk::io;

use common::client_commands::{
    CommitPageContentMessage, CommitPageMessage, GetPageMessage, Message, SectionKind,
};
use common::constants::PAGE_SIZE;

use crate::{AppSW, Instruction};

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
    #[cfg(feature = "metrics")]
    pub n_page_loads: usize,
    #[cfg(feature = "metrics")]
    pub n_page_commits: usize,
}

impl<'c> core::fmt::Debug for OutsourcedMemory<'c> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutsourcedMemory")
            .field("comm", &"...")
            .field("pages", &self.pages)
            .field("is_readonly", &self.is_readonly)
            .field("section_kind", &self.section_kind)
            .field("usage_counter", &self.usage_counter)
            .finish()
    }
}

// Sends an APDU, and receives the reply, without processing other events in between.
// Similar to io_exchange fron the C sdk.
// Using the normal SDK functionalities (Comm::reply and Comm::next_command) was causing
// messages to be throttled by 0.1s.
// TODO: refactor after the io revamp in the SDK.
fn io_exchange<R, T>(comm: &mut io::Comm, reply: R) -> T
where
    R: Into<io::Reply>,
    T: TryFrom<io::ApduHeader>,
    io::Reply: From<<T as TryFrom<io::ApduHeader>>::Error>,
{
    use ledger_secure_sdk_sys::seph as sys_seph;
    #[cfg(any(target_os = "nanox", target_os = "stax", target_os = "flex"))]
    use ledger_secure_sdk_sys::APDU_BLE;
    use ledger_secure_sdk_sys::{
        io_usb_send_apdu_data, G_io_app, APDU_IDLE, APDU_RAW, APDU_USB_HID, IO_APDU_MEDIA_NONE,
    };

    let sw = reply.into().0;
    // Append status word
    comm.apdu_buffer[comm.tx] = (sw >> 8) as u8;
    comm.apdu_buffer[comm.tx + 1] = sw as u8;
    comm.tx += 2;

    // apdu_send
    let mut spi_buffer = [0u8; 256];
    match unsafe { G_io_app.apdu_state } {
        APDU_USB_HID => unsafe {
            ledger_secure_sdk_sys::io_usb_hid_send(
                Some(io_usb_send_apdu_data),
                comm.tx as u16,
                comm.apdu_buffer.as_mut_ptr(),
            );
        },
        APDU_RAW => {
            let len = (comm.tx as u16).to_be_bytes();
            sys_seph::seph_send(&[sys_seph::SephTags::RawAPDU as u8, len[0], len[1]]);
            sys_seph::seph_send(&comm.apdu_buffer[..comm.tx]);
        }
        #[cfg(any(target_os = "nanox", target_os = "stax", target_os = "flex"))]
        APDU_BLE => {
            ledger_device_sdk::ble::send(&comm.apdu_buffer[..comm.tx]);
        }
        _ => (),
    }
    comm.tx = 0;
    comm.rx = 0;

    loop {
        unsafe {
            G_io_app.apdu_state = APDU_IDLE;
            G_io_app.apdu_media = IO_APDU_MEDIA_NONE;
            G_io_app.apdu_length = 0;
        }

        let res = loop {
            // Signal end of command stream from SE to MCU
            // And prepare reception
            if !sys_seph::is_status_sent() {
                sys_seph::send_general_status();
            }

            // Fetch the next message from the MCU
            let _rx = sys_seph::seph_recv(&mut spi_buffer, 0);

            if let Some(value) = comm.decode_event(&mut spi_buffer) {
                break value;
            }
        };

        if let io::Event::Command(ins) = res {
            return ins;
        }
    }
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
            #[cfg(feature = "metrics")]
            n_page_loads: 0,
            #[cfg(feature = "metrics")]
            n_page_commits: 0,
        }
    }

    fn commit_page_at(&mut self, index: usize) -> Result<(), common::vm::MemoryError> {
        let page = &self.pages[index];
        assert!(page.valid, "Trying to commit an invalid page");

        #[cfg(feature = "metrics")]
        {
            self.n_page_commits += 1;
        }

        let mut comm = self.comm.borrow_mut();
        CommitPageMessage::new(self.section_kind, page.idx).serialize_to_comm(&mut comm);

        let Instruction::Continue(p1, p2) = io_exchange(&mut comm, AppSW::InterruptedExecution)
        else {
            return Err(common::vm::MemoryError::GenericError("INS not supported"));
            // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err(common::vm::MemoryError::GenericError("Wrong P1/P2"));
        }

        // Second message: communicate the page content
        CommitPageContentMessage::new(page.page.data.to_vec()).serialize_to_comm(&mut comm);

        let Instruction::Continue(p1, p2) = io_exchange(&mut comm, AppSW::InterruptedExecution)
        else {
            return Err(common::vm::MemoryError::GenericError("INS not supported"));
            // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err(common::vm::MemoryError::GenericError("Wrong P1/P2"));
        }

        Ok(())
    }

    fn load_page(&mut self, page_index: u32) -> Result<Page, common::vm::MemoryError> {
        #[cfg(feature = "metrics")]
        {
            self.n_page_loads += 1;
        }

        let mut comm = self.comm.borrow_mut();
        GetPageMessage::new(self.section_kind, page_index).serialize_to_comm(&mut comm);

        let Instruction::Continue(p1, p2) = io_exchange(&mut comm, AppSW::InterruptedExecution)
        else {
            // expected "Continue"
            return Err(common::vm::MemoryError::GenericError("INS not supported"));
        };

        if p2 != 0 {
            return Err(common::vm::MemoryError::GenericError("Wrong P2"));
        }

        let fetched_data = comm
            .get_data()
            .map_err(|_| common::vm::MemoryError::GenericError("Wrong APDU length"))?;
        if fetched_data.len() != PAGE_SIZE - 1 {
            return Err(common::vm::MemoryError::GenericError("Wrong APDU length"));
        }

        let mut data = [0u8; PAGE_SIZE];
        data[0..PAGE_SIZE - 1].copy_from_slice(&fetched_data);
        data[PAGE_SIZE - 1] = p1;

        Ok(Page { data })
    }
}

impl<'c> PagedMemory for OutsourcedMemory<'c> {
    type PageRef<'a>
        = &'a mut Page
    where
        Self: 'a;

    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, common::vm::MemoryError> {
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
