use core::cell::RefCell;

use alloc::{rc::Rc, vec, vec::Vec};
use common::accumulator::{HashOutput, Hasher, MerkleAccumulator, VectorAccumulator};
use common::vm::{Page, PagedMemory};
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::io;

use common::client_commands::{
    CommitPageContentMessage, CommitPageMessage, CommitPageProofContinuedMessage,
    CommitPageProofContinuedResponse, CommitPageProofResponse, GetPageMessage,
    GetPageProofContinuedMessage, GetPageProofContinuedResponse, GetPageProofMessage,
    GetPageProofResponse, Message, SectionKind,
};
use common::constants::PAGE_SIZE;

use crate::{AppSW, Instruction};

#[derive(Clone, Debug)]
struct CachedPage {
    idx: u32,                  // Page index
    page: Page,                // Page data
    page_hash: HashOutput<32>, // Hash of the page data when loaded (before any changes)
    usage_counter: u32,        // For LRU tracking
    valid: bool,               // Indicates if the slot contains a valid page
    modified: bool,            // Indicates if the page has been modified since it was loaded
}

impl Default for CachedPage {
    fn default() -> Self {
        Self {
            idx: 0,
            page: Page {
                data: [0; PAGE_SIZE],
            },
            page_hash: [0; 32].into(),
            usage_counter: 0,
            valid: false,
            modified: false,
        }
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

struct Sha256Hasher(ledger_device_sdk::hash::sha2::Sha2_256);
impl Hasher<32> for Sha256Hasher {
    fn new() -> Self {
        Self(ledger_device_sdk::hash::sha2::Sha2_256::new())
    }

    fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data).unwrap();
        self
    }

    fn digest(mut self, out: &mut [u8; 32]) {
        self.0.finalize(out).unwrap();
    }
}

pub struct OutsourcedMemory<'c> {
    comm: Rc<RefCell<&'c mut io::Comm>>,
    cached_pages: Vec<CachedPage>,
    n_pages: u32,
    merkle_root: HashOutput<32>,
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
            .field("cached_pages", &self.cached_pages)
            .field("is_readonly", &self.is_readonly)
            .field("section_kind", &self.section_kind)
            .field("usage_counter", &self.usage_counter)
            .finish()
    }
}

impl<'c> OutsourcedMemory<'c> {
    pub fn new(
        comm: Rc<RefCell<&'c mut io::Comm>>,
        max_pages_in_cache: usize,
        is_readonly: bool,
        section_kind: SectionKind,
        n_pages: u32,
        merkle_root: HashOutput<32>,
    ) -> Self {
        Self {
            comm,
            cached_pages: vec![CachedPage::default(); max_pages_in_cache],
            n_pages,
            merkle_root,
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
        let cached_page = &self.cached_pages[index];
        assert!(cached_page.valid, "Trying to commit an invalid page");

        let page_hash_old = &cached_page.page_hash;

        #[cfg(feature = "metrics")]
        {
            self.n_page_commits += 1;
        }

        let mut comm = self.comm.borrow_mut();
        CommitPageMessage::new(self.section_kind, cached_page.idx).serialize_to_comm(&mut comm);

        let Instruction::Continue(p1, p2) = io_exchange(&mut comm, AppSW::InterruptedExecution)
        else {
            return Err(common::vm::MemoryError::GenericError("INS not supported"));
            // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err(common::vm::MemoryError::GenericError("Wrong P1/P2"));
        }

        // Second message: communicate the updated page content
        CommitPageContentMessage::new(cached_page.page.data.to_vec()).serialize_to_comm(&mut comm);

        let Instruction::Continue(p1, p2) = io_exchange(&mut comm, AppSW::InterruptedExecution)
        else {
            return Err(common::vm::MemoryError::GenericError("INS not supported"));
            // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err(common::vm::MemoryError::GenericError("Wrong P1/P2"));
        }

        // Decode the proof
        let proof_data = comm.get_data().map_err(|_| {
            common::vm::MemoryError::GenericError("Wrong APDU length in proof response")
        })?;

        let proof_response = CommitPageProofResponse::deserialize(&proof_data)
            .map_err(|_| common::vm::MemoryError::GenericError("Invalid proof data"))?;

        let n = proof_response.n; // Total number of elements in the proof
        let mut proof_elements = proof_response.proof;
        let new_root: HashOutput<32> = proof_response.new_root.into();

        // If we need more elements, request them
        while proof_elements.len() < n as usize {
            CommitPageProofContinuedMessage::new().serialize_to_comm(&mut comm);

            let Instruction::Continue(p1, p2) = io_exchange(&mut comm, AppSW::InterruptedExecution)
            else {
                return Err(common::vm::MemoryError::GenericError(
                    "INS not supported during continued proof request",
                ));
            };

            if (p1, p2) != (0, 0) {
                return Err(common::vm::MemoryError::GenericError(
                    "Wrong P1/P2 in continued proof response",
                ));
            }

            let continued_proof_data = comm.get_data().map_err(|_| {
                common::vm::MemoryError::GenericError(
                    "Wrong APDU length in continued proof response",
                )
            })?;

            let continued_response = CommitPageProofContinuedResponse::deserialize(
                &continued_proof_data,
            )
            .map_err(|_| common::vm::MemoryError::GenericError("Invalid continued proof data"))?;

            proof_elements.extend_from_slice(&continued_response.proof);
        }

        // Convert proof elements to HashOutput format
        let proof_elements: Vec<HashOutput<32>> =
            proof_elements.into_iter().map(Into::into).collect();

        // Create update proof (InclusionProof, new_root)
        let update_proof = (proof_elements, new_root.clone());

        // Calculate hashes for verification
        let new_page_hash =
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_element(&cached_page.page.data);

        // Verify the update proof
        if !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
            &self.merkle_root,
            &update_proof,
            page_hash_old,
            &new_page_hash,
            cached_page.idx as usize,
            self.n_pages as usize,
        ) {
            return Err(common::vm::MemoryError::GenericError(
                "Merkle update verification failed",
            ));
        }

        // Update the root to the new root
        self.merkle_root = new_root;

        Ok(())
    }

    fn load_page(
        &mut self,
        page_index: u32,
    ) -> Result<(Page, HashOutput<32>), common::vm::MemoryError> {
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

        // Request the Merkle proof for the page
        GetPageProofMessage::new().serialize_to_comm(&mut comm);

        let Instruction::Continue(p1, p2) = io_exchange(&mut comm, AppSW::InterruptedExecution)
        else {
            return Err(common::vm::MemoryError::GenericError(
                "INS not supported during proof request",
            ));
        };

        if (p1, p2) != (0, 0) {
            return Err(common::vm::MemoryError::GenericError(
                "Wrong P1/P2 in proof response",
            ));
        }

        // Decode the proof
        let proof_data = comm.get_data().map_err(|_| {
            common::vm::MemoryError::GenericError("Wrong APDU length in proof response")
        })?;

        let proof_response = GetPageProofResponse::deserialize(&proof_data)
            .map_err(|_| common::vm::MemoryError::GenericError("Invalid proof data"))?;

        let n = proof_response.n; // Total number of elements in the proof
        let mut proof_elements = proof_response.proof;

        // If we need more elements, request them
        while proof_elements.len() < n as usize {
            GetPageProofContinuedMessage::new().serialize_to_comm(&mut comm);

            let Instruction::Continue(p1, p2) = io_exchange(&mut comm, AppSW::InterruptedExecution)
            else {
                return Err(common::vm::MemoryError::GenericError(
                    "INS not supported during continued proof request",
                ));
            };

            if (p1, p2) != (0, 0) {
                return Err(common::vm::MemoryError::GenericError(
                    "Wrong P1/P2 in continued proof response",
                ));
            }

            let continued_proof_data = comm.get_data().map_err(|_| {
                common::vm::MemoryError::GenericError(
                    "Wrong APDU length in continued proof response",
                )
            })?;

            let continued_response = GetPageProofContinuedResponse::deserialize(
                &continued_proof_data,
            )
            .map_err(|_| common::vm::MemoryError::GenericError("Invalid continued proof data"))?;

            proof_elements.extend_from_slice(&continued_response.proof);
        }

        // Verify the Merkle proof
        let proof_elements: Vec<HashOutput<32>> =
            proof_elements.into_iter().map(Into::into).collect();

        let page = Page { data };
        let page_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_element(&page.data);

        if !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(
            &self.merkle_root,
            &proof_elements,
            &page_hash,
            page_index as usize,
            self.n_pages as usize,
        ) {
            return Err(common::vm::MemoryError::GenericError(
                "Merkle inclusion verification failed",
            ));
        }

        Ok((Page { data }, page_hash))
    }
}

pub struct CachedPageRef<'a> {
    cached_page: &'a mut CachedPage,
}

impl<'a> core::ops::Deref for CachedPageRef<'a> {
    type Target = Page;

    fn deref(&self) -> &Self::Target {
        &self.cached_page.page
    }
}

impl<'a> core::ops::DerefMut for CachedPageRef<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.cached_page.modified = true;
        &mut self.cached_page.page
    }
}

impl<'c> PagedMemory for OutsourcedMemory<'c> {
    type PageRef<'a>
        = CachedPageRef<'a>
    where
        Self: 'a;

    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, common::vm::MemoryError> {
        // Increment the global usage counter
        self.usage_counter = self.usage_counter.wrapping_add(1);

        // Search for the page in cache
        for i in 0..self.cached_pages.len() {
            if self.cached_pages[i].valid && self.cached_pages[i].idx == page_index {
                // Update usage_counter for LRU
                self.cached_pages[i].usage_counter = self.usage_counter;

                // Return mutable reference to the page with tracking
                return Ok(CachedPageRef {
                    cached_page: &mut self.cached_pages[i],
                });
            }
        }

        // Page not found in cache
        // Find a free slot
        let mut slot: Option<usize> = None;
        for i in 0..self.cached_pages.len() {
            if !self.cached_pages[i].valid {
                slot = Some(i);
                break;
            }
        }

        // If no free slot, evict the least recently used page
        if slot.is_none() {
            let mut oldest_usage = u32::MAX;
            let mut evict_index = 0;
            for i in 0..self.cached_pages.len() {
                if self.cached_pages[i].usage_counter < oldest_usage {
                    oldest_usage = self.cached_pages[i].usage_counter;
                    evict_index = i;
                }
            }

            // Commit the page if this memory is not readonly and the page was modified
            if !self.is_readonly && self.cached_pages[evict_index].modified {
                self.commit_page_at(evict_index)?;
            }

            // Invalidate the evicted page
            self.cached_pages[evict_index].valid = false;
            slot = Some(evict_index);
        }

        let slot = slot.unwrap();

        // Load the page into the slot
        let (page_data, page_hash) = self.load_page(page_index)?;
        self.cached_pages[slot] = CachedPage {
            idx: page_index,
            page: page_data,
            page_hash,
            usage_counter: self.usage_counter,
            valid: true,
            modified: false,
        };

        // Return mutable reference to the page with tracking
        Ok(CachedPageRef {
            cached_page: &mut self.cached_pages[slot],
        })
    }
}
