use std::cmp::min;

use common::accumulator::{HashOutput, Hasher, MerkleAccumulator, VectorAccumulator};
use common::client_commands::{ClientCommandCode, SectionKind};
use common::constants::{page_start, PAGE_SIZE};
use common::manifest::Manifest;
use sha2::{Digest, Sha256};

use crate::apdu::{APDUCommand, StatusWord};
use crate::elf::ElfFile;
use crate::Transport;

pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Hasher<32> for Sha256Hasher {
    fn new() -> Self {
        Sha256Hasher {
            hasher: Sha256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        let result = self.hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// Represents a memory segment stored by the client, using a MerkleAccumulator to provide proofs of integrity.
struct MemorySegment {
    start: u32,
    end: u32,
    content: MerkleAccumulator<Sha256Hasher, Vec<u8>, 32>,
}

impl MemorySegment {
    fn new(start: u32, data: &[u8]) -> Result<Self, &'static str> {
        let end = start + data.len() as u32;

        let mut pages: Vec<Vec<u8>> = Vec::new();

        // current position, in terms of address; `start` needs to be subtracted for the position in `data`
        let mut current_addr = start;
        loop {
            if current_addr >= end {
                break;
            }
            let mut page_content: Vec<u8> = Vec::with_capacity(PAGE_SIZE);
            let page_start_addr = page_start(current_addr as u32);
            let page_end_addr = page_start_addr + PAGE_SIZE as u32;
            let content_end_addr = min(page_end_addr, end);

            // 0-pad with current_addr - page_start_addr bytes (always 0, except for the first page if unaligned to PAGE_SIZE)
            page_content.extend_from_slice(&vec![0; (current_addr - page_start_addr) as usize]);

            // copy content_end_addr - current_addr bytes from data
            page_content.extend_from_slice(
                &data[(current_addr - start) as usize..(content_end_addr - start) as usize],
            );

            // 0-pad with page_end_addr - content_end_addr bytes bytes (always 0, except possibly for last page)
            page_content.extend_from_slice(&vec![0; (page_end_addr - content_end_addr) as usize]);

            current_addr = page_end_addr;
            pages.push(page_content);
        }

        Ok(Self {
            start,
            end,
            content: MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(pages),
        })
    }

    fn get_page(&self, page_index: u32) -> Result<(Vec<u8>, Vec<HashOutput<32>>), &'static str> {
        let content = self
            .content
            .get(page_index as usize)
            .ok_or("Page not found")?
            .clone();

        let proof = self.content.prove(page_index as usize)?;

        Ok((content, proof))
    }

    fn store_page(
        &mut self,
        page_index: u32,
        content: &[u8],
    ) -> Result<(Vec<HashOutput<32>>, Vec<u8>), &'static str> {
        if content.len() != PAGE_SIZE {
            return Err("Invalid page size");
        }
        let proof = self.content.update(page_index as usize, content.to_vec())?;
        Ok(proof)
    }
}

pub struct VanadiumClient<T: Transport> {
    transport: T,
}

impl<T: Transport> VanadiumClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub async fn register_vapp(&self, manifest: &Manifest) -> Result<[u8; 32], &'static str> {
        let command = APDUCommand {
            cla: 0xE0,
            ins: 2,
            p1: 0,
            p2: 0,
            data: postcard::to_allocvec(manifest).map_err(|_| "manifest serialization failed")?,
        };

        let (status, result) = self
            .transport
            .exchange(&command)
            .await
            .map_err(|_| "exchange failed")?;

        match status {
            StatusWord::OK => {
                // fail if the response is not exactly 32 bytes; otherwise return it as a [u8; 32]
                if result.len() != 32 {
                    return Err("Invalid response length");
                }

                // convert result to a [u8; 32]
                let mut hmac = [0u8; 32];
                hmac.copy_from_slice(&result);
                Ok(hmac)
            }
            _ => Err("Failed to register vapp"),
        }
    }

    pub async fn run_vapp(
        &self,
        manifest: &Manifest,
        app_hmac: &[u8; 32],
        elf: &ElfFile,
    ) -> Result<(), &'static str> {
        // concatenate the serialized manifest and the app_hmac
        let mut data =
            postcard::to_allocvec(manifest).map_err(|_| "manifest serialization failed")?;
        data.extend_from_slice(app_hmac);

        let mut command = APDUCommand {
            cla: 0xE0,
            ins: 3,
            p1: 0,
            p2: 0,
            data,
        };

        // Create the memory segments for the code, data, and stack sections
        let code_seg = MemorySegment::new(elf.code_segment.start, &elf.code_segment.data)?;
        let mut data_seg = MemorySegment::new(elf.data_segment.start, &elf.data_segment.data)?;
        let mut stack_seg = MemorySegment::new(
            manifest.stack_start,
            &vec![0; (manifest.stack_end - manifest.stack_start) as usize],
        )?;

        // create the pages in the code segment. Each page is aligned to PAGE_SIZE (the first page is zero padded if the initial address is not divisible by
        // PAGE_SIZE, and the last page is zero_padded if it's smaller than PAGE_SIZE).\

        loop {
            let (status, result) = self
                .transport
                .exchange(&command)
                .await
                .map_err(|_| "exchange failed")?;

            match status {
                StatusWord::OK => {
                    // fail if the response is not exactly 32 bytes; otherwise return it as a [u8; 32]
                    if result.len() != 32 {
                        return Err("Invalid response length");
                    }

                    return Ok(());
                }
                StatusWord::InterruptedExecution => {
                    let client_command: ClientCommandCode = result[0].try_into()?;
                    match client_command {
                        ClientCommandCode::GetPage => {
                            let section_kind: SectionKind = result[1].try_into()?;

                            let page_index =
                                u32::from_be_bytes([result[2], result[3], result[4], result[5]]);

                            let segment = match section_kind {
                                SectionKind::Code => &code_seg,
                                SectionKind::Data => &data_seg,
                                SectionKind::Stack => &stack_seg,
                            };

                            // TODO: for now we're ignoring proofs
                            let (mut data, _) = segment.get_page(page_index)?;
                            let p1 = data.pop().unwrap();

                            // return the content of the page
                            command = APDUCommand {
                                cla: 0xE0,
                                ins: 0xff, // continue execution
                                p1,        // the last byte of the page
                                p2: 0,
                                data,
                            };
                            continue;
                        }
                        ClientCommandCode::CommitPage => {
                            let section_kind: SectionKind = result[1].try_into()?;
                            let page_index =
                                u32::from_be_bytes([result[2], result[3], result[4], result[5]]);

                            let segment = match section_kind {
                                SectionKind::Code => {
                                    return Err("The code segment is immutable");
                                }
                                SectionKind::Data => &mut data_seg,
                                SectionKind::Stack => &mut stack_seg,
                            };

                            command = APDUCommand {
                                cla: 0xE0,
                                ins: 0xff,
                                p1: 0,
                                p2: 0,
                                data: vec![],
                            };

                            println!("Committing page {}. Requesting content.", page_index);

                            // get the next message, which contains the content of the page
                            let (status, result) = self
                                .transport
                                .exchange(&command)
                                .await
                                .map_err(|_| "exchange failed")?;

                            if status != StatusWord::InterruptedExecution {
                                return Err("Expected InterruptedExecution status word");
                            }
                            if result[0] != ClientCommandCode::CommitPageContent as u8 {
                                return Err("Expected CommitPageContent client command");
                            }
                            if result.len() != 1 + PAGE_SIZE {
                                return Err("Invalid page content length");
                            }

                            let update_proof = segment.store_page(page_index, &result[1..])?;

                            // TODO: for now we ignore the update proof

                            println!("Updated; should send the proof, but we send an empty message instead");

                            command = APDUCommand {
                                cla: 0xE0,
                                ins: 0xff,
                                p1: 0,
                                p2: 0,
                                data: vec![],
                            };
                        }
                        ClientCommandCode::CommitPageContent => {
                            return Err("Unexpected CommitPageContent client command");
                        }
                    }
                }
                _ => return Err("Failed to run vapp"),
            }
        }
    }
}
