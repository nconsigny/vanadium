use std::cmp::min;

use common::accumulator::{HashOutput, Hasher, MerkleAccumulator, VectorAccumulator};
use common::client_commands::{
    ClientCommandCode, CommitPageContentMessage, CommitPageMessage, GetPageMessage, Message,
    ReceiveBufferMessage, ReceiveBufferResponse, SectionKind, SendBufferMessage,
    SendPanicBufferMessage,
};
use common::constants::{page_start, PAGE_SIZE};
use common::manifest::Manifest;
use sha2::{Digest, Sha256};

use crate::apdu::{APDUCommand, StatusWord};
use crate::elf::ElfFile;
use crate::transport::Transport;

fn apdu_continue(data: Vec<u8>) -> APDUCommand {
    APDUCommand {
        cla: 0xE0,
        ins: 0xff,
        p1: 0,
        p2: 0,
        data,
    }
}

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

struct VAppEngine<'a> {
    manifest: &'a Manifest,
    code_seg: MemorySegment,
    data_seg: MemorySegment,
    stack_seg: MemorySegment,
    callbacks: &'a dyn Callbacks,
}

impl<'a> VAppEngine<'a> {
    // Sends and APDU and repeatedly processes the response if it's a GetPage or CommitPage client command.
    // Returns as soon as a different response is received.
    async fn exchange_and_process_page_requests<T: Transport>(
        &mut self,
        transport: &T,
        apdu: &APDUCommand,
    ) -> Result<(StatusWord, Vec<u8>), &'static str> {
        let (mut status, mut result) = transport
            .exchange(apdu)
            .await
            .map_err(|_| "exchange failed")?;

        loop {
            if status != StatusWord::InterruptedExecution || result.len() == 0 {
                return Ok((status, result));
            }
            let client_command_code: ClientCommandCode = result[0].try_into()?;
            (status, result) = match client_command_code {
                ClientCommandCode::GetPage => self.process_get_page(transport, &result).await?,
                ClientCommandCode::CommitPage => {
                    self.process_commit_page(transport, &result).await?
                }
                _ => return Ok((status, result)),
            }
        }
    }

    async fn process_get_page<T: Transport>(
        &mut self,
        transport: &T,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), &'static str> {
        let GetPageMessage {
            command_code: _,
            section_kind,
            page_index,
        } = GetPageMessage::deserialize(command)?;

        let segment = match section_kind {
            SectionKind::Code => &self.code_seg,
            SectionKind::Data => &self.data_seg,
            SectionKind::Stack => &self.stack_seg,
        };

        // TODO: for now we're ignoring proofs
        let (mut data, _) = segment.get_page(page_index)?;
        let p1 = data.pop().unwrap();

        // return the content of the page

        Ok(transport
            .exchange(&APDUCommand {
                cla: 0xE0,
                ins: 0xff,
                p1,
                p2: 0,
                data,
            })
            .await
            .map_err(|_| "exchange failed")?)
    }

    async fn process_commit_page<T: Transport>(
        &mut self,
        transport: &T,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), &'static str> {
        let msg = CommitPageMessage::deserialize(command)?;

        let segment = match msg.section_kind {
            SectionKind::Code => {
                return Err("The code segment is immutable");
            }
            SectionKind::Data => &mut self.data_seg,
            SectionKind::Stack => &mut self.stack_seg,
        };

        // get the next message, which contains the content of the page
        let (tmp_status, tmp_result) = transport
            .exchange(&apdu_continue(vec![]))
            .await
            .map_err(|_| "exchange failed")?;

        if tmp_status != StatusWord::InterruptedExecution {
            return Err("Expected InterruptedExecution status word");
        }

        let CommitPageContentMessage {
            command_code: _,
            data,
        } = CommitPageContentMessage::deserialize(&tmp_result)?;

        let update_proof = segment.store_page(msg.page_index, &data)?;

        // TODO: for now we ignore the update proof

        Ok(transport
            .exchange(&apdu_continue(vec![]))
            .await
            .map_err(|_| "exchange failed")?)
    }

    // receive a buffer sent by the V-App via xsend; show it in hex via stdout
    async fn process_send_buffer<T: Transport>(
        &mut self,
        transport: &T,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), &'static str> {
        let SendBufferMessage {
            command_code: _,
            total_remaining_size: mut remaining_len,
            data: mut buf,
        } = SendBufferMessage::deserialize(command)?;

        if (buf.len() as u32) > remaining_len {
            return Err("Received data length exceeds expected remaining length");
        }

        remaining_len -= buf.len() as u32;

        while remaining_len > 0 {
            let (status, result) = self
                .exchange_and_process_page_requests(transport, &apdu_continue(vec![]))
                .await
                .map_err(|_| "exchange failed")?;

            if status != StatusWord::InterruptedExecution || result.len() == 0 {
                return Err("Unexpected response");
            }
            let msg = SendBufferMessage::deserialize(&result)?;

            if msg.total_remaining_size != remaining_len {
                return Err("Received total_remaining_size does not match expected");
            }

            buf.extend_from_slice(&msg.data);
            remaining_len -= msg.data.len() as u32;
        }

        self.callbacks.send_buffer(&buf);

        Ok(self
            .exchange_and_process_page_requests(transport, &apdu_continue(vec![]))
            .await
            .map_err(|_| "exchange failed")?)
    }

    // the V-App is expecting a buffer via xrecv; get it in hex from standard input, and send it to the V-App
    async fn process_receive_buffer<T: Transport>(
        &mut self,
        transport: &T,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), &'static str> {
        ReceiveBufferMessage::deserialize(command)?;

        let bytes = self
            .callbacks
            .receive_buffer()
            .map_err(|_| "receive buffer callback failed")?;

        let mut remaining_len = bytes.len() as u32;
        let mut offset: usize = 0;

        loop {
            // TODO: wrong if the buffer is long
            let chunk_len = min(remaining_len, 255 - 4);
            let data = ReceiveBufferResponse::new(
                remaining_len,
                bytes[offset..offset + chunk_len as usize].to_vec(),
            )
            .serialize();

            let (status, result) = self
                .exchange_and_process_page_requests(transport, &apdu_continue(data))
                .await
                .map_err(|_| "exchange failed")?;

            remaining_len -= chunk_len;
            offset += chunk_len as usize;

            if remaining_len == 0 {
                return Ok((status, result));
            } else {
                // the message is not over, so we expect an InterruptedExecution status word
                // and another ReceiveBufferMessage to receive the rest.
                if status != StatusWord::InterruptedExecution || result.len() == 0 {
                    return Err("Unexpected response");
                }
                ReceiveBufferMessage::deserialize(&result)?;
            }
        }
        // return Ok((status, result));
    }

    // receive a buffer sent by the V-App during a panic; show it to stdout
    // TODO: almost identical to process_send_buffer; it might be nice to refactor
    async fn process_send_panic_buffer<T: Transport>(
        &mut self,
        transport: &T,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), &'static str> {
        let SendPanicBufferMessage {
            command_code: _,
            total_remaining_size: mut remaining_len,
            data: mut buf,
        } = SendPanicBufferMessage::deserialize(command)?;

        if (buf.len() as u32) > remaining_len {
            return Err("Received data length exceeds expected remaining length");
        }

        remaining_len -= buf.len() as u32;

        while remaining_len > 0 {
            let (status, result) = self
                .exchange_and_process_page_requests(transport, &apdu_continue(vec![]))
                .await
                .map_err(|_| "exchange failed")?;

            if status != StatusWord::InterruptedExecution || result.len() == 0 {
                return Err("Unexpected response");
            }
            let msg = SendPanicBufferMessage::deserialize(&result)?;

            if msg.total_remaining_size != remaining_len {
                return Err("Received total_remaining_size does not match expected");
            }

            buf.extend_from_slice(&msg.data);
            remaining_len -= msg.data.len() as u32;
        }

        println!(
            "Received panic message:\n{}",
            core::str::from_utf8(&buf).unwrap()
        );

        Ok(self
            .exchange_and_process_page_requests(transport, &apdu_continue(vec![]))
            .await
            .map_err(|_| "exchange failed")?)
    }

    async fn busy_loop<T: Transport>(
        &mut self,
        transport: &T,
        first_sw: StatusWord,
        first_result: Vec<u8>,
    ) -> Result<Vec<u8>, &'static str> {
        // create the pages in the code segment. Each page is aligned to PAGE_SIZE (the first page is zero padded if the initial address is not divisible by
        // PAGE_SIZE, and the last page is zero_padded if it's smaller than PAGE_SIZE).\

        let mut status = first_sw;
        let mut result = first_result;

        loop {
            if status == StatusWord::OK {
                return Ok(result);
            }

            if status == StatusWord::VMRuntimeError {
                return Err("VM runtime error");
            }

            if status == StatusWord::VAppPanic {
                return Err("V-App panicked");
            }

            if status != StatusWord::InterruptedExecution {
                return Err("Unexpected status word");
            }

            if result.len() == 0 {
                return Err("empty command");
            }

            let client_command_code: ClientCommandCode = result[0].try_into()?;

            (status, result) = match client_command_code {
                ClientCommandCode::GetPage => self.process_get_page(transport, &result).await?,
                ClientCommandCode::CommitPage => {
                    self.process_commit_page(transport, &result).await?
                }
                ClientCommandCode::CommitPageContent => {
                    // not a top-level command, part of CommitPage handling
                    return Err("Unexpected CommitPageContent client command");
                }
                ClientCommandCode::SendBuffer => {
                    self.process_send_buffer(transport, &result).await?
                }
                ClientCommandCode::ReceiveBuffer => {
                    self.process_receive_buffer(transport, &result).await?
                }
                ClientCommandCode::SendPanicBuffer => {
                    self.process_send_panic_buffer(transport, &result).await?
                }
            }
        }
    }
}

pub struct VanadiumClient<T: Transport> {
    transport: T,
}

pub enum ReceiveBufferError {
    ReceiveFailed, // TODO: do we need to distinguish between more errors?
}

pub trait Callbacks {
    fn receive_buffer(&self) -> Result<Vec<u8>, ReceiveBufferError>;
    fn send_buffer(&self, buffer: &[u8]);
    fn send_panic(&self, msg: &[u8]);
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

    pub async fn run_vapp<C: Callbacks>(
        &self,
        manifest: &Manifest,
        app_hmac: &[u8; 32],
        elf: &ElfFile,
        callbacks: &C,
    ) -> Result<Vec<u8>, &'static str> {
        // concatenate the serialized manifest and the app_hmac
        let mut data =
            postcard::to_allocvec(manifest).map_err(|_| "manifest serialization failed")?;
        data.extend_from_slice(app_hmac);

        // Create the memory segments for the code, data, and stack sections
        let code_seg = MemorySegment::new(elf.code_segment.start, &elf.code_segment.data)?;
        let data_seg = MemorySegment::new(elf.data_segment.start, &elf.data_segment.data)?;
        let stack_seg = MemorySegment::new(
            manifest.stack_start,
            &vec![0; (manifest.stack_end - manifest.stack_start) as usize],
        )?;

        let mut vapp_engine = VAppEngine {
            manifest,
            code_seg,
            data_seg,
            stack_seg,
            callbacks,
        };

        // initial APDU to start the V-App
        let command = APDUCommand {
            cla: 0xE0,
            ins: 3,
            p1: 0,
            p2: 0,
            data,
        };

        let (status, result) = self
            .transport
            .exchange(&command)
            .await
            .map_err(|_| "exchange failed")?;

        let result = vapp_engine
            .busy_loop(&self.transport, status, result)
            .await?;

        Ok(result)
    }
}
