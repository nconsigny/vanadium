use std::cmp::min;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use common::accumulator::{HashOutput, Hasher, MerkleAccumulator, VectorAccumulator};
use common::client_commands::{
    ClientCommandCode, CommitPageContentMessage, CommitPageMessage, GetPageMessage, Message,
    ReceiveBufferMessage, ReceiveBufferResponse, SectionKind, SendBufferMessage,
    SendPanicBufferMessage,
};
use common::constants::{page_start, PAGE_SIZE};
use common::manifest::Manifest;
use sha2::{Digest, Sha256};

use crate::apdu::{apdu_continue, APDUCommand, StatusWord};
use crate::elf::ElfFile;
use crate::transport::Transport;

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

enum VAppMessage {
    SendBuffer(Vec<u8>),
    SendPanicBuffer(String),
    VAppExited { status: i32 },
}

enum ClientMessage {
    ReceiveBuffer(Vec<u8>),
}

struct VAppEngine<E: std::fmt::Debug + 'static> {
    manifest: Manifest,
    code_seg: MemorySegment,
    data_seg: MemorySegment,
    stack_seg: MemorySegment,
    transport: Arc<dyn Transport<Error = E>>,
    engine_to_client_sender: mpsc::Sender<VAppMessage>,
    client_to_engine_receiver: mpsc::Receiver<ClientMessage>,
}

impl<E: std::fmt::Debug + 'static> VAppEngine<E> {
    pub async fn run(mut self) -> Result<(), &'static str> {
        let mut data =
            postcard::to_allocvec(&self.manifest).map_err(|_| "manifest serialization failed")?;

        // TODO: need to actually get the app_hmac somehow
        let app_hmac = [0x42u8; 32];
        data.extend_from_slice(&app_hmac);

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

        self.busy_loop(status, result).await?;

        Ok(())
    }

    // Sends and APDU and repeatedly processes the response if it's a GetPage or CommitPage client command.
    // Returns as soon as a different response is received.
    async fn exchange_and_process_page_requests(
        &mut self,
        apdu: &APDUCommand,
    ) -> Result<(StatusWord, Vec<u8>), &'static str> {
        let (mut status, mut result) = self
            .transport
            .exchange(apdu)
            .await
            .map_err(|_| "exchange failed")?;

        loop {
            if status != StatusWord::InterruptedExecution || result.len() == 0 {
                return Ok((status, result));
            }
            let client_command_code: ClientCommandCode = result[0].try_into()?;
            (status, result) = match client_command_code {
                ClientCommandCode::GetPage => self.process_get_page(&result).await?,
                ClientCommandCode::CommitPage => self.process_commit_page(&result).await?,
                _ => return Ok((status, result)),
            }
        }
    }

    async fn process_get_page(
        &mut self,
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
        Ok(self
            .transport
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

    async fn process_commit_page(
        &mut self,
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
        let (tmp_status, tmp_result) = self
            .transport
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

        Ok(self
            .transport
            .exchange(&apdu_continue(vec![]))
            .await
            .map_err(|_| "exchange failed")?)
    }

    // receive a buffer sent by the V-App via xsend; send it to the VappEngine
    async fn process_send_buffer(
        &mut self,
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
                .exchange_and_process_page_requests(&apdu_continue(vec![]))
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

        // Send the buffer back to the client via engine_to_client_sender
        self.engine_to_client_sender
            .send(VAppMessage::SendBuffer(buf))
            .await
            .map_err(|_| "Failed to send buffer data")?;

        Ok(self
            .exchange_and_process_page_requests(&apdu_continue(vec![]))
            .await
            .map_err(|_| "exchange failed")?)
    }

    // the V-App is expecting a buffer via xrecv; get it from the VAppEngine, and send it to the V-App
    async fn process_receive_buffer(
        &mut self,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), &'static str> {
        ReceiveBufferMessage::deserialize(command)?;

        // Wait for the message from the client
        let ClientMessage::ReceiveBuffer(bytes) = self
            .client_to_engine_receiver
            .recv()
            .await
            .ok_or("Failed to receive buffer from client")?;

        let mut remaining_len = bytes.len() as u32;
        let mut offset: usize = 0;

        loop {
            // TODO: check if correct when the buffer is long
            let chunk_len = min(remaining_len, 255 - 4);
            let data = ReceiveBufferResponse::new(
                remaining_len,
                bytes[offset..offset + chunk_len as usize].to_vec(),
            )
            .serialize();

            let (status, result) = self
                .exchange_and_process_page_requests(&apdu_continue(data))
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
    }

    // receive a buffer sent by the V-App during a panic; send it to the VAppEngine
    // TODO: almost identical to process_send_buffer; it might be nice to refactor
    async fn process_send_panic_buffer(
        &mut self,
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
                .exchange_and_process_page_requests(&apdu_continue(vec![]))
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

        let panic_message = String::from_utf8(buf).map_err(|_| "Invalid UTF-8 in panic message")?;

        // Send the panic message back to the client via engine_to_client_sender
        self.engine_to_client_sender
            .send(VAppMessage::SendPanicBuffer(panic_message))
            .await
            .map_err(|_| "Failed to send panic message")?;

        // Continue processing
        Ok(self
            .exchange_and_process_page_requests(&apdu_continue(vec![]))
            .await
            .map_err(|_| "exchange failed")?)
    }

    async fn busy_loop(
        &mut self,
        first_sw: StatusWord,
        first_result: Vec<u8>,
    ) -> Result<(), &'static str> {
        let mut status = first_sw;
        let mut result = first_result;

        loop {
            if status == StatusWord::OK {
                if result.len() != 4 {
                    return Err("The V-App should return a 4-byte exit code");
                }
                let st = i32::from_be_bytes(result.try_into().unwrap());
                self.engine_to_client_sender
                    .send(VAppMessage::VAppExited { status: st })
                    .await
                    .map_err(|_| "Failed to send exit code")?;
                return Ok(());
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
                ClientCommandCode::GetPage => self.process_get_page(&result).await?,
                ClientCommandCode::CommitPage => self.process_commit_page(&result).await?,
                ClientCommandCode::CommitPageContent => {
                    // not a top-level command, part of CommitPage handling
                    return Err("Unexpected CommitPageContent client command");
                }
                ClientCommandCode::SendBuffer => self.process_send_buffer(&result).await?,
                ClientCommandCode::ReceiveBuffer => self.process_receive_buffer(&result).await?,
                ClientCommandCode::SendPanicBuffer => {
                    self.process_send_panic_buffer(&result).await?
                }
            }
        }
    }
}

pub struct VanadiumClient {
    client_to_engine_sender: Option<mpsc::Sender<ClientMessage>>,
    engine_to_client_receiver: Option<Mutex<mpsc::Receiver<VAppMessage>>>,
    vapp_engine_handle: Option<JoinHandle<Result<(), &'static str>>>,
}

#[derive(Debug)]
pub enum VanadiumClientError {
    VAppPanicked(String),
    VAppExited(i32),
    GenericError(String),
}

impl From<&str> for VanadiumClientError {
    fn from(s: &str) -> Self {
        VanadiumClientError::GenericError(s.to_string())
    }
}

impl VanadiumClient {
    pub fn new() -> Self {
        Self {
            client_to_engine_sender: None,
            engine_to_client_receiver: None,
            vapp_engine_handle: None,
        }
    }

    pub async fn register_vapp<T: Transport>(
        &self,
        transport: &T,
        manifest: &Manifest,
    ) -> Result<[u8; 32], &'static str> {
        let command = APDUCommand {
            cla: 0xE0,
            ins: 2,
            p1: 0,
            p2: 0,
            data: postcard::to_allocvec(manifest).map_err(|_| "manifest serialization failed")?,
        };

        let (status, result) = transport
            .exchange(&command)
            .await
            .map_err(|_| "exchange failed")?;

        match status {
            StatusWord::OK => {
                if result.len() != 32 {
                    return Err("Invalid response length");
                }
                let mut hmac = [0u8; 32];
                hmac.copy_from_slice(&result);
                Ok(hmac)
            }
            _ => Err("Failed to register vapp"),
        }
    }

    pub fn run_vapp<E: std::fmt::Debug + 'static>(
        &mut self,
        transport: Arc<dyn Transport<Error = E>>,
        manifest: &Manifest,
        app_hmac: &[u8; 32],
        elf: &ElfFile,
    ) -> Result<(), &'static str> {
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

        let (client_to_engine_sender, client_to_engine_receiver) =
            mpsc::channel::<ClientMessage>(10);
        let (engine_to_client_sender, engine_to_client_receiver) = mpsc::channel::<VAppMessage>(10);

        let vapp_engine = VAppEngine {
            manifest: manifest.clone(),
            code_seg,
            data_seg,
            stack_seg,
            transport,
            engine_to_client_sender,
            client_to_engine_receiver,
        };

        // Start the VAppEngine in a task
        let vapp_engine_handle = tokio::spawn(async move { vapp_engine.run().await });

        // Store the senders and receivers
        self.client_to_engine_sender = Some(client_to_engine_sender);
        self.engine_to_client_receiver = Some(Mutex::new(engine_to_client_receiver));
        self.vapp_engine_handle = Some(vapp_engine_handle);

        Ok(())
    }

    pub async fn send_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>, VanadiumClientError> {
        // Send the message to VAppEngine when receive_buffer is called
        self.client_to_engine_sender
            .as_ref()
            .ok_or("VAppEngine not running")?
            .send(ClientMessage::ReceiveBuffer(message))
            .await
            .map_err(|_| "Failed to send message to VAppEngine")?;

        // Wait for the response from VAppEngine
        match self.engine_to_client_receiver.as_mut() {
            Some(engine_to_client_receiver) => {
                let mut receiver = engine_to_client_receiver.lock().await;
                match receiver.recv().await {
                    Some(VAppMessage::SendBuffer(buf)) => Ok(buf),
                    Some(VAppMessage::SendPanicBuffer(panic_msg)) => {
                        Err(VanadiumClientError::VAppPanicked(panic_msg))
                    }
                    Some(VAppMessage::VAppExited { status }) => {
                        Err(VanadiumClientError::VAppExited(status))
                    }
                    None => Err("VAppEngine stopped".into()),
                }
            }
            None => Err("VAppEngine not running".into()),
        }
    }
}
