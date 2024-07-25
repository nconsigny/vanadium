use common::constants::PAGE_SIZE;
use common::manifest::Manifest;
use common::client_commands::ClientCommandCode;

use crate::apdu::{APDUCommand, StatusWord};
use crate::elf::ElfFile;
use crate::Transport;

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
            data: postcard::to_allocvec(manifest).map_err(|_| "manifest serialization failed" )?,
        };
    
        let (status, result) = self.transport.exchange(&command).await.map_err(|_| "exchange failed" )?;

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
            },
            _ => Err("Failed to register vapp"),
        }
    }

    pub async fn run_vapp(&self, manifest: &Manifest, app_hmac: &[u8; 32], elf: &ElfFile) -> Result<(), &'static str> {
        // concatenate the serialized manifest and the app_hmac
        let mut data = postcard::to_allocvec(manifest).map_err(|_| "manifest serialization failed" )?;
        data.extend_from_slice(app_hmac);

        let mut command = APDUCommand {
            cla: 0xE0,
            ins: 3,
            p1: 0,
            p2: 0,
            data,
        };
    
        loop {
            let (status, result) = self.transport.exchange(&command).await.map_err(|_| "exchange failed")?;
            
            match status {
                StatusWord::OK => {
                    // fail if the response is not exactly 32 bytes; otherwise return it as a [u8; 32]
                    if result.len() != 32 {
                        return Err("Invalid response length");
                    }
        
                    return Ok(());
                },
                StatusWord::InterruptedExecution => {
                    let client_command: ClientCommandCode = result[0].try_into()?;
                    match client_command {
                        ClientCommandCode::GetPage => {
                            // TODO: for now we assume all pages are read from the code segment. YOLO

                            let page_index = u32::from_be_bytes([result[1], result[2], result[3], result[4]]);
                            let page_start = (page_index as usize) * PAGE_SIZE;
                            let page_end = page_start + PAGE_SIZE;

                            // if the page is the last one, it might be smaller than PAGE_SIZE; in that case; pad with zeros
                            let (data, p1) = if page_end > elf.code_segment.data.len() {
                                let mut data = vec![0; PAGE_SIZE - 1];
                                data[..elf.code_segment.data.len() - page_start].copy_from_slice(&elf.code_segment.data[page_start..]);
                                (data, 0u8)
                            } else {
                                (elf.code_segment.data[page_start..page_end - 1].to_vec(), elf.code_segment.data[page_end - 1])
                            };

                            // return the content of the page
                            command = APDUCommand {
                                cla: 0xE0,
                                ins: 0xff, // continue execution
                                p1, // the last byte of the page
                                p2: 0,
                                data,
                            };
                            continue;
                        }
                        ClientCommandCode::CommitPage => todo!(),
                    }
                },
                _ => return Err("Failed to run vapp"),
            }
        }
    }
}