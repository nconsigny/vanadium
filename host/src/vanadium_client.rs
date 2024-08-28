use std::cmp::min;

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

                            let mut data = vec![0; PAGE_SIZE];
                            let code_start = elf.code_segment.start as usize;
                            let code_end = elf.code_segment.end as usize;
                            let copy_start = if page_index == 0 { code_start } else { page_start };

                            let copy_end = min(page_end, code_end - code_start);
                            let data_start = if page_index == 0 { code_start % PAGE_SIZE } else { 0 };

                            data[data_start..data_start + copy_end - copy_start].copy_from_slice(&elf.code_segment.data[copy_start..copy_end]);
                            
                            let p1 = data.pop().unwrap();

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
                        ClientCommandCode::CommitPage => todo!(), // TODO: Not implemented
                        ClientCommandCode::CommitPageContent => todo!(), // TODO: Not implemented
                    }
                },
                _ => return Err("Failed to run vapp"),
            }
        }
    }
}