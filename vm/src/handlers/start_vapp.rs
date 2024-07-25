
use crate::{println, AppSW, Instruction};

use ledger_device_sdk::io;

use common::manifest::Manifest;
use common::constants::PAGE_SIZE;
use common::client_commands::ClientCommandCode;

pub fn handler_start_vapp(comm: &mut io::Comm) -> Result<(), AppSW> {
    let data_raw = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    let (manifest, hmac) = postcard::take_from_bytes::<Manifest>(data_raw)
        .map_err(|_| AppSW::IncorrectData)?;


    if hmac.len() != 32 {
        return Err(AppSW::IncorrectData);
    }

    // TODO: actually check the HMAC (and use a constant-time comparison)
    if hmac != [0x42u8; 32] {
        return Err(AppSW::SignatureFail);
    }
    
    println!("Running app with Manifest: {:?}", manifest);
    println!("hmac: {:?}", hmac);

    let mut pc = manifest.entrypoint;

    assert!(pc % 4 == 0, "Unaligned entrypoint");
    assert!(manifest.code_start % PAGE_SIZE as u32 == 0, "Unaligned code start");

    loop {
        let page_index: u32 = (pc - manifest.code_start) / (PAGE_SIZE as u32);
        comm.append(&[ClientCommandCode::GetPage as u8]);
        comm.append(&page_index.to_be_bytes());
        comm.reply(AppSW::InterruptedExecution);
    
        if let Instruction::Continue(p1, p2) = comm.next_command() {
            if p2 != 0 {
                return Err(AppSW::WrongP1P2);
            }

            let index_in_page = (pc % (PAGE_SIZE as u32)) as usize;

            let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;
            if data.len() != PAGE_SIZE - 1 {
                return Err(AppSW::WrongApduLength);
            }

            let instr: [u8; 4] = if index_in_page < PAGE_SIZE - 4 {
                // read 4 bytes from the data
                let mut instr = [0u8; 4];
                instr.copy_from_slice(&data[index_in_page..index_in_page + 4]);
                instr
            } else {
                // special case: read 3 bytes from the data, and concatenate with p1
                let mut instr = [0u8; 4];
                instr[0..3].copy_from_slice(&data[index_in_page..index_in_page + 3]);
                instr[3] = p1;
                instr
            };

            // TODO: process instruction. For now we assume that each instruction is NOP
            println!("Instruction: {:x?}", instr);
            pc += 4;
        } else {
            return Err(AppSW::InsNotSupported); // we only accept "Continue" here
        }
    }
}
