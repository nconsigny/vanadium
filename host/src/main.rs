mod apdu;
mod elf;
mod transport;
mod vanadium_client;

use common::manifest::Manifest;
use transport::{Transport, TransportTcp};

use std::env;
use std::path::Path;
use vanadium_client::VanadiumClient;

use elf::ElfFile;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the path to the ELF file from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path to elf file>", args[0]);
        std::process::exit(1);
    }

    let path = Path::new(&args[1]);

    let elf_file = ElfFile::new(path)?;

    println!("Entrypoint: {:?}", elf_file.entrypoint);
    println!("{:?}", elf_file);

    let transport = TransportTcp::new().await?;

    let manifest = Manifest::new(
        0,
        "Test",
        "0.1.0",
        [0u8; 32], // TODO
        elf_file.entrypoint,
        65536, // TODO
        elf_file.code_segment.start,
        elf_file.code_segment.end,
        0xd47a2000 - 65536, // TODO
        0xd47a2000, // TODO
        elf_file.data_segment.start,
        elf_file.data_segment.end,
        [0u8; 32], // TODO
        0 // TODO
    ).unwrap();

    let client = VanadiumClient::new(transport);
    let app_hmac = client.register_vapp(&manifest).await?;

    println!("HMAC: {:?}", app_hmac);

    client.run_vapp(&manifest, &app_hmac, &elf_file).await?;

    Ok(())
}
