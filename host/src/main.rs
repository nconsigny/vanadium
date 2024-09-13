mod apdu;
mod elf;
mod transport;
mod vanadium_client;

use clap::Parser;
use common::manifest::Manifest;
use hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;
use transport::{Transport, TransportHID, TransportTcp, TransportWrapper};

use std::path::Path;
use std::sync::Arc;
use vanadium_client::VanadiumClient;

use elf::ElfFile;

#[derive(Parser)]
#[command(name = "Vanadium", about = "Run a V-App on Vanadium")]
struct Args {
    /// Path to the ELF file of the V-App
    #[arg(required = true)]
    elf: String,

    /// Use the HID interface for a real device, instead of Speculos
    #[arg(long)]
    hid: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let elf_path = Path::new(&args.elf);
    let elf_file = ElfFile::new(elf_path)?;

    // println!("Entrypoint: {:?}", elf_file.entrypoint);
    // println!("{:?}", elf_file);

    let transport_raw: Arc<dyn Transport<Error = Box<dyn std::error::Error>> + Send + Sync> =
        if args.hid {
            Arc::new(TransportHID::new(
                TransportNativeHID::new(
                    &HidApi::new().expect("Unable to get connect to the device"),
                )
                .unwrap(),
            ))
        } else {
            Arc::new(
                TransportTcp::new()
                    .await
                    .expect("Unable to get TCP transport. Is speculos running?"),
            )
        };
    let transport = TransportWrapper::new(transport_raw);

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
        0xd47a2000,         // TODO
        elf_file.data_segment.start,
        elf_file.data_segment.end,
        [0u8; 32], // TODO
        0,         // TODO
    )
    .unwrap();

    let client = VanadiumClient::new(transport);
    let app_hmac = client.register_vapp(&manifest).await?;

    println!("HMAC: {:?}", app_hmac);

    client.run_vapp(&manifest, &app_hmac, &elf_file).await?;

    Ok(())
}
