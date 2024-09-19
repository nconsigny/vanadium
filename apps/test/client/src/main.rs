use clap::Parser;
use hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;

use sdk::{
    elf::ElfFile,
    manifest::Manifest,
    transport::{Transport, TransportHID, TransportTcp, TransportWrapper},
    vanadium_client::{Callbacks, ReceiveBufferError, VanadiumClient},
};

mod commands;

use commands::Command;

use std::io::{stdin, Write};
use std::sync::Arc;
use std::{io::stdout, path::Path};
#[derive(Parser)]
#[command(name = "Vanadium", about = "Run a V-App on Vanadium")]
struct Args {
    /// Path to the ELF file of the V-App (if not the default one)
    elf: Option<String>,

    /// Use the HID interface for a real device, instead of Speculos
    #[arg(long)]
    hid: bool,
}

// TODO: maybe this can be made generic enough to move to the client-sdk
struct TestClientRunner<T: Transport> {
    client: VanadiumClient<T>,
    elf_file: ElfFile,
    manifest: Manifest,
    app_hmac: Option<[u8; 32]>,
}

impl<T: Transport> TestClientRunner<T> {
    pub fn new(transport: T, elf_path: &str) -> Result<Self, std::io::Error> {
        let elf_file = ElfFile::new(Path::new(&elf_path))?;

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

        Ok(Self {
            client: VanadiumClient::new(transport),
            elf_file,
            manifest,
            app_hmac: None,
        })
    }

    pub async fn register_vapp(&mut self) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let app_hmac = self.client.register_vapp(&self.manifest).await?;
        self.app_hmac = Some(app_hmac);

        Ok(app_hmac)
    }

    pub async fn run_vapp(
        &mut self,
        callbacks: TestAppCallbacks,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        let app_hmac = self.app_hmac.ok_or("V-App not registered")?;

        let result = self
            .client
            .run_vapp(&self.manifest, &app_hmac, &self.elf_file, &callbacks)
            .await?;
        if result.len() != 4 {
            panic!("The V-App exited, but did not return correctly return a status");
        }
        let status = i32::from_be_bytes([result[0], result[1], result[2], result[3]]);
        println!("App exited with status: {}", status);

        Ok(status)
    }
}

struct TestAppCallbacks;

impl Callbacks for TestAppCallbacks {
    fn receive_buffer(&self) -> Result<Vec<u8>, ReceiveBufferError> {
        // Prompt the user to input a data buffer in hex; send it to the V-App
        let mut buffer = String::new();
        let bytes = loop {
            print!("Enter a data buffer in hexadecimal: ");
            stdout().flush().unwrap();
            buffer.clear();
            stdin().read_line(&mut buffer).unwrap();
            buffer = buffer.trim().to_string();

            if let Ok(bytes) = hex::decode(&buffer) {
                break bytes;
            } else {
                println!("Invalid hexadecimal input. Please try again.");
            }
        };

        Ok(bytes)
    }

    fn send_buffer(&self, buffer: &[u8]) {
        println!("Received buffer: {}", hex::encode(&buffer));
    }

    fn send_panic(&self, msg: &[u8]) {
        println!(
            "Received panic message:\n{}",
            core::str::from_utf8(&msg).unwrap()
        );
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let default_elf_path = "../app/target/riscv32i-unknown-none-elf/release/vnd-test";
    let elf_path_str = args.elf.unwrap_or(default_elf_path.to_string());

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

    let callbacks = TestAppCallbacks;

    let mut test_runner = TestClientRunner::new(transport, &elf_path_str)?;

    test_runner.register_vapp().await?;

    let status = test_runner.run_vapp(callbacks).await?;

    println!("App exited with status: {}", status);

    Ok(())
}
