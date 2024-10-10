use crate::commands::Command;
use sdk::vanadium_client::VanadiumClientError;
use sdk::{
    elf::ElfFile, manifest::Manifest, transport::Transport, vanadium_client::VanadiumClient,
};
use std::path::Path;
use std::sync::Arc;

pub struct TestClient {
    client: VanadiumClient,
    elf_file: ElfFile,
    manifest: Manifest,
    app_hmac: Option<[u8; 32]>,
}

impl TestClient {
    pub fn new(elf_path: &str) -> Result<Self, std::io::Error> {
        // TODO: some of this should be moved to the client-sdk
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
            client: VanadiumClient::new(),
            elf_file,
            manifest,
            app_hmac: None,
        })
    }

    pub async fn register_vapp<T: Transport>(
        &mut self,
        transport: &T,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let app_hmac = self.client.register_vapp(transport, &self.manifest).await?;
        self.app_hmac = Some(app_hmac);

        Ok(app_hmac)
    }

    pub fn run_vapp<E: std::fmt::Debug + 'static>(
        &mut self,
        transport: Arc<dyn Transport<Error = E>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let app_hmac = self.app_hmac.ok_or("V-App not registered")?;

        self.client
            .run_vapp(transport, &self.manifest, &app_hmac, &self.elf_file)?;

        Ok(())
    }

    pub async fn reverse(&mut self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::Reverse as u8]);
        msg.extend_from_slice(data);

        Ok(self.client.send_message(msg).await.map_err(|_| "Failed")?)
    }

    pub async fn add_numbers(&mut self, n: u32) -> Result<u64, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::AddNumbers as u8]);
        msg.extend_from_slice(&n.to_be_bytes());

        let result_raw = self.client.send_message(msg).await.map_err(|_| "Failed")?;

        if result_raw.len() != 8 {
            return Err("Invalid response length");
        }
        Ok(u64::from_be_bytes(result_raw.try_into().unwrap()))
    }

    pub async fn sha256(&mut self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::Sha256 as u8]);
        msg.extend_from_slice(data);

        Ok(self.client.send_message(msg).await.map_err(|_| "Failed")?)
    }

    pub async fn b58enc(&mut self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::Base58Encode as u8]);
        msg.extend_from_slice(data);

        Ok(self.client.send_message(msg).await.map_err(|_| "Failed")?)
    }

    pub async fn nprimes(&mut self, n: u32) -> Result<u32, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::CountPrimes as u8]);
        msg.extend_from_slice(&n.to_be_bytes());

        let result_raw = self.client.send_message(msg).await.map_err(|_| "Failed")?;

        if result_raw.len() != 4 {
            return Err("Invalid response length");
        }
        Ok(u32::from_be_bytes(result_raw.try_into().unwrap()))
    }

    pub async fn exit(&mut self) -> Result<i32, &'static str> {
        match self.client.send_message(Vec::new()).await {
            Ok(_) => {
                return Err("Exit message shouldn't return!");
            }
            Err(e) => match e {
                VanadiumClientError::VAppExited(status) => Ok(status),
                _ => Err("Unexpected error"),
            },
        }
    }
}
