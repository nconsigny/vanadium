use crate::commands::Command;
use sdk::vanadium_client::{VAppClient, VAppExecutionError};

pub struct TestClient {
    app_client: Box<dyn VAppClient + Send + Sync>,
}

impl TestClient {
    pub fn new(app_client: Box<dyn VAppClient + Send + Sync>) -> Self {
        Self { app_client }
    }

    pub async fn reverse(&mut self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::Reverse as u8]);
        msg.extend_from_slice(data);

        Ok(self
            .app_client
            .send_message(msg)
            .await
            .map_err(|_| "Failed")?)
    }

    pub async fn add_numbers(&mut self, n: u32) -> Result<u64, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::AddNumbers as u8]);
        msg.extend_from_slice(&n.to_be_bytes());

        let result_raw = self
            .app_client
            .send_message(msg)
            .await
            .map_err(|_| "Failed")?;

        if result_raw.len() != 8 {
            return Err("Invalid response length");
        }
        Ok(u64::from_be_bytes(result_raw.try_into().unwrap()))
    }

    pub async fn sha256(&mut self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::Sha256 as u8]);
        msg.extend_from_slice(data);

        Ok(self
            .app_client
            .send_message(msg)
            .await
            .map_err(|_| "Failed")?)
    }

    pub async fn b58enc(&mut self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::Base58Encode as u8]);
        msg.extend_from_slice(data);

        Ok(self
            .app_client
            .send_message(msg)
            .await
            .map_err(|_| "Failed")?)
    }

    pub async fn nprimes(&mut self, n: u32) -> Result<u32, &'static str> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[Command::CountPrimes as u8]);
        msg.extend_from_slice(&n.to_be_bytes());

        let result_raw = self
            .app_client
            .send_message(msg)
            .await
            .map_err(|_| "Failed")?;

        if result_raw.len() != 4 {
            return Err("Invalid response length");
        }
        Ok(u32::from_be_bytes(result_raw.try_into().unwrap()))
    }

    pub async fn exit(&mut self) -> Result<i32, &'static str> {
        match self.app_client.send_message(Vec::new()).await {
            Ok(_) => {
                return Err("Exit message shouldn't return!");
            }
            Err(e) => match e {
                VAppExecutionError::AppExited(status) => Ok(status),
                _ => Err("Unexpected error"),
            },
        }
    }
}
