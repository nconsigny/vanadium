use sdk::{
    comm::{self, SendMessageError},
    vanadium_client::{VAppClient, VAppExecutionError},
};
use serde::{Deserialize, Serialize};

pub struct DemoClient {
    app_client: Box<dyn VAppClient + Send + Sync>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Command {
    Commit { c_a: [u8; 32] },
    Reveal { m_a: u8, r_a: [u8; 32] },
}

impl DemoClient {
    pub fn new(app_client: Box<dyn VAppClient + Send + Sync>) -> Self {
        Self { app_client }
    }

    pub async fn commit(&mut self, c_a: [u8; 32]) -> Result<u8, Box<dyn core::error::Error>> {
        let command = Command::Commit { c_a };
        let msg = postcard::to_allocvec(&command).map_err(|_| "Serialization failed")?;
        let response = comm::send_message(&mut self.app_client, &msg).await?;
        if response.len() != 1 || response[0] > 2 {
            return Err("Invalid response from the app".into());
        }
        Ok(response[0])
    }

    pub async fn reveal(
        &mut self,
        m_a: u8,
        r_a: [u8; 32],
    ) -> Result<u8, Box<dyn core::error::Error>> {
        let command = Command::Reveal { m_a, r_a };
        let msg = postcard::to_allocvec(&command).map_err(|_| "Serialization failed")?;
        let response = comm::send_message(&mut self.app_client, &msg).await?;
        if response.len() != 1 || response[0] > 2 {
            return Err("Invalid response from the app".into());
        }
        Ok(response[0])
    }

    pub async fn exit(&mut self) -> Result<i32, Box<dyn core::error::Error>> {
        match comm::send_message(&mut self.app_client, &[]).await {
            Ok(_) => Err("Exit message shouldn't return!".into()),
            Err(SendMessageError::VAppExecutionError(VAppExecutionError::AppExited(code))) => {
                Ok(code)
            }
            Err(_) => Err("Unexpected error".into()),
        }
    }
}
