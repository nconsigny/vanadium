use sdk::{comm, vanadium_client::VAppClient};

pub struct DemoClient {
    app_client: Box<dyn VAppClient + Send + Sync>,
}

impl DemoClient {
    pub fn new(app_client: Box<dyn VAppClient + Send + Sync>) -> Self {
        Self { app_client }
    }

    pub async fn echo(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
        Ok(comm::send_message(&mut self.app_client, &data).await?)
    }
}
