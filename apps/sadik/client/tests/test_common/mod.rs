use std::process::{Child, Command};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use vnd_sadik_client::SadikClient;

use sdk::{
    transport::{Transport, TransportTcp, TransportWrapper},
    vanadium_client::VanadiumAppClient,
};

pub struct TestSetup {
    pub client: SadikClient,
    child: Child,
}

impl TestSetup {
    async fn new() -> Self {
        let vanadium_binary = std::env::var("VANADIUM_BINARY")
            .unwrap_or_else(|_| "../../../vm/build/nanos2/bin/app.elf".to_string());
        let vapp_binary = std::env::var("VAPP_BINARY").unwrap_or_else(|_| {
            "../app/target/riscv32i-unknown-none-elf/release/vnd-sadik".to_string()
        });

        let child = Command::new("speculos")
            .arg(vanadium_binary)
            .arg("--display")
            .arg("headless")
            .spawn()
            .expect("Failed to start speculos process");

        sleep(Duration::from_secs(1));

        let transport_raw: Arc<
            dyn Transport<Error = Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
        > = Arc::new(
            TransportTcp::new()
                .await
                .expect("Unable to get TCP transport. Is speculos running?"),
        );
        let transport = TransportWrapper::new(transport_raw.clone());

        let (vanadium_client, _) = VanadiumAppClient::new(&vapp_binary, Arc::new(transport), None)
            .await
            .expect("Failed to create client");

        let client = SadikClient::new(Box::new(vanadium_client));

        TestSetup { client, child }
    }
}

impl Drop for TestSetup {
    fn drop(&mut self) {
        self.child.kill().expect("Failed to kill speculos process");
        self.child
            .wait()
            .expect("Failed to wait on speculos process");
    }
}

pub async fn setup() -> TestSetup {
    TestSetup::new().await
}
