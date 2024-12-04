use common::{BigIntOperator, Command, HashId};
use sdk::{
    comm::{send_message, SendMessageError},
    vanadium_client::{VAppClient, VAppExecutionError},
};

#[derive(Debug)]
pub enum SadikClientError {
    VAppExecutionError(VAppExecutionError),
    GenericError(&'static str),
}

impl From<VAppExecutionError> for SadikClientError {
    fn from(e: VAppExecutionError) -> Self {
        Self::VAppExecutionError(e)
    }
}

impl From<&'static str> for SadikClientError {
    fn from(e: &'static str) -> Self {
        Self::GenericError(e)
    }
}

impl std::fmt::Display for SadikClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SadikClientError::VAppExecutionError(e) => write!(f, "VAppExecutionError: {}", e),
            SadikClientError::GenericError(e) => write!(f, "GenericError: {}", e),
        }
    }
}

impl std::error::Error for SadikClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SadikClientError::VAppExecutionError(e) => Some(e),
            SadikClientError::GenericError(_) => None,
        }
    }
}

pub struct SadikClient {
    app_client: Box<dyn VAppClient + Send + Sync>,
}

impl SadikClient {
    pub fn new(app_client: Box<dyn VAppClient + Send + Sync>) -> Self {
        Self { app_client }
    }

    pub async fn hash(
        &mut self,
        hash_id: HashId,
        data: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::Hash {
            hash_id: hash_id.into(),
            msg: data.to_vec(),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.app_client, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn bignum_operation(
        &mut self,
        operator: BigIntOperator,
        a: &[u8],
        b: &[u8],
        modulus: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::BigIntOperation {
            operator,
            a: a.to_vec(),
            b: b.to_vec(),
            modulus: modulus.to_vec(),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.app_client, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn exit(&mut self) -> Result<i32, &'static str> {
        match send_message(&mut self.app_client, &[]).await {
            Ok(_) => Err("Exit message shouldn't return!"),
            Err(SendMessageError::VAppExecutionError(VAppExecutionError::AppExited(code))) => {
                Ok(code)
            }
            Err(_) => Err("Unexpected error"),
        }
    }
}
