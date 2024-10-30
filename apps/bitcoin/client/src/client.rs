use common::message::{
    mod_Request::OneOfrequest, mod_Response::OneOfresponse, Request, RequestGetMasterFingerprint,
    Response,
};
use common::message::{RequestExit, RequestGetVersion};
use quick_protobuf::{BytesReader, BytesWriter, MessageRead, MessageWrite, Writer};
use sdk::vanadium_client::{VAppClient, VAppExecutionError};

use sdk::comm::SendMessageError;

#[derive(Debug)]
pub enum BitcoinClientError {
    VAppExecutionError(VAppExecutionError),
    SendMessageError(SendMessageError),
    InvalidResponse(&'static str),
    GenericError(&'static str),
}

impl From<VAppExecutionError> for BitcoinClientError {
    fn from(e: VAppExecutionError) -> Self {
        Self::VAppExecutionError(e)
    }
}

impl From<SendMessageError> for BitcoinClientError {
    fn from(e: SendMessageError) -> Self {
        Self::SendMessageError(e)
    }
}

impl From<&'static str> for BitcoinClientError {
    fn from(e: &'static str) -> Self {
        Self::GenericError(e)
    }
}

impl std::fmt::Display for BitcoinClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinClientError::VAppExecutionError(e) => write!(f, "VAppExecutionError: {}", e),
            BitcoinClientError::SendMessageError(e) => write!(f, "SendMessageError: {}", e),
            BitcoinClientError::InvalidResponse(e) => write!(f, "InvalidResponse: {}", e),
            BitcoinClientError::GenericError(e) => write!(f, "GenericError: {}", e),
        }
    }
}

impl std::error::Error for BitcoinClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BitcoinClientError::VAppExecutionError(e) => Some(e),
            BitcoinClientError::SendMessageError(e) => Some(e),
            BitcoinClientError::InvalidResponse(_) => None,
            BitcoinClientError::GenericError(_) => None,
        }
    }
}

pub struct BitcoinClient {
    app_client: Box<dyn VAppClient + Send + Sync>,
}

impl BitcoinClient {
    pub fn new(app_client: Box<dyn VAppClient + Send + Sync>) -> Self {
        Self { app_client }
    }

    pub async fn get_version(&mut self) -> Result<String, BitcoinClientError> {
        let req = Request {
            request: OneOfrequest::get_version(RequestGetVersion {}),
        };

        let mut out = vec![0; req.get_size()];
        let mut writer = Writer::new(BytesWriter::new(&mut out));
        req.write_message(&mut writer).unwrap();

        let response_raw = sdk::comm::send_message(&mut self.app_client, &out).await?;

        let mut reader = BytesReader::from_bytes(&response_raw);
        let response: Response = Response::from_reader(&mut reader, &response_raw)
            .map_err(|_| "Failed to parse request")?; // TODO: proper error handling

        match response.response {
            OneOfresponse::get_version(resp) => Ok(String::from(resp.version)),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }

    pub async fn exit(&mut self) -> Result<i32, BitcoinClientError> {
        let req = Request {
            request: OneOfrequest::exit(RequestExit {}),
        };

        let mut out = vec![0; req.get_size()];
        let mut writer = Writer::new(BytesWriter::new(&mut out));
        req.write_message(&mut writer).unwrap();

        match sdk::comm::send_message(&mut self.app_client, &out).await {
            Ok(_) => Err(BitcoinClientError::InvalidResponse(
                "Exit message shouldn't return!",
            )),
            Err(e) => match e {
                SendMessageError::VAppExecutionError(VAppExecutionError::AppExited(status)) => {
                    Ok(status)
                }
                _ => Err(BitcoinClientError::InvalidResponse(
                    "Unexpected error on exit",
                )),
            },
        }
    }

    pub async fn get_master_fingerprint(&mut self) -> Result<u32, BitcoinClientError> {
        let req = Request {
            request: OneOfrequest::get_master_fingerprint(RequestGetMasterFingerprint {}),
        };

        let mut out = vec![0; req.get_size()];
        let mut writer = Writer::new(BytesWriter::new(&mut out));
        req.write_message(&mut writer).unwrap();

        let response_raw = sdk::comm::send_message(&mut self.app_client, &out).await?;

        let mut reader = BytesReader::from_bytes(&response_raw);
        let response: Response = Response::from_reader(&mut reader, &response_raw)
            .map_err(|_| "Failed to parse request")?; // TODO: proper error handling

        match response.response {
            OneOfresponse::get_master_fingerprint(resp) => Ok(resp.fingerprint),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }
}
