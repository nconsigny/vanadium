use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use common::message::{
    mod_Request::OneOfrequest, mod_Response::OneOfresponse, Request, RequestGetMasterFingerprint,
    Response,
};
use common::message::{
    Account, AccountCoordinates, RequestExit, RequestGetAddress, RequestGetExtendedPubkey,
    RequestGetVersion,
};
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

impl<'a> BitcoinClient {
    pub fn new(app_client: Box<dyn VAppClient + Send + Sync>) -> Self {
        Self { app_client }
    }

    async fn create_request<T: MessageWrite>(
        request: OneOfrequest<'_>,
    ) -> Result<Vec<u8>, BitcoinClientError> {
        let req = Request { request };
        let mut out = vec![0; req.get_size()];
        let mut writer = Writer::new(BytesWriter::new(&mut out));
        req.write_message(&mut writer)
            .map_err(|_| BitcoinClientError::GenericError("Failed to write message"))?;
        Ok(out)
    }

    async fn send_message(&mut self, out: Vec<u8>) -> Result<Vec<u8>, BitcoinClientError> {
        sdk::comm::send_message(&mut self.app_client, &out)
            .await
            .map_err(BitcoinClientError::from)
    }

    async fn parse_response<T: MessageRead<'a>>(
        response_raw: &'a [u8],
    ) -> Result<T, BitcoinClientError> {
        let mut reader = BytesReader::from_bytes(&response_raw);
        T::from_reader(&mut reader, response_raw)
            .map_err(|_| BitcoinClientError::GenericError("Failed to parse response"))
    }

    pub async fn get_version(&mut self) -> Result<String, BitcoinClientError> {
        let out = Self::create_request::<RequestGetVersion>(OneOfrequest::get_version(
            RequestGetVersion {},
        ))
        .await?;

        let response_raw = self.send_message(out).await?;
        let response: Response = Self::parse_response(&response_raw).await?;
        match response.response {
            OneOfresponse::get_version(resp) => Ok(String::from(resp.version)),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }

    pub async fn exit(&mut self) -> Result<i32, BitcoinClientError> {
        let out = Self::create_request::<RequestExit>(OneOfrequest::exit(RequestExit {})).await?;
        match self.send_message(out).await {
            Ok(_) => Err(BitcoinClientError::InvalidResponse(
                "Exit message shouldn't return!",
            )),
            Err(e) => match e {
                BitcoinClientError::VAppExecutionError(VAppExecutionError::AppExited(status)) => {
                    Ok(status)
                }
                e => {
                    println!("Unexpected error on exit: {:?}", e);
                    Err(BitcoinClientError::InvalidResponse(
                        "Unexpected error on exit",
                    ))
                }
            },
        }
    }

    pub async fn get_master_fingerprint(&mut self) -> Result<u32, BitcoinClientError> {
        let out = Self::create_request::<RequestGetMasterFingerprint>(
            OneOfrequest::get_master_fingerprint(RequestGetMasterFingerprint {}),
        )
        .await?;
        let response_raw = self.send_message(out).await?;
        let response: Response = Self::parse_response(&response_raw).await?;
        match response.response {
            OneOfresponse::get_master_fingerprint(resp) => Ok(resp.fingerprint),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }

    pub async fn get_extended_pubkey(
        &mut self,
        bip32_path: &str,
        display: bool,
    ) -> Result<[u8; 78], BitcoinClientError> {
        let path =
            DerivationPath::from_str(bip32_path).map_err(|_| "Failed to convert bip32_path")?;

        let out = Self::create_request::<RequestGetExtendedPubkey>(
            OneOfrequest::get_extended_pubkey(RequestGetExtendedPubkey {
                display,
                bip32_path: path.into_iter().map(|step| (*step).into()).collect(),
            }),
        )
        .await?;
        let response_raw = self.send_message(out).await?;
        let response: Response = Self::parse_response(&response_raw).await?;
        match response.response {
            OneOfresponse::get_extended_pubkey(resp) => resp
                .pubkey
                .as_ref()
                .try_into()
                .map_err(|_| BitcoinClientError::InvalidResponse("Invalid pubkey length")),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }

    pub async fn get_address<'b, T: common::account::Account + 'static>(
        &mut self,
        account: &'b T,
        name: &str,
        coords: &'b T::Coordinates,
        display: bool,
    ) -> Result<String, BitcoinClientError>
    where
        Account<'b>: From<&'b T>,
        AccountCoordinates: From<&'b T::Coordinates>,
    {
        let out = Self::create_request::<RequestGetAddress>(OneOfrequest::get_address(
            RequestGetAddress {
                display,
                name: name.into(),
                account: Some(Account::try_from(account).map_err(|_| "Failed to convert account")?),
                account_coordinates: Some(
                    AccountCoordinates::try_from(coords)
                        .map_err(|_| "Failed to convert coordinates")?,
                ),
            },
        ))
        .await?;
        let response_raw = self.send_message(out).await?;
        let response: Response = Self::parse_response(&response_raw).await?;
        match response.response {
            OneOfresponse::get_address(resp) => Ok(resp.address.into()),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }
}
