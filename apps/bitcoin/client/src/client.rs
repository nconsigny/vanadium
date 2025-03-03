use common::message::mod_Account::OneOfaccount;
use common::message::{
    mod_Request::OneOfrequest, mod_Response::OneOfresponse, Request, RequestGetMasterFingerprint,
    Response,
};
use common::message::{
    Account, AccountCoordinates, KeyInformation, KeyOrigin, RequestExit, RequestGetAddress,
    RequestGetVersion, WalletPolicy, WalletPolicyCoordinates,
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

    pub async fn get_address(&mut self) -> Result<String, BitcoinClientError> {
        // TODO: actually add params
        let pubkey_str ="tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U";
        let pubkey = bitcoin::base58::decode_check(pubkey_str).unwrap();

        let out = Self::create_request::<RequestGetAddress>(OneOfrequest::get_address(
            RequestGetAddress {
                display: true,
                name: "".into(),
                account: Some(Account {
                    account: OneOfaccount::wallet_policy(WalletPolicy {
                        descriptor_template: "tr(@0/**)".into(),
                        keys_info: vec![
                            KeyInformation {
                                pubkey: std::borrow::Cow::Borrowed(&pubkey),
                                origin: Some(KeyOrigin {
                                    fingerprint: 0xf5acc2fd,
                                    path: vec![0x80000056, 0x80000001, 0x80000000]
                                }),
                            },
                        ],
                    }),
                }),
                account_coordinates: Some(AccountCoordinates {
                    account: common::message::mod_AccountCoordinates::OneOfaccount::wallet_policy_coordinates(WalletPolicyCoordinates {
                        is_change: false,
                        address_index: 0,
                    }),
                }),
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
