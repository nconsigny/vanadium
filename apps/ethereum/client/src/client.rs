//! Ethereum V-App client implementation.
//!
//! Provides async methods for all V-App commands.

#![allow(dead_code)]

use common::error::Error as AppError;
use common::message::{Request, Response};
use common::types::{
    AppConfiguration, Bip32Path, DomainInfo, EthAddress, Hash256, NftInfo, Signature, TokenInfo,
};
use sdk::comm::SendMessageError;
use sdk::vanadium_client::{VAppExecutionError, VAppTransport};

/// Errors that can occur when using the Ethereum client.
#[derive(Debug)]
pub enum EthereumClientError {
    /// Error executing V-App.
    VAppExecutionError(VAppExecutionError),
    /// Error sending message.
    SendMessageError(SendMessageError),
    /// V-App returned an error response.
    AppError(AppError),
    /// V-App response was unexpected type.
    InvalidResponse(String),
    /// Generic error.
    GenericError(String),
}

impl From<VAppExecutionError> for EthereumClientError {
    fn from(e: VAppExecutionError) -> Self {
        Self::VAppExecutionError(e)
    }
}

impl From<SendMessageError> for EthereumClientError {
    fn from(e: SendMessageError) -> Self {
        Self::SendMessageError(e)
    }
}

impl From<&'static str> for EthereumClientError {
    fn from(e: &'static str) -> Self {
        Self::GenericError(e.to_string())
    }
}

impl From<String> for EthereumClientError {
    fn from(e: String) -> Self {
        Self::GenericError(e)
    }
}

impl std::fmt::Display for EthereumClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EthereumClientError::VAppExecutionError(e) => write!(f, "VAppExecutionError: {}", e),
            EthereumClientError::SendMessageError(e) => write!(f, "SendMessageError: {}", e),
            EthereumClientError::AppError(e) => write!(f, "AppError: {}", e),
            EthereumClientError::InvalidResponse(e) => write!(f, "InvalidResponse: {}", e),
            EthereumClientError::GenericError(e) => write!(f, "GenericError: {}", e),
        }
    }
}

impl std::error::Error for EthereumClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EthereumClientError::VAppExecutionError(e) => Some(e),
            EthereumClientError::SendMessageError(e) => Some(e),
            _ => None,
        }
    }
}

/// Ethereum V-App client.
pub struct EthereumClient {
    app_transport: Box<dyn VAppTransport + Send>,
}

impl EthereumClient {
    /// Creates a new Ethereum client with the given transport.
    pub fn new(app_transport: Box<dyn VAppTransport + Send>) -> Self {
        Self { app_transport }
    }

    /// Sends a message to the V-App and receives the response.
    async fn send_message(&mut self, out: &[u8]) -> Result<Vec<u8>, EthereumClientError> {
        sdk::comm::send_message(&mut self.app_transport, out)
            .await
            .map_err(EthereumClientError::from)
    }

    /// Parses a response from the V-App.
    fn parse_response(response_raw: &[u8]) -> Result<Response, EthereumClientError> {
        let resp: Response = postcard::from_bytes(response_raw).map_err(|_| {
            EthereumClientError::GenericError("Failed to parse response".to_string())
        })?;

        if let Response::Error(e) = resp {
            return Err(EthereumClientError::AppError(e));
        }

        Ok(resp)
    }

    /// Exits the V-App.
    pub async fn exit(&mut self) -> Result<i32, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::Exit)
            .map_err(|_| EthereumClientError::GenericError("Failed to serialize Exit".to_string()))?;

        match self.send_message(&msg).await {
            Ok(_) => Err(EthereumClientError::GenericError(
                "exit shouldn't return a response".to_string(),
            )),
            Err(e) => match e {
                EthereumClientError::SendMessageError(SendMessageError::VAppExecutionError(
                    VAppExecutionError::AppExited(status),
                )) => Ok(status),
                e => Err(EthereumClientError::InvalidResponse(format!(
                    "Unexpected error on exit: {:?}",
                    e
                ))),
            },
        }
    }

    /// Gets the app configuration and version.
    pub async fn get_app_configuration(&mut self) -> Result<AppConfiguration, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::GetAppConfiguration).map_err(|_| {
            EthereumClientError::GenericError("Failed to serialize GetAppConfiguration".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::AppConfiguration(config) => Ok(config),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Gets a random challenge for replay protection.
    pub async fn get_challenge(&mut self) -> Result<[u8; 32], EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::GetChallenge).map_err(|_| {
            EthereumClientError::GenericError("Failed to serialize GetChallenge".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::Challenge(challenge) => Ok(challenge),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Signs a transaction.
    ///
    /// # Arguments
    /// * `path` - BIP32 derivation path (e.g., "m/44'/60'/0'/0/0")
    /// * `tx_data` - RLP-encoded transaction data
    pub async fn sign_transaction(
        &mut self,
        path: &[u32],
        tx_data: &[u8],
    ) -> Result<Signature, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::SignTransaction {
            path: Bip32Path::from_slice(path),
            tx_data: tx_data.to_vec(),
        })
        .map_err(|_| {
            EthereumClientError::GenericError("Failed to serialize SignTransaction".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::Signature(sig) => Ok(sig),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Signs a personal message (EIP-191).
    ///
    /// # Arguments
    /// * `path` - BIP32 derivation path
    /// * `message` - Message to sign
    pub async fn sign_personal_message(
        &mut self,
        path: &[u32],
        message: &[u8],
    ) -> Result<Signature, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::SignPersonalMessage {
            path: Bip32Path::from_slice(path),
            message: message.to_vec(),
        })
        .map_err(|_| {
            EthereumClientError::GenericError("Failed to serialize SignPersonalMessage".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::Signature(sig) => Ok(sig),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Signs pre-hashed EIP-712 typed data.
    ///
    /// # Arguments
    /// * `path` - BIP32 derivation path
    /// * `domain_hash` - EIP-712 domain separator hash
    /// * `message_hash` - EIP-712 message hash
    pub async fn sign_eip712_hashed(
        &mut self,
        path: &[u32],
        domain_hash: &Hash256,
        message_hash: &Hash256,
    ) -> Result<Signature, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::SignEip712Hashed {
            path: Bip32Path::from_slice(path),
            domain_hash: *domain_hash,
            message_hash: *message_hash,
        })
        .map_err(|_| {
            EthereumClientError::GenericError("Failed to serialize SignEip712Hashed".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::Signature(sig) => Ok(sig),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Signs full EIP-712 typed data.
    pub async fn sign_eip712_message(
        &mut self,
        path: &[u32],
        typed_data: &[u8],
    ) -> Result<Signature, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::SignEip712Message {
            path: Bip32Path::from_slice(path),
            typed_data: typed_data.to_vec(),
        })
        .map_err(|_| {
            EthereumClientError::GenericError("Failed to serialize SignEip712Message".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::Signature(sig) => Ok(sig),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Provides ERC-20 token information.
    pub async fn provide_erc20_token_info(
        &mut self,
        info: TokenInfo,
        signature: Vec<u8>,
    ) -> Result<bool, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::ProvideErc20TokenInfo { info, signature })
            .map_err(|_| {
            EthereumClientError::GenericError(
                "Failed to serialize ProvideErc20TokenInfo".to_string(),
            )
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::Accepted(accepted) => Ok(accepted),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Provides NFT collection information.
    pub async fn provide_nft_info(
        &mut self,
        info: NftInfo,
        signature: Vec<u8>,
    ) -> Result<bool, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::ProvideNftInfo { info, signature }).map_err(
            |_| EthereumClientError::GenericError("Failed to serialize ProvideNftInfo".to_string()),
        )?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::Accepted(accepted) => Ok(accepted),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Provides domain name resolution.
    pub async fn provide_domain_name(
        &mut self,
        info: DomainInfo,
        signature: Vec<u8>,
    ) -> Result<bool, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::ProvideDomainName { info, signature }).map_err(
            |_| {
                EthereumClientError::GenericError("Failed to serialize ProvideDomainName".to_string())
            },
        )?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::Accepted(accepted) => Ok(accepted),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Sets context for metadata lookup.
    pub async fn by_contract_address_and_chain(
        &mut self,
        chain_id: u64,
        address: EthAddress,
    ) -> Result<bool, EthereumClientError> {
        let msg = postcard::to_allocvec(&Request::ByContractAddressAndChain { chain_id, address })
            .map_err(|_| {
                EthereumClientError::GenericError(
                    "Failed to serialize ByContractAddressAndChain".to_string(),
                )
            })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw)? {
            Response::ContextBound(bound) => Ok(bound),
            e => Err(EthereumClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }
}

/// Parses a derivation path string into u32 array.
///
/// # Arguments
/// * `path` - Path string like "m/44'/60'/0'/0/0"
///
/// # Returns
/// Vector of u32 path components with hardened flag.
pub fn parse_derivation_path(path: &str) -> Result<Vec<u32>, String> {
    let mut components = path.split('/').collect::<Vec<&str>>();

    // Remove "m" prefix if present
    if let Some(first) = components.first() {
        if *first == "m" {
            components.remove(0);
        }
    }

    let mut indices = Vec::new();
    for comp in components {
        let hardened = comp.ends_with('\'') || comp.ends_with('h');
        let raw_index = if hardened {
            &comp[..comp.len() - 1]
        } else {
            comp
        };

        let index: u32 = raw_index
            .parse()
            .map_err(|e| format!("Invalid index '{}': {}", comp, e))?;

        let child_number = if hardened {
            0x80000000u32
                .checked_add(index)
                .ok_or_else(|| format!("Index overflow for '{}'", comp))?
        } else {
            index
        };

        indices.push(child_number);
    }

    Ok(indices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_derivation_path() {
        let path = parse_derivation_path("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(path.len(), 5);
        assert_eq!(path[0], 0x8000002C); // 44'
        assert_eq!(path[1], 0x8000003C); // 60'
        assert_eq!(path[2], 0x80000000); // 0'
        assert_eq!(path[3], 0);          // 0
        assert_eq!(path[4], 0);          // 0
    }

    #[test]
    fn test_parse_derivation_path_no_m() {
        let path = parse_derivation_path("44'/60'/0'/0/0").unwrap();
        assert_eq!(path.len(), 5);
    }
}
