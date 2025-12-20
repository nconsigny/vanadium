//! Command identifiers for the Ethereum V-App wire protocol.
//!
//! These constants define the command bytes used in the protocol.
//! See `docs/protocol.md` for the full specification.

/// Command identifiers for the Ethereum V-App.
///
/// Each command has a unique byte identifier used in the wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    // Configuration commands
    /// Return version, feature flags, and settings.
    GetAppConfiguration = 0x01,
    /// Return 32 random bytes for challenge-response.
    GetChallenge = 0x02,

    // Transaction signing
    /// Sign a legacy or EIP-2718 typed transaction.
    SignTransaction = 0x03,
    /// Sign an EIP-191 personal message.
    SignPersonalMessage = 0x04,
    /// Sign pre-hashed EIP-712 typed data.
    SignEip712Hashed = 0x05,
    /// Sign full EIP-712 typed data with parsing.
    SignEip712Message = 0x06,

    // Eth2 staking (not implemented in minimal version)
    /// Return BLS public key for validator.
    Eth2GetPublicKey = 0x10,
    /// Configure withdrawal credential index.
    Eth2SetWithdrawalIndex = 0x11,

    // Metadata provision
    /// Provide verified ERC-20 token metadata.
    ProvideErc20TokenInfo = 0x20,
    /// Provide verified NFT collection metadata.
    ProvideNftInfo = 0x21,
    /// Provide verified domain name resolution.
    ProvideDomainName = 0x22,
    /// Provide verified contract method ABI info.
    LoadContractMethodInfo = 0x23,
    /// Set context for metadata lookup.
    ByContractAddressAndChain = 0x24,

    // Clear signing
    /// Sign transaction with full metadata display.
    ClearSignTransaction = 0x30,

    // Internal
    /// Exit the V-App (for testing).
    Exit = 0xFF,
}

impl TryFrom<u8> for Command {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Command::GetAppConfiguration),
            0x02 => Ok(Command::GetChallenge),
            0x03 => Ok(Command::SignTransaction),
            0x04 => Ok(Command::SignPersonalMessage),
            0x05 => Ok(Command::SignEip712Hashed),
            0x06 => Ok(Command::SignEip712Message),
            0x10 => Ok(Command::Eth2GetPublicKey),
            0x11 => Ok(Command::Eth2SetWithdrawalIndex),
            0x20 => Ok(Command::ProvideErc20TokenInfo),
            0x21 => Ok(Command::ProvideNftInfo),
            0x22 => Ok(Command::ProvideDomainName),
            0x23 => Ok(Command::LoadContractMethodInfo),
            0x24 => Ok(Command::ByContractAddressAndChain),
            0x30 => Ok(Command::ClearSignTransaction),
            0xFF => Ok(Command::Exit),
            _ => Err(()),
        }
    }
}

/// Chunk flags for multi-part messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkFlags {
    /// Continuation chunk (neither first nor last).
    Continue = 0x00,
    /// First chunk of a multi-part message.
    First = 0x01,
    /// Last chunk of a multi-part message.
    Last = 0x02,
    /// Single chunk (both first and last).
    Single = 0x03,
}

impl ChunkFlags {
    /// Returns true if this is the first chunk.
    pub fn is_first(self) -> bool {
        matches!(self, ChunkFlags::First | ChunkFlags::Single)
    }

    /// Returns true if this is the last chunk.
    pub fn is_last(self) -> bool {
        matches!(self, ChunkFlags::Last | ChunkFlags::Single)
    }
}

impl TryFrom<u8> for ChunkFlags {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(ChunkFlags::Continue),
            0x01 => Ok(ChunkFlags::First),
            0x02 => Ok(ChunkFlags::Last),
            0x03 => Ok(ChunkFlags::Single),
            _ => Err(()),
        }
    }
}
