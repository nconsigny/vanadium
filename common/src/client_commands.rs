// Vanadium VM client commands (responsed to InterruptedExecution status word), and other related types

use crate::constants::PAGE_SIZE;
use alloc::vec::Vec;

#[cfg(feature = "device_sdk")]
use ledger_device_sdk::io::Comm;

pub trait Message: Sized {
    fn serialize_with<F: FnMut(&[u8])>(&self, f: F);

    #[cfg(feature = "device_sdk")]
    #[inline]
    fn serialize_to_comm(&self, comm: &mut Comm) {
        self.serialize_with(|data| comm.append(data));
    }

    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.serialize_with(|data| result.extend_from_slice(data));
        result
    }

    fn deserialize(data: &[u8]) -> Result<Self, &'static str>;
}

// Commands from the VM to the client
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ClientCommandCode {
    GetPage = 0,
    CommitPage = 1,
    CommitPageContent = 2,
    SendBuffer = 3,
    ReceiveBuffer = 4,
    SendPanicBuffer = 5,
}

impl TryFrom<u8> for ClientCommandCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ClientCommandCode::GetPage),
            1 => Ok(ClientCommandCode::CommitPage),
            2 => Ok(ClientCommandCode::CommitPageContent),
            3 => Ok(ClientCommandCode::SendBuffer),
            4 => Ok(ClientCommandCode::ReceiveBuffer),
            5 => Ok(ClientCommandCode::SendPanicBuffer),
            _ => Err("Invalid value for ClientCommandCode"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SectionKind {
    Code = 0,
    Data = 1,
    Stack = 2,
}

impl TryFrom<u8> for SectionKind {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SectionKind::Code),
            1 => Ok(SectionKind::Data),
            2 => Ok(SectionKind::Stack),
            _ => Err("Invalid section kind"),
        }
    }
}

// We use the _Message ending for messages from the VM to the host, and the _Response ending for messages from the host to the VM.

/// Message sent by the VM to commit a page to the host
#[derive(Debug, Clone)]
pub struct CommitPageMessage {
    pub command_code: ClientCommandCode,
    pub section_kind: SectionKind,
    pub page_index: u32,
}

impl CommitPageMessage {
    #[inline]
    pub fn new(section_kind: SectionKind, page_index: u32) -> Self {
        CommitPageMessage {
            command_code: ClientCommandCode::CommitPage,
            section_kind,
            page_index,
        }
    }
}

impl Message for CommitPageMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&[self.section_kind as u8]);
        f(&self.page_index.to_be_bytes());
    }

    fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 6 {
            return Err("Invalid data for CommitPageMessage");
        }
        let command_code = ClientCommandCode::try_from(data[0])?;
        if !matches!(command_code, ClientCommandCode::CommitPage) {
            return Err("Invalid data for CommitPageMessage");
        }

        let section_kind = SectionKind::try_from(data[1])?;
        let page_index = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);

        Ok(CommitPageMessage {
            command_code,
            section_kind,
            page_index,
        })
    }
}

/// Part of the flow started with a CommitPageMessage; it contains the content of the page
#[derive(Debug, Clone)]
pub struct CommitPageContentMessage {
    pub command_code: ClientCommandCode,
    pub data: Vec<u8>,
}

impl CommitPageContentMessage {
    #[inline]
    pub fn new(data: Vec<u8>) -> Self {
        if data.len() != PAGE_SIZE {
            panic!("Invalid data length for CommitPageContentMessage");
        }
        CommitPageContentMessage {
            command_code: ClientCommandCode::CommitPageContent,
            data,
        }
    }
}

impl Message for CommitPageContentMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&self.data);
    }

    fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != PAGE_SIZE + 1 {
            return Err("Invalid data for CommitPageContentMessage");
        }

        let command_code = ClientCommandCode::try_from(data[0])?;
        if !matches!(command_code, ClientCommandCode::CommitPageContent) {
            return Err("Invalid data for CommitPageContentMessage");
        }
        Ok(CommitPageContentMessage {
            command_code,
            data: data[1..].to_vec(),
        })
    }
}

/// Message sent by the VM to request a page from the host
#[derive(Debug, Clone)]
pub struct GetPageMessage {
    pub command_code: ClientCommandCode,
    pub section_kind: SectionKind,
    pub page_index: u32,
}

impl GetPageMessage {
    #[inline]
    pub fn new(section_kind: SectionKind, page_index: u32) -> Self {
        GetPageMessage {
            command_code: ClientCommandCode::GetPage,
            section_kind,
            page_index,
        }
    }
}

impl Message for GetPageMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&[self.section_kind as u8]);
        f(&self.page_index.to_be_bytes());
    }

    fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 6 {
            return Err("Invalid data for GetPageMessage");
        }
        let command_code = ClientCommandCode::try_from(data[0])?;
        if !matches!(command_code, ClientCommandCode::GetPage) {
            return Err("Invalid data for GetPageMessage");
        }
        let section_kind = SectionKind::try_from(data[1])?;
        let page_index = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);

        Ok(GetPageMessage {
            command_code,
            section_kind,
            page_index,
        })
    }
}

/// Message sent by the VM to send a buffer (or the first chunk of it) to the host during an ECALL_XSEND.
#[derive(Debug, Clone)]
pub struct SendBufferMessage {
    pub command_code: ClientCommandCode,
    pub total_remaining_size: u32,
    pub data: Vec<u8>,
}

impl SendBufferMessage {
    #[inline]
    pub fn new(total_remaining_size: u32, data: Vec<u8>) -> Self {
        if data.len() > total_remaining_size as usize {
            panic!("Data size exceeds total remaining size");
        }

        SendBufferMessage {
            command_code: ClientCommandCode::SendBuffer,
            total_remaining_size,
            data,
        }
    }
}

impl Message for SendBufferMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&self.total_remaining_size.to_be_bytes());
        f(&self.data);
    }

    fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        let command_code = ClientCommandCode::try_from(data[0])?;
        if (!matches!(command_code, ClientCommandCode::SendBuffer)) || (data.len() < 5) {
            return Err("Invalid data for SendBufferMessage");
        }
        let total_remaining_size = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let data = data[5..].to_vec();

        if data.len() > total_remaining_size as usize {
            return Err("Data size exceeds total remaining size");
        }

        Ok(SendBufferMessage {
            command_code,
            total_remaining_size,
            data,
        })
    }
}

/// Message sent by the VM to receive a buffer during an ECALL_XRECV.
#[derive(Debug, Clone)]
pub struct ReceiveBufferMessage {
    pub command_code: ClientCommandCode,
}

impl ReceiveBufferMessage {
    #[inline]
    pub fn new() -> Self {
        ReceiveBufferMessage {
            command_code: ClientCommandCode::ReceiveBuffer,
        }
    }
}

impl Message for ReceiveBufferMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
    }
    fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 1 {
            return Err("Invalid data for ReceiveBufferMessage");
        }
        let command_code = ClientCommandCode::try_from(data[0])?;
        if !matches!(command_code, ClientCommandCode::ReceiveBuffer) {
            return Err("Invalid data for ReceiveBufferMessage");
        }

        Ok(ReceiveBufferMessage { command_code })
    }
}

/// The host's response to a ReceiveBufferMessage.
#[derive(Debug, Clone)]
pub struct ReceiveBufferResponse {
    pub remaining_length: u32,
    pub content: Vec<u8>,
}

impl ReceiveBufferResponse {
    #[inline]
    pub fn new(remaining_length: u32, content: Vec<u8>) -> Self {
        ReceiveBufferResponse {
            remaining_length,
            content,
        }
    }
}

impl Message for ReceiveBufferResponse {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&self.remaining_length.to_be_bytes());
        f(&self.content);
    }

    #[inline]
    fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 4 {
            return Err("Invalid data for ReceiveBufferResponse");
        }
        let remaining_length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if data.len() - 4 > remaining_length as usize {
            return Err("Data for ReceiveBufferResponse is too long");
        }
        Ok(ReceiveBufferResponse {
            remaining_length,
            content: data[4..].to_vec(),
        })
    }
}

/// Identical to SendBufferMessage, except for the different command code; used for panics.
#[derive(Debug, Clone)]
pub struct SendPanicBufferMessage {
    pub command_code: ClientCommandCode,
    pub total_remaining_size: u32,
    pub data: Vec<u8>,
}

impl SendPanicBufferMessage {
    #[inline]
    pub fn new(total_remaining_size: u32, data: Vec<u8>) -> Self {
        if data.len() > total_remaining_size as usize {
            panic!("Data size exceeds total remaining size");
        }

        SendPanicBufferMessage {
            command_code: ClientCommandCode::SendPanicBuffer,
            total_remaining_size,
            data,
        }
    }
}

impl Message for SendPanicBufferMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&self.total_remaining_size.to_be_bytes());
        f(&self.data);
    }

    fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        let command_code = ClientCommandCode::try_from(data[0])?;
        if (!matches!(command_code, ClientCommandCode::SendPanicBuffer)) || (data.len() < 5) {
            return Err("Invalid data for SendPanicBufferMessage");
        }
        let total_remaining_size = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let data = data[5..].to_vec();

        if data.len() > total_remaining_size as usize {
            return Err("Data size exceeds total remaining size");
        }

        Ok(SendPanicBufferMessage {
            command_code,
            total_remaining_size,
            data,
        })
    }
}
