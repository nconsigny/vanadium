#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusWord {
    /// Rejected by user
    Deny = 0x6985,
    /// Incorrect Data
    IncorrectData = 0x6A80,
    /// Not Supported
    NotSupported = 0x6A82,
    /// Wrong P1P2
    WrongP1P2 = 0x6A86,
    /// Wrong DataLength
    WrongDataLength = 0x6A87,
    /// Ins not supported
    InsNotSupported = 0x6D00,
    /// Cla not supported
    ClaNotSupported = 0x6E00,
    /// Bad state
    BadState = 0xB007,
    /// Signature fail
    SignatureFail = 0xB008,
    /// Success
    OK = 0x9000,
    /// The command is interrupted, and requires the client's response
    InterruptedExecution = 0xE000,
    /// Unknown
    Unknown,
}

impl TryFrom<u16> for StatusWord {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x6985 => Ok(StatusWord::Deny),
            0x6A80 => Ok(StatusWord::IncorrectData),
            0x6A82 => Ok(StatusWord::NotSupported),
            0x6A86 => Ok(StatusWord::WrongP1P2),
            0x6A87 => Ok(StatusWord::WrongDataLength),
            0x6D00 => Ok(StatusWord::InsNotSupported),
            0x6E00 => Ok(StatusWord::ClaNotSupported),
            0xB007 => Ok(StatusWord::BadState),
            0xB008 => Ok(StatusWord::SignatureFail),
            0x9000 => Ok(StatusWord::OK),
            0xE000 => Ok(StatusWord::InterruptedExecution),
            _ => Err(()),
        }
    }
}

#[derive(Clone)]
pub struct APDUCommand {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

impl APDUCommand {
    pub fn encode(&self) -> Vec<u8> {
        let mut vec = vec![self.cla, self.ins, self.p1, self.p2, self.data.len() as u8];
        vec.extend(self.data.iter());
        vec
    }
}
