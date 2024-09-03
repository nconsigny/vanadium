// Vanadium VM client commands (responsed to InterruptedExecution status word), and other related types

// Commands from the VM to the client
#[repr(u8)]
pub enum ClientCommandCode {
    GetPage = 0,
    CommitPage = 1,
    CommitPageContent = 2,
}

impl TryFrom<u8> for ClientCommandCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ClientCommandCode::GetPage),
            1 => Ok(ClientCommandCode::CommitPage),
            2 => Ok(ClientCommandCode::CommitPageContent),
            _ => Err("Invalid value for ClientCommandCode"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
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
