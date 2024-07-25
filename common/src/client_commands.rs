// Vanadium VM client commands (responsed to InterruptedExecution status word)

// Commands from the VM to the client
#[repr(u8)]
pub enum ClientCommandCode {
    GetPage = 0,
    CommitPage = 1,
}

impl TryFrom<u8> for ClientCommandCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ClientCommandCode::GetPage),
            1 => Ok(ClientCommandCode::CommitPage),
            _ => Err("Invalid value for ClientCommandCode"),
        }
    }
}