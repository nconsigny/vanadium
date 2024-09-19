#[derive(Debug)]
pub enum Command {
    Reverse,
    Sum,
    Base58Encode,
    Sha256,
    CountPrimes,
}

impl TryFrom<u8> for Command {
    type Error = ();

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x00 => Ok(Command::Reverse),
            0x01 => Ok(Command::Sum),
            0x02 => Ok(Command::Base58Encode),
            0x03 => Ok(Command::Sha256),
            0x04 => Ok(Command::CountPrimes),
            _ => Err(()),
        }
    }
}
