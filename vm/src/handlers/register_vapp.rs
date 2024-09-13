use crate::AppSW;
use ledger_device_sdk::io;

pub fn handler_register_vapp(comm: &mut io::Comm) -> Result<(), AppSW> {
    let _manifest_raw = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    // TODO: check manifest, ask user confirmation, compute hmac

    let hmac = [0x42u8; 32];
    comm.append(&hmac);

    Ok(())
}
