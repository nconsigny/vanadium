use crate::handlers::lib::vapp::get_vapp_hmac;
use crate::{hash::Sha256Hasher, AppSW};
use alloc::{vec, vec::Vec};
use common::manifest::Manifest;
use ledger_device_sdk::io;

pub fn handler_register_vapp(comm: &mut io::Comm) -> Result<Vec<u8>, AppSW> {
    let data_raw = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    let (manifest, rest) =
        postcard::take_from_bytes::<Manifest>(data_raw).map_err(|_| AppSW::IncorrectData)?;

    if rest.len() != 0 {
        return Err(AppSW::IncorrectData); // extra data
    }

    let vapp_hash = manifest.get_vapp_hash::<Sha256Hasher, 32>();

    // TODO: show vapp_hash to user for confirmation

    crate::println!("Registering V-App with Manifest: {:?}", manifest);
    crate::println!("V-App hash: {:?}", vapp_hash);

    let vapp_hmac = get_vapp_hmac(&manifest);
    comm.append(&vapp_hmac);

    Ok(vec![])
}
