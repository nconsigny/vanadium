use common::message::ResponseGetMasterFingerprint;

pub fn handle_get_master_fingerprint() -> Result<ResponseGetMasterFingerprint, &'static str> {
    // TODO: replace with proper sdk call
    Ok(ResponseGetMasterFingerprint {
        fingerprint: 0xf5acc2fd,
    })
}
