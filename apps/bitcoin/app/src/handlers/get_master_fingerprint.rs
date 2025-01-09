use common::message::ResponseGetMasterFingerprint;
use sdk::curve::Curve;

pub fn handle_get_master_fingerprint() -> Result<ResponseGetMasterFingerprint, &'static str> {
    Ok(ResponseGetMasterFingerprint {
        fingerprint: sdk::curve::Secp256k1::get_master_fingerprint(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_get_master_fingerprint() {
        let response = handle_get_master_fingerprint().unwrap();
        assert_eq!(response.fingerprint, 0xf5acc2fdu32);
    }
}
