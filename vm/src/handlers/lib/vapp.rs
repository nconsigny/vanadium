use common::manifest::Manifest;
use ledger_device_sdk::hmac::{self, HMACInit};

use crate::hash::Sha256Hasher;

/// Computes the HMAC for the V-App.
///
/// SECURITY: The caller is responsible for ensuring that comparisons involving the
/// result of this function run in constant time, in order to prevent timing attacks.
pub fn get_vapp_hmac(manifest: &Manifest) -> [u8; 32] {
    let vapp_hash: [u8; 32] = manifest.get_vapp_hash::<Sha256Hasher, 32>();

    // TODO: derive a key using SLIP-21, or otherwise initialize it elsewhere.
    let hmac_key = [42u8; 32];

    let mut sha2 = hmac::sha2::Sha2_256::new(&hmac_key);
    sha2.update(&vapp_hash).expect("Should never fail");
    let mut vapp_hmac = [0u8; 32];
    sha2.finalize(&mut vapp_hmac).expect("Should never fail");

    vapp_hmac
}
