use alloc::vec::Vec;
use sha2::Digest;

pub fn handle_sha256(data: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(data).to_vec()
}
