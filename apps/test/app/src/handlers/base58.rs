use alloc::vec::Vec;

pub fn handle_base58_encode(data: &[u8]) -> Vec<u8> {
    bs58::encode(data).into_vec()
}
