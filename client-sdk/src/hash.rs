use common::accumulator::Hasher;
use sha2::{Digest, Sha256};

pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Hasher<32> for Sha256Hasher {
    fn new() -> Self {
        Sha256Hasher {
            hasher: Sha256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) -> &mut Self {
        self.hasher.update(data);
        self
    }

    fn digest(self, out: &mut [u8; 32]) {
        let result = self.hasher.finalize();
        out.copy_from_slice(&result);
    }
}
