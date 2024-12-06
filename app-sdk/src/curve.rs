use zeroize::Zeroizing;

use common::ecall_constants::CurveKind;

use crate::ecalls::{Ecall, EcallsInterface};

/// A struct representing a Hierarchical Deterministic (HD) node composed of a private key, and a 32-byte chaincode.
///
/// # Type Parameters
///
/// * `SCALAR_LENGTH` - The length of the private key scalar.
///
/// # Fields
///
/// * `chaincode` - A 32-byte array representing the chain code.
/// * `privkey` - An array of bytes representing the private key, with a length defined by `SCALAR_LENGTH`.
pub struct HDPrivNode<const SCALAR_LENGTH: usize> {
    pub chaincode: [u8; 32],
    pub privkey: Zeroizing<[u8; SCALAR_LENGTH]>,
}

impl<const SCALAR_LENGTH: usize> Default for HDPrivNode<SCALAR_LENGTH> {
    fn default() -> Self {
        Self {
            chaincode: [0u8; 32],
            privkey: Zeroizing::new([0u8; SCALAR_LENGTH]),
        }
    }
}

/// A trait representing a cryptographic curve with hierarchical deterministic (HD) key derivation capabilities.
///
/// # Constants
/// - `SCALAR_LENGTH`: The length of the scalar in bytes.
///
/// # Required Methods
///
/// ## `derive_hd_node`
/// Derives an HD node (a pair of private and public keys) from a given path.
///
/// - `path`: A slice of `u32` values representing the derivation path.
/// - Returns: A `Result` containing a tuple with a 32-byte array (private key) and an array of `SCALAR_LENGTH` bytes (public key) on success, or a static string slice error message on failure.
///
/// ## `get_master_fingerprint`
/// Retrieves the fingerprint of the master key.
///
/// - Returns: A `u32` value representing the fingerprint of the master key.
pub trait Curve<const SCALAR_LENGTH: usize> {
    fn derive_hd_node(path: &[u32]) -> Result<HDPrivNode<SCALAR_LENGTH>, &'static str>;
    fn get_master_fingerprint() -> u32;
}

// A trait to simplify the implementation of `Curve` for different curves.
pub(crate) trait HasCurveKind<const SCALAR_LENGTH: usize> {
    // Returns the value that represents this curve in ECALLs.
    fn get_curve_kind() -> CurveKind;
}

impl<T, const SCALAR_LENGTH: usize> Curve<SCALAR_LENGTH> for T
where
    T: HasCurveKind<SCALAR_LENGTH>,
{
    fn derive_hd_node(path: &[u32]) -> Result<HDPrivNode<SCALAR_LENGTH>, &'static str> {
        let curve_kind = T::get_curve_kind();
        let mut result = HDPrivNode::default();

        if 1 != Ecall::derive_hd_node(
            curve_kind as u32,
            path.as_ptr(),
            path.len(),
            result.privkey.as_mut_ptr(),
            result.chaincode.as_mut_ptr(),
        ) {
            return Err("Failed to derive HD node");
        }

        Ok(result)
    }

    fn get_master_fingerprint() -> u32 {
        let curve_kind = T::get_curve_kind();
        Ecall::get_master_fingerprint(curve_kind as u32)
    }
}

pub struct Secp256k1;

impl HasCurveKind<32> for Secp256k1 {
    fn get_curve_kind() -> CurveKind {
        CurveKind::Secp256k1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_secp256k1_get_master_fingerprint() {
        assert_eq!(Secp256k1::get_master_fingerprint(), 0xf5acc2fdu32);
    }

    #[test]
    fn test_derive_hd_node_secp256k1() {
        let node = Secp256k1::derive_hd_node(&[]).unwrap();
        assert_eq!(
            node.chaincode,
            hex!("eb473a0fa0af5031f14db9fe7c37bb8416a4ff01bb69dae9966dc83b5e5bf921")
        );
        assert_eq!(
            node.privkey[..],
            hex!("34ac5d784ebb4df4727bcddf6a6743f5d5d46d83dd74aa825866390c694f2938")
        );

        let path = [0x8000002c, 0x80000000, 0x80000001, 0, 3];
        let node = Secp256k1::derive_hd_node(&path).unwrap();
        assert_eq!(
            node.chaincode,
            hex!("6da5f32f47232b3b9b2d6b59b802e2b313afa7cbda242f73da607139d8e04989")
        );
        assert_eq!(
            node.privkey[..],
            hex!("239841e64103fd024b01283e752a213fee1a8969f6825204ee3617a45c5e4a91")
        );
    }
}
