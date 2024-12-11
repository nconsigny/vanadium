use core::{
    marker::PhantomData,
    ops::{Add, Mul},
};

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

impl<const SCALAR_LENGTH: usize> core::fmt::Debug for HDPrivNode<SCALAR_LENGTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "HDPrivNode {{ chaincode: {:?}, privkey: [REDACTED] }}",
            self.chaincode
        )
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
trait HasCurveKind<const SCALAR_LENGTH: usize> {
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

/// A representation of an elliptic curve point in uncompressed form.
///
/// The format is:
///
/// `prefix | X-coordinate | Y-coordinate`
///
/// Where `prefix` is always `0x04` for uncompressed points, and `X` and `Y` are `SCALAR_LENGTH`
/// byte arrays representing the coordinates.
///
/// # Type Parameters
/// * `C` - The curve type implementing `Curve<SCALAR_LENGTH>`.
/// * `SCALAR_LENGTH` - The byte length of the scalar and coordinate elements.
#[repr(C)]
pub struct Point<C, const SCALAR_LENGTH: usize>
where
    C: Curve<SCALAR_LENGTH>,
{
    curve_marker: PhantomData<C>,
    prefix: u8,
    x: [u8; SCALAR_LENGTH],
    y: [u8; SCALAR_LENGTH],
}

impl<C, const SCALAR_LENGTH: usize> Default for Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    fn default() -> Self {
        Self {
            curve_marker: PhantomData,
            prefix: 0x04,
            x: [0u8; SCALAR_LENGTH],
            y: [0u8; SCALAR_LENGTH],
        }
    }
}

impl<C, const SCALAR_LENGTH: usize> Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    /// Returns a mutable pointer to the beginning of the point's data.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        &mut self.prefix as *mut u8
    }
    /// Returns a pointer to the beginning of the point's data.
    pub fn as_ptr(&self) -> *const u8 {
        &self.prefix as *const u8
    }

    /// Creates a new Point with the given coordinates.
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate of the point.
    /// * `y` - The y-coordinate of the point.
    ///
    /// # Returns
    ///
    /// A new `Point` instance.
    pub fn new(x: [u8; SCALAR_LENGTH], y: [u8; SCALAR_LENGTH]) -> Self {
        Self {
            curve_marker: PhantomData,
            prefix: 0x04,
            x,
            y,
        }
    }
}

pub struct Secp256k1;

impl HasCurveKind<32> for Secp256k1 {
    fn get_curve_kind() -> CurveKind {
        CurveKind::Secp256k1
    }
}

pub type Secp256k1Point = Point<Secp256k1, 32>;

// We could implement this for any SCALAR_LENGTH, but this currently requires
// the #![feature(generic_const_exprs)], as the byte size is 1 + 2*SCALAR_LENGTH.
impl<C: Curve<32>> Point<C, 32> {
    /// Converts the point to a byte array.
    ///
    /// # Returns
    ///
    /// A byte array of length `1 + 2 * 32` representing the point.
    pub fn to_bytes(&self) -> &[u8; 65] {
        // SAFETY: `Point` is `#[repr(C)]` with a known layout:
        // prefix (1 byte), x (32 bytes), y (32 bytes) = 65 bytes total.
        // Therefore, we can safely reinterpret the memory as a [u8; 65].
        unsafe { &*(self as *const Self as *const [u8; 65]) }
    }

    /// Creates a point from a byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte array of length `1 + 2 * 32` representing the point.
    ///
    /// # Returns
    ///
    /// A new instance of `Self`.
    pub fn from_bytes(bytes: &[u8; 65]) -> &Self {
        if bytes[0] != 0x04 {
            panic!("Invalid point prefix. Expected 0x04");
        }
        // SAFETY: The input slice has exactly 65 bytes and must match
        // the memory layout of `Point`. The prefix is validated.
        unsafe { &*(bytes as *const [u8; 65] as *const Self) }
    }
}

impl<C, const SCALAR_LENGTH: usize> Add for &Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH> + HasCurveKind<SCALAR_LENGTH>,
{
    type Output = Point<C, SCALAR_LENGTH>;

    fn add(self, other: Self) -> Self::Output {
        let mut result = Point::default();

        if 1 != Ecall::ecfp_add_point(
            C::get_curve_kind() as u32,
            result.as_mut_ptr(),
            self.as_ptr(),
            other.as_ptr(),
        ) {
            panic!("Failed to add points");
        }

        result
    }
}

impl<C, const SCALAR_LENGTH: usize> Mul<&[u8; SCALAR_LENGTH]> for &Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH> + HasCurveKind<SCALAR_LENGTH>,
{
    type Output = Point<C, SCALAR_LENGTH>;

    fn mul(self, scalar: &[u8; SCALAR_LENGTH]) -> Self::Output {
        let mut result = Point::default();

        if 1 != Ecall::ecfp_scalar_mult(
            C::get_curve_kind() as u32,
            result.as_mut_ptr(),
            self.as_ptr(),
            scalar.as_ptr(),
            SCALAR_LENGTH,
        ) {
            panic!("Failed to multiply point by scalar");
        }

        result
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

    #[test]
    fn test_secp256k1_point_addition() {
        let point1 = Secp256k1Point::new(
            hex!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
            hex!("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
        );
        let point2 = Secp256k1Point::new(
            hex!("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
            hex!("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
        );

        let result = &point1 + &point2;

        assert_eq!(
            result.x,
            hex!("2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4")
        );
        assert_eq!(
            result.y,
            hex!("d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6")
        );
    }

    #[test]
    fn test_secp256k1_point_scalarmul() {
        let point1 = Secp256k1Point::new(
            hex!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            hex!("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        );
        let scalar = hex!("22445566778899aabbccddeeff0011223344556677889900aabbccddeeff0011");

        let result = &point1 * &scalar;

        assert_eq!(
            result.x,
            hex!("2748bce8ffc3f815e69e594ae974be5e9a3be69a233d5557ea9c92b71d69367b")
        );
        assert_eq!(
            result.y,
            hex!("747206115143153c85f3e8bb94d392bd955d36f1f0204921e6dd7684e81bdaab")
        );
    }
}
