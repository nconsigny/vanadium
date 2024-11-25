//! Module providing arbitrary-sized big number arithmetic and modular operations, built
//! using the ECALLs provided in the Vanadium app sdk.
//!
//! This module defines the `BigNum`, `Modulus`, and `BigNumMod` structs, which allow for
//! arithmetic operations on big numbers of a specified size, including modular addition,
//! subtraction, multiplication, and exponentiation.

use core::{
    ops::{Add, AddAssign, MulAssign, Sub, SubAssign},
    panic,
};

use crate::ecalls::{Ecall, EcallsInterface};

use common::ecall_constants::MAX_BIGNUMBER_SIZE;
use subtle::ConstantTimeEq;

/// Represents an arbitrary-sized big number, up to the maximum supported size `MAX_BIGNUMBER_SIZE`.
/// Numbers are contained in a byte array of size `N`.
///
/// The `BigNum<N>` struct holds a big number in a byte array of size `N`.
///
/// Additions and subtractions are implemented only for operators of the same size, and are wrapping
/// in case of overflow or underflow.
#[derive(Debug, Clone)]
pub struct BigNum<const N: usize> {
    buffer: [u8; N],
}

impl<const N: usize> PartialEq for BigNum<N> {
    fn eq(&self, other: &Self) -> bool {
        self.buffer.ct_eq(&other.buffer).into()
    }
}

impl<const N: usize> Eq for BigNum<N> {}

impl<const N: usize> BigNum<N> {
    /// Creates a new `BigNum` from a big-endian byte array.
    ///
    /// # Panics
    ///
    /// Panics if the size `N` is larger than `MAX_BIGNUMBER_SIZE`.
    pub fn from_be_bytes(bytes: [u8; N]) -> Self {
        if N > MAX_BIGNUMBER_SIZE {
            panic!("Buffer too large");
        }
        Self { buffer: bytes }
    }

    /// Creates a `BigNum` from a `u32` value.
    ///
    /// # Panics
    ///
    /// Panics if the buffer size `N` is smaller than 4 bytes.
    pub fn from_u32(value: u32) -> Self {
        if N < 4 {
            panic!("Buffer too small to hold u32");
        }
        let mut buffer = [0u8; N];
        buffer[N - 4..N].copy_from_slice(&value.to_be_bytes());
        Self { buffer }
    }

    /// Returns the big number as a big-endian byte array.
    pub fn to_be_bytes(&self) -> [u8; N] {
        self.buffer
    }
}

// Implementations for addition and subtraction on `BigNum`

impl<const N: usize> Add for &BigNum<N> {
    type Output = BigNum<N>;

    fn add(self, other: Self) -> BigNum<N> {
        let mut result = [0u8; N];
        let mut carry = 0u16;

        for i in (0..N).rev() {
            let sum = self.buffer[i] as u16 + other.buffer[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }

        BigNum { buffer: result }
    }
}

impl<const N: usize> AddAssign<&Self> for BigNum<N> {
    fn add_assign(&mut self, other: &Self) {
        let mut carry = 0u16;

        for i in (0..N).rev() {
            let sum = self.buffer[i] as u16 + other.buffer[i] as u16 + carry;
            self.buffer[i] = sum as u8;
            carry = sum >> 8;
        }
    }
}

impl<const N: usize> Sub for &BigNum<N> {
    type Output = BigNum<N>;

    fn sub(self, other: Self) -> BigNum<N> {
        let mut result = [0u8; N];
        let mut borrow = 0i16;

        for i in (0..N).rev() {
            let diff = self.buffer[i] as i16 - other.buffer[i] as i16 - borrow;
            if diff >= 0 {
                result[i] = diff as u8;
                borrow = 0;
            } else {
                result[i] = (diff + 256) as u8;
                borrow = 1;
            }
        }

        BigNum { buffer: result }
    }
}

impl<const N: usize> SubAssign<&Self> for BigNum<N> {
    fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0i16;

        for i in (0..N).rev() {
            let diff = self.buffer[i] as i16 - other.buffer[i] as i16 - borrow;
            if diff >= 0 {
                self.buffer[i] = diff as u8;
                borrow = 0;
            } else {
                self.buffer[i] = (diff + 256) as u8;
                borrow = 1;
            }
        }
    }
}

/// Represents a modulus for modular arithmetic operations.
///
/// The `Modulus<N>` struct holds a modulus value in a byte array of size `N`.
/// It is used with `BigNumMod` to perform modular arithmetic operations.
#[derive(Debug, Clone, Copy)]
pub struct Modulus<const N: usize> {
    m: [u8; N],
}

impl<const N: usize> Modulus<N> {
    /// Creates a new `Modulus` from a big-endian byte array.
    pub const fn from_be_bytes(m: [u8; N]) -> Self {
        Self { m }
    }

    /// Creates a new `BigNumMod` with this modulus.
    pub fn new_big_num_mod(&self, buffer: [u8; N]) -> BigNumMod<N> {
        BigNumMod::from_be_bytes(buffer, self)
    }
}

impl<const N: usize> PartialEq for Modulus<N> {
    fn eq(&self, other: &Self) -> bool {
        self.m.ct_eq(&other.m).into()
    }
}

impl<const N: usize> Eq for Modulus<N> {}

/// Represents a big number under a given modulus.
///
/// The `BigNumMod` struct provides arithmetic operations for big numbers under a specified modulus.
/// Operations between `BigNumMod` instances will panic if their moduli differ.
#[derive(Debug, Clone, Copy)]
pub struct BigNumMod<'a, const N: usize> {
    buffer: [u8; N],
    modulus: &'a Modulus<N>,
}

impl<'a, const N: usize> BigNumMod<'a, N> {
    /// Creates a new `BigNumMod` from a big-endian byte array and a modulus.
    ///
    /// The value is reduced modulo the modulus during creation, therefore the
    /// value in the buffer is guaranteed to be strictly smaller than the modulus.
    ///
    /// # Panics
    ///
    /// Panics if the modulus is zero.
    pub fn from_be_bytes(buffer: [u8; N], modulus: &'a Modulus<N>) -> Self {
        if modulus.m.ct_eq(&[0u8; N]).into() {
            panic!("Modulus cannot be 0");
        }
        // reduce the buffer my the modulus
        let mut buffer = buffer;
        if 1 != Ecall::bn_modm(
            buffer.as_mut_ptr(),
            buffer.as_ptr(),
            N,
            modulus.m.as_ptr(),
            N,
        ) {
            panic!("bn_modm failed")
        }

        Self { buffer, modulus }
    }

    /// Creates a `BigNumMod` from a `u32` value and a modulus.
    ///
    /// The value is reduced modulo the modulus during creation.
    ///
    /// # Panics
    ///
    /// Panics if the modulus is zero.
    pub fn from_u32(value: u32, modulus: &'a Modulus<N>) -> Self {
        if modulus.m.ct_eq(&[0u8; N]).into() {
            panic!("Modulus cannot be 0");
        }

        let mut buffer = [0u8; N];
        buffer[N - 4..N].copy_from_slice(&value.to_be_bytes());

        if 1 != Ecall::bn_modm(
            buffer.as_mut_ptr(),
            buffer.as_ptr(),
            N,
            modulus.m.as_ptr(),
            N,
        ) {
            panic!("bn_modm failed")
        }

        Self { buffer, modulus }
    }

    /// Returns the value as a big-endian byte array.
    pub fn to_be_bytes(&self) -> [u8; N] {
        self.buffer
    }

    /// Computes the modular exponentiation of the value raised to the given exponent.
    ///
    /// Returns a new `BigNumMod` representing `(self ^ exponent) mod modulus`.
    pub fn pow<const N_EXP: usize>(&self, exponent: &BigNum<N_EXP>) -> Self {
        let mut result = [0u8; N];
        let res = Ecall::bn_powm(
            result.as_mut_ptr(),
            self.buffer.as_ptr(),
            exponent.buffer.as_ptr(),
            N_EXP,
            self.modulus.m.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Exponentiation failed");
        }
        Self::from_be_bytes(result, self.modulus)
    }
}

/// Checks if two `BigNumMod` instances are equal.
/// Two BigModNum instances are equal if and only if their buffers are equal, and their moduli are equal.
///
/// The comparison of the moduli and the comparison of the buffers are done in constant time; however,
/// timing analysis allows to determine whether the references are equal or not, and in case of inequality,
/// whether it was the moduli or the buffers that were different.
impl<'a, const N: usize> PartialEq for BigNumMod<'a, N> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // typically, this would be called with number with the same modulus reference;
        // therefore, we just check the pointer first instead of checking the reference,
        // since the constant-time comparison is costlier.
        if !core::ptr::eq(self.modulus, other.modulus) {
            if self.modulus != other.modulus {
                return false;
            }
        }

        self.buffer.ct_eq(&other.buffer).into()
    }
}

impl<'a, const N: usize> Eq for BigNumMod<'a, N> {}

impl<'a, const N: usize> Add for &BigNumMod<'a, N> {
    type Output = BigNumMod<'a, N>;

    fn add(self, other: Self) -> BigNumMod<'a, N> {
        if self.modulus != other.modulus {
            panic!("Moduli do not match");
        }

        let mut result = [0u8; N];
        let res = Ecall::bn_addm(
            result.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            self.modulus.m.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Addition failed");
        }
        BigNumMod::from_be_bytes(result, self.modulus)
    }
}

impl<'a, const N: usize> AddAssign for BigNumMod<'a, N> {
    fn add_assign(&mut self, other: Self) {
        if self.modulus != other.modulus {
            panic!("Moduli do not match");
        }

        let res = Ecall::bn_addm(
            self.buffer.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            self.modulus.m.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Addition failed");
        }
    }
}

impl<'a, const N: usize> Add<u32> for &BigNumMod<'a, N> {
    type Output = BigNumMod<'a, N>;

    fn add(self, other: u32) -> BigNumMod<'a, N> {
        self + &BigNumMod::from_u32(other, self.modulus)
    }
}

impl<'a, const N: usize> Add<&BigNumMod<'a, N>> for u32 {
    type Output = BigNumMod<'a, N>;

    fn add(self, other: &BigNumMod<'a, N>) -> BigNumMod<'a, N> {
        &BigNumMod::from_u32(self, other.modulus) + other
    }
}

impl<'a, const N: usize> AddAssign<u32> for BigNumMod<'a, N> {
    fn add_assign(&mut self, other: u32) {
        *self += Self::from_u32(other, self.modulus);
    }
}

impl<'a, const N: usize> Sub for &BigNumMod<'a, N> {
    type Output = BigNumMod<'a, N>;

    fn sub(self, other: Self) -> BigNumMod<'a, N> {
        if self.modulus != other.modulus {
            panic!("Moduli do not match");
        }

        let mut result = [0u8; N];
        let res = Ecall::bn_subm(
            result.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            self.modulus.m.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Subtraction failed");
        }
        BigNumMod::from_be_bytes(result, self.modulus)
    }
}

impl<'a, const N: usize> SubAssign for BigNumMod<'a, N> {
    fn sub_assign(&mut self, other: Self) {
        if self.modulus != other.modulus {
            panic!("Moduli do not match");
        }

        let res = Ecall::bn_subm(
            self.buffer.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            self.modulus.m.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Subtraction failed");
        }
    }
}

impl<'a, const N: usize> core::ops::Sub<u32> for BigNumMod<'a, N> {
    type Output = Self;

    fn sub(self, other: u32) -> Self {
        &self - &Self::from_u32(other, self.modulus)
    }
}

impl<'a, const N: usize> SubAssign<u32> for BigNumMod<'a, N> {
    fn sub_assign(&mut self, other: u32) {
        *self -= Self::from_u32(other, self.modulus);
    }
}

impl<'a, const N: usize> core::ops::Mul for &BigNumMod<'a, N> {
    type Output = BigNumMod<'a, N>;

    fn mul(self, other: Self) -> BigNumMod<'a, N> {
        if self.modulus != other.modulus {
            panic!("Moduli do not match");
        }

        let mut result = [0u8; N];
        let res = Ecall::bn_multm(
            result.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            self.modulus.m.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Multiplication failed");
        }
        BigNumMod::from_be_bytes(result, self.modulus)
    }
}

impl<'a, const N: usize> MulAssign<&Self> for BigNumMod<'a, N> {
    fn mul_assign(&mut self, other: &Self) {
        if self.modulus != other.modulus {
            panic!("Moduli do not match");
        }

        let res = Ecall::bn_multm(
            self.buffer.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            self.modulus.m.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Multiplication failed");
        }
    }
}

impl<'a, const N: usize> core::ops::Mul<u32> for BigNumMod<'a, N> {
    type Output = Self;

    fn mul(self, other: u32) -> Self {
        &self * &BigNumMod::from_u32(other, self.modulus)
    }
}

impl<'a, const N: usize> core::ops::MulAssign<u32> for BigNumMod<'a, N> {
    fn mul_assign(&mut self, other: u32) {
        *self *= &BigNumMod::from_u32(other, self.modulus);
    }
}

impl<'a, const N: usize> core::ops::Mul<&BigNumMod<'a, N>> for u32 {
    type Output = BigNumMod<'a, N>;

    fn mul(self, other: &BigNumMod<'a, N>) -> BigNumMod<'a, N> {
        &BigNumMod::from_u32(self, other.modulus) * other
    }
}

#[cfg(test)]
mod tests {
    // TODO: these tests are only for the native target. We would like to run them for both the native
    // and the RISC-V target, inside Vanadium. Perhaps we can make an app specifically to test ecalls.

    use super::*;
    use hex_literal::hex;

    const M: Modulus<32> = Modulus::from_be_bytes(hex!(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    ));
    const M2: Modulus<32> = Modulus::from_be_bytes(hex!(
        "3d4b0f9e4e4d5b6e5e5d6e7e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9e"
    ));

    #[test]
    fn test_big_num_addition() {
        assert_eq!(
            &BigNum::<4>::from_u32(0x77989873) + &BigNum::<4>::from_u32(0xa4589234),
            BigNum::<4>::from_u32(0x1bf12aa7)
        );
        assert_eq!(
            &BigNum::<4>::from_u32(0x47989873) + &BigNum::<4>::from_u32(0xa4589234),
            BigNum::<4>::from_u32(0xebf12aa7)
        );
        assert_eq!(
            &BigNum::<4>::from_u32(0xffffffff) + &BigNum::<4>::from_u32(1),
            BigNum::<4>::from_u32(0)
        );

        let zero_large = BigNum::<MAX_BIGNUMBER_SIZE>::from_u32(0);
        let minus_one_large = BigNum::from_be_bytes([0xff; MAX_BIGNUMBER_SIZE]);
        let one_large = BigNum::<MAX_BIGNUMBER_SIZE>::from_u32(1);
        assert_eq!(&minus_one_large + &one_large, zero_large);
    }

    #[test]
    fn test_big_num_subtraction() {
        assert_eq!(
            &BigNum::<4>::from_u32(0xa4589234) - &BigNum::<4>::from_u32(0x77989873),
            BigNum::<4>::from_u32(0x2cbff9c1)
        );
        assert_eq!(
            &BigNum::<4>::from_u32(0x77989873) - &BigNum::<4>::from_u32(0xa4589234),
            BigNum::<4>::from_u32(0xd340063f)
        );
        assert_eq!(
            &BigNum::<4>::from_u32(0) - &BigNum::<4>::from_u32(1),
            BigNum::<4>::from_u32(0xffffffff)
        );

        let minus_one_large = BigNum::from_be_bytes([0xff; MAX_BIGNUMBER_SIZE]);
        let one_large = BigNum::<MAX_BIGNUMBER_SIZE>::from_u32(1);
        let zero_large = BigNum::<MAX_BIGNUMBER_SIZE>::from_u32(0);
        assert_eq!(&zero_large - &one_large, minus_one_large);
    }

    #[test]
    fn test_modulus_equality() {
        let m1 = Modulus::from_be_bytes([0x01; 32]);
        let m2 = Modulus::from_be_bytes([0x01; 32]);
        let m3 = Modulus::from_be_bytes([0x02; 32]);
        assert_eq!(m1, m2);
        assert_ne!(m1, m3);
    }

    #[test]
    fn test_big_num_mod_equality() {
        let modulus = Modulus::from_be_bytes([0x05; 32]);
        let modulus2 = Modulus::from_be_bytes([0x06; 32]);

        let a = BigNumMod::from_be_bytes([0x01; 32], &modulus);

        // same modulus and buffer
        let b = BigNumMod::from_be_bytes([0x01; 32], &modulus);

        // different buffer
        let c = BigNumMod::from_be_bytes([0x02; 32], &modulus);

        // different modulus
        let d = BigNumMod::from_be_bytes([0x01; 32], &modulus2);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    #[should_panic(expected = "Modulus cannot be 0")]
    fn test_zero_modulus() {
        let zero_modulus = Modulus::from_be_bytes([0x00; 32]);
        let _ = BigNumMod::from_be_bytes([0x01; 32], &zero_modulus);
    }

    #[test]
    fn test_big_num_mod_new() {
        let modulus = Modulus::from_be_bytes(hex!("12345678"));
        let a = BigNumMod::from_u32(2, &modulus);
        assert_eq!(a.buffer, hex!("00000002"));
        // make sure that the buffer is reduced by the modulus on creation
        let a = BigNumMod::from_u32(0x12345679, &modulus);
        assert_eq!(a.buffer, hex!("00000001"));
    }

    #[test]
    fn test_from_u32() {
        let a = BigNumMod::from_u32(2, &M);
        assert_eq!(
            a.buffer,
            hex!("0000000000000000000000000000000000000000000000000000000000000002")
        );
    }

    #[test]
    fn test_add() {
        let a = BigNumMod::from_u32(2, &M);
        let b = BigNumMod::from_u32(3, &M);
        assert_eq!(&a + &b, BigNumMod::from_u32(5, &M));

        let a = M.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));
        let b = M.new_big_num_mod(hex!(
            "7390984098209380980948098230840982340294098092384092834923840923"
        ));
        assert_eq!(
            &a + &b,
            M.new_big_num_mod(hex!(
                "15d7f1c4cab897b32c12c8a1b638879e023d5a9d8ca0da88d89bdb53a7b61679"
            ))
        );

        // add with u32
        assert_eq!(
            &BigNumMod::from_u32(2, &M) + 3u32,
            BigNumMod::from_u32(5, &M)
        );
        assert_eq!(
            3u32 + &BigNumMod::from_u32(2, &M),
            BigNumMod::from_u32(5, &M)
        );

        // tests with AddAssign
        let mut a_copy = a;
        a_copy += b;
        assert_eq!(a_copy, &a + &b);

        let mut a = BigNumMod::from_u32(13, &M);
        a += 7u32;
        assert_eq!(a, BigNumMod::from_u32(20, &M));
    }

    #[test]
    #[should_panic(expected = "Moduli do not match")]
    fn test_add_different_modulus() {
        // this should panic
        let _ = &BigNumMod::from_u32(2, &M) + &BigNumMod::from_u32(3, &M2);
    }

    #[test]
    fn test_sub() {
        let a = BigNumMod::from_u32(5, &M);
        let b = BigNumMod::from_u32(3, &M);
        assert_eq!(&a - &b, BigNumMod::from_u32(2, &M));

        let a = M.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));
        let b = M.new_big_num_mod(hex!(
            "7390984098209380980948098230840982340294098092384092834923840923"
        ));
        assert_eq!(
            &a - &b,
            M.new_big_num_mod(hex!(
                "2eb6c1439a7770b1fc00388eb1d77f8afdd55575799fb6185776d4c060ae0062"
            ))
        );
        assert_eq!(
            &b - &a,
            M.new_big_num_mod(hex!(
                "d1493ebc65888f4e03ffc7714e288075022aaa8a866049e7a8892b3e9f51fbcd"
            ))
        );

        // sub with u32
        assert_eq!(
            BigNumMod::from_u32(5, &M) - 3u32,
            BigNumMod::from_u32(2, &M)
        );

        // tests with SubAssign
        let mut a_copy = a;
        a_copy -= b;
        assert_eq!(a_copy, &a - &b);
        let mut a = BigNumMod::from_u32(13, &M);
        a -= 7u32;
        assert_eq!(a, BigNumMod::from_u32(6, &M));
    }

    #[test]
    #[should_panic(expected = "Moduli do not match")]
    fn test_sub_different_modulus() {
        // this should panic
        let _ = &BigNumMod::from_u32(5, &M) - &BigNumMod::from_u32(3, &M2);
    }

    #[test]
    fn test_mul() {
        let m = Modulus::from_be_bytes(hex!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        ));

        let a = BigNumMod::from_u32(2, &M);
        let b = BigNumMod::from_u32(3, &M);
        assert_eq!(&a * &b, BigNumMod::from_u32(6, &m));

        let a = M.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));
        let b = M.new_big_num_mod(hex!(
            "7390984098209380980948098230840982340294098092384092834923840923"
        ));
        assert_eq!(
            &a * &b,
            M.new_big_num_mod(hex!(
                "2d5daeb3ed823bef5a4480a2c5aa0708e8e37ed7302d2b21c9b442b244d48ce6"
            ))
        );

        // mul with u32
        assert_eq!(
            BigNumMod::from_u32(2, &m) * 3u32,
            BigNumMod::from_u32(6, &m)
        );
        assert_eq!(
            3u32 * &BigNumMod::from_u32(2, &m),
            BigNumMod::from_u32(6, &m)
        );

        // tests for MulAssign
        let mut a_copy = a;
        a_copy *= &b;
        assert_eq!(a_copy, &a * &b);

        let mut a = BigNumMod::from_u32(7, &M);
        a *= 13u32;
        assert_eq!(a, BigNumMod::from_u32(91, &M));
    }

    #[test]
    #[should_panic(expected = "Moduli do not match")]
    fn test_mul_different_modulus() {
        // this should panic
        let _ = &BigNumMod::from_u32(2, &M) * &BigNumMod::from_u32(3, &M2);
    }

    #[test]
    fn test_pow() {
        let a = M2.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));

        // 0 always returns 1
        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("00"))).buffer,
            hex!("0000000000000000000000000000000000000000000000000000000000000001")
        );

        // 1 is the identity
        assert_eq!(a.pow(&BigNum::from_be_bytes(hex!("01"))), a);

        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("02"))).buffer,
            hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7")
        );
        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("00000002"))).buffer,
            hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7")
        );
        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!(
                "0000000000000000000000000000000000000000000000000000000000000002"
            )))
            .buffer,
            hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7")
        );

        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("23"))).buffer,
            hex!("1ed32565487715d9669418dbaa00db9e03f8271af2074857cc6178e6905b0501")
        );

        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd722e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7"))).buffer,
            hex!("1329e291eb25b61d17cff7cc9c00457532f917c23f44af7469ed55b6988f0dd1")
        );
    }
}
