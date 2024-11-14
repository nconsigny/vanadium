use core::{
    ops::{Add, AddAssign, MulAssign, Sub, SubAssign},
    panic,
};

use crate::ecalls::{Ecall, EcallsInterface};

use common::ecall_constants::MAX_BIGNUMBER_SIZE;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone)]
pub struct BigNum<const N: usize> {
    buffer: [u8; N],
}

impl<const N: usize> BigNum<N> {
    pub fn new(buffer: [u8; N]) -> Self {
        if N > MAX_BIGNUMBER_SIZE {
            panic!("Buffer too large");
        }
        Self { buffer }
    }
    pub fn from_bytes_be(bytes: [u8; N]) -> Self {
        Self { buffer: bytes }
    }

    pub fn from_u32(value: u32) -> Self {
        if N < 4 {
            panic!("Buffer too small to hold u32");
        }
        let mut buffer = [0u8; N];
        buffer[N - 4..N].copy_from_slice(&value.to_be_bytes());
        Self { buffer }
    }

    pub fn to_bytes_be(&self) -> [u8; N] {
        self.buffer
    }
}

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

#[derive(Debug, Clone, Copy)]
pub struct Modulus<const N: usize> {
    m: [u8; N],
}

impl<const N: usize> Modulus<N> {
    pub const fn new(m: [u8; N]) -> Self {
        Self { m }
    }

    pub fn new_big_num_mod(&self, buffer: [u8; N]) -> BigNumMod<N> {
        BigNumMod::new(buffer, self)
    }
}

impl<const N: usize> PartialEq for Modulus<N> {
    fn eq(&self, other: &Self) -> bool {
        self.m.ct_eq(&other.m).into()
    }
}

impl<const N: usize> Eq for Modulus<N> {}

/// A structure representing a big number with a modulus.
///
/// This structure provides arithmetic operations for big numbers under a given modulus.
/// Operations will panic if attempted on two numbers with a different modulus.
///
/// # Fields
///
/// * `buffer` - The byte array representing the big number.
/// * `modulus` - A reference to the modulus under which the arithmetic operations are performed.
///
/// # Methods
///
/// * `new(buffer: [u8; N], modulus: &'a Modulus<N>) -> Self`
///     - Creates a new `BigNumMod` instance and reduces the buffer by the modulus.
///
/// * `from_u32(value: u32, modulus: &'a Modulus<N>) -> Self`
///     - Creates a new `BigNumMod` instance from a `u32` value and reduces it by the modulus.
///
/// * `to_bytes_be(&self) -> [u8; N]`
///     - Returns the byte array representing the big number.
///
/// * `pow(&self, exponent: &BigNumMod<N>) -> Self`
///     - Computes the power of the big number to the given exponent under the modulus.
///
/// # Traits Implementations
///
/// * `PartialEq`
///     - Checks if two `BigNumMod` instances are equal. Two instances are equal if their buffers and moduli are equal.
///
/// * `Eq`
///     - Provides equality comparison for `BigNumMod`.
///
/// * `Add`
///     - Adds two `BigNumMod` instances under the same modulus.
///
/// * `AddAssign`
///     - Adds another `BigNumMod` instance to the current instance under the same modulus.
///
/// * `Add<u32>`
///     - Adds a `u32` value to the `BigNumMod` instance under the same modulus.
///
/// * `AddAssign<u32>`
///     - Adds a `u32` value to the current `BigNumMod` instance under the same modulus.
///
/// * `Sub`
///     - Subtracts one `BigNumMod` instance from another under the same modulus.
///
/// * `SubAssign`
///     - Subtracts another `BigNumMod` instance from the current instance under the same modulus.
///
/// * `Sub<u32>`
///     - Subtracts a `u32` value from the `BigNumMod` instance under the same modulus.
///
/// * `SubAssign<u32>`
///     - Subtracts a `u32` value from the current `BigNumMod` instance under the same modulus.
///
/// * `Mul`
///     - Multiplies two `BigNumMod` instances under the same modulus.
///
/// * `MulAssign`
///     - Multiplies another `BigNumMod` instance with the current instance under the same modulus.
///
/// * `Mul<u32>`
///     - Multiplies a `u32` value with the `BigNumMod` instance under the same modulus.
///
/// * `MulAssign<u32>`
///     - Multiplies a `u32` value with the current `BigNumMod` instance under the same modulus.
///
/// # Panics
///
/// The methods will panic if the moduli of the two `BigNumMod` instances do not match.
#[derive(Debug, Clone, Copy)]
pub struct BigNumMod<'a, const N: usize> {
    buffer: [u8; N],
    modulus: &'a Modulus<N>,
}

impl<'a, const N: usize> BigNumMod<'a, N> {
    pub fn new(buffer: [u8; N], modulus: &'a Modulus<N>) -> Self {
        if modulus.m.ct_eq(&[0u8; N]).into() {
            panic!("Modulus cannot be 0");
        }
        // reduce the buffer my the modulus
        let mut buffer = buffer;
        if !Ecall::bn_modm(
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

    pub fn from_u32(value: u32, modulus: &'a Modulus<N>) -> Self {
        let mut buffer = [0u8; N];
        buffer[N - 4..N].copy_from_slice(&value.to_be_bytes());

        if !Ecall::bn_modm(
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

    pub fn to_bytes_be(&self) -> [u8; N] {
        self.buffer
    }

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
        if !res {
            panic!("Exponentiation failed");
        }
        Self::new(result, self.modulus)
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
        // typically, this would be called with number with the same modulus;
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
        if !res {
            panic!("Addition failed");
        }
        BigNumMod::new(result, self.modulus)
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
        if !res {
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

impl<'a, const N: usize> Sub for BigNumMod<'a, N> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
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
        if !res {
            panic!("Subtraction failed");
        }
        Self::new(result, self.modulus)
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
        if !res {
            panic!("Subtraction failed");
        }
    }
}

impl<'a, const N: usize> core::ops::Sub<u32> for BigNumMod<'a, N> {
    type Output = Self;

    fn sub(self, other: u32) -> Self {
        self - Self::from_u32(other, self.modulus)
    }
}

impl<'a, const N: usize> SubAssign<u32> for BigNumMod<'a, N> {
    fn sub_assign(&mut self, other: u32) {
        *self -= Self::from_u32(other, self.modulus);
    }
}

impl<'a, const N: usize> core::ops::Mul for BigNumMod<'a, N> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
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
        if !res {
            panic!("Multiplication failed");
        }
        Self::new(result, self.modulus)
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
        if !res {
            panic!("Multiplication failed");
        }
    }
}

impl<'a, const N: usize> core::ops::Mul<u32> for BigNumMod<'a, N> {
    type Output = Self;

    fn mul(self, other: u32) -> Self {
        self * BigNumMod::from_u32(other, self.modulus)
    }
}

impl<'a, const N: usize> core::ops::MulAssign<u32> for BigNumMod<'a, N> {
    fn mul_assign(&mut self, other: u32) {
        *self *= &BigNumMod::from_u32(other, self.modulus);
    }
}

impl<'a, const N: usize> core::ops::Mul<BigNumMod<'a, N>> for u32 {
    type Output = BigNumMod<'a, N>;

    fn mul(self, other: BigNumMod<'a, N>) -> BigNumMod<'a, N> {
        BigNumMod::from_u32(self, other.modulus) * other
    }
}

#[cfg(test)]
mod tests {
    // TODO: these tests are only for the native target. We would like to run them for both the native
    // and the RISC-V target, inside Vanadium. Perhaps we can make an app specifically to test ecalls.

    use super::*;
    use hex_literal::hex;

    const M: Modulus<32> = Modulus::new(hex!(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    ));
    const M2: Modulus<32> = Modulus::new(hex!(
        "3d4b0f9e4e4d5b6e5e5d6e7e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9e"
    ));

    #[test]
    fn test_big_num_mod_new() {
        let modulus = Modulus::new(hex!("12345678"));
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
        assert_eq!(a - b, BigNumMod::from_u32(2, &M));

        let a = M.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));
        let b = M.new_big_num_mod(hex!(
            "7390984098209380980948098230840982340294098092384092834923840923"
        ));
        assert_eq!(
            a - b,
            M.new_big_num_mod(hex!(
                "2eb6c1439a7770b1fc00388eb1d77f8afdd55575799fb6185776d4c060ae0062"
            ))
        );
        assert_eq!(
            b - a,
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
        assert_eq!(a_copy, a - b);
        let mut a = BigNumMod::from_u32(13, &M);
        a -= 7u32;
        assert_eq!(a, BigNumMod::from_u32(6, &M));
    }

    #[test]
    #[should_panic(expected = "Moduli do not match")]
    fn test_sub_different_modulus() {
        // this should panic
        let _ = BigNumMod::from_u32(5, &M) - BigNumMod::from_u32(3, &M2);
    }

    #[test]
    fn test_mul() {
        let m = Modulus::new(hex!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        ));

        let a = BigNumMod::from_u32(2, &M);
        let b = BigNumMod::from_u32(3, &M);
        assert_eq!(a * b, BigNumMod::from_u32(6, &m));

        let a = M.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));
        let b = M.new_big_num_mod(hex!(
            "7390984098209380980948098230840982340294098092384092834923840923"
        ));
        assert_eq!(
            a * b,
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
            3u32 * BigNumMod::from_u32(2, &m),
            BigNumMod::from_u32(6, &m)
        );

        // tests for MulAssign
        let mut a_copy = a;
        a_copy *= &b;
        assert_eq!(a_copy, a * b);

        let mut a = BigNumMod::from_u32(7, &M);
        a *= 13u32;
        assert_eq!(a, BigNumMod::from_u32(91, &M));
    }

    #[test]
    #[should_panic(expected = "Moduli do not match")]
    fn test_mul_different_modulus() {
        // this should panic
        let _ = BigNumMod::from_u32(2, &M) * BigNumMod::from_u32(3, &M2);
    }

    #[test]
    fn test_pow() {
        let a = M2.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));

        // 0 always returns 1
        assert_eq!(
            a.pow(&BigNum::new(hex!("00"))).buffer,
            hex!("0000000000000000000000000000000000000000000000000000000000000001")
        );

        // 1 is the identity
        assert_eq!(a.pow(&BigNum::new(hex!("01"))), a);

        assert_eq!(
            a.pow(&BigNum::new(hex!("02"))).buffer,
            hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7")
        );
        assert_eq!(
            a.pow(&BigNum::new(hex!("00000002"))).buffer,
            hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7")
        );
        assert_eq!(
            a.pow(&BigNum::new(hex!(
                "0000000000000000000000000000000000000000000000000000000000000002"
            )))
            .buffer,
            hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7")
        );
    }
}
