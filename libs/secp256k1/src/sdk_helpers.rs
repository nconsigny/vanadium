use sdk::bignum::{BigNum, BigNumMod};

use crate::constants::P;
use crate::Error::{self, InvalidPublicKey};

// helper function to compute the square root candidate
// returns Some(y) if a square root (y) exists for x^3 + 7, otherwise None.
#[inline(always)]
fn secp256k1_compute_y_internal<'a>(x: &'a BigNumMod<'a, 32>) -> Option<BigNumMod<'a, 32>> {
    let mut t = x * x;
    t *= x;
    t += BigNumMod::from_u32(7, &P);
    let y = t.pow(&BigNum::from_be_bytes(crate::constants::SQR_EXPONENT));

    if &y * &y == t {
        Some(y)
    } else {
        None
    }
}

// Computes a y-coordinate using (x^3 + 7)^SQR_EXPONENT
// It returns InvalidPublicKey if the x does not have a corresponding y on the curve
#[inline]
pub fn secp256k1_compute_y<'a>(x: &'a BigNumMod<'a, 32>) -> Result<BigNumMod<'a, 32>, Error> {
    secp256k1_compute_y_internal(x).ok_or(InvalidPublicKey)
}

// Computes the even y-coordinate using (x^3 + 7)^SQR_EXPONENT
// It returns InvalidPublicKey if the x does not have a corresponding y on the curve
#[inline]
pub fn secp256k1_compute_even_y<'a>(x: &'a BigNumMod<'a, 32>) -> Result<BigNumMod<'a, 32>, Error> {
    let mut y = secp256k1_compute_y_internal(x).ok_or(InvalidPublicKey)?;

    // if the last byte of y is odd, negate it to ensure an even y-coordinate
    if y.as_be_bytes()[31] & 1 != 0 {
        let zero = BigNumMod::from_u32(0, &P);
        y = &zero - &y;
    }

    Ok(y)
}
