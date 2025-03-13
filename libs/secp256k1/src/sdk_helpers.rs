use sdk::bignum::{BigNum, BigNumMod};

use crate::Error::{self, InvalidPublicKey};

// helper function to compute the square root candidate
// returns Some(y) if a square root (y) exists for x^3 + 7, otherwise None.
#[inline(always)]
fn secp256k1_compute_y_internal<'a>(x: &'a BigNumMod<'a, 32>) -> Option<BigNumMod<'a, 32>> {
    let t = x * x * x + 7;
    let y = t.pow(&BigNum::from_be_bytes(crate::constants::SQR_EXPONENT));

    if y * y == t {
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

// Computes the y-coordinate using (x^3 + 7)^SQR_EXPONENT with the given parity
// It returns InvalidPublicKey if the x does not have a corresponding y on the curve
#[inline]
pub fn secp256k1_compute_y_with_parity<'a>(
    x: &'a BigNumMod<'a, 32>,
    parity: u8,
) -> Result<BigNumMod<'a, 32>, Error> {
    if parity > 1 {
        panic!("This function must be called with parity equal to exactly 0 or 1");
    }

    let mut y = secp256k1_compute_y_internal(x).ok_or(InvalidPublicKey)?;

    // if the last byte of y doesn't have the correct parity, negate it
    if y.as_be_bytes()[31] & 1 != parity {
        y = -y;
    }

    Ok(y)
}
