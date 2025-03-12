use sdk::bignum::{BigNum, BigNumMod};

use crate::constants::P;
use crate::Error::{self, InvalidPublicKey};

// computes a y-coordinate using (x^3 + 7)^SQR_EXPONENT
// it returns InvalidPublicKey if the x does not have a corresponding y on the curve
#[inline]
pub fn secp256k1_compute_y<'a>(x: &'a BigNumMod<'a, 32>) -> Result<BigNumMod<'a, 32>, Error> {
    let mut t = x * x;
    t *= x;
    t += BigNumMod::from_u32(7, &P);
    let y = t.pow(&BigNum::from_be_bytes(crate::constants::SQR_EXPONENT));

    if &y * &y == t {
        Ok(y)
    } else {
        Err(InvalidPublicKey)
    }
}
