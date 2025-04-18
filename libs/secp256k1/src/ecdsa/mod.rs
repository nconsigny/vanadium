// SPDX-License-Identifier: CC0-1.0

//! Structs and functionality related to the ECDSA signature algorithm.
//!

pub mod serialized_signature;

use core::{fmt, str};

pub use self::serialized_signature::SerializedSignature;
use crate::{from_hex, Error, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

/// An ECDSA signature
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Signature(pub(crate) [u8; 64]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sig = self.serialize_der();
        sig.fmt(f)
    }
}

impl str::FromStr for Signature {
    type Err = Error;
    fn from_str(s: &str) -> Result<Signature, Error> {
        let mut res = [0u8; 72];
        match from_hex(s, &mut res) {
            Ok(x) => Signature::from_der(&res[0..x]),
            _ => Err(Error::InvalidSignature),
        }
    }
}

impl Signature {
    #[inline]
    /// Converts a DER-encoded byte slice to a signature
    pub fn from_der(data: &[u8]) -> Result<Signature, Error> {
        if data.len() < 6 {
            return Err(Error::InvalidSignature);
        }

        // Check tag
        if data[0] != 0x30 {
            return Err(Error::InvalidSignature);
        }

        // Total length of the sequence
        let total_len = data[1];
        if data.len() < total_len as usize + 2 {
            return Err(Error::InvalidSignature);
        }

        // Parse r value
        let mut pos = 2;
        if data[pos] != 0x02 {
            return Err(Error::InvalidSignature);
        }
        pos += 1;
        let r_len = data[pos] as usize;
        pos += 1;

        // Handle r value (skip leading zero if present)
        let r_start = if r_len > 32 && data[pos] == 0 { pos + 1 } else { pos };
        let r_actual_len = if r_len > 32 { r_len - 1 } else { r_len };
        if r_actual_len > 32 {
            return Err(Error::InvalidSignature);
        }

        // Parse s value
        pos = pos + r_len;
        if pos >= data.len() || data[pos] != 0x02 {
            return Err(Error::InvalidSignature);
        }
        pos += 1;
        let s_len = data[pos] as usize;
        pos += 1;

        // Handle s value (skip leading zero if present)
        let s_start = if s_len > 32 && data[pos] == 0 { pos + 1 } else { pos };
        let s_actual_len = if s_len > 32 { s_len - 1 } else { s_len };
        if s_actual_len > 32 {
            return Err(Error::InvalidSignature);
        }

        let mut result = [0u8; 64];

        // Copy r (left-pad with zeros if necessary)
        let r_dest_start = 32 - r_actual_len;
        result[r_dest_start..32].copy_from_slice(&data[r_start..r_start + r_actual_len]);
        // Copy s (left-pad with zeros if necessary)
        let s_dest_start = 64 - s_actual_len;
        result[s_dest_start..64].copy_from_slice(&data[s_start..s_start + s_actual_len]);

        Ok(Self(result))
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature
    pub fn from_compact(data: &[u8]) -> Result<Signature, Error> {
        if data.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        todo!()
    }

    /// Converts a "lax DER"-encoded byte slice to a signature. This is basically
    /// only useful for validating signatures in the Bitcoin blockchain from before
    /// 2016. It should never be used in new applications. This library does not
    /// support serializing to this "format"
    pub fn from_der_lax(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {
            return Err(Error::InvalidSignature);
        }

        todo!()
    }

    /// Normalizes a signature to a "low S" form. In ECDSA, signatures are
    /// of the form (r, s) where r and s are numbers lying in some finite
    /// field. The verification equation will pass for (r, s) iff it passes
    /// for (r, -s), so it is possible to ``modify'' signatures in transit
    /// by flipping the sign of s. This does not constitute a forgery since
    /// the signed message still cannot be changed, but for some applications,
    /// changing even the signature itself can be a problem. Such applications
    /// require a "strong signature". It is believed that ECDSA is a strong
    /// signature except for this ambiguity in the sign of s, so to accommodate
    /// these applications libsecp256k1 considers signatures for which s is in
    /// the upper half of the field range invalid. This eliminates the
    /// ambiguity.
    ///
    /// However, for some systems, signatures with high s-values are considered
    /// valid. (For example, parsing the historic Bitcoin blockchain requires
    /// this.) For these applications we provide this normalization function,
    /// which ensures that the s value lies in the lower half of its range.
    pub fn normalize_s(&mut self) { todo!() }

    #[inline]
    /// Serializes the signature in DER format
    pub fn serialize_der(&self) -> SerializedSignature {
        let r = &self.0[0..32];
        let s = &self.0[32..64];

        // Calculate lengths for r and s, including potential leading zero
        let r_len = 32 + ((r[0] >= 0x80) as usize);
        let s_len = 32 + ((s[0] >= 0x80) as usize);

        let inner_len = 2 + r_len + 2 + s_len; // 2 bytes each for INTEGER tags and lengths

        let mut data = [0u8; serialized_signature::MAX_LEN];

        let mut pos = 0;

        // Write SEQUENCE tag and length
        data[pos] = 0x30;
        pos += 1;
        data[pos] = inner_len as u8;
        pos += 1;

        // Write r value
        data[pos] = 0x02;
        pos += 1;
        data[pos] = r_len as u8;
        pos += 1;
        if r[0] >= 0x80 {
            data[pos] = 0x00;
            pos += 1;
        }
        data[pos..pos + 32].copy_from_slice(r);
        pos += 32;

        // Write s value
        data[pos] = 0x02;
        pos += 1;
        data[pos] = s_len as u8;
        pos += 1;
        if s[0] >= 0x80 {
            data[pos] = 0x00;
            pos += 1;
        }
        data[pos..pos + 32].copy_from_slice(s);
        pos += 32;

        SerializedSignature::new(data, pos)
    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize_compact(&self) -> [u8; 64] { self.0 }
}

/// Creates a new signature from a FFI signature
impl From<[u8; 64]> for Signature {
    #[inline]
    fn from(sig: [u8; 64]) -> Signature { Signature(sig) }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize_der())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(crate::serde_util::FromStrVisitor::new(
                "a hex string representing a DER encoded Signature",
            ))
        } else {
            d.deserialize_bytes(crate::serde_util::BytesVisitor::new(
                "raw byte stream, that represents a DER encoded Signature",
                Signature::from_der,
            ))
        }
    }
}

impl<C: Signing> Secp256k1<C> {
    fn sign_ecdsa_with_noncedata_pointer(
        &self,
        msg: &Message,
        sk: &SecretKey,
        noncedata: Option<&[u8; 32]>,
    ) -> Signature {
        match noncedata {
            Some(_) => todo!(), // not implemented
            None => {
                let privkey =
                    sdk::curve::EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*sk.as_ref());
                let sig_raw = privkey.ecdsa_sign_hash(msg.as_ref()).unwrap();
                Signature::from_der(&sig_raw).unwrap()
            }
        }
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign_ecdsa(&self, msg: &Message, sk: &SecretKey) -> Signature {
        self.sign_ecdsa_with_noncedata_pointer(msg, sk, None)
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// and includes 32 bytes of noncedata in the nonce generation via inclusion in
    /// one of the hash operations during nonce generation. This is useful when multiple
    /// signatures are needed for the same Message and SecretKey while still using RFC6979.
    /// Requires a signing-capable context.
    pub fn sign_ecdsa_with_noncedata(
        &self,
        msg: &Message,
        sk: &SecretKey,
        noncedata: &[u8; 32],
    ) -> Signature {
        self.sign_ecdsa_with_noncedata_pointer(msg, sk, Some(noncedata))
    }

    fn sign_grind_with_check(
        &self,
        msg: &Message,
        sk: &SecretKey,
        check: impl Fn(&[u8; 64]) -> bool,
    ) -> Signature {
        todo!()
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 - `bytes_to_grind` bytes. The number
    /// of signing operation performed by this function is exponential in the
    /// number of bytes grinded.
    /// Requires a signing capable context.
    pub fn sign_ecdsa_grind_r(
        &self,
        msg: &Message,
        sk: &SecretKey,
        bytes_to_grind: usize,
    ) -> Signature {
        let len_check = |s: &[u8; 64]| der_length_check(s, 71 - bytes_to_grind);
        self.sign_grind_with_check(msg, sk, len_check)
    }

    /// Constructs a signature for `msg` using the secret key `sk`, RFC6979 nonce
    /// and "grinds" the nonce by passing extra entropy if necessary to produce
    /// a signature that is less than 71 bytes and compatible with the low r
    /// signature implementation of bitcoin core. In average, this function
    /// will perform two signing operations.
    /// Requires a signing capable context.
    pub fn sign_ecdsa_low_r(&self, msg: &Message, sk: &SecretKey) -> Signature {
        self.sign_grind_with_check(msg, sk, compact_sig_has_zero_first_bit)
    }
}

impl<C: Verification> Secp256k1<C> {
    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(())` on success. Note that this function cannot
    /// be used for Bitcoin consensus checking since there may exist signatures
    /// which OpenSSL would verify but not libsecp256k1, or vice-versa. Requires a
    /// verify-capable context.
    ///
    /// ```rust
    /// # #[cfg(feature = "rand-std")] {
    /// # use secp256k1::{rand, Secp256k1, Message, Error};
    /// #
    /// # let secp = Secp256k1::new();
    /// # let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
    /// #
    /// let message = Message::from_digest_slice(&[0xab; 32]).expect("32 bytes");
    /// let sig = secp.sign_ecdsa(&message, &secret_key);
    /// assert_eq!(secp.verify_ecdsa(&message, &sig, &public_key), Ok(()));
    ///
    /// let message = Message::from_digest_slice(&[0xcd; 32]).expect("32 bytes");
    /// assert_eq!(secp.verify_ecdsa(&message, &sig, &public_key), Err(Error::IncorrectSignature));
    /// # }
    /// ```
    #[inline]
    pub fn verify_ecdsa(
        &self,
        msg: &Message,
        sig: &Signature,
        pk: &PublicKey,
    ) -> Result<(), Error> {
        todo!()
    }
}

pub(crate) fn compact_sig_has_zero_first_bit(sig: &[u8; 64]) -> bool { todo!() }

pub(crate) fn der_length_check(sig: &[u8; 64], max_len: usize) -> bool { todo!() }
