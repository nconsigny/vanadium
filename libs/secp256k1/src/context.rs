// SPDX-License-Identifier: CC0-1.0

use core::marker::PhantomData;

#[cfg(feature = "alloc")]
pub use self::alloc_only::{All, SignOnly, VerifyOnly};

/// A trait for all kinds of contexts that lets you define the exact flags and a function to
/// deallocate memory. It isn't possible to implement this for types outside this crate.
///
/// # Safety
///
/// This trait is marked unsafe to allow unsafe implementations of `deallocate`.
pub unsafe trait Context: private::Sealed {
    /// A constant description of the context.
    const DESCRIPTION: &'static str;
    /// A function to deallocate the memory when the context is dropped.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid. Further safety constraints may be imposed by [`std::alloc::dealloc`].
    unsafe fn deallocate(ptr: *mut u8, size: usize);
}

/// Marker trait for indicating that an instance of [`Secp256k1`] can be used for signing.
pub trait Signing: Context {}

/// Marker trait for indicating that an instance of [`Secp256k1`] can be used for verification.
pub trait Verification: Context {}

/// Represents the set of capabilities needed for signing (preallocated memory).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of capabilities needed for verification (preallocated memory).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of all capabilities (preallocated memory).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

mod private {
    use super::*;
    pub trait Sealed {}

    impl<'buf> Sealed for AllPreallocated<'buf> {}
    impl<'buf> Sealed for VerifyOnlyPreallocated<'buf> {}
    impl<'buf> Sealed for SignOnlyPreallocated<'buf> {}
}

#[cfg(feature = "alloc")]
mod alloc_only {
    use core::marker::PhantomData;

    use super::private;
    use crate::{Context, Secp256k1, Signing, Verification};

    impl private::Sealed for SignOnly {}
    impl private::Sealed for All {}
    impl private::Sealed for VerifyOnly {}

    /// Represents the set of capabilities needed for signing.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SignOnly {}

    /// Represents the set of capabilities needed for verification.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum VerifyOnly {}

    /// Represents the set of all capabilities.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum All {}

    impl Signing for SignOnly {}
    impl Signing for All {}

    impl Verification for VerifyOnly {}
    impl Verification for All {}

    unsafe impl Context for SignOnly {
        const DESCRIPTION: &'static str = "signing only";

        unsafe fn deallocate(_ptr: *mut u8, _size: usize) {}
    }

    unsafe impl Context for VerifyOnly {
        const DESCRIPTION: &'static str = "verification only";

        unsafe fn deallocate(_ptr: *mut u8, _size: usize) {}
    }

    unsafe impl Context for All {
        const DESCRIPTION: &'static str = "all capabilities";

        unsafe fn deallocate(_ptr: *mut u8, _size: usize) {}
    }

    impl<C: Context> Secp256k1<C> {
        /// Lets you create a context in a generic manner (sign/verify/all).
        ///
        /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// If `rand-std` feature is not enabled please consider randomizing the context as follows:
        /// ```
        /// # #[cfg(feature = "rand-std")] {
        /// # use secp256k1::Secp256k1;
        /// # use secp256k1::rand::{thread_rng, RngCore};
        /// let mut ctx = Secp256k1::new();
        /// # let mut rng = thread_rng();
        /// # let mut seed = [0u8; 32];
        /// # rng.fill_bytes(&mut seed);
        /// // let seed = <32 bytes of random data>
        /// ctx.seeded_randomize(&seed);
        /// # }
        /// ```
        #[allow(clippy::let_and_return, unused_mut)]
        pub fn gen_new() -> Secp256k1<C> {
            #[allow(unused_mut)] // ctx is not mutated under some feature combinations.
            let mut ctx = Secp256k1 { phantom: PhantomData };

            #[allow(clippy::let_and_return)] // as for unusted_mut
            ctx
        }
    }

    impl Secp256k1<All> {
        /// Creates a new Secp256k1 context with all capabilities.
        ///
        /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// If `rand-std` feature is not enabled please consider randomizing the context (see docs
        /// for `Secp256k1::gen_new()`).
        pub fn new() -> Secp256k1<All> { Secp256k1::gen_new() }
    }

    impl Secp256k1<SignOnly> {
        /// Creates a new Secp256k1 context that can only be used for signing.
        ///
        /// If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// If `rand-std` feature is not enabled please consider randomizing the context (see docs
        /// for `Secp256k1::gen_new()`).
        pub fn signing_only() -> Secp256k1<SignOnly> { Secp256k1::gen_new() }
    }

    impl Secp256k1<VerifyOnly> {
        /// Creates a new Secp256k1 context that can only be used for verification.
        ///
        /// * If `rand-std` feature is enabled, context will have been randomized using `thread_rng`.
        /// * If `rand-std` feature is not enabled please consider randomizing the context (see docs
        /// for `Secp256k1::gen_new()`).
        pub fn verification_only() -> Secp256k1<VerifyOnly> { Secp256k1::gen_new() }
    }

    impl Default for Secp256k1<All> {
        fn default() -> Self { Self::new() }
    }

    impl<C: Context> Clone for Secp256k1<C> {
        fn clone(&self) -> Secp256k1<C> { Secp256k1 { phantom: PhantomData } }
    }
}

impl<'buf> Signing for SignOnlyPreallocated<'buf> {}
impl<'buf> Signing for AllPreallocated<'buf> {}

impl<'buf> Verification for VerifyOnlyPreallocated<'buf> {}
impl<'buf> Verification for AllPreallocated<'buf> {}

unsafe impl<'buf> Context for SignOnlyPreallocated<'buf> {
    const DESCRIPTION: &'static str = "signing only";

    unsafe fn deallocate(_ptr: *mut u8, _size: usize) {
        // Allocated by the user
    }
}

unsafe impl<'buf> Context for VerifyOnlyPreallocated<'buf> {
    const DESCRIPTION: &'static str = "verification only";

    unsafe fn deallocate(_ptr: *mut u8, _size: usize) {
        // Allocated by the user.
    }
}

unsafe impl<'buf> Context for AllPreallocated<'buf> {
    const DESCRIPTION: &'static str = "all capabilities";

    unsafe fn deallocate(_ptr: *mut u8, _size: usize) {
        // Allocated by the user.
    }
}
