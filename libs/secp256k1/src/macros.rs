// SPDX-License-Identifier: CC0-1.0

/// Implement methods and traits for types that contain an inner array.
#[macro_export]
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:expr) => {
        impl AsRef<[$ty; $len]> for $thing {
            #[inline]
            /// Gets a reference to the underlying array
            fn as_ref(&self) -> &[$ty; $len] {
                let &$thing(ref dat) = self;
                dat
            }
        }

        impl<I> core::ops::Index<I> for $thing
        where
            [$ty]: core::ops::Index<I>,
        {
            type Output = <[$ty] as core::ops::Index<I>>::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }
    };
}

macro_rules! impl_pretty_debug {
    ($thing:ident) => {
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}(", stringify!($thing))?;
                for i in &self[..] {
                    write!(f, "{:02x}", i)?;
                }
                f.write_str(")")
            }
        }
    };
}

/// Formats error. If `std` feature is OFF appends error source (delimited by `: `). We do this
/// because `e.source()` is only available in std builds, without this macro the error source is
/// lost for no-std builds.
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr),*; $source:expr) => {
        {
            write!($writer, concat!($string, ": {}") $(, $args)*, $source)
        }
    }
}
