use alloc::{string::String, vec::Vec};
use core::convert::TryInto;

pub trait Serializable: Sized {
    fn get_serialized_length(&self) -> usize;

    fn serialize(&self, buf: &mut [u8], pos: &mut usize);
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str>;

    #[inline(always)]
    fn serialized(&self) -> Vec<u8> {
        let len = self.get_serialized_length();
        let mut buf = Vec::with_capacity(len);
        unsafe {
            // we don't bother initializing the content, since it will be overwritten
            buf.set_len(len);
        }
        let mut pos = 0;
        self.serialize(&mut buf, &mut pos);
        buf
    }

    fn deserialize_full(slice: &[u8]) -> Result<Self, &'static str> {
        let (value, rest) = Self::deserialize(slice)?;
        if !rest.is_empty() {
            Err("extra bytes remaining after deserialization")
        } else {
            Ok(value)
        }
    }
}

impl Serializable for bool {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        1
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        buf[*pos] = *self as u8;
        *pos += 1;
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if let Some((&byte, rest)) = slice.split_first() {
            match byte {
                0 => Ok((false, rest)),
                1 => Ok((true, rest)),
                _ => Err("invalid boolean value"),
            }
        } else {
            Err("slice too short for bool")
        }
    }
}

impl Serializable for u8 {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        1
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        buf[*pos] = *self;
        *pos += 1;
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if let Some((&byte, rest)) = slice.split_first() {
            Ok((byte, rest))
        } else {
            Err("slice too short for u8")
        }
    }
}

impl Serializable for u16 {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        2
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        // we avoid using to_be_bytes() and copy_from_slice to make it easier for the compiler to
        // optimize this when serializing a fixed known constant.
        buf[*pos] = (*self >> 8) as u8;
        buf[*pos + 1] = (*self & 0xFF) as u8;
        *pos += 2;
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.len() < 2 {
            Err("slice too short for u16")
        } else {
            let (bytes, rest) = slice.split_at(2);
            let arr: [u8; 2] = bytes.try_into().unwrap();
            Ok((u16::from_be_bytes(arr), rest))
        }
    }
}

impl Serializable for u32 {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        4
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        // we avoid using to_be_bytes() and copy_from_slice to make it easier for the compiler to
        // optimize this when serializing a fixed known constant.
        buf[*pos] = (*self >> 24) as u8;
        buf[*pos + 1] = ((*self >> 16) & 0xFF) as u8;
        buf[*pos + 2] = ((*self >> 8) & 0xFF) as u8;
        buf[*pos + 3] = (*self & 0xFF) as u8;
        *pos += 4;
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.len() < 4 {
            Err("slice too short for u32")
        } else {
            let (bytes, rest) = slice.split_at(4);
            let arr: [u8; 4] = bytes.try_into().unwrap();
            Ok((u32::from_be_bytes(arr), rest))
        }
    }
}

impl Serializable for String {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        core::mem::size_of::<u16>() + self.len()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let bytes = self.as_bytes();
        let len = bytes.len();
        if len > u16::MAX as usize {
            panic!("string too long");
        }
        (len as u16).serialize(buf, pos);

        buf[*pos..*pos + len].copy_from_slice(bytes);
        *pos += len;
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        let (len, rest) = u16::deserialize(slice)?;
        let len = len as usize;
        if rest.len() < len {
            return Err("slice too short for string");
        }
        let (string_bytes, rest) = rest.split_at(len);
        let s = String::from_utf8(string_bytes.to_vec()).map_err(|_| "invalid utf8")?;
        Ok((s, rest))
    }
}

impl<T: Serializable> Serializable for Option<T> {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        1 + match self {
            Some(value) => value.get_serialized_length(),
            None => 0,
        }
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        match self {
            Some(value) => {
                buf[*pos] = 1;
                *pos += 1;
                value.serialize(buf, pos);
            }
            None => {
                buf[*pos] = 0;
                *pos += 1;
            }
        }
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if let Some((&tag, rest)) = slice.split_first() {
            match tag {
                1 => {
                    let (value, rest) = T::deserialize(rest)?;
                    Ok((Some(value), rest))
                }
                0 => Ok((None, rest)),
                _ => Err("invalid Option tag"),
            }
        } else {
            Err("slice too short for Option tag")
        }
    }
}

impl<T: Serializable> Serializable for Vec<T> {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        4 + self
            .iter()
            .map(Serializable::get_serialized_length)
            .sum::<usize>()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let len = self.len();
        if len > (u32::MAX as usize) {
            panic!("vector too long");
        }
        (len as u32).serialize(buf, pos);
        for item in self {
            item.serialize(buf, pos);
        }
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        let (len, mut rem) = u32::deserialize(slice)?;
        let mut vec = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let (item, next) = T::deserialize(rem)?;
            vec.push(item);
            rem = next;
        }
        Ok((vec, rem))
    }
}

// a reduced-functionality version of Serializable, only used for &str
// and its composite types, and slices of Serializable types.
pub trait MiniSerializable: Sized {
    fn get_serialized_length(&self) -> usize;
    fn serialize(&self, buf: &mut [u8], pos: &mut usize);
}

impl MiniSerializable for &str {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        core::mem::size_of::<u16>() + self.len()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let bytes = self.as_bytes();
        let len = bytes.len();
        if len > u16::MAX as usize {
            panic!("string too long");
        }
        (len as u16).serialize(buf, pos);
        buf[*pos..*pos + len].copy_from_slice(bytes);
        *pos += len;
    }
}

impl<T: Serializable> MiniSerializable for &[T] {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        4 + self
            .iter()
            .map(Serializable::get_serialized_length)
            .sum::<usize>()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let len = self.len();
        if len > (u32::MAX as usize) {
            panic!("slice too long");
        }
        (len as u32).serialize(buf, pos);
        for item in self.iter() {
            item.serialize(buf, pos);
        }
    }
}

impl<T: MiniSerializable> MiniSerializable for Option<T> {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        1 + match self {
            Some(value) => value.get_serialized_length(),
            None => 0,
        }
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        match self {
            Some(value) => {
                buf[*pos] = 1;
                *pos += 1;
                value.serialize(buf, pos);
            }
            None => {
                buf[*pos] = 0;
                *pos += 1;
            }
        }
    }
}

impl<T: MiniSerializable> MiniSerializable for Vec<T> {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        4 + self
            .iter()
            .map(MiniSerializable::get_serialized_length)
            .sum::<usize>()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let len = self.len();
        if len > (u32::MAX as usize) {
            panic!("vector too long");
        }

        (len as u32).serialize(buf, pos);
        for item in self {
            item.serialize(buf, pos);
        }
    }
}

/// Wrapped Serialization
///
/// This module extends the basic serialization functionality by introducing the concept
/// of wrapped serialization. It allows a type to be serialized as a sequence of parts, where
/// each part can either be a static byte sequence (known at compile-time) or a runtime placeholder
/// (to be resolved later).
///
/// The main components for wrapped serialization are:
///
/// - `MaybeConst<T>` and `MaybeConstStr`:
///   - These enums distinguish between a constant serialized value (the `Const` variant)
///     and a value that is to be provided at runtime (the `Runtime` variant).
///
/// - `SerializedPart`:
///   - This enum represents a part of the wrapped serialization output. It holds either a
///     static vector of bytes (`Static` variant) or a runtime placeholder with associated
///     argument details (`Runtime` variant).
///
/// - `WrappedSerializable` trait:
///   - Types that implement this trait provide a method `serialize_wrapped` which returns
///     a vector of `SerializedPart` instances. This allows complex types to have their serialization
///     split into multiple parts, mixing static and runtime-defined segments.
///
/// - `Wrappable` trait:
///   - This trait defines an association between a type and its wrapped counterpart. It is used
///     to automatically generate wrapped versions of serializable types (e.g., for structs or enums)
///     when the feature flag `wrapped_serializable` is enabled.
///
/// Wrapped serialization is used in the build.rs script of the app-sdk to create efficient serializers
/// for the various types of Page objects.

#[cfg(feature = "wrapped_serializable")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MaybeConst<T: Serializable> {
    Const(T),
    Runtime {
        arg_name: &'static str,
        arg_type: &'static str,
    },
}

#[cfg(feature = "wrapped_serializable")]
impl<T: Serializable> WrappedSerializable for MaybeConst<T> {
    fn serialize_wrapped(&self) -> Vec<SerializedPart> {
        match self {
            MaybeConst::Const(value) => {
                let mut buf = alloc::vec![0; value.get_serialized_length()];
                let mut pos = 0;
                value.serialize(&mut buf, &mut pos);
                alloc::vec![SerializedPart::Static(buf)]
            }
            MaybeConst::Runtime { arg_name, arg_type } => {
                alloc::vec![SerializedPart::Runtime { arg_name, arg_type }]
            }
        }
    }
}

#[cfg(feature = "wrapped_serializable")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MaybeConstStr {
    Const(&'static str),
    Runtime {
        arg_name: &'static str,
        arg_type: &'static str,
    },
}

#[cfg(feature = "wrapped_serializable")]
impl WrappedSerializable for MaybeConstStr {
    fn serialize_wrapped(&self) -> Vec<SerializedPart> {
        match self {
            MaybeConstStr::Const(value) => {
                let mut buf = (value.len() as u16).serialized();
                buf.extend_from_slice(value.as_bytes());
                alloc::vec![SerializedPart::Static(buf)]
            }
            MaybeConstStr::Runtime { arg_name, arg_type } => {
                alloc::vec![SerializedPart::Runtime { arg_name, arg_type }]
            }
        }
    }
}

#[cfg(feature = "wrapped_serializable")]
impl<T: WrappedSerializable> WrappedSerializable for Option<T> {
    fn serialize_wrapped(&self) -> Vec<SerializedPart> {
        let mut result = Vec::new();
        match self {
            Some(value) => {
                result.push(SerializedPart::Static(alloc::vec![1]));
                result.extend(value.serialize_wrapped());
            }
            None => {
                result.push(SerializedPart::Static(alloc::vec![0]));
            }
        }
        result
    }
}

#[cfg(feature = "wrapped_serializable")]
pub const fn ct<T: Serializable>(value: T) -> MaybeConst<T> {
    MaybeConst::Const(value)
}

#[cfg(feature = "wrapped_serializable")]
pub const fn rt<T: Serializable>(arg_name: &'static str, arg_type: &'static str) -> MaybeConst<T> {
    MaybeConst::Runtime { arg_name, arg_type }
}

#[cfg(feature = "wrapped_serializable")]
pub const fn ct_str(value: &'static str) -> MaybeConstStr {
    MaybeConstStr::Const(value)
}

#[cfg(feature = "wrapped_serializable")]
pub const fn rt_str(arg_name: &'static str, arg_type: &'static str) -> MaybeConstStr {
    MaybeConstStr::Runtime { arg_name, arg_type }
}

#[cfg(feature = "wrapped_serializable")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SerializedPart {
    Static(Vec<u8>),
    Runtime {
        arg_name: &'static str,
        arg_type: &'static str,
    },
}

#[cfg(feature = "wrapped_serializable")]
pub trait WrappedSerializable {
    fn serialize_wrapped(&self) -> Vec<SerializedPart>;
}

// This allows to associate what is the wrapped type for a given type.
#[cfg(feature = "wrapped_serializable")]
pub trait Wrappable {
    type Wrapped;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for bool {
    type Wrapped = MaybeConst<bool>;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for u8 {
    type Wrapped = MaybeConst<u8>;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for u16 {
    type Wrapped = MaybeConst<u16>;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for u32 {
    type Wrapped = MaybeConst<u32>;
}

#[cfg(feature = "wrapped_serializable")]
impl<T: Wrappable> Wrappable for Option<T> {
    type Wrapped = Option<T::Wrapped>;
}

#[cfg(feature = "wrapped_serializable")]
impl<T: Serializable> Wrappable for Vec<T> {
    // for vectors, we can't really wrap individual elements,
    // as the length of the vector is not statically known
    type Wrapped = MaybeConst<Vec<T>>;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for String {
    type Wrapped = MaybeConstStr;
}

// The makeable trait allows to specify the type of argument that should be passed
// to the maker function. This is allows to have (for example) a maker function that
// accepts a `&str` argument, when actual field in the object is a `String`.
pub trait Makeable<'a> {
    type ArgType;
}

impl Makeable<'_> for bool {
    type ArgType = bool;
}

impl Makeable<'_> for u8 {
    type ArgType = u8;
}

impl Makeable<'_> for u16 {
    type ArgType = u16;
}

impl Makeable<'_> for u32 {
    type ArgType = u32;
}

impl<'a, T: Makeable<'a> + 'a> Makeable<'a> for Vec<T> {
    type ArgType = &'a [T];
}

impl<'a> Makeable<'a> for String {
    type ArgType = &'a str;
}

impl<'a, T: Makeable<'a>> Makeable<'a> for Option<T> {
    type ArgType = Option<T::ArgType>;
}

// MACROS

macro_rules! define_serializable_struct {
    (
        $name:ident {
            $($field:ident : $field_ty:ty),* $(,)?
        },
        wrapped: $wrapped_name:ident
    ) => {
        // Non-wrapped struct
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name {
            $(pub $field: $field_ty),*
        }

        impl Serializable for $name {
            #[inline(always)]
            fn get_serialized_length(&self) -> usize {
                0 $( + self.$field.get_serialized_length() )*
            }

            #[inline(always)]
            fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
                $( self.$field.serialize(buf, pos); )*
            }

            fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
                let mut slice = slice;
                $(
                    let ($field, new_slice) = <$field_ty>::deserialize(slice)?;
                    slice = new_slice;
                )*
                Ok((Self { $($field),* }, slice))
            }
        }

        // Wrapped struct (under feature flag)
        #[cfg(feature = "wrapped_serializable")]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $wrapped_name {
            $(pub $field: <$field_ty as Wrappable>::Wrapped),*
        }

        #[cfg(feature = "wrapped_serializable")]
        impl WrappedSerializable for $wrapped_name {
            fn serialize_wrapped(&self) -> alloc::vec::Vec<SerializedPart> {
                let mut parts = alloc::vec::Vec::new();
                $(
                    parts.extend(self.$field.serialize_wrapped());
                )*
                parts
            }
        }

        #[cfg(feature = "wrapped_serializable")]
        impl Wrappable for $name {
            type Wrapped = $wrapped_name;
        }

        impl Makeable<'_> for $name {
            type ArgType = $name;
        }
    };
}

macro_rules! define_serializable_enum {
    (
        $name:ident {
            $(
                $tag:expr => $variant:ident {
                    $($field:ident : $enum_ty:ty),* $(,)?
                } as ($fn_maker:ident, $fn_maker_wrapped:ident)
            ),* $(,)?
        },
        wrapped: $wrapped_name:ident
    ) => {
        // Non-wrapped enum
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum $name {
            $(
                $variant { $($field: $enum_ty),* },
            )*
        }

        impl Serializable for $name {
            #[inline(always)]
            fn get_serialized_length(&self) -> usize {
                match self {
                    $(
                        Self::$variant { $($field),* } => 1 $( + $field.get_serialized_length() )*
                    ),*
                }
            }

            #[inline(always)]
            fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
                match self {
                    $(
                        Self::$variant { $($field),* } => {
                            $tag.serialize(buf, pos);
                            $(
                                $field.serialize(buf, pos);
                            )*
                        }
                    ),*
                }
            }

            fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
                if slice.is_empty() {
                    return Err(concat!(stringify!($name), " slice too short for tag"));
                }
                let (tag, rest) = slice.split_first().unwrap();
                match tag {
                    $(
                        x if *x == $tag => {
                            let mut r = rest;
                            $(
                                let ($field, new_r) = <$enum_ty>::deserialize(r)?;
                                r = new_r;
                            )*
                            Ok((Self::$variant { $($field),* }, r))
                        }
                    ),*,
                    _ => Err("unknown tag"),
                }
            }
        }

        // Maker functions
        impl $name {
            $(
                #[inline(always)]
                pub fn $fn_maker($($field: <$enum_ty as Makeable>::ArgType),*) -> alloc::vec::Vec<u8> {
                    let len = {
                        let mut len = $tag.get_serialized_length();
                        $( len += $field.get_serialized_length(); )*
                        len
                    };
                    let mut buf = alloc::vec::Vec::with_capacity(len);
                    unsafe { buf.set_len(len); }
                    let mut pos: usize = 0;
                    $tag.serialize(&mut buf, &mut pos);
                    $( $field.serialize(&mut buf, &mut pos); )*
                    buf
                }
            )*
        }

        // Wrapped enum
        #[cfg(feature = "wrapped_serializable")]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum $wrapped_name {
            $(
                $variant { $($field: <$enum_ty as Wrappable>::Wrapped),* },
            )*
        }

        #[cfg(feature = "wrapped_serializable")]
        impl WrappedSerializable for $wrapped_name {
            fn serialize_wrapped(&self) -> alloc::vec::Vec<SerializedPart> {
                let mut parts = alloc::vec::Vec::new();
                match self {
                    $(
                        Self::$variant { $($field),* } => {
                            parts.push(SerializedPart::Static(alloc::vec![$tag]));
                            $(
                                parts.extend($field.serialize_wrapped());
                            )*
                        }
                    ),*
                }
                parts
            }
        }

        #[cfg(feature = "wrapped_serializable")]
        impl Wrappable for $name {
            type Wrapped = $wrapped_name;
        }

        impl Makeable<'_> for $name {
            type ArgType = $name;
        }
    };
}

pub(crate) use define_serializable_enum;
pub(crate) use define_serializable_struct;
