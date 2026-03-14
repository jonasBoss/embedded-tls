use crate::{TlsError, buffer::CryptoBuffer, parse_buffer::ParseBuffer};
use core::convert::identity;
use core::fmt::Debug;
use core::iter;
use std::marker::PhantomData;

pub trait Parse<'a>: Sized {
    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError>;
}

pub trait Encode {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError>;
}

macro_rules! int_p_e {
    ($t:ty, $parse:tt, $encode:tt) => {
        impl<'a> Parse<'a> for $t {
            fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
                buf.$parse().map_err(From::from)
            }
        }
        impl Encode for $t {
            fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
                buf.$encode(self)
            }
        }
    };
}
int_p_e!(u8, read_u8, push);
int_p_e!(u16, read_u16, push_u16);
int_p_e!(u32, read_u32, push_u32);

/// A slice of u8 with the size encoded as a u8
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SliceU8<'a>(pub &'a [u8]);

impl<'a> Parse<'a> for SliceU8<'a> {
    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
        let len = buf.read_u8()? as usize;
        Ok(Self(buf.slice(len)?.as_slice()))
    }
}

impl Encode for SliceU8<'_> {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u8_length(|buf| buf.extend_from_slice(self.0))
    }
}

#[cfg(not(feature = "defmt"))]
pub(crate) trait FormatBounds: Debug {}
#[cfg(feature = "defmt")]
pub(crate) trait FormatBounds: Debug + defmt::Format {}
impl<#[cfg(not(feature = "defmt"))] T: Debug, #[cfg(feature = "defmt")] T: Debug + defmt::Format>
    FormatBounds for T
{
}

/// The storage type trait can provide the storage for a struct via a generic parameter
///
/// Currently only the `ListType` is provided, used by the [`List`] as its internal data storage.
/// This may be extende with more associated types for different containers in the future.
pub(crate) trait StorageType {
    type ListType<'a, U: 'a + Parse<'a> + Encode + FormatBounds + Clone>: FormatBounds + Clone;
    type Binders<'a>: FormatBounds + Clone;
}

/// marker type that provides the [`StorageType`] for structures recieved from a remote peer
#[derive(Debug)]
pub struct Remote;
impl StorageType for Remote {
    type ListType<'a, U: 'a + Parse<'a> + Encode + FormatBounds + Clone> = ZerocopyList<'a, U>;
    type Binders<'a> = ZerocopyList<'a, SliceU8<'a>>;
}

/// marker type that provides the [`StorageType`] for structures sent to a remote peer
#[derive(Debug)]
pub struct Local;
impl StorageType for Local {
    type ListType<'a, U: 'a + Parse<'a> + Encode + FormatBounds + Clone> = DynIterList<'a, U>;
    type Binders<'a> = DynIterList<'a, u8>; // for binders we only provide the lengh for each binder locally
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ZerocopyList<'a, U: Parse<'a> + FormatBounds>(
    pub(crate) &'a [u8],
    PhantomData<U>,
);

impl<'a, U: Parse<'a> + FormatBounds> ZerocopyList<'a, U> {
    pub fn iter(&self) -> impl Iterator<Item = U> {
        let mut buf = ParseBuffer::new(self.0);
        iter::from_fn(move || U::parse(&mut buf).ok())
    }
}

impl<'a, U: Parse<'a> + FormatBounds> Parse<'a> for ZerocopyList<'a, U> {
    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
        let data = buf.as_slice();
        // this is only run to validate the data,
        iter::from_fn(|| {
            if buf.is_empty() {
                None
            } else {
                Some(U::parse(buf).map(|_parsed| ()))
            }
        })
        .try_for_each(identity)?;
        Ok(Self(data, PhantomData))
    }
}

impl<'a, U: Parse<'a> + FormatBounds> Debug for ZerocopyList<'a, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[cfg(feature = "defmt")]
impl<'a, U: Parse<'a> + FormatBounds> defmt::Format for ZerocopyList<'a, U> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "[");
        self.iter().for_each(|u| defmt::write!(fmt, "{},", u));
        defmt::write!(fmt, "]")
    }
}

pub(crate) struct DynIterList<'a, U: Encode>(pub(crate) &'a mut dyn Iterator<Item = U>);

impl<'a, U: Encode> DynIterList<'a, U> {
    pub fn new(iter: &'a mut dyn Iterator<Item = U>) -> Self {
        Self(iter)
    }
}

impl<U: Encode> Encode for DynIterList<'_, U> {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        for u in self.0 {
            u.encode(buf)?;
        }
        Ok(())
    }
}

impl<U: Encode> Debug for DynIterList<'_, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DynIterList").finish()
    }
}

#[cfg(feature = "defmt")]
impl<'a, U: Encode> defmt::Format for DynIterList<'a, U> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "DynIterList")
    }
}

impl<U: Encode> Clone for DynIterList<'_, U> {
    fn clone(&self) -> Self {
        // this impl is here so we can derive(Clone) on any wrapping types that use the StorageType trait
        #[cfg(not(feature = "defmt"))]
        core::unreachable!("there is never a need to clone a DynIterList");
        #[cfg(feature = "defmt")]
        defmt::unreachable!("there is never a need to clone a DynIterList");
    }
}

/// create a [`List`] wrapping newtype that encodes its lenght with the given type
///
/// The macro:
/// ``` ignore
/// # // we cannot doctest private items sadly
/// parse_encode_list!{
///     #[derive(Debug, Clone)]
///     #[lenght = u8] // the lenght attribute defaults to u16
///     pub struct MyListWithU8Lengh<'a, Location>(u32);
/// }
/// ```
/// will generate the following type:
/// ```ignore
/// #[derive(Debug, Clone)]
/// pub struct MyListWithU8Lenght<'a, Location>(Location::List<u32>)
/// where Location: StorageType;
/// ```
///
/// The [`Parse`](crate::parse_encode::Parse) and [`Encode`](crate::parse_encode::Encode) traits will be implemented where
/// the `Location` is [`Remote`](crate::parse_encode::Remote) and [`Local`](crate::parse_encode::Local) respecively.
///
/// For the remote type a `pub fn iter(&self) -> impl Iterator<Item = ...>`  and `pub fn len(&self) -> usize` is implemented.
/// For the local type a `pub fn new(iter: &mut dyn Iterator<Item = ...>) -> Self` is impelmented.
macro_rules! make_zerocopy_list {
    (@read u8, $buf:ident) => {
        $buf.read_u8()
    };
    (@read u16, $buf:ident) => {
        $buf.read_u16()
    };
    (@read u32, $buf:ident) => {
        $buf.read_u32()
    };

    (@encode u8, |$buf:ident| $fn:expr) => {
        $buf.with_u8_length(|$buf| $fn)
    };
    (@encode u16, |$buf:ident| $fn:expr) => {
        $buf.with_u16_length(|$buf| $fn)
    };
    (@encode u32, |$buf:ident| $fn:expr) => {
        $buf.with_u32_length(|$buf| $fn)
    };
    (
        $(#[$($attr:tt)*])*
        $vis:vis struct $name:ident<'a, Location>($item:ty);
    ) => {
        make_zerocopy_list!(
            @vis $vis,
            @name $name,
            @item $item,
            @attr ,
            @attr_to_parse $(#[$($attr)*])*
        );
    };
    (
        @vis $vis:vis,
        @name $name:ident,
        @item $item:ty,
        @attr $(#[$attr:meta])*,
        @attr_to_parse  // we found no lenght attribute
    ) => {
        make_zerocopy_list!(
            @vis $vis,
            @name $name,
            @item $item,
            @len u16, // set the default lenght to u16
            @attr $(#[$attr])*
        );
    };
    (
        @vis $vis:vis,
        @name $name:ident,
        @item $item:ty,
        @attr $(#[$attr:meta])*,
        @attr_to_parse #[lenght=$len:tt] $(#[$attr2:meta])* // we found the lenght attribute
    ) => {
        make_zerocopy_list!(
            @vis $vis,
            @name $name,
            @item $item,
            @len $len,
            @attr $(#[$attr])* $(#[$attr2])*
        );
    };
    (
        @vis $vis:vis,
        @name $name:ident,
        @item $item:ty,
        @attr $(#[$attr:meta])*,
        @attr_to_parse #[$attr2:meta] $($rest:tt)* // just a normal attribute
    ) => {
        make_zerocopy_list!(
            @vis $vis,
            @name $name,
            @item $item,
            @attr $(#[$attr])* #[$attr2],
            @attr_to_parse $($rest)*
        );
    };
    (
        @vis $vis:vis,
        @name $name:ident,
        @item $item:ty,
        @len $len:tt,
        @attr $(#[$attr:meta])*
    ) => {
        $(#[$attr])*
        $vis struct $name<'a, Location>(Location::ListType<'a, $item>)
        where
            Location: $crate::parse_encode::StorageType;

        impl<'a> $crate::parse_encode::Parse<'a> for $name<'a, $crate::parse_encode::Remote> {
            fn parse(
                buf: &mut $crate::parse_buffer::ParseBuffer<'a>,
            ) -> Result<Self, $crate::TlsError> {
                let len = make_zerocopy_list!(@read $len, buf)? as usize;
                let mut buf = buf.slice(len)?;
                <$crate::parse_encode::Remote as $crate::parse_encode::StorageType>::ListType::parse(&mut buf).map(Self)
            }
        }

        impl<'a> $crate::parse_encode::Encode for $name<'a, $crate::parse_encode::Local> {
            fn encode(self, buf: &mut $crate::buffer::CryptoBuffer) -> Result<(), crate::TlsError> {
                make_zerocopy_list!(@encode $len, |buf| self.0.encode(buf))
            }
        }

        #[allow(unused)]
        impl<'a> $name<'a, $crate::parse_encode::Local> {
            pub fn new(iter: &'a mut dyn Iterator<Item = $item>) -> Self {
                Self(<$crate::parse_encode::Local as $crate::parse_encode::StorageType>::ListType::new(iter))
            }
        }

        #[allow(unused)]
        impl<'a> $name<'a, $crate::parse_encode::Remote> {
            pub fn iter(&self) -> impl Iterator<Item = $item> {
                self.0.iter()
            }

            pub fn len(&self) -> usize {
                let mut buf = $crate::parse_buffer::ParseBuffer::new(&self.0.0);
                core::iter::from_fn(||{
                    let len = make_zerocopy_list!(@read $len, buf).ok()? as  usize;
                    let _ = buf.slice(len);
                    Some(())
                }).count()
            }        }
    };
}
pub(crate) use make_zerocopy_list;
