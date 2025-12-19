use std::{borrow::Borrow, convert::identity, fmt::Debug, iter, ops::Deref};

use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
};

/// marker type for remote storage
#[derive(Debug)]
pub struct Remote;
/// marker type for local storage
#[derive(Debug)]
pub struct Local;

/// The storage type trait can provide the storage for a struct
///
/// ```ignore
/// // sadly this can not be run as doctest because it is private
/// # embedded_tls::buffer_iter::*;
/// #[derive(Debug)]
/// pub struct MyData<'a, Location>
///     where Self: StorageType<T: Debug>,
/// {
///     data: <Self as StorageType>::T,
/// }
///
/// impl<'a> StorageType for MyData<'a, Remote> {
///     type T = &'a [u8];
/// }
///
/// impl<'a> StorageType for MyData<'a, Local> {
///     type T = i32;
/// }
///
/// fn main() {
///    let remote: MyData<'_, Remote> = MyData {
///       data: &[1,2,3,4],
///    };
///    let local: MyData<'_, Local> = MyData {
///        data: 42,
///    };
///    println!("{remote:?}");
///    println!("{local:?}");
/// }
/// ```
pub trait StorageType {
    type T;
}

/// A list of type T that is encoded with the length as u16
#[derive(Debug)]
pub struct List<'a, T, Location>
where
    Self: StorageType<T: Debug>,
{
    data: &'a [<Self as StorageType>::T],
}

impl<'a, T> StorageType for List<'a, T, Remote> {
    type T = u8;
}
impl<'a, T: Debug> StorageType for List<'a, T, Local> {
    type T = T;
}

impl<'a, T> List<'a, T, Remote>
where
    T: ParseEncode,
{
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let len = buf.read_u16()? as usize;
        let mut buf = buf.slice(len)?;
        let data = buf.as_slice();

        // this is only run to validate the data,
        iter::from_fn(|| {
            if buf.is_empty() {
                None
            } else {
                Some(T::parse(&mut buf).map(|_parsed| ()))
            }
        })
        .try_for_each(identity)?;
        Ok(Self { data })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| buf.extend_from_slice(self.data))
    }

    pub fn iter(&self) -> impl Iterator<Item = T> {
        let mut buf = ParseBuffer::new(self.data);
        iter::from_fn(move || T::parse(&mut buf).ok())
    }
}

impl<'a, T: Debug> List<'a, T, Local>
where
    T: ParseEncode,
{
    pub fn new(data: &'a [T]) -> Self {
        Self { data }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        Self::encode_from_iter(buf, self.data.iter())
    }

    pub fn encode_from_iter(
        buf: &mut CryptoBuffer,
        mut iter: impl Iterator<Item: Deref<Target = T>>,
    ) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| iter.try_for_each(|t| t.encode(buf)))
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data.iter()
    }
}

pub trait ParseEncode: Sized {
    fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError>;
    fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError>;
}
