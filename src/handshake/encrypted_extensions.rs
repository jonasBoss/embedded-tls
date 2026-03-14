use core::marker::PhantomData;

use crate::extensions::messages::EncryptedExtensionsExtension;

use crate::TlsError;
use crate::parse_buffer::ParseBuffer;
use crate::parse_encode::Parse;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptedExtensions<'a> {
    _todo: PhantomData<&'a ()>,
}

impl<'a> EncryptedExtensions<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<EncryptedExtensions<'a>, TlsError> {
        EncryptedExtensionsExtension::parse(buf)?;
        Ok(EncryptedExtensions { _todo: PhantomData })
    }
}
