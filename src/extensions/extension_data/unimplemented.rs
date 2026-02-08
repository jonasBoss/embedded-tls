use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    parse_encode::{Encode, Parse},
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Unimplemented<'a> {
    pub data: &'a [u8],
}

impl<'a> Parse<'a> for Unimplemented<'a> {
    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        Ok(Self {
            data: buf.as_slice(),
        })
    }
}

impl Encode for Unimplemented<'_> {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.extend_from_slice(self.data)
    }
}
