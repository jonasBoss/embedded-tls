use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    parse_encode::{Encode, Parse, parse_encode_list},
};

#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProtocolVersion(u16);

impl Encode for ProtocolVersion {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(self.0).map_err(|_| TlsError::EncodeError)
    }
}
impl Parse<'_> for ProtocolVersion {
    fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        buf.read_u16().map(Self)
    }
}

pub const TLS13: ProtocolVersion = ProtocolVersion(0x0304);

parse_encode_list!(SupportedVersionsClientHello<'a, Location>(ProtocolVersion), u8);

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedVersionsServerHello {
    pub selected_version: ProtocolVersion,
}

impl Parse<'_> for SupportedVersionsServerHello {
    fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self {
            selected_version: ProtocolVersion::parse(buf)?,
        })
    }
}
impl Encode for SupportedVersionsServerHello {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.selected_version.encode(buf)
    }
}
