use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::ParseBuffer,
    parse_encode::{Encode, Parse, make_zerocopy_list},
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
    fn parse(buf: &mut ParseBuffer) -> Result<Self, TlsError> {
        buf.read_u16().map(Self).map_err(From::from)
    }
}

pub const TLS13: ProtocolVersion = ProtocolVersion(0x0304);

make_zerocopy_list! {
    #[lenght = u8]
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct SupportedVersionsClientHello<'a, Location>(ProtocolVersion);
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedVersionsServerHello {
    pub selected_version: ProtocolVersion,
}

impl Parse<'_> for SupportedVersionsServerHello {
    fn parse(buf: &mut ParseBuffer) -> Result<Self, TlsError> {
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
