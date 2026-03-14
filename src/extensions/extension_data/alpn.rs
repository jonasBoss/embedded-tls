use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    parse_encode::{Encode, Parse, parse_encode_list},
};

/// ALPN protocol name list per RFC 7301, Section 3.1.
///
/// Wire format:
/// ```text
/// opaque ProtocolName<1..2^8-1>;
///
/// struct {
///     ProtocolName protocol_name_list<2..2^16-1>
/// } ProtocolNameList;
/// ```
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProtocolName<'a>(pub &'a [u8]);

parse_encode_list!(ProtocolNameList<'a, Location>(ProtocolName<'a>));

impl<'a> Parse<'a> for ProtocolName<'a> {
    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let len = buf.read_u8()? as usize;
        let name = buf.slice(len)?.as_slice();
        Ok(Self(name))
    }
}

impl Encode for ProtocolName<'_> {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u8_length(|buf| buf.extend_from_slice(self.0))
    }
}
