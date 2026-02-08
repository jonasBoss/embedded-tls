use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    parse_encode::{Encode, Parse, parse_encode_list},
};

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NameType {
    HostName = 0,
}

impl NameType {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        match buf.read_u8()? {
            0 => Ok(Self::HostName),
            other => {
                warn!("Read unknown NameType: {}", other);
                Err(ParseError::InvalidData)
            }
        }
    }

    pub fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self as u8).map_err(|_| TlsError::EncodeError)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerName<'a> {
    pub name_type: NameType,
    pub name: &'a str,
}

impl<'a> ServerName<'a> {
    pub fn hostname(name: &'a str) -> Self {
        Self {
            name_type: NameType::HostName,
            name,
        }
    }
}

impl<'a> Parse<'a> for ServerName<'a> {
    fn parse(buf: &mut ParseBuffer<'a>) -> Result<ServerName<'a>, ParseError> {
        let name_type = NameType::parse(buf)?;
        let name_len = buf.read_u16()?;
        let name = buf.slice(name_len as usize)?.as_slice();

        // RFC 6066, Section 3.  Server Name Indication
        // The hostname is represented as a byte
        // string using ASCII encoding without a trailing dot.
        if name.is_ascii() {
            Ok(ServerName {
                name_type,
                name: core::str::from_utf8(name).map_err(|_| ParseError::InvalidData)?,
            })
        } else {
            Err(ParseError::InvalidData)
        }
    }
}
impl Encode for ServerName<'_> {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.name_type.encode(buf)?;

        buf.with_u16_length(|buf| buf.extend_from_slice(self.name.as_bytes()))
            .map_err(|_| TlsError::EncodeError)
    }
}

parse_encode_list!(ServerNameList<'a, Location>(ServerName<'a>));

// RFC 6066, Section 3.  Server Name Indication
// A server that receives a client hello containing the "server_name"
// extension [..].  In this event, the server
// SHALL include an extension of type "server_name" in the (extended)
// server hello.  The "extension_data" field of this extension SHALL be
// empty.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerNameResponse;

impl Parse<'_> for ServerNameResponse {
    fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        if buf.is_empty() {
            Ok(Self)
        } else {
            Err(ParseError::InvalidData)
        }
    }
}

impl Encode for ServerNameResponse {
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn encode(self, _buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        Ok(())
    }
}
