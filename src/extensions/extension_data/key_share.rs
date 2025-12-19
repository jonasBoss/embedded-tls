use core::convert::identity;
use core::iter;

use crate::buffer::CryptoBuffer;
use crate::extensions::extension_data::supported_groups::NamedGroup;

use crate::TlsError;
use crate::parse_buffer::{ParseBuffer, ParseError};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareServerHello<'a>(pub KeyShareEntry<'a>);

impl<'a> KeyShareServerHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        Ok(KeyShareServerHello(KeyShareEntry::parse(buf)?))
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.0.encode(buf)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareClientHello<'a> {
    client_shares: &'a [u8],
}

impl<'a> KeyShareClientHello<'a> {
    pub fn encode_from_iter<'i>(
        buf: &mut CryptoBuffer<'a>,
        mut iter: impl Iterator<Item = KeyShareEntry<'i>>,
    ) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| iter.try_for_each(|key_share| key_share.encode(buf)))
    }

    pub fn key_shares(&self) -> impl Iterator<Item = KeyShareEntry<'a>> {
        let mut buf = ParseBuffer::new(self.client_shares);
        iter::from_fn(move || KeyShareEntry::parse(&mut buf).ok())
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let len = buf.read_u16()? as usize;
        let mut buf = buf.slice(len)?;
        let client_shares = buf.as_slice();

        // we check that the whole buffer parses  so that the `key_shares()` method does not return an error
        iter::from_fn(|| {
            if buf.is_empty() {
                return None;
            }
            Some(KeyShareEntry::parse(&mut buf).map(|_| ()))
        })
        .try_for_each(identity)?;

        Ok(KeyShareClientHello { client_shares })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| buf.extend_from_slice(self.client_shares))
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareHelloRetryRequest {
    pub selected_group: NamedGroup,
}

#[allow(dead_code)]
impl KeyShareHelloRetryRequest {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self {
            selected_group: NamedGroup::parse(buf)?,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.selected_group.encode(buf)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareEntry<'a> {
    pub(crate) group: NamedGroup,
    pub(crate) opaque: &'a [u8],
}

impl<'a> KeyShareEntry<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let group = NamedGroup::parse(buf)?;

        let opaque_len = buf.read_u16()?;
        let opaque = buf.slice(opaque_len as usize)?;

        Ok(Self {
            group,
            opaque: opaque.as_slice(),
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.group.encode(buf)?;

        buf.with_u16_length(|buf| buf.extend_from_slice(self.opaque))
            .map_err(|_| TlsError::EncodeError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            env_logger::init();
        });
    }

    #[test]
    fn test_parse_empty() {
        setup();
        let buffer = [
            0x00, 0x17, // Secp256r1
            0x00, 0x00, // key_exchange length = 0 bytes
        ];
        let result = KeyShareEntry::parse(&mut ParseBuffer::new(&buffer)).unwrap();

        assert_eq!(NamedGroup::Secp256r1, result.group);
        assert_eq!(0, result.opaque.len());
    }

    #[test]
    fn test_parse() {
        setup();
        let buffer = [
            0x00, 0x17, // Secp256r1
            0x00, 0x02, // key_exchange length = 2 bytes
            0xAA, 0xBB,
        ];
        let result = KeyShareEntry::parse(&mut ParseBuffer::new(&buffer)).unwrap();

        assert_eq!(NamedGroup::Secp256r1, result.group);
        assert_eq!(2, result.opaque.len());
        assert_eq!([0xAA, 0xBB], result.opaque);
    }
}
