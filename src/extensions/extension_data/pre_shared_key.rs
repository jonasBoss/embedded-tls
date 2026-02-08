use crate::buffer::CryptoBuffer;

use crate::TlsError;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::parse_encode::{
    DynIterList, Encode, Local, Parse, Remote, StorageType, ZerocopyList, parse_encode_list,
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PskIdentity<'a> {
    pub identity: &'a [u8],
    pub obfuscated_ticket_age: u32,
}

impl<'a> PskIdentity<'a> {
    pub(crate) fn external(identity: &'a [u8]) -> Self {
        Self {
            identity,
            // set this to zeor as per RFC for externaly established identities
            obfuscated_ticket_age: 0,
        }
    }
}

impl<'a> Parse<'a> for PskIdentity<'a> {
    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let len = buf.read_u16()? as usize;
        Ok(Self {
            identity: buf.slice(len)?.as_slice(),
            obfuscated_ticket_age: buf.read_u32()?,
        })
    }
}

impl Encode for PskIdentity<'_> {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| buf.extend_from_slice(self.identity))
            .map_err(|_| TlsError::EncodeError)?;
        buf.push_u32(self.obfuscated_ticket_age)
    }
}

parse_encode_list!(PskIdentityList<'a, Location>(PskIdentity<'a>));

impl PartialEq for PskIdentityList<'_, Remote> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Binders<'a, Location>(Location::Binders<'a>)
where
    Location: StorageType;

impl<'a> Parse<'a> for Binders<'a, Remote> {
    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let len = buf.read_u16()? as usize;
        let mut buf = buf.slice(len)?;
        Ok(Self(ZerocopyList::parse(&mut buf)?))
    }
}

impl<'a> Binders<'a, Remote> {
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> {
        self.0.iter().map(|s| s.0)
    }
    pub fn len(&self) -> usize {
        self.0.iter().count()
    }
}

impl Encode for Binders<'_, Local> {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for len in self.0.0 {
                buf.push(len)?;
                for _ in 0..len {
                    buf.push(0)?;
                }
            }
            Ok(())
        })
    }
}

impl<'a> Binders<'a, Local> {
    pub fn placeholders(iter: &'a mut dyn Iterator<Item = u8>) -> Self {
        Self(DynIterList(iter))
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PreSharedKeyClientHello<'a, Location>
where
    Location: StorageType,
{
    pub identities: PskIdentityList<'a, Location>,
    /// The list of binders must be the same lenght as the list of identities.
    /// For encoding these just reserve space in the buffer, as the binders are calculated seperately.
    pub binders: Binders<'a, Location>,
}

impl<'a> Parse<'a> for PreSharedKeyClientHello<'a, Remote> {
    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let len = buf.read_u16()? as usize;
        let mut ident_buf = buf.slice(len)?;
        let len = buf.read_u16()? as usize;
        let mut bind_buf = buf.slice(len)?;
        let this = Self {
            identities: PskIdentityList::parse(&mut ident_buf)?,
            binders: Binders::parse(&mut bind_buf)?,
        };
        if this.binders.len() == this.identities.len() {
            Ok(this)
        } else {
            Err(ParseError::InvalidData)
        }
    }
}

impl Encode for PreSharedKeyClientHello<'_, Local> {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        let Self {
            identities,
            binders,
        } = self;
        identities.encode(buf)?;
        binders.encode(buf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PreSharedKeyServerHello {
    pub selected_identity: u16,
}

impl Parse<'_> for PreSharedKeyServerHello {
    fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self {
            selected_identity: buf.read_u16()?,
        })
    }
}
impl Encode for PreSharedKeyServerHello {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(self.selected_identity)
            .map_err(|_| TlsError::EncodeError)
    }
}
