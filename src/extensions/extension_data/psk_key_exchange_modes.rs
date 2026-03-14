use crate::buffer::CryptoBuffer;

use crate::TlsError;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::parse_encode::{Encode, Parse, make_zerocopy_list};

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
}
impl Parse<'_> for PskKeyExchangeMode {
    fn parse(buf: &mut ParseBuffer) -> Result<Self, TlsError> {
        match buf.read_u8()? {
            0 => Ok(Self::PskKe),
            1 => Ok(Self::PskDheKe),
            other => {
                warn!("Read unknown PskKeyExchangeMode: {}", other);
                Err(ParseError::InvalidData.into())
            }
        }
    }
}
impl Encode for PskKeyExchangeMode {
    fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self as u8).map_err(|_| TlsError::EncodeError)
    }
}

make_zerocopy_list! {
    #[lenght = u8]
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct PskKeyExchangeModes<'a, Location>(PskKeyExchangeMode);
}
