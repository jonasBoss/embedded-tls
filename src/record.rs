use crate::TlsError;
use crate::application_data::ApplicationData;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::content_types::ContentType;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::{LocalHandshake, RemoteHandshake};
use crate::key_schedule::WriteKeySchedule;
use crate::{CryptoProvider, buffer::CryptoBuffer};
use crate::{
    alert::{Alert, AlertDescription, AlertLevel},
    parse_buffer::ParseBuffer,
};
use core::fmt::Debug;

pub type Encrypted = bool;

#[allow(clippy::large_enum_variant)]
pub enum LocalRecord<'config, 'a, CipherSuite>
where
    // N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    Handshake(LocalHandshake<'config, 'a, CipherSuite>, Encrypted),
    Alert(Alert, Encrypted),
}

#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientRecordHeader {
    Handshake(Encrypted),
    Alert(Encrypted),
    ApplicationData,
}

impl ClientRecordHeader {
    pub fn is_encrypted(self) -> bool {
        match self {
            ClientRecordHeader::Handshake(encrypted) | ClientRecordHeader::Alert(encrypted) => {
                encrypted
            }
            ClientRecordHeader::ApplicationData => true,
        }
    }

    pub fn header_content_type(self) -> ContentType {
        match self {
            Self::Handshake(false) => ContentType::Handshake,
            Self::Alert(false) => ContentType::ChangeCipherSpec,
            Self::Handshake(true) | Self::Alert(true) | Self::ApplicationData => {
                ContentType::ApplicationData
            }
        }
    }

    pub fn trailer_content_type(self) -> ContentType {
        match self {
            Self::Handshake(_) => ContentType::Handshake,
            Self::Alert(_) => ContentType::Alert,
            Self::ApplicationData => ContentType::ApplicationData,
        }
    }

    pub fn version(self) -> [u8; 2] {
        match self {
            Self::Handshake(true) | Self::Alert(true) | Self::ApplicationData => [0x03, 0x03],
            Self::Handshake(false) | Self::Alert(false) => [0x03, 0x01],
        }
    }

    pub fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self.header_content_type() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(&self.version())
            .map_err(|_| TlsError::EncodeError)?;

        Ok(())
    }
}

impl<'config, CipherSuite> LocalRecord<'config, '_, CipherSuite>
where
    //N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    pub fn header(&self) -> ClientRecordHeader {
        match self {
            LocalRecord::Handshake(_, encrypted) => ClientRecordHeader::Handshake(*encrypted),
            LocalRecord::Alert(_, encrypted) => ClientRecordHeader::Alert(*encrypted),
        }
    }

    pub fn client_hello<Provider>(
        config: &'config TlsConfig<'config>,
        provider: &mut Provider,
    ) -> Self
    where
        Provider: CryptoProvider,
    {
        LocalRecord::Handshake(
            LocalHandshake::ClientHello(ClientHello::new(config, provider)),
            false,
        )
    }

    pub fn close_notify(opened: bool) -> Self {
        LocalRecord::Alert(
            Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
            opened,
        )
    }

    pub(crate) fn encode_payload(&self, buf: &mut CryptoBuffer) -> Result<usize, TlsError> {
        let record_length_marker = buf.len();

        match self {
            LocalRecord::Handshake(handshake, _) => handshake.encode(buf)?,
            LocalRecord::Alert(alert, _) => alert.encode(buf)?,
        };

        Ok(buf.len() - record_length_marker)
    }

    pub fn finish_record(
        &self,
        buf: &mut CryptoBuffer,
        transcript: &mut CipherSuite::Hash,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        match self {
            LocalRecord::Handshake(handshake, false) => {
                handshake.finalize(buf, transcript, write_key_schedule)
            }
            LocalRecord::Handshake(_, true) => {
                LocalHandshake::<CipherSuite>::finalize_encrypted(buf, transcript);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(clippy::large_enum_variant)]
pub enum RemoteRecord<'a, CipherSuite: TlsCipherSuite> {
    Handshake(RemoteHandshake<'a, CipherSuite>),
    ChangeCipherSpec(ChangeCipherSpec),
    Alert(Alert),
    ApplicationData(ApplicationData<'a>),
}

pub struct RecordHeader {
    header: [u8; 5],
}

impl RecordHeader {
    pub const LEN: usize = 5;

    pub fn content_type(&self) -> ContentType {
        // Content type already validated in read
        unwrap!(ContentType::of(self.header[0]))
    }

    pub fn content_length(&self) -> usize {
        // Content length already validated in read
        u16::from_be_bytes([self.header[3], self.header[4]]) as usize
    }

    pub fn data(&self) -> &[u8; 5] {
        &self.header
    }

    pub fn decode(header: [u8; 5]) -> Result<RecordHeader, TlsError> {
        match ContentType::of(header[0]) {
            None => Err(TlsError::InvalidRecord),
            Some(_) => Ok(RecordHeader { header }),
        }
    }
}

impl<'a, CipherSuite: TlsCipherSuite> RemoteRecord<'a, CipherSuite> {
    pub fn content_type(&self) -> ContentType {
        match self {
            RemoteRecord::Handshake(_) => ContentType::Handshake,
            RemoteRecord::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            RemoteRecord::Alert(_) => ContentType::Alert,
            RemoteRecord::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub fn decode(
        header: RecordHeader,
        data: &'a mut [u8],
        digest: &mut CipherSuite::Hash,
    ) -> Result<RemoteRecord<'a, CipherSuite>, TlsError> {
        assert_eq!(header.content_length(), data.len());
        match header.content_type() {
            ContentType::Invalid => Err(TlsError::Unimplemented),
            ContentType::ChangeCipherSpec => Ok(RemoteRecord::ChangeCipherSpec(
                ChangeCipherSpec::read(data)?,
            )),
            ContentType::Alert => {
                let mut parse = ParseBuffer::new(data);
                let alert = Alert::parse(&mut parse)?;
                Ok(RemoteRecord::Alert(alert))
            }
            ContentType::Handshake => {
                let mut parse = ParseBuffer::new(data);
                Ok(RemoteRecord::Handshake(RemoteHandshake::read(
                    &mut parse, digest,
                )?))
            }
            ContentType::ApplicationData => {
                let buf = CryptoBuffer::wrap_with_pos(data, data.len());
                Ok(RemoteRecord::ApplicationData(ApplicationData::new(
                    buf, header,
                )))
            }
        }
    }

    //pub fn parse<D: Digest>(buf: &[u8]) -> Result<Self, TlsError> {}
}
