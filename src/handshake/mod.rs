//use p256::elliptic_curve::AffinePoint;
use crate::TlsError;
use crate::config::TlsCipherSuite;
use crate::handshake::certificate::CertificateRef;
use crate::handshake::certificate_request::CertificateRequestRef;
use crate::handshake::certificate_verify::{CertificateVerify, CertificateVerifyRef};
use crate::handshake::encrypted_extensions::EncryptedExtensions;
use crate::handshake::finished::Finished;
use crate::handshake::local_hello::ClientHello;
use crate::handshake::new_session_ticket::NewSessionTicket;
use crate::handshake::remote_hello::RemoteServerHello;
use crate::key_schedule::HashOutputSize;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::{buffer::CryptoBuffer, key_schedule::WriteKeySchedule};
use core::fmt::{Debug, Formatter};
use sha2::Digest;

pub mod binder;
pub mod certificate;
pub mod certificate_request;
pub mod certificate_verify;
pub mod encrypted_extensions;
pub mod finished;
pub mod local_hello;
pub mod new_session_ticket;
pub mod remote_hello;

const LEGACY_VERSION: u16 = 0x0303;

type Random = [u8; 32];

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl HandshakeType {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        match buf.read_u8()? {
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            8 => Ok(HandshakeType::EncryptedExtensions),
            11 => Ok(HandshakeType::Certificate),
            13 => Ok(HandshakeType::CertificateRequest),
            15 => Ok(HandshakeType::CertificateVerify),
            20 => Ok(HandshakeType::Finished),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(ParseError::InvalidData),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum LocalHandshake<'config, 'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    ClientCert(CertificateRef<'a>),
    ClientCertVerify(CertificateVerify),
    ClientHello(ClientHello<'config, CipherSuite>),
    Finished(Finished<HashOutputSize<CipherSuite>>),
}

impl<CipherSuite> LocalHandshake<'_, '_, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn handshake_type(&self) -> HandshakeType {
        match self {
            LocalHandshake::ClientHello(_) => HandshakeType::ClientHello,
            LocalHandshake::Finished(_) => HandshakeType::Finished,
            LocalHandshake::ClientCert(_) => HandshakeType::Certificate,
            LocalHandshake::ClientCertVerify(_) => HandshakeType::CertificateVerify,
        }
    }

    fn encode_inner(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        match self {
            LocalHandshake::ClientHello(inner) => inner.encode(buf),
            LocalHandshake::Finished(inner) => inner.encode(buf),
            LocalHandshake::ClientCert(inner) => inner.encode(buf),
            LocalHandshake::ClientCertVerify(inner) => inner.encode(buf),
        }
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.push(self.handshake_type() as u8)
            .map_err(|_| TlsError::EncodeError)?;

        buf.with_u24_length(|buf| self.encode_inner(buf))
    }

    pub fn finalize(
        &self,
        buf: &mut CryptoBuffer,
        transcript: &mut CipherSuite::Hash,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        let enc_buf = buf.as_mut_slice();
        if let LocalHandshake::ClientHello(hello) = self {
            hello.finalize(enc_buf, transcript, write_key_schedule)
        } else {
            transcript.update(enc_buf);
            Ok(())
        }
    }

    pub fn finalize_encrypted(buf: &mut CryptoBuffer, transcript: &mut CipherSuite::Hash) {
        let enc_buf = buf.as_slice();
        let end = enc_buf.len();
        transcript.update(&enc_buf[0..end]);
    }
}

#[allow(clippy::large_enum_variant)]
pub enum RemoteHandshake<'a, CipherSuite: TlsCipherSuite> {
    ServerHello(RemoteServerHello<'a>),
    EncryptedExtensions(EncryptedExtensions<'a>),
    NewSessionTicket(NewSessionTicket<'a>),
    Certificate(CertificateRef<'a>),
    CertificateRequest(CertificateRequestRef<'a>),
    CertificateVerify(CertificateVerifyRef<'a>),
    Finished(Finished<HashOutputSize<CipherSuite>>),
}

impl<CipherSuite: TlsCipherSuite> RemoteHandshake<'_, CipherSuite> {
    #[allow(dead_code)]
    pub fn handshake_type(&self) -> HandshakeType {
        match self {
            RemoteHandshake::ServerHello(_) => HandshakeType::ServerHello,
            RemoteHandshake::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            RemoteHandshake::NewSessionTicket(_) => HandshakeType::NewSessionTicket,
            RemoteHandshake::Certificate(_) => HandshakeType::Certificate,
            RemoteHandshake::CertificateRequest(_) => HandshakeType::CertificateRequest,
            RemoteHandshake::CertificateVerify(_) => HandshakeType::CertificateVerify,
            RemoteHandshake::Finished(_) => HandshakeType::Finished,
        }
    }
}

impl<CipherSuite: TlsCipherSuite> Debug for RemoteHandshake<'_, CipherSuite> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            RemoteHandshake::ServerHello(inner) => Debug::fmt(inner, f),
            RemoteHandshake::EncryptedExtensions(inner) => Debug::fmt(inner, f),
            RemoteHandshake::Certificate(inner) => Debug::fmt(inner, f),
            RemoteHandshake::CertificateRequest(inner) => Debug::fmt(inner, f),
            RemoteHandshake::CertificateVerify(inner) => Debug::fmt(inner, f),
            RemoteHandshake::Finished(inner) => Debug::fmt(inner, f),
            RemoteHandshake::NewSessionTicket(inner) => Debug::fmt(inner, f),
        }
    }
}

#[cfg(feature = "defmt")]
impl<'a, CipherSuite: TlsCipherSuite> defmt::Format for RemoteHandshake<'a, CipherSuite> {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            RemoteHandshake::ServerHello(inner) => defmt::write!(f, "{}", inner),
            RemoteHandshake::EncryptedExtensions(inner) => defmt::write!(f, "{}", inner),
            RemoteHandshake::Certificate(inner) => defmt::write!(f, "{}", inner),
            RemoteHandshake::CertificateRequest(inner) => defmt::write!(f, "{}", inner),
            RemoteHandshake::CertificateVerify(inner) => defmt::write!(f, "{}", inner),
            RemoteHandshake::Finished(inner) => defmt::write!(f, "{}", inner),
            RemoteHandshake::NewSessionTicket(inner) => defmt::write!(f, "{}", inner),
        }
    }
}

impl<'a, CipherSuite: TlsCipherSuite> RemoteHandshake<'a, CipherSuite> {
    pub fn read(
        buf: &mut ParseBuffer<'a>,
        digest: &mut CipherSuite::Hash,
    ) -> Result<Self, TlsError> {
        let handshake_start = buf.offset();
        let mut handshake = Self::parse(buf)?;
        let handshake_end = buf.offset();

        if let RemoteHandshake::Finished(finished) = &mut handshake {
            finished.hash.replace(digest.clone().finalize());
        }

        digest.update(&buf.as_slice()[handshake_start..handshake_end]);

        Ok(handshake)
    }

    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
        let handshake_type = HandshakeType::parse(buf).map_err(|_| TlsError::InvalidHandshake)?;

        trace!("handshake = {:?}", handshake_type);

        let content_len = buf.read_u24().map_err(|_| TlsError::InvalidHandshake)?;

        let handshake = match handshake_type {
            //HandshakeType::ClientHello => {}
            HandshakeType::ServerHello => {
                RemoteHandshake::ServerHello(RemoteServerHello::parse(buf)?)
            }
            HandshakeType::NewSessionTicket => {
                RemoteHandshake::NewSessionTicket(NewSessionTicket::parse(buf)?)
            }
            //HandshakeType::EndOfEarlyData => {}
            HandshakeType::EncryptedExtensions => {
                RemoteHandshake::EncryptedExtensions(EncryptedExtensions::parse(buf)?)
            }
            HandshakeType::Certificate => RemoteHandshake::Certificate(CertificateRef::parse(buf)?),

            HandshakeType::CertificateRequest => {
                RemoteHandshake::CertificateRequest(CertificateRequestRef::parse(buf)?)
            }

            HandshakeType::CertificateVerify => {
                RemoteHandshake::CertificateVerify(CertificateVerifyRef::parse(buf)?)
            }
            HandshakeType::Finished => {
                RemoteHandshake::Finished(Finished::parse(buf, content_len)?)
            }
            //HandshakeType::KeyUpdate => {}
            //HandshakeType::MessageHash => {}
            t => {
                warn!("Unimplemented handshake type: {:?}", t);
                return Err(TlsError::Unimplemented);
            }
        };

        Ok(handshake)
    }
}
