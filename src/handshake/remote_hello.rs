use heapless::Vec;

use crate::cipher_suites::CipherSuite;
use crate::crypto_engine::CryptoEngine;
use crate::extensions::extension_data::key_share::KeyShareEntry;
use crate::extensions::messages::{ClientHelloExtension, ServerHelloExtension};
use crate::parse_buffer::ParseBuffer;
use crate::{TlsError, unused};
use p256::PublicKey;
use p256::ecdh::{EphemeralSecret, SharedSecret};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoteServerHello<'a> {
    extensions: Vec<ServerHelloExtension<'a>, 4>,
}

/// Parses the the remote hello message from the beginnig to the session id
///
/// # returns
/// the session id
fn parse_session_id<'a>(buf: &mut ParseBuffer<'a>) -> Result<ParseBuffer<'a>, TlsError> {
    let _version = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)?;

    let mut random = [0; 32];
    buf.fill(&mut random)?;

    let session_id_length = buf
        .read_u8()
        .map_err(|_| TlsError::InvalidSessionIdLength)?;

    buf.slice(session_id_length as usize)
        .map_err(|_| TlsError::InvalidSessionIdLength)
}

impl<'a> RemoteServerHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<RemoteServerHello<'a>, TlsError> {
        let session_id = parse_session_id(buf)?;
        let cipher_suite = CipherSuite::parse(buf).map_err(|_| TlsError::InvalidCipherSuite)?;

        ////info!("sh 3");
        // skip compression method, it's 0.
        buf.read_u8()?;

        let extensions = ServerHelloExtension::parse_vector(buf)?;

        // debug!("server random {:x}", random);
        // debug!("server session-id {:x}", session_id.as_slice());
        debug!("server cipher_suite {:?}", cipher_suite);
        debug!("server extensions {:?}", extensions);

        unused(session_id);
        Ok(Self { extensions })
    }

    pub fn key_share(&self) -> Option<&KeyShareEntry<'_>> {
        self.extensions.iter().find_map(|e| {
            if let ServerHelloExtension::KeyShare(entry) = e {
                Some(&entry.0)
            } else {
                None
            }
        })
    }

    pub fn calculate_shared_secret(&self, secret: &EphemeralSecret) -> Option<SharedSecret> {
        let server_key_share = self.key_share()?;
        let server_public_key = PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
        Some(secret.diffie_hellman(&server_public_key))
    }

    #[allow(dead_code)]
    pub fn initialize_crypto_engine(&self, secret: &EphemeralSecret) -> Option<CryptoEngine> {
        let server_key_share = self.key_share()?;

        let group = server_key_share.group;

        let server_public_key = PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
        let shared = secret.diffie_hellman(&server_public_key);

        Some(CryptoEngine::new(group, shared))
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoteClientHello<'a> {
    cipher_suites: &'a [u8],
    extensions: Vec<ClientHelloExtension<'a>, 8>,
}

impl<'a> RemoteClientHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
        let session_id = parse_session_id(buf)?;
        let cipher_suites_len = buf.read_u16().map_err(|_| TlsError::InvalidCipherSuite)?;
        if cipher_suites_len % 2 != 0 {
            return Err(TlsError::InvalidCipherSuite);
        }
        let cipher_suites = buf
            .slice(cipher_suites_len as usize)
            .map_err(|_| TlsError::InvalidCipherSuite)?
            .as_slice();

        // skip the compression methods, tls 1.3 does not support them
        let compression_len = buf.read_u8().map_err(|_| TlsError::InvalidHandshake)?;
        let _compression = buf
            .slice(compression_len as usize)
            .map_err(|_| TlsError::InvalidHandshake)?;

        let extensions = ClientHelloExtension::parse_vector(buf)?;

        unused(session_id);
        Ok(Self {
            cipher_suites,
            extensions,
        })
    }

    pub fn cipher_suites(&self) -> impl Iterator<Item = Result<CipherSuite, TlsError>> {
        self.cipher_suites.chunks(2).map(|c| {
            CipherSuite::parse(&mut ParseBuffer::new(c)).map_err(|_| TlsError::InvalidCipherSuite)
        })
    }
}
