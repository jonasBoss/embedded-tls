use crate::extensions::{
    extension_data::{
        alpn::ProtocolNameList,
        key_share::{KeyShareClientHello, KeyShareServerHello},
        max_fragment_length::MaxFragmentLength,
        pre_shared_key::{PreSharedKeyClientHello, PreSharedKeyServerHello},
        psk_key_exchange_modes::PskKeyExchangeModes,
        server_name::{ServerNameList, ServerNameResponse},
        signature_algorithms::SignatureAlgorithms,
        signature_algorithms_cert::SignatureAlgorithmsCert,
        supported_groups::SupportedGroups,
        supported_versions::{SupportedVersionsClientHello, SupportedVersionsServerHello},
        unimplemented::Unimplemented,
    },
    extension_group_macro::extension_group,
};

pub use both::CertificateExtension;
pub use client::ClientHelloExtension;
pub use server::CertificateRequestExtension;
pub use server::EncryptedExtensionsExtension;
#[allow(unused)]
pub use server::HelloRetryRequestExtension;
pub use server::NewSessionTicketExtension;
pub use server::ServerHelloExtension;

use ProtocolNameList as ApplicationLayerProtocolNegotiation;

use Unimplemented as StatusRequest;
use Unimplemented as UseSrtp;
use Unimplemented as Heartbeat;
use Unimplemented as SignedCertificateTimestamp;
use Unimplemented as ClientCertificateType;
use Unimplemented as ServerCertificateType;
use Unimplemented as Padding;
use Unimplemented as EarlyData;
use Unimplemented as Cookie;
use Unimplemented as CertificateAuthorities;
use Unimplemented as PostHandshakeAuth;
use Unimplemented as OidFilters;
use Unimplemented as CompressCertificate;

mod server {
    use super::*;
    use KeyShareServerHello as KeyShare;
    use PreSharedKeyServerHello as PreSharedKey;
    use ServerNameResponse as ServerName;
    use SupportedVersionsServerHello as SupportedVersions;

    // Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with SH
    extension_group! {
        #[derive(Debug)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct ServerHelloExtension<'a> {
            // either key_share or psk are required
            pub key_share: Option<KeyShare<'a>>,
            // either key_share or psk are required
            pub psk: Option<PreSharedKey>,
            pub cookie: Option<Cookie<'a>>, // temporary so we don't trip up on HelloRetryRequests
            pub supported_versions: SupportedVersions,
        }
    }

    // Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with EE
    extension_group! {
        #[derive(Debug)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct EncryptedExtensionsExtension<'a, Location> {
            pub server_name: Option<ServerName>,
            pub max_fragment_length: Option<MaxFragmentLength>,
            pub supported_groups: Option<SupportedGroups<'a, Location>>,
            pub use_srtp: Option<UseSrtp<'a>>,
            pub heartbeat: Option<Heartbeat<'a>>,
            pub apl_negitiation: Option<ApplicationLayerProtocolNegotiation<'a, Location>>,
            pub client_cert_type: Option<ClientCertificateType<'a>>,
            pub server_cert_type: Option<ServerCertificateType<'a>>,
            pub early_data: Option<EarlyData<'a>>,
        }
    }

    // Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CR
    extension_group! {
        #[derive(Debug)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct CertificateRequestExtension<'a, Location> {
            pub status_request: Option<StatusRequest<'a>>,
            pub signature_algorithms: Option<SignatureAlgorithms<'a, Location>>,
            pub signed_cert_timestamp: Option<SignedCertificateTimestamp<'a>>,
            pub certificate_authorities: Option<CertificateAuthorities<'a>>,
            pub oid_filters: Option<OidFilters<'a>>,
            pub signature_algirithms_cert: Option<SignatureAlgorithmsCert<'a, Location>>,
            pub compress_certificate: Option<CompressCertificate<'a>>,
        }
    }

    // Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with NST
    extension_group! {
        #[derive(Debug)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct NewSessionTicketExtension<'a> {
            pub early_data: Option<EarlyData<'a>>
        }
    }

    // Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with HRR
    extension_group! {
        #[derive(Debug)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct HelloRetryRequestExtension<'a> {
            pub key_share: Option<KeyShare<'a>>,
            pub cookie: Option<Cookie<'a>>, // temporary so we don't trip up on HelloRetryRequests
            pub supported_versions: SupportedVersions,
        }
    }
}

mod both {
    use super::*;

    // Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CT
    extension_group! {
        #[derive(Debug)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct CertificateExtension<'a> {
            pub status_request: Option<StatusRequest<'a>>,
            pub signed_certificate_timestamp: Option<SignedCertificateTimestamp<'a>>
        }
    }
}

mod client {
    use super::*;
    use KeyShareClientHello as KeyShare;
    use PreSharedKeyClientHello as PreSharedKey;
    use ServerNameList as ServerName;
    use SupportedVersionsClientHello as SupportedVersions;

    // Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CH
    extension_group! {
        #[derive(Debug)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct ClientHelloExtension<'a, Location> {
            pub server_name: Option<ServerName<'a, Location>>,
            // For TLS 1.3 this is always required,
            // if we choose to implement older tls versions this must be optional
            pub supported_versions: SupportedVersions<'a, Location>,
            pub signature_algorithms: SignatureAlgorithms<'a, Location>,
            pub supported_groups: SupportedGroups<'a, Location>,
            // Technically, a ClientHello could omit key_share and wait for a HelloRetryRequest,
            // but in practice, it is mandatory for a standard 1-RTT connection.

            pub key_share: KeyShare<'a, Location>,
            pub psk_key_exchange_modes: Option<PskKeyExchangeModes<'a, Location>>,
            pub signature_algorithms_cert: Option<SignatureAlgorithmsCert<'a, Location>>,
            pub max_fragment_length: Option<MaxFragmentLength>,
            pub status_request: Option<StatusRequest<'a>>,
            pub use_srtp: Option<UseSrtp<'a>>,
            pub heartbeat: Option<Heartbeat<'a>>,
            pub alp_negotiation: Option<ApplicationLayerProtocolNegotiation<'a, Location>>,
            pub signed_cert_timestamp: Option<SignedCertificateTimestamp<'a>>,
            pub client_cert_type: Option<ClientCertificateType<'a>>,
            pub server_cert_type: Option<ServerCertificateType<'a>>,
            pub padding: Option<Padding<'a>>,
            pub early_data: Option<EarlyData<'a>>,
            pub cookie: Option<Cookie<'a>>,
            pub certificate_authorities: Option<CertificateAuthorities<'a>>,
            pub post_handshake_auth: Option<PostHandshakeAuth<'a>>,
            // Section 4.2
            // When multiple extensions of different types are present, the
            // extensions MAY appear in any order, with the exception of
            // "pre_shared_key" which MUST be the last extension in
            // the ClientHello.
            pub psk: Option<PreSharedKey<'a, Location>>,
        }
    }
}
