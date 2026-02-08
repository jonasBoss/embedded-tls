use crate::extensions::{
    extension_data::{
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

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CH
extension_group! {
    pub enum ClientHelloExtension<'a, Location> {
        ServerName(ServerNameList<'a, Location>),
        SupportedVersions(SupportedVersionsClientHello<'a, Location>),
        SignatureAlgorithms(SignatureAlgorithms<'a, Location>),
        SupportedGroups(SupportedGroups<'a, Location>),
        KeyShare(KeyShareClientHello<'a, Location>),
        PreSharedKey(PreSharedKeyClientHello<'a, Location>),
        PskKeyExchangeModes(PskKeyExchangeModes<'a, Location>),
        SignatureAlgorithmsCert(SignatureAlgorithmsCert<'a, Location>),
        MaxFragmentLength(MaxFragmentLength),
        StatusRequest(Unimplemented<'a>),
        UseSrtp(Unimplemented<'a>),
        Heartbeat(Unimplemented<'a>),
        ApplicationLayerProtocolNegotiation(Unimplemented<'a>),
        SignedCertificateTimestamp(Unimplemented<'a>),
        ClientCertificateType(Unimplemented<'a>),
        ServerCertificateType(Unimplemented<'a>),
        Padding(Unimplemented<'a>),
        EarlyData(Unimplemented<'a>),
        Cookie(Unimplemented<'a>),
        CertificateAuthorities(Unimplemented<'a>),
        OidFilters(Unimplemented<'a>),
        PostHandshakeAuth(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with SH
extension_group! {
    pub enum ServerHelloExtension<'a> {
        KeyShare(KeyShareServerHello<'a>),
        PreSharedKey(PreSharedKeyServerHello),
        Cookie(Unimplemented<'a>), // temporary so we don't trip up on HelloRetryRequests
        SupportedVersions(SupportedVersionsServerHello)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with EE
extension_group! {
    pub enum EncryptedExtensionsExtension<'a, Location> {
        ServerName(ServerNameResponse),
        MaxFragmentLength(MaxFragmentLength),
        SupportedGroups(SupportedGroups<'a, Location>),
        UseSrtp(Unimplemented<'a>),
        Heartbeat(Unimplemented<'a>),
        ApplicationLayerProtocolNegotiation(Unimplemented<'a>),
        ClientCertificateType(Unimplemented<'a>),
        ServerCertificateType(Unimplemented<'a>),
        EarlyData(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CR
extension_group! {
    pub enum CertificateRequestExtension<'a, Location> {
        StatusRequest(Unimplemented<'a>),
        SignatureAlgorithms(SignatureAlgorithms<'a, Location>),
        SignedCertificateTimestamp(Unimplemented<'a>),
        CertificateAuthorities(Unimplemented<'a>),
        OidFilters(Unimplemented<'a>),
        SignatureAlgorithmsCert(Unimplemented<'a>),
        CompressCertificate(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CT
extension_group! {
    pub enum CertificateExtension<'a> {
        StatusRequest(Unimplemented<'a>),
        SignedCertificateTimestamp(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with NST
extension_group! {
    pub enum NewSessionTicketExtension<'a> {
        EarlyData(Unimplemented<'a>)
    }
}

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with HRR
extension_group! {
    pub enum HelloRetryRequestExtension<'a> {
        KeyShare(Unimplemented<'a>),
        Cookie(Unimplemented<'a>),
        SupportedVersions(Unimplemented<'a>)
    }
}
