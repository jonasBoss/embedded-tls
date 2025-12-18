#![cfg(feature = "server")]

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_io_async::{Read, Write};
use embedded_tls::{
    Aes128GcmSha256, Certificate, TlsConfig, TlsConnection, TlsContext, UnsecureProvider,
};
use log::info;
use rand_core::OsRng;
use std::{sync::Once, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};

static LOG_INIT: Once = Once::new();

fn init_log() {
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}

const TIMEOUT: Duration = Duration::from_secs(1);

#[tokio::test]
async fn test_server_and_client() {
    init_log();

    let server = async {
        info!("Starting server");
        let listener = TcpListener::bind("localhost:1234").await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();

        let cert_pem = include_str!("data/server-cert.pem");
        let cert_der = pem_parser::pem_to_der(cert_pem);
        let key_pem = include_str!("data/server-key.pem");
        let key_der = pem_parser::pem_to_der(key_pem);

        let mut record_read_buf = [0; 16384];
        let mut record_write_buf = [0; 16384];

        let config = TlsConfig::new_server(Certificate::X509(&cert_der), &key_der);
        let mut tls = TlsConnection::new(
            FromTokio::new(stream),
            &mut record_read_buf,
            &mut record_write_buf,
        );

        tls.open(TlsContext::new(
            &config,
            UnsecureProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .await
        .expect("Server error establishing TLS connection");

        let mut rx_buf = [0; 4];
        tls.read_exact(&mut rx_buf).await.unwrap();
        tls.write_all("pong".as_bytes()).await.unwrap();
        assert_eq!(&rx_buf, b"ping");
    };
    let client = async {
        info!("Starting client");
        let stream = TcpStream::connect("localhost:1234").await.unwrap();

        let mut record_read_buf = [0; 16384];
        let mut record_write_buf = [0; 16384];

        let config = TlsConfig::new();
        let mut tls = TlsConnection::new(
            FromTokio::new(stream),
            &mut record_read_buf,
            &mut record_write_buf,
        );
        tls.open(TlsContext::new(
            &config,
            UnsecureProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .await
        .expect("client error establishing TLS connection");

        tls.write_all("ping".as_bytes()).await.unwrap();
        let mut rx_buf = [0; 4];
        tls.read_exact(&mut rx_buf).await.unwrap();
        assert_eq!(&rx_buf, b"pong");
    };

    let (server, client) = tokio::join!(timeout(TIMEOUT, server), timeout(TIMEOUT, client));
    server.expect("server timed out");
    client.expect("client timed out");
}
