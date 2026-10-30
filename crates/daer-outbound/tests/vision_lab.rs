// SPDX-License-Identifier: AGPL-3.0-only

//! Vision framing against a local Xray inbound over plain TLS.
//!
//! REALITY's own layer hides the bugs beneath it: its `padding: -4` failure happens during
//! the handshake, long before Vision runs. This test removes REALITY from the path — a real
//! `xray run` inbound with `security: tls` and `flow=xtls-rprx-vision` — so a failure can
//! only be the Vision frame.
//!
//! Start the server first (see `docs/vision-lab.md`):
//!
//! ```sh
//! /tmp/xray run -c /tmp/lab/server_tls.json
//! cargo test -p daer-outbound --test vision_lab -- --nocapture --include-unignored
//! ```
//!
//! Ignored by default: it needs that server.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;

const UUID_HEX: &str = "df4af3d0030e4062baa6eb9dd45298ef";

fn uuid_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    for (index, chunk) in UUID_HEX.as_bytes().chunks(2).enumerate() {
        out[index] =
            u8::from_str_radix(std::str::from_utf8(chunk).expect("ascii"), 16).expect("hex");
    }
    out
}

/// The VLESS request header for `host:port`.
fn vless_header(host: &str, port: u16, vision: bool) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0); // version
    header.extend_from_slice(&uuid_bytes());
    if vision {
        let flow = b"xtls-rprx-vision";
        let mut addons = vec![0x0a, flow.len() as u8];
        addons.extend_from_slice(flow);
        header.push(addons.len() as u8);
        header.extend_from_slice(&addons);
    } else {
        header.push(0);
    }
    header.push(0x01); // CMD: TCP
    // VLESS uses `PortThenAddress`, so the port comes first.
    header.extend_from_slice(&port.to_be_bytes());
    if host.parse::<std::net::IpAddr>().is_ok() {
        panic!("this probe only writes domain addresses");
    }
    header.push(0x02); // ATYP: domain
    header.push(host.len() as u8);
    header.extend_from_slice(host.as_bytes());
    header
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs a local xray inbound; see docs/vision-lab.md"]
async fn vision_uplink_reaches_a_real_xray_inbound() {
    let server = std::env::var("DAER_VISION_SERVER").unwrap_or_else(|_| "127.0.0.1:18443".into());

    // The lab server uses a self-signed certificate; the point of this probe is the frame,
    // not the TLS identity.
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(AcceptAny));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(&server)
        .await
        .expect("connects");
    let domain = rustls::pki_types::ServerName::try_from("apple.com").expect("valid name");
    let tls = connector.connect(domain, tcp).await.expect("tls");
    println!("handshake ok with {server}");

    let (mut read, mut write) = tokio::io::split(tls);

    // header (unframed) || opening block (empty, long padding)
    let header = vless_header("example.com", 80, true);
    let opening = {
        // uuid || cmd=Continue || content_len=0 || padding_len
        let mut block = Vec::new();
        block.extend_from_slice(&uuid_bytes());
        block.push(0x00);
        block.extend_from_slice(&0u16.to_be_bytes());
        let padding = 900u16;
        block.extend_from_slice(&padding.to_be_bytes());
        block.resize(block.len() + usize::from(padding), 0);
        block
    };

    let mut flight = header.clone();
    flight.extend_from_slice(&opening);
    write.write_all(&flight).await.expect("writes header");
    write.flush().await.expect("flushes");
    println!(
        "sent header {} + opening {} bytes",
        header.len(),
        opening.len()
    );

    // Then the payload, framed as a second block that ends the stream.
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let mut block = Vec::new();
    block.push(0x01); // End
    block.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    block.extend_from_slice(&0u16.to_be_bytes());
    block.extend_from_slice(payload);
    write.write_all(&block).await.expect("writes payload");
    write.flush().await.expect("flushes");
    println!("sent payload block {} bytes", block.len());

    let mut buffer = [0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(10), read.read(&mut buffer)).await {
        Ok(Ok(0)) => panic!("the inbound closed without answering"),
        Ok(Ok(n)) => {
            println!("read {n} bytes: {:02x?}", &buffer[..n.min(64)]);
            println!("txt: {}", String::from_utf8_lossy(&buffer[..n.min(300)]));
            assert!(n > 0);
        }
        Ok(Err(error)) => panic!("read failed: {error}"),
        Err(_) => panic!("read timed out"),
    }
}

/// Accepts any certificate: the lab server is self-signed and this probe is about framing.
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
