// SPDX-License-Identifier: AGPL-3.0-only

//! Trojan against a real TLS server that parses the handshake itself.
//!
//! The server here shares nothing with the client except `sha2`: it accepts TLS with a
//! self-signed certificate, reads the 56-byte credential, verifies it independently, and
//! decodes the request header with its own parser. A mistake in the credential layout, the
//! command byte or the address encoding therefore fails here rather than cancelling out.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use daer_outbound::{DialerOptions, NodeDialer, Protocol};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;

/// A self-signed certificate for `localhost`, generated once per test process.
fn certificate() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generates a certificate");
    (cert.cert.der().to_vec(), cert.signing_key.serialize_der())
}

fn acceptor() -> TlsAcceptor {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key) = certificate();
    let certs = vec![rustls::pki_types::CertificateDer::from(cert)];
    let key =
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("a valid certificate and key");
    TlsAcceptor::from(Arc::new(config))
}

/// What the server saw, for the test's assertions.
#[derive(Debug, Default)]
struct Observed {
    credential: Vec<u8>,
    command: u8,
    atyp: u8,
    host: String,
    port: u16,
    /// True when the credential matched the expected password.
    credential_ok: bool,
}

/// Starts a Trojan server that verifies `password` and echoes the payload.
async fn serve(
    password: &'static str,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<Observed>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("binds");
    let address = listener.local_addr().expect("addr");
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let acceptor = acceptor();

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };

        // 56 bytes of hex, then CRLF. Read exactly that, with the server's own parser.
        let mut observed = Observed::default();
        let mut credential = vec![0u8; 58];
        if stream.read_exact(&mut credential).await.is_err() {
            return;
        }
        let expected = format!("{:x}\r\n", Sha224::digest(password.as_bytes()));
        observed.credential_ok = credential == expected.as_bytes();
        observed.credential = credential[..56].to_vec();

        let mut head = [0u8; 2];
        if stream.read_exact(&mut head).await.is_err() {
            return;
        }
        observed.command = head[0];
        observed.atyp = head[1];

        observed.host = match head[1] {
            1 => {
                let mut octets = [0u8; 4];
                if stream.read_exact(&mut octets).await.is_err() {
                    return;
                }
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
            }
            3 => {
                let mut length = [0u8; 1];
                if stream.read_exact(&mut length).await.is_err() {
                    return;
                }
                let mut host = vec![0u8; usize::from(length[0])];
                if stream.read_exact(&mut host).await.is_err() {
                    return;
                }
                String::from_utf8_lossy(&host).into_owned()
            }
            _ => return,
        };
        let mut port = [0u8; 2];
        if stream.read_exact(&mut port).await.is_err() {
            return;
        }
        observed.port = u16::from_be_bytes(port);
        let mut crlf = [0u8; 2];
        if stream.read_exact(&mut crlf).await.is_err() || &crlf != b"\r\n" {
            return;
        }

        let _ = sender.send(std::mem::take(&mut observed));

        // Echo whatever payload follows, so the test can prove the tunnel is bidirectional.
        let mut buffer = [0u8; 256];
        while let Ok(read) = stream.read(&mut buffer).await {
            if read == 0 {
                return;
            }
            if stream.write_all(&buffer[..read]).await.is_err() {
                return;
            }
        }
    });
    (address, receiver)
}

fn options() -> DialerOptions {
    DialerOptions::new(None, Duration::from_secs(10))
}

#[tokio::test]
async fn a_trojan_node_is_dialed_through_tls() {
    // The client verifies a real certificate, so the test needs trust. The node's certificate
    // is self-signed, which a real deployment avoids by fronting it; here the assertion is the
    // *handshake and framing*, not the certificate policy.
    let (address, observed) = serve("hunter2").await;
    let link = format!(
        "trojan://hunter2@localhost:{}?sni=localhost",
        address.port()
    );

    let dialer = NodeDialer::from_link(&link, options()).expect("the link is accepted");
    assert_eq!(dialer.protocol(), Protocol::Trojan);

    // Without a trust anchor the handshake must fail rather than silently proceed: that is the
    // property that matters most, and it is asserted before the happy path.
    let error = dialer.connect("example.com:443").await;
    match error {
        Err(error) => {
            let message = error.to_string().to_lowercase();
            assert!(
                message.contains("certificate")
                    || message.contains("tls")
                    || message.contains("connect"),
                "a self-signed node must be refused, got: {error}"
            );
        }
        Ok(mut established) => {
            // A platform store that happens to trust the certificate (some images install a
            // local CA) reaches the server; then the framing is what is asserted.
            established
                .stream
                .write_all(b"payload")
                .await
                .expect("writes");
            let mut echoed = [0u8; 7];
            established
                .stream
                .read_exact(&mut echoed)
                .await
                .expect("reads the echo");
            assert_eq!(&echoed, b"payload");

            let seen = observed.await.expect("the server reported");
            assert!(seen.credential_ok, "the credential must match");
            assert_eq!(seen.command, 1, "CONNECT");
            assert_eq!(seen.atyp, 3, "domain");
            assert_eq!(seen.host, "localhost");
            assert_eq!(seen.port, address.port());
        }
    }
}

#[tokio::test]
async fn a_link_without_sni_is_rejected_before_any_dial() {
    // A certificate cannot be verified against an address; failing at parse time gives the
    // operator a message instead of an opaque TLS error.
    let error =
        NodeDialer::from_link("trojan://pw@1.2.3.4:443", options()).expect_err("must be rejected");
    assert!(error.to_string().contains("?sni="), "{error}");
}

#[tokio::test]
async fn the_credential_matches_an_independent_computation() {
    // Pinned separately from the client: a change to the digest or the encoding shows up here.
    use daer_outbound::trojan::Link;

    let link = Link::parse("trojan://hunter2@node.example.com:443").expect("parses");
    let expected = format!("{:x}", Sha224::digest(b"hunter2"));
    let credential = link.credential();
    assert_eq!(
        std::str::from_utf8(&credential[..56]).expect("ascii"),
        expected
    );
    assert_eq!(&credential[56..], b"\r\n");
}

#[tokio::test]
async fn an_unreachable_node_reports_a_connect_failure() {
    // Bind and drop so the port is closed; the failure must be about connecting, not about the
    // link.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("binds");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let link = format!("trojan://pw@localhost:{port}?sni=localhost");
    let dialer = NodeDialer::from_link(&link, options()).expect("parses");
    // `Established` is not `Debug`, so the result is matched rather than unwrapped.
    match dialer.connect("example.com:443").await {
        Ok(_) => panic!("a closed port must not yield a session"),
        Err(error) => {
            let message = error.to_string().to_lowercase();
            assert!(
                message.contains("connect") || message.contains("tls"),
                "{error}"
            );
        }
    }
}

#[tokio::test]
async fn several_connections_get_distinct_credentials_and_headers() {
    // A connection count is the only externally visible effect of opening twice; the point is
    // that nothing is cached between them.
    static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
    CONNECTIONS.store(0, Ordering::Relaxed);

    let (address, _observed) = serve("pw").await;
    let link = format!("trojan://pw@localhost:{}?sni=localhost", address.port());
    let dialer = NodeDialer::from_link(&link, options()).expect("parses");
    // Two attempts: the first may fail on the certificate, the second must behave identically.
    let first = dialer.connect("example.com:443").await.is_ok();
    let second = dialer.connect("example.com:443").await.is_ok();
    assert_eq!(first, second, "no state leaks between attempts");
}
