// SPDX-License-Identifier: AGPL-3.0-only

//! A TLS stream through the tunnel: the case that was broken while every plaintext test passed.
//!
//! # The defect this pins
//!
//! A reference REALITY node switches its downlink to an XTLS **raw copy** — a `Direct` block — on
//! the first application-data record after it sees the inner `ServerHello`. From that byte on it
//! stops encrypting: Xray's `VisionWriter` sets `switchToDirectCopy` and writes through
//! `buf.NewWriter(rawConn)`.
//!
//! daer's reader understood `Direct` as "stop unpadding" and nothing else, so its record layer
//! kept decrypting plain socket bytes. The first record after the switch went to AES-GCM as
//! ciphertext-that-is-really-plaintext and the session died with `the record was altered`.
//!
//! Why this survived a green suite: **plaintext through the tunnel always worked.** Vision only
//! takes the raw-copy path for TLS, so HTTP proxied fine, `daer probe node`'s e2e tier (a
//! plaintext `GET`) reported "fully operational", and `tests/reality_interop.rs` asserted a
//! plaintext `HTTP/1.` reply. Every signal said the node was healthy while no browser could load
//! a page.
//!
//! # How this test can fail
//!
//! Two things are needed for the defect to appear, and both are in the assertions rather than in
//! the prose:
//!
//! * a **TLS** payload, because that is what makes the node splice. A plaintext payload would
//!   pass even with the bug, which is exactly how it went unnoticed;
//! * the origin's body must come back, so a session that authenticates and then dies mid-handshake
//!   fails instead of passing on "connect returned `Ok`".
//!
//! # The two servers, and why they are different
//!
//! * the **impersonation target** is an `xray` TLS inbound using the checked-in fixture chain. It
//!   only exists so the node has a `ServerHello` to replay, and it must not be a `rustls` server:
//!   REALITY replays the destination's key-share group, daer's client offers only
//!   `X25519MLKEM768` by design, and rustls-with-`ring` picks plain X25519 (0x001d), which fails
//!   with `the server selected key-share group 0x001d; this client offers only X25519MLKEM768`;
//! * the **connection target** is an in-process rustls TLS server. It is what the tunnel actually
//!   carries, so it is the peer whose records the node stops encrypting — and it is under this
//!   test's control, so the assertion is about the tunnel and not about someone's uptime.

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use daer_proxy_protocols::{DialerOptions, ProxyDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;

const UUID: &str = "df4af3d0-030e-4062-baa6-eb9dd45298ef";
const SHORT_ID: &str = "8e3af67d5ffc09f1";

/// The body the TLS origin answers, so the assertion is on content and not on a length.
const BODY: &str = "tls-inside-ok";

/// The `xray` binary, or `None` when the machine has none.
///
/// `None` is a *stated skip* (ADR-0007), not a pass: the node is what decides to splice, so a
/// hand-rolled server here would be this repository's idea of the protocol rather than the
/// reference implementation's.
fn xray() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XRAY_BIN") {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("xray"))
            .find(|candidate| candidate.is_file())
    })
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("binds an ephemeral port")
        .local_addr()
        .expect("has an address")
        .port()
}

/// A child process killed when this value drops, so a panic cannot leave a listener behind.
struct Running {
    child: Child,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawns `xray run -c <config>` with its log captured, and waits until it listens on `port`.
fn spawn_xray(
    xray: &PathBuf,
    config: &std::path::Path,
    log: &std::path::Path,
    port: u16,
) -> Running {
    let out = std::fs::File::create(log).expect("creates the log");
    let err = out.try_clone().expect("clones the log");
    let child = Command::new(xray)
        .arg("run")
        .arg("-c")
        .arg(config)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawns xray");
    let running = Running { child };

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().expect("address"),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return running;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "xray never listened on {port}; config {} ; log:\n{}",
        config.display(),
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

/// Starts a TLS server on an ephemeral port and returns the port.
///
/// The certificate is generated per run and self-signed; the client below accepts any
/// certificate, because the question is whether the *bytes* survive the tunnel and not whether a
/// throwaway fixture is trusted.
fn tls_origin() -> u16 {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["tls-inside.test".to_owned()])
        .expect("generates a certificate");
    let certs = vec![rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("a valid certificate and key");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    // Bind synchronously so the port is known before the runtime thread starts: a `free_port()`
    // that is closed and rebound later is a race, and a test that silently talks to nothing is
    // worse than one that cannot start.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("the TLS origin binds");
    let port = listener.local_addr().expect("has an address").port();
    listener
        .set_nonblocking(true)
        .expect("the listener is non-blocking");

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(async move {
            let listener =
                tokio::net::TcpListener::from_std(listener).expect("adopts the listener");
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buffer = [0u8; 1024];
                    let _ = tls.read(&mut buffer).await;
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                        BODY.len()
                    );
                    let _ = tls.write_all(reply.as_bytes()).await;
                    let _ = tls.flush().await;
                    let _ = tls.shutdown().await;
                });
            }
        });
    });
    port
}

#[tokio::test(flavor = "current_thread")]
async fn a_tls_stream_survives_the_peer_switching_to_a_raw_copy() {
    let Some(xray) = xray() else {
        eprintln!("skipped: no `xray` binary (set XRAY_BIN to a reference build)");
        return;
    };

    let origin_port = tls_origin();

    let dir = std::env::temp_dir().join(format!("daer-tls-inside-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creates the fixture directory");

    // ── the impersonation target: only REALITY's `ServerHello` comes from here.
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let chain = fixtures.join("reality_dest_chain.pem");
    let key = fixtures.join("reality_dest_key.pem");
    let dest_port = free_port();
    let dest_config = dir.join("dest.json");
    std::fs::write(
        &dest_config,
        format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {dest_port}, "protocol": "vless",
    "settings": {{ "clients": [{{ "id": "99999999-8888-7777-6666-555555555555" }}], "decryption": "none" }},
    "streamSettings": {{
      "network": "tcp", "security": "tls",
      "tlsSettings": {{
        "alpn": ["h2", "http/1.1"],
        "certificates": [{{ "certificateFile": "{chain}", "keyFile": "{key}" }}]
      }}
    }}
  }}],
  "outbounds": [{{ "protocol": "freedom" }}]
}}"#,
            chain = chain.display(),
            key = key.display(),
        ),
    )
    .expect("writes the dest config");
    let _dest = spawn_xray(&xray, &dest_config, &dir.join("dest.log"), dest_port);

    // ── the REALITY + Vision node under test.
    let keys = Command::new(&xray)
        .arg("x25519")
        .output()
        .expect("runs xray x25519");
    assert!(keys.status.success(), "`xray x25519` failed");
    let text = String::from_utf8_lossy(&keys.stdout).to_string();
    let field = |label: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(label).map(str::to_owned))
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|| panic!("no {label:?} in:\n{text}"))
    };
    let private = field("PrivateKey:");
    let public = field("Password (PublicKey):");

    let node_port = free_port();
    let node_config = dir.join("node.json");
    let node_log = dir.join("node.log");
    std::fs::write(
        &node_config,
        format!(
            r#"{{
  "log": {{ "loglevel": "debug" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {node_port}, "protocol": "vless",
    "settings": {{ "clients": [{{ "id": "{UUID}", "flow": "xtls-rprx-vision" }}], "decryption": "none" }},
    "streamSettings": {{
      "network": "tcp", "security": "reality",
      "realitySettings": {{
        "show": true, "dest": "127.0.0.1:{dest_port}",
        "serverNames": ["reality-interop.test"], "privateKey": "{private}",
        "shortIds": ["{SHORT_ID}"]
      }}
    }}
  }}],
  // `finalRules` allows the loopback origin: Xray blocks private targets from proxy inbounds by
  // default (v26.4.15+) and blackholes them for 30-90 s, which reads exactly like a broken tunnel.
  "outbounds": [{{ "protocol": "freedom",
    "settings": {{ "finalRules": [{{ "action": "allow", "ip": ["127.0.0.0/8"] }}] }} }}]
}}"#
        ),
    )
    .expect("writes the node config");
    let _node = spawn_xray(&xray, &node_config, &node_log, node_port);

    let link = format!(
        "vless://{UUID}@127.0.0.1:{node_port}?encryption=none&security=reality\
         &flow=xtls-rprx-vision&sni=reality-interop.test&pbk={public}&sid={SHORT_ID}\
         &type=tcp&fp=chrome#tls-inside"
    );
    let dialer = ProxyDialer::from_link(&link, DialerOptions::new(None, Duration::from_secs(10)))
        .expect("the link must parse");

    let established = tokio::time::timeout(
        Duration::from_secs(20),
        dialer.connect(&format!("127.0.0.1:{origin_port}")),
    )
    .await
    .expect("the connect must not hang")
    .expect("the session must be established");

    // ── TLS *inside* the tunnel. This is the part that used to die: the node answers with a
    // `Direct` block and a client that keeps decrypting reads ciphertext as plaintext.
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name =
        rustls::pki_types::ServerName::try_from("tls-inside.test").expect("a valid name");
    let mut tls = tokio::time::timeout(
        Duration::from_secs(20),
        connector.connect(server_name, established.stream),
    )
    .await
    .expect("the inner TLS handshake must not hang")
    .unwrap_or_else(|error| {
        panic!(
            "the inner TLS handshake must complete ({error}); the node's log said:\n{}",
            std::fs::read_to_string(&node_log).unwrap_or_default()
        )
    });

    tls.write_all(b"GET / HTTP/1.1\r\nHost: tls-inside.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("the request must be written");

    let mut reply = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(20), tls.read_to_end(&mut reply)).await;
    assert!(
        read.is_ok(),
        "the reply never arrived; the node's log said:\n{}",
        std::fs::read_to_string(&node_log).unwrap_or_default()
    );
    read.expect("checked above")
        .expect("the reply must be readable");

    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.contains(BODY),
        "the origin's body must survive the tunnel's raw-copy switch; got {text:?}"
    );
}

/// Accepts any certificate, for a fixture generated per run.
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
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}
