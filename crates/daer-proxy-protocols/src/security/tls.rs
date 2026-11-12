// SPDX-License-Identifier: AGPL-3.0-only

//! Ordinary TLS to the node (ADR-0028).
//!
//! # netune owns the handshake
//!
//! The `ClientConfig` is built from netune's profile registry, then handed to
//! [`netune::TlsConnector`]. That keeps the handshake, its timeout and its trace events in
//! one implementation; daer only decides the node's ALPN offer and certificate policy.
//!
//! netune's stock `TlsConnector::platform` offers `http/1.1` because its consumer is an HTTP
//! client. A `vless` node speaks no ALPN at all (or `h2`), and offering `http/1.1` to it is
//! a fingerprint the operator did not choose. The profile's ALPN field expresses that
//! difference without a second TLS handshake: the profile still supplies cipher suites,
//! groups and extension order, and the connector still performs the handshake.
//!
//! # Certificate policy
//!
//! Platform trust by default. `allow-insecure` is a real setting for a real situation (a
//! node with a self-signed certificate) and is honoured, but it is never a default: a
//! daemon that silently stopped verifying would be a vulnerability nobody configured.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune::{
    Connector, Established, NetError, Preset, Target, TlsConnector, TlsProfile, Transport, Verifier,
};
use netune_trace::TraceCollector;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::ProxyProtocolError;
use crate::security::{Opaque, crypto_provider};

/// The parameters of a standard-TLS security layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsParams {
    /// SNI to present. `None` uses the node's own host.
    pub server_name: Option<String>,
    /// Accept any certificate. A deliberate assertion, never a default.
    pub allow_insecure: bool,
    /// ALPN to offer. Empty offers none, which is what a node without `alpn=` expects.
    pub alpn: Vec<String>,
    /// netune TLS preset name, or `None` for the deployment default.
    pub fingerprint: Option<String>,
}

impl TlsParams {
    /// The name presented in SNI: the explicit one, else the node's host.
    #[must_use]
    pub fn sni<'a>(&'a self, node_host: &'a str) -> &'a str {
        self.server_name.as_deref().unwrap_or(node_host)
    }
}

/// Wraps `stream` in TLS.
///
/// `alpn` is the node's own list; when it is empty the profile's defaults are dropped too,
/// because a node that asked for no ALPN must receive no ALPN extension — offering one
/// would change the hello the operator configured.
pub(super) async fn wrap<S>(
    stream: S,
    params: &TlsParams,
    node_host: &str,
    recorder: &TraceCollector,
    timeout: Duration,
) -> Result<Opaque, ProxyProtocolError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let config = build_config(params)?;
    let server_name = params.sni(node_host).to_owned();
    let target = Target::tls(server_name.clone(), server_name.clone());

    // The stream is already established: this connector exists only so netune's TLS layer
    // can own the handshake and trace events. It deliberately cannot be called twice,
    // because a security layer wraps exactly one stream.
    //
    // The deadline is daer's, not netune's: `ProxyProtocolError::Timeout` is a distinct
    // contract used by health checks and the relay, and netune's handshake timeout reports a
    // generic connect failure. `None` is netune's documented mode for a caller that owns the
    // outer deadline.
    let connector =
        TlsConnector::new(Preconnected::new(stream), config).with_handshake_timeout(None);
    let established =
        match tokio::time::timeout(timeout, connector.connect(&target, recorder)).await {
            Ok(result) => result.map_err(|error| {
                ProxyProtocolError::Connect(format!("TLS handshake with {server_name}: {error}"))
            })?,
            // netune's pinned tracer has no diagnostic-record API. The caller's deadline is
            // the only place that can keep `Timeout` distinct from a certificate or protocol
            // error, which is why the outer bound is not delegated to netune here.
            Err(_) => return Err(ProxyProtocolError::Timeout),
        };

    // rustls exposes no splice path, so there is nothing for a `Direct` command to switch
    // off here. A node that sends `Direct` on this layer is answered with `End` instead, and
    // Vision keeps unpadding — which is correct, and is why the switch is `None`.
    let Established {
        stream,
        alpn_protocol,
        ..
    } = established;
    let alpn = alpn_protocol
        .as_deref()
        .and_then(|name| std::str::from_utf8(name).ok())
        .map(str::to_owned);
    Ok(Opaque {
        stream,
        raw_read: None,
        alpn,
        alpn_protocol,
    })
}

/// A one-shot [`Connector`] over an already-established stream.
///
/// netune's TLS layer wraps a `Connector`, but ADR-0028 applies TLS *above* a transport
/// that another layer already opened. This adapter is the smallest possible seam between
/// those two facts; it performs no I/O of its own.
struct Preconnected {
    stream: Mutex<Option<Box<dyn Transport>>>,
}

impl Preconnected {
    fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self {
            stream: Mutex::new(Some(Box::new(stream))),
        }
    }
}

impl Connector for Preconnected {
    async fn connect(
        &self,
        _target: &Target,
        _recorder: &TraceCollector,
    ) -> Result<Established, NetError> {
        let stream = self
            .stream
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| {
                NetError::Connect(
                    "the TLS security layer was asked to connect twice for one stream".to_owned(),
                )
            })?;
        Ok(Established {
            stream,
            local_port: None,
            socket: None,
            alpn: None,
            alpn_protocol: None,
        })
    }
}

/// Compiles the profile and the node's ALPN into one client config.
/// The TLS identity this layer presents.
///
/// Split out from [`build_config`] so the invariant *"the trust setting does not change the
/// identity"* is assertable: `TlsProfile` exposes its suites, groups and ALPN, while
/// `rustls::ClientConfig` exposes none of them. Testing it through the config would have meant
/// asserting nothing.
fn profile_for(params: &TlsParams) -> Result<TlsProfile, ProxyProtocolError> {
    let mut profile = resolve_profile(params.fingerprint.as_deref())?;

    // `fingerprint` is an assertion about what the peer sees; `allow-insecure` is an assertion
    // about what we accept. They are orthogonal, so only the verifier moves — the suites, groups
    // and extension order stay exactly as the profile chose them.
    if params.allow_insecure {
        profile.verifier = Verifier::Roots(rustls::RootCertStore::empty());
    }

    // A node that names no ALPN must offer no ALPN. `netune-default` offers `http/1.1`, which is
    // netune's own consumer's identity, not this node's.
    profile.alpn_protocols = params
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(profile)
}

/// Resolves a netune preset name (or the deployment default) to profile data.
///
/// A bare browser name is what every panel and every `fp=chrome` link says, while netune
/// registers the versioned `chrome-current`. Resolving the suffix is not leniency for its own
/// sake: an error here means the node cannot load at all, and the operator wrote the spelling
/// the rest of the ecosystem uses.
fn resolve_profile(fingerprint: Option<&str>) -> Result<TlsProfile, ProxyProtocolError> {
    match fingerprint {
        Some(name) => {
            let preset = Preset::by_name(name)
                .or_else(|| Preset::by_name(&format!("{name}-current")))
                .ok_or_else(|| {
                    let known: Vec<&str> =
                        Preset::all().iter().map(|preset| preset.name()).collect();
                    ProxyProtocolError::UnsupportedLink(format!(
                        "node.security.fingerprint = {name:?} is not a netune TLS preset; the \
                         registered names are {known:?}"
                    ))
                })?;
            Ok(preset.profile())
        }
        None => Ok(TlsProfile::netune_default()),
    }
}

/// Compiles the profile into one client config.
fn build_config(params: &TlsParams) -> Result<Arc<rustls::ClientConfig>, ProxyProtocolError> {
    let profile = profile_for(params)?;
    compile_profile(profile, params.allow_insecure)
}

/// Builds a profile-driven config for a product TLS layer outside the standard security
/// layer (Trojan and AnyTLS).
///
/// The profile's own ALPN offer is preserved: those protocols previously used
/// `TlsConnector::platform`, whose `http/1.1` offer is the same default, but a configured
/// fingerprint must keep the ALPN it declares.
pub(crate) fn profile_config(
    fingerprint: Option<&str>,
    allow_insecure: bool,
) -> Result<Arc<rustls::ClientConfig>, ProxyProtocolError> {
    compile_profile(resolve_profile(fingerprint)?, allow_insecure)
}

fn compile_profile(
    profile: TlsProfile,
    allow_insecure: bool,
) -> Result<Arc<rustls::ClientConfig>, ProxyProtocolError> {
    let built = profile
        .build(Arc::clone(&crypto_provider()))
        .map_err(|error| {
            ProxyProtocolError::Connect(format!("TLS profile {:?}: {error}", profile.name))
        })?;
    let mut config = (*built).clone();
    if allow_insecure {
        // `root_certificates(empty)` cannot express "accept anything", so the *verifier* is
        // replaced on the already-profiled config. This is the only `dangerous()` call on the
        // crate's TLS path, and it is reachable only from `allow-insecure = true`.
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAny));
    }
    Ok(Arc::new(config))
}

/// Accepts any certificate chain.
///
/// Reached only through `node.security.allow-insecure = true`, which is a decision an
/// operator writes down. The name says what it does so a reviewer cannot miss it.
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
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
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_that_names_no_alpn_offers_no_alpn() {
        // The failure this pins: `netune-default` advertises `http/1.1`, and a VLESS node
        // that did not ask for ALPN must not receive an extension it would have to answer.
        let params = TlsParams {
            server_name: Some("example.com".to_owned()),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: None,
        };
        let config = build_config(&params).expect("builds");
        assert!(
            config.alpn_protocols.is_empty(),
            "offered {:?}",
            config.alpn_protocols
        );

        // The control: an explicit list survives verbatim and in order.
        let params = TlsParams {
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            ..params
        };
        let config = build_config(&params).expect("builds");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn a_bare_browser_fingerprint_resolves_to_its_versioned_preset() {
        // `fp=chrome` is what links and panels write; netune registers `chrome-current`. Refusing
        // the bare spelling would mean a node that cannot load at all for writing the name the
        // rest of the ecosystem uses — and `vless://…?fp=chrome` is in every subscription.
        let bare = profile_for(&TlsParams {
            server_name: None,
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: Some("chrome".to_owned()),
        })
        .expect("a bare browser name resolves");
        let versioned = profile_for(&TlsParams {
            server_name: None,
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: Some("chrome-current".to_owned()),
        })
        .expect("the versioned name resolves too");
        assert_eq!(bare.cipher_suites, versioned.cipher_suites);
        assert_eq!(bare.name, versioned.name);

        // A name that matches neither spelling is still refused, with the list.
        let error = match profile_for(&TlsParams {
            server_name: None,
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: Some("netscape".to_owned()),
        }) {
            Ok(_) => panic!("netscape is not a preset"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("chrome-current"), "{error}");
    }

    #[test]
    fn an_unknown_fingerprint_is_refused_by_name_with_the_alternatives() {
        let params = TlsParams {
            server_name: None,
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: Some("chrom".to_owned()),
        };
        let error = build_config(&params).expect_err("typo must fail");
        let message = error.to_string();
        assert!(message.contains("chrom"), "{message}");
        assert!(message.contains("chrome"), "{message}");
    }

    #[test]
    fn allow_insecure_keeps_the_profiles_identity() {
        // The defect this pins: the insecure arm used to open a *bare* `rustls::ClientConfig`,
        // which discarded the profile's cipher suites, groups and extension order — so a node's
        // ClientHello depended on whether its certificate happened to be trusted. That is a
        // fingerprint leak caused by a trust setting, exactly the sort of difference an on-path
        // observer fingerprints.
        let secure = TlsParams {
            server_name: Some("example.com".to_owned()),
            allow_insecure: false,
            alpn: vec!["h2".to_owned()],
            fingerprint: Some("chrome".to_owned()),
        };
        let insecure = TlsParams {
            allow_insecure: true,
            ..secure.clone()
        };
        let secure_profile = profile_for(&secure).expect("builds");
        let insecure_profile = profile_for(&insecure).expect("builds");

        assert_eq!(
            secure_profile.cipher_suites, insecure_profile.cipher_suites,
            "the suite allowlist is the profile's, in both arms"
        );
        assert_eq!(
            secure_profile.kx_groups, insecure_profile.kx_groups,
            "the group allowlist is the profile's, in both arms"
        );
        assert_eq!(
            secure_profile.alpn_protocols, insecure_profile.alpn_protocols,
            "ALPN must not depend on the trust setting"
        );
        // `netune::Verifier` derives no `PartialEq` (it wraps a `RootCertStore`), so the
        // distinction is asserted by shape rather than by equality.
        assert!(
            matches!(secure_profile.verifier, Verifier::Platform),
            "the trusted arm keeps the platform store"
        );
        assert!(
            matches!(insecure_profile.verifier, Verifier::Roots(_)),
            "the insecure arm replaces the verifier, and that is the only thing it changes"
        );

        // And the control: `chrome-current` really is the named preset and not the deployment
        // default. The comparison is on the *name* and on `alpn_protocols`, because a profile
        // expresses "use the provider's defaults" for suites and groups as `None` — asserting a
        // difference there would have compared `None` with `None` and passed for the wrong reason.
        let plain = profile_for(&TlsParams {
            server_name: None,
            allow_insecure: true,
            alpn: Vec::new(),
            fingerprint: None,
        })
        .expect("builds");
        assert_eq!(plain.name, "netune-default");
        assert_eq!(insecure_profile.name, "chrome-current");
        assert_ne!(
            plain.alpn_protocols, insecure_profile.alpn_protocols,
            "the default offers `http/1.1`; a node that named none must offer none"
        );
    }

    #[test]
    fn sni_falls_back_to_the_node_host() {
        let params = TlsParams {
            server_name: None,
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: None,
        };
        assert_eq!(params.sni("node.example.com"), "node.example.com");
        let params = TlsParams {
            server_name: Some("cdn.example.com".to_owned()),
            ..params
        };
        assert_eq!(params.sni("node.example.com"), "cdn.example.com");
    }

    #[test]
    fn a_product_tls_profile_reaches_the_connector_config() {
        let config = profile_config(Some("chrome"), true).expect("profile config");
        let preset = Preset::by_name("chrome-current").expect("preset");
        assert_eq!(
            config.alpn_protocols,
            preset.profile().alpn_protocols,
            "Trojan/AnyTLS must use the configured fingerprint's ALPN, not a bare platform config"
        );
    }

    #[tokio::test]
    async fn a_stalled_handshake_stays_a_timeout_not_a_connect_failure() {
        use crate::error::ProxyProtocolError;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accepts");
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let params = TlsParams {
            server_name: Some("localhost".to_owned()),
            allow_insecure: true,
            alpn: Vec::new(),
            fingerprint: None,
        };
        let result = wrap(
            tokio::net::TcpStream::connect(address)
                .await
                .expect("connects"),
            &params,
            "localhost",
            &TraceCollector::disabled(),
            Duration::from_millis(50),
        )
        .await;
        assert!(
            matches!(result, Err(ProxyProtocolError::Timeout)),
            "a stalled TLS handshake must keep the caller's timeout contract, got {result:?}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn the_handshake_runs_through_netune_and_reports_the_negotiated_alpn() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
        let certs = vec![rustls::pki_types::CertificateDer::from(
            certificate.cert.der().to_vec(),
        )];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()),
        );
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config");
        server_config.alpn_protocols = vec![b"h2".to_vec()];

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accepts");
            let mut stream = acceptor.accept(stream).await.expect("server handshake");
            stream.write_all(b"ok").await.expect("writes");
        });

        let params = TlsParams {
            server_name: Some("localhost".to_owned()),
            allow_insecure: true,
            alpn: vec!["h2".to_owned()],
            fingerprint: None,
        };
        let mut opaque = wrap(
            tokio::net::TcpStream::connect(address)
                .await
                .expect("connects"),
            &params,
            "localhost",
            &TraceCollector::disabled(),
            Duration::from_secs(2),
        )
        .await
        .expect("TLS handshake");
        assert_eq!(opaque.alpn.as_deref(), Some("h2"));
        assert_eq!(opaque.alpn_protocol.as_deref(), Some(b"h2".as_slice()));

        let mut payload = [0u8; 2];
        opaque
            .stream
            .read_exact(&mut payload)
            .await
            .expect("reads through the TLS stream");
        assert_eq!(&payload, b"ok");
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn a_custom_alpn_name_survives_the_netune_handshake() {
        use tokio::io::AsyncWriteExt as _;

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
        let certs = vec![rustls::pki_types::CertificateDer::from(
            certificate.cert.der().to_vec(),
        )];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()),
        );
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config");
        server_config.alpn_protocols = vec![b"daer-probe".to_vec()];

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accepts");
            let mut stream = acceptor.accept(stream).await.expect("server handshake");
            stream.write_all(b"ok").await.expect("writes");
        });

        let params = TlsParams {
            server_name: Some("localhost".to_owned()),
            allow_insecure: true,
            alpn: vec!["daer-probe".to_owned()],
            fingerprint: None,
        };
        let opaque = wrap(
            tokio::net::TcpStream::connect(address)
                .await
                .expect("connects"),
            &params,
            "localhost",
            &TraceCollector::disabled(),
            Duration::from_secs(2),
        )
        .await
        .expect("TLS handshake");
        assert_eq!(opaque.alpn.as_deref(), Some("daer-probe"));
        assert_eq!(
            opaque.alpn_protocol.as_deref(),
            Some(b"daer-probe".as_slice())
        );
        server.await.expect("server task");
    }
}
