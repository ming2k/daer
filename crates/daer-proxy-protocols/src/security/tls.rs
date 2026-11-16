// SPDX-License-Identifier: AGPL-3.0-only

//! Ordinary TLS to the node (ADR-0028).
//!
//! # netune owns the handshake
//!
//! The [`TlsProfile`] is resolved from netune's preset registry, then driven by
//! [`netune::TlsRouterConnector`] (or [`netune_tls::OwnedTlsConnector`] with [`AcceptAny`] when
//! `allow-insecure = true`). That keeps the handshake, its timeout and its trace events in one
//! implementation; daer only decides the node's ALPN offer and certificate policy.
//!
//! netune's `NetuneDefault` preset offers `http/1.1` because its primary consumer is an HTTP
//! client. A `vless` node speaks no ALPN at all (or `h2`), and offering `http/1.1` to it is
//! a fingerprint the operator did not choose. Overriding `blueprint.alpn` via
//! [`TlsProfile::with_alpn`] expresses that difference without changing the rest of the
//! declarative `ClientHelloBlueprint` (cipher suites, groups, extensions).
//!
//! # Certificate policy
//!
//! Platform trust by default. `allow-insecure` is a real setting for a real situation (a
//! node with a self-signed certificate) and is honoured, but it is never a default: a
//! daemon that silently stopped verifying would be a vulnerability nobody configured.

use std::sync::Mutex;

use netune::{
    ConnectError, Connector, Established, NetError, Preset, ServerCertVerifier, Target, TlsProfile,
    TlsRouterConnector, Transport,
};
use netune_tls::{OwnedConnectParams, OwnedTlsConnector, ProtectorsKind};
use netune_trace::{
    Alpn, DiagnosticCode, DiagnosticPhase, DiagnosticRecord, EventKind, TraceCollector,
};

use crate::error::ProxyProtocolError;
use crate::security::Opaque;

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

/// Wraps `stream` in TLS within `deadline`.
///
/// `alpn` is the node's own list; when it is empty the profile's defaults are dropped too,
/// because a node that asked for no ALPN must receive no ALPN extension — offering one
/// would change the hello the operator configured.
pub(super) async fn wrap_until<S>(
    stream: S,
    params: &TlsParams,
    node_host: &str,
    recorder: &TraceCollector,
    deadline: tokio::time::Instant,
) -> Result<Opaque, ProxyProtocolError>
where
    S: Transport + 'static,
{
    let profile = profile_for(params)?;
    let server_name = params.sni(node_host).to_owned();
    let established = wrap_profile(
        stream,
        &profile,
        &server_name,
        params.allow_insecure,
        recorder,
        deadline,
    )
    .await?;

    // netune's TLS stream exposes no splice path, so there is nothing for a `Direct` command to
    // switch off here. A node that sends `Direct` on this layer is answered with `End` instead,
    // and Vision keeps unpadding — which is correct, and is why the switch is `None`.
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

/// Applies `profile` TLS handshake to an already-connected `stream` within `deadline`.
pub(crate) async fn wrap_profile<S>(
    stream: S,
    profile: &TlsProfile,
    server_name: &str,
    allow_insecure: bool,
    recorder: &TraceCollector,
    deadline: tokio::time::Instant,
) -> Result<Established, ProxyProtocolError>
where
    S: Transport + 'static,
{
    let remaining =
        ProxyProtocolError::remaining_until(deadline, daer_observe::DialStage::Tls, server_name)?;
    let target = Target::tls(server_name.to_owned(), server_name.to_owned());

    // The stream is already established: this connector wraps that single socket so netune's TLS
    // layer owns the ClientHello fingerprint, certificate verification, and trace events.
    // Verified mode sets `with_handshake_timeout(None)` and insecure mode runs `OwnedTlsConnector`
    // directly, so both modes share this single outer `deadline` and yield `DialStage::Tls` on
    // timeout rather than racing two timers.
    let connector =
        ProfiledTlsConnector::new(Preconnected::new(stream), profile.clone(), allow_insecure);
    match tokio::time::timeout(remaining, connector.connect(&target, recorder)).await {
        Ok(Ok(established)) => Ok(established),
        Ok(Err(error)) => {
            if error.is_timeout() {
                Err(ProxyProtocolError::timeout(
                    daer_observe::DialStage::Tls,
                    format!("TLS handshake with {server_name}: {error}"),
                ))
            } else {
                Err(ProxyProtocolError::tls(format!(
                    "TLS handshake with {server_name}: {error}"
                )))
            }
        }
        Err(_) => Err(ProxyProtocolError::timeout(
            daer_observe::DialStage::Tls,
            format!(
                "TLS handshake with {server_name} exceeded {} ms",
                remaining.as_millis()
            ),
        )),
    }
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
        S: Transport + 'static,
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
                NetError::Connect(ConnectError::config(
                    DiagnosticPhase::Tls,
                    "the TLS security layer was asked to connect twice for one stream",
                ))
            })?;
        Ok(Established::new(stream))
    }
}

/// The TLS identity this layer presents.
///
/// Split out so the invariant *"the trust setting does not change the identity"* is assertable
/// directly on [`TlsProfile`]'s declarative `ClientHelloBlueprint`.
fn profile_for(params: &TlsParams) -> Result<TlsProfile, ProxyProtocolError> {
    let profile = resolve_profile(params.fingerprint.as_deref())?;

    // A node that names no ALPN must offer no ALPN. `netune-default` offers `http/1.1`, which is
    // netune's own consumer's identity, not this node's.
    let alpn_slices: Vec<&[u8]> = params.alpn.iter().map(String::as_bytes).collect();
    Ok(profile.with_alpn(&alpn_slices))
}

/// Resolves a netune preset name (or the deployment default) to profile data.
///
/// A bare browser name is what every panel and every `fp=chrome` link says, while netune
/// registers the versioned `chrome-current`. Resolving the suffix is not leniency for its own
/// sake: an error here means the node cannot load at all, and the operator wrote the spelling
/// the rest of the ecosystem uses.
pub(crate) fn resolve_profile(fingerprint: Option<&str>) -> Result<TlsProfile, ProxyProtocolError> {
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
        None => Ok(Preset::NetuneDefault.profile()),
    }
}

/// A TLS connector that applies a resolved [`TlsProfile`] and trust policy (`allow_insecure`)
/// orthogonally.
///
/// When `allow_insecure` is `false`, [`TlsRouterConnector`] owns the handshake, PSK resumption,
/// and trace events. When `allow_insecure` is `true`, [`OwnedTlsConnector`] drives the exact
/// same `ClientHelloBlueprint` with [`AcceptAny`] so the trust setting never alters the wire
/// identity.
pub(crate) struct ProfiledTlsConnector<C: Connector> {
    mode: ProfiledTlsMode<C>,
    profile: TlsProfile,
}

enum ProfiledTlsMode<C: Connector> {
    Verified(TlsRouterConnector<C>),
    Insecure(C),
}

impl<C: Connector> ProfiledTlsConnector<C> {
    pub(crate) fn new(inner: C, profile: TlsProfile, allow_insecure: bool) -> Self {
        let mode = if allow_insecure {
            ProfiledTlsMode::Insecure(inner)
        } else {
            let router = TlsRouterConnector::new(inner)
                .with_profile_named(profile.name, profile.clone())
                .with_handshake_timeout(None);
            ProfiledTlsMode::Verified(router)
        };
        Self { mode, profile }
    }
}

impl<C: Connector> Connector for ProfiledTlsConnector<C> {
    fn socket_shape(&self) -> Option<String> {
        match &self.mode {
            ProfiledTlsMode::Verified(router) => router.socket_shape(),
            ProfiledTlsMode::Insecure(inner) => inner.socket_shape(),
        }
    }

    fn route_shape(&self) -> Option<String> {
        match &self.mode {
            ProfiledTlsMode::Verified(router) => router.route_shape(),
            ProfiledTlsMode::Insecure(inner) => inner.route_shape(),
        }
    }

    async fn connect(
        &self,
        target: &Target,
        recorder: &TraceCollector,
    ) -> Result<Established, NetError> {
        match &self.mode {
            ProfiledTlsMode::Verified(router) => {
                if target.tls_server_name().is_some() {
                    let routed = target.clone().with_tls_profile(self.profile.name);
                    router.connect(&routed, recorder).await
                } else {
                    router.connect(target, recorder).await
                }
            }
            ProfiledTlsMode::Insecure(inner) => {
                let established = inner.connect(target, recorder).await?;
                let Some(server_name) = target.tls_server_name().map(str::to_owned) else {
                    return Ok(established);
                };
                recorder.mark(EventKind::TlsStart, 0, 0);
                let (hello, shares) = self.profile.connect_params(&server_name)?;
                let stream = OwnedTlsConnector
                    .connect(
                        established.stream,
                        OwnedConnectParams { hello, shares },
                        AcceptAny,
                    )
                    .await
                    .map_err(|error| {
                        let message = format!("TLS handshake with {server_name}: {error}");
                        recorder.record_error(
                            DiagnosticRecord::new(DiagnosticCode::EGRESS_TLS_FAILED)
                                .with_phase(DiagnosticPhase::Tls)
                                .with_message(message.clone()),
                        );
                        NetError::Connect(ConnectError::tls(&server_name, message))
                    })?;

                let alpn = match stream.alpn() {
                    Some(b"http/1.1") => Alpn::Http11,
                    Some(b"h2") => Alpn::H2,
                    _ => Alpn::Unknown,
                };
                let alpn_protocol = stream.alpn().map(<[u8]>::to_vec);
                let version_code = match stream.protectors_kind() {
                    ProtectorsKind::Tls13 => 13u32,
                    ProtectorsKind::Tls12 => 12u32,
                };
                recorder.mark(EventKind::TlsEnd, 0, 0);
                recorder.mark(EventKind::TlsInfo, u32::from(alpn.code()), version_code);

                Ok(Established::new(Box::new(stream))
                    .with_local_port(established.local_port)
                    .with_socket(established.socket)
                    .with_alpn(Some(alpn), alpn_protocol))
            }
        }
    }
}

/// Accepts any certificate chain.
///
/// Reached only through `node.security.allow-insecure = true`, which is a decision an
/// operator writes down. The name says what it does so a reviewer cannot miss it.
#[derive(Debug, Clone, Copy)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_chain(
        &mut self,
        _server_name: &str,
        _end_entity: &[u8],
        _intermediates: &[Vec<u8>],
    ) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

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
        let profile = profile_for(&params).expect("builds");
        assert!(
            profile.blueprint.alpn.is_empty(),
            "offered {:?}",
            profile.blueprint.alpn
        );

        // The control: an explicit list survives verbatim and in order.
        let params = TlsParams {
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            ..params
        };
        let profile = profile_for(&params).expect("builds");
        assert_eq!(
            profile.blueprint.alpn,
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
        assert_eq!(
            bare.blueprint.cipher_suites,
            versioned.blueprint.cipher_suites
        );
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
        let error = profile_for(&params).expect_err("typo must fail");
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
            secure_profile.blueprint.cipher_suites, insecure_profile.blueprint.cipher_suites,
            "the suite allowlist is the profile's, in both arms"
        );
        assert_eq!(
            secure_profile.blueprint.supported_groups, insecure_profile.blueprint.supported_groups,
            "the group allowlist is the profile's, in both arms"
        );
        assert_eq!(
            secure_profile.blueprint.alpn, insecure_profile.blueprint.alpn,
            "ALPN must not depend on the trust setting"
        );
        assert_eq!(
            secure_profile.blueprint, insecure_profile.blueprint,
            "the full ClientHello blueprint must be identical regardless of allow_insecure"
        );

        // And the control: `chrome-current` really is the named preset and not the deployment
        // default.
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
            plain.blueprint.alpn, insecure_profile.blueprint.alpn,
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
        let profile = resolve_profile(Some("chrome")).expect("profile resolves");
        let preset = Preset::by_name("chrome-current").expect("preset");
        assert_eq!(
            profile.blueprint.alpn,
            preset.profile().blueprint.alpn,
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
        let result = wrap_until(
            netune::Untapped(
                tokio::net::TcpStream::connect(address)
                    .await
                    .expect("connects"),
            ),
            &params,
            "localhost",
            &TraceCollector::disabled(),
            tokio::time::Instant::now() + Duration::from_millis(50),
        )
        .await;
        assert!(
            matches!(
                result,
                Err(ProxyProtocolError::Timeout {
                    stage: daer_observe::DialStage::Tls,
                    ..
                })
            ),
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
        let mut opaque = wrap_until(
            netune::Untapped(
                tokio::net::TcpStream::connect(address)
                    .await
                    .expect("connects"),
            ),
            &params,
            "localhost",
            &TraceCollector::disabled(),
            tokio::time::Instant::now() + Duration::from_secs(2),
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
        let opaque = wrap_until(
            netune::Untapped(
                tokio::net::TcpStream::connect(address)
                    .await
                    .expect("connects"),
            ),
            &params,
            "localhost",
            &TraceCollector::disabled(),
            tokio::time::Instant::now() + Duration::from_secs(2),
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
