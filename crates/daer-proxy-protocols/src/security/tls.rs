// SPDX-License-Identifier: AGPL-3.0-only

//! Ordinary TLS to the node (ADR-0028).
//!
//! # Why daer builds this `ClientConfig` instead of calling netune's connector
//!
//! netune's [`TlsConnector`](netune::TlsConnector) fixes ALPN to `http/1.1`, because its
//! consumer is an HTTP client. A `vless` node speaks no ALPN at all (or `h2`), and offering
//! `http/1.1` to it is a fingerprint the operator did not choose — so the config is built
//! here, where the ALPN is known, and the *profile* (cipher suites, groups, extension order)
//! still comes from netune's registry so one deployment presents one identity.
//!
//! # Certificate policy
//!
//! Platform trust by default. `allow-insecure` is a real setting for a real situation (a
//! node with a self-signed certificate) and is honoured, but it is never a default: a
//! daemon that silently stopped verifying would be a vulnerability nobody configured.

use std::sync::Arc;
use std::time::Duration;

use netune::{Preset, TlsProfile, Verifier};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

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
    timeout: Duration,
) -> Result<Opaque, ProxyProtocolError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let config = build_config(params)?;
    let server_name = params.sni(node_host).to_owned();
    let name = rustls::pki_types::ServerName::try_from(server_name.clone()).map_err(|error| {
        ProxyProtocolError::Connect(format!("TLS server name {server_name:?}: {error}"))
    })?;

    let connector = TlsConnector::from(config);
    let stream = tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .map_err(|_| ProxyProtocolError::Timeout)?
        .map_err(|error| {
            ProxyProtocolError::Connect(format!("TLS handshake with {server_name}: {error}"))
        })?;

    let negotiated = stream
        .get_ref()
        .1
        .alpn_protocol()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::to_owned);
    // rustls exposes no splice path, so there is nothing for a `Direct` command to switch
    // off here. A node that sends `Direct` on this layer is answered with `End` instead, and
    // Vision keeps unpadding — which is correct, and is why the switch is `None`.
    Ok(Opaque {
        stream: Box::new(stream),
        raw_read: None,
        alpn: negotiated,
    })
}

/// Compiles the profile and the node's ALPN into one client config.
/// The TLS identity this layer presents.
///
/// Split out from [`build_config`] so the invariant *"the trust setting does not change the
/// identity"* is assertable: `TlsProfile` exposes its suites, groups and ALPN, while
/// `rustls::ClientConfig` exposes none of them. Testing it through the config would have meant
/// asserting nothing.
fn profile_for(params: &TlsParams) -> Result<TlsProfile, ProxyProtocolError> {
    let mut profile = match &params.fingerprint {
        Some(name) => {
            let preset = Preset::by_name(name)
                // A bare browser name is what every panel and every `fp=chrome` link says, while
                // netune registers the versioned `chrome-current`. Resolving the suffix is not
                // leniency for its own sake: an error here means the node cannot load at all, and
                // the operator wrote the spelling the rest of the ecosystem uses.
                .or_else(|| Preset::by_name(&format!("{name}-current")))
                .ok_or_else(|| {
                    let known: Vec<&str> =
                        Preset::all().iter().map(|preset| preset.name()).collect();
                    ProxyProtocolError::UnsupportedLink(format!(
                        "node.security.fingerprint = {name:?} is not a netune TLS preset; the \
                         registered names are {known:?}"
                    ))
                })?;
            preset.profile()
        }
        None => TlsProfile::netune_default(),
    };

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

/// Compiles the profile into one client config.
fn build_config(params: &TlsParams) -> Result<Arc<rustls::ClientConfig>, ProxyProtocolError> {
    let provider = crypto_provider();
    let profile = profile_for(params)?;
    let built = profile.build(Arc::clone(&provider)).map_err(|error| {
        ProxyProtocolError::Connect(format!("TLS profile {:?}: {error}", profile.name))
    })?;
    let mut config = (*built).clone();
    if params.allow_insecure {
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
}
