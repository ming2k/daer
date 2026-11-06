// SPDX-License-Identifier: AGPL-3.0-only

//! Unified dialer dispatching across all supported proxy protocols.
//!
//! # One entry point per direction
//!
//! [`ProxyDialer::from_link`] and [`ProxyDialer::from_node`] are the whole public surface for
//! constructing a session (ADR-0028). Everything below them — a handshake, a header codec, a
//! socket wrapper — is reachable only from a parsed node, which is what keeps a configuration
//! from reaching a layer it did not ask for.

use std::sync::{Arc, Mutex};

use netune::{DatagramConnector, Established};
use netune_trace::Recorder;

use crate::ProxyProtocol;
use crate::anytls::AnyTlsConnector;
use crate::error::ProxyProtocolError;
use crate::hysteria2::Hysteria2Connector;
use crate::options::DialerOptions;
use crate::security::Security;
use crate::shadowsocks::ShadowSocksConnector;
use crate::transport::TransportLayer;
use crate::trojan::TrojanConnector;
use crate::vless::VlessConnector;
use crate::vmess::VmessConnector;

/// Unified proxy protocol dialer.
#[derive(Debug, Clone)]
pub enum ProxyDialer {
    ShadowSocks(ShadowSocksConnector),
    Trojan(TrojanConnector),
    AnyTls(AnyTlsConnector),
    Hysteria2(Hysteria2Connector),
    Vless(VlessConnector),
    Vmess(VmessConnector),
}

impl ProxyDialer {
    /// Builds a proxy dialer from a protocol link URI.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, ProxyProtocolError> {
        Self::from_node(
            &daer_config::NodeEndpoint::from_link(link)
                .map_err(ProxyProtocolError::UnsupportedLink)?,
            options,
        )
    }

    /// Builds a proxy dialer from a typed `NodeEndpoint`.
    ///
    /// One function, one place where a layer is resolved, so there is no second copy of the
    /// mapping that can drift (the `config_keys` gate exists for the same reason).
    pub fn from_node(
        endpoint: &daer_config::NodeEndpoint,
        options: DialerOptions,
    ) -> Result<Self, ProxyProtocolError> {
        use daer_config::NodeEndpoint;

        // Parse and support are different questions, and `NodeEndpoint::from_link` answers only
        // the first on purpose: a subscription's unusable link must still enter the pool so the
        // generation builder can report it by name. A *dialer* is the second question, so it
        // validates first — and the refusal names the field.
        endpoint
            .validate()
            .map_err(ProxyProtocolError::UnsupportedLink)?;

        match endpoint {
            NodeEndpoint::Shadowsocks(n) => {
                let connector =
                    ShadowSocksConnector::new(&n.server, n.port, &n.method, &n.password, options)?;
                Ok(Self::ShadowSocks(connector))
            }
            NodeEndpoint::Trojan(n) => {
                let connector = TrojanConnector::new(
                    &n.server,
                    n.port,
                    &n.password,
                    n.sni.as_deref(),
                    n.allow_insecure,
                    options,
                )?;
                Ok(Self::Trojan(connector))
            }
            NodeEndpoint::AnyTls(n) => {
                let connector = AnyTlsConnector::new(
                    &n.server,
                    n.port,
                    &n.password,
                    n.sni.as_deref(),
                    n.allow_insecure,
                    n.idle_sessions,
                    options,
                )?;
                Ok(Self::AnyTls(connector))
            }
            NodeEndpoint::Hysteria2(n) => {
                let connector = Hysteria2Connector::new(
                    crate::hysteria2::connector::Hysteria2Params {
                        server: &n.server,
                        ports: &n.ports,
                        password: &n.password,
                        sni: n.sni.as_deref(),
                        allow_insecure: n.allow_insecure,
                        pin_sha256: n.pin_sha256.as_deref(),
                        up_mbps: n.up_mbps,
                        down_mbps: n.down_mbps,
                        obfs: n.obfs.as_ref(),
                        congestion: n.congestion,
                        quic: &n.quic,
                    },
                    options,
                )?;
                Ok(Self::Hysteria2(connector))
            }
            NodeEndpoint::Vless(n) => {
                let connector = VlessConnector::new(
                    crate::vless::connector::VlessParams {
                        server: &n.server,
                        port: n.port,
                        uuid: &n.uuid,
                        flow: match n.flow {
                            daer_config::Flow::None => crate::vless::Flow::None,
                            daer_config::Flow::Vision => crate::vless::Flow::Vision,
                            // The suffix is the *server's* account setting; the client encodes the
                            // same addons. Keeping the variant means `check --nodes` reports the
                            // flow the operator wrote rather than silently flattening it.
                            daer_config::Flow::VisionUdp443 => crate::vless::Flow::VisionUdp443,
                        },
                        security: security_of(&n.security)?,
                        transport: transport_of(&n.transport),
                    },
                    options,
                )?;
                Ok(Self::Vless(connector))
            }
            NodeEndpoint::Vmess(n) => {
                let connector = VmessConnector::new(
                    crate::vmess::connector::VmessParams {
                        server: &n.server,
                        port: n.port,
                        uuid: &n.uuid,
                        cipher: n.cipher,
                        authenticated_length: n.authenticated_length,
                        no_termination_signal: n.no_termination_signal,
                        security: security_of(&n.security)?,
                        transport: transport_of(&n.transport),
                    },
                    options,
                )?;
                Ok(Self::Vmess(connector))
            }
            NodeEndpoint::Direct(_) => Err(ProxyProtocolError::UnsupportedLink(
                "a direct node has no proxy protocol".to_owned(),
            )),
            NodeEndpoint::Socks5(_) | NodeEndpoint::Http(_) => {
                Err(ProxyProtocolError::UnsupportedLink(
                    "a socks5/http node is a netune connector, not a proxy protocol".to_owned(),
                ))
            }
            NodeEndpoint::Unsupported { scheme, .. } => Err(ProxyProtocolError::UnsupportedLink(
                format!("unsupported proxy protocol scheme {scheme:?}"),
            )),
        }
    }

    /// The protocol variant this dialer executes.
    #[must_use]
    pub const fn protocol(&self) -> ProxyProtocol {
        match self {
            Self::ShadowSocks(_) => ProxyProtocol::ShadowSocks,
            Self::Trojan(_) => ProxyProtocol::Trojan,
            Self::AnyTls(_) => ProxyProtocol::AnyTls,
            Self::Hysteria2(_) => ProxyProtocol::Hysteria2,
            Self::Vless(_) => ProxyProtocol::Vless,
            Self::Vmess(_) => ProxyProtocol::Vmess,
        }
    }

    /// Connects to `authority` (`host:port`) using a throwaway recorder.
    pub async fn connect(&self, authority: &str) -> Result<Established, ProxyProtocolError> {
        let recorder = Arc::new(Mutex::new(Recorder::start(16)));
        self.connect_with_recorder(authority, &recorder).await
    }

    /// Connects to `authority` (`host:port`) with the given trace recorder.
    pub async fn connect_with_recorder(
        &self,
        authority: &str,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<Established, ProxyProtocolError> {
        match self {
            Self::ShadowSocks(c) => c.connect(authority, recorder).await,
            Self::Trojan(c) => c.connect(authority, recorder).await,
            Self::AnyTls(c) => c.connect(authority, recorder).await,
            Self::Hysteria2(c) => c.connect(authority, recorder).await,
            Self::Vless(c) => c.connect(authority, recorder).await,
            Self::Vmess(c) => c.connect(authority, recorder).await,
        }
    }

    /// Returns the datagram connector if this protocol carries UDP.
    ///
    /// `None` is a fact about the protocol, not a failure: shadowsocks AEAD and trojan in
    /// this build are stream-only, and a caller that asks must be told so rather than
    /// handed a connector that would silently drop packets.
    #[must_use]
    pub fn datagram_connector(&self) -> Option<Arc<dyn DatagramConnector>> {
        match self {
            Self::ShadowSocks(_) => None,
            Self::Trojan(_) => None,
            Self::AnyTls(c) => Some(c.datagram_connector()),
            Self::Hysteria2(c) => Some(c.datagram_connector()),
            Self::Vless(c) => Some(c.datagram_connector()),
            Self::Vmess(c) => Some(c.datagram_connector()),
        }
    }
}

/// Lowers the configuration's security layer onto the crate's (ADR-0028).
pub(crate) fn security_of(
    security: &daer_config::SecurityConfig,
) -> Result<Security, ProxyProtocolError> {
    use daer_config::SecurityConfig;

    match security {
        SecurityConfig::None {} => Ok(Security::None),
        SecurityConfig::Tls(tls) => Ok(Security::Tls(crate::security::tls::TlsParams {
            server_name: tls.sni.clone(),
            allow_insecure: tls.allow_insecure,
            alpn: tls.alpn.clone(),
            fingerprint: tls.fingerprint.clone(),
        })),
        SecurityConfig::Reality(reality) => {
            let public_key = crate::reality::decode_public_key(&reality.public_key)
                .map_err(ProxyProtocolError::UnsupportedLink)?;
            let short_id = match reality.short_id.as_deref() {
                Some(short_id) if !short_id.is_empty() => crate::reality::decode_short_id(short_id)
                    .map_err(ProxyProtocolError::UnsupportedLink)?,
                _ => Vec::new(),
            };
            Ok(Security::Reality(
                crate::security::reality::RealitySecurity::new(
                    crate::security::reality::RealityParams {
                        server_name: reality.sni.clone(),
                        public_key,
                        short_id,
                        alpn: reality
                            .alpn
                            .iter()
                            .map(|protocol| protocol.as_bytes().to_vec())
                            .collect(),
                    },
                ),
            ))
        }
    }
}

/// Lowers the configuration's transport layer onto the crate's (ADR-0028).
pub(crate) fn transport_of(transport: &daer_config::TransportConfig) -> TransportLayer {
    use daer_config::TransportConfig;

    match transport {
        TransportConfig::Tcp => TransportLayer::Tcp,
        TransportConfig::Ws(ws) => TransportLayer::Ws(crate::transport::WsParams {
            path: ws.path.clone(),
            host: ws.host.clone(),
            headers: ws
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        }),
    }
}
