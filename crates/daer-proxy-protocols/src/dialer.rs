// SPDX-License-Identifier: AGPL-3.0-only

//! Unified dialer dispatching across all supported proxy protocols.

use std::sync::{Arc, Mutex};

use netune::{DatagramConnector, Established};
use netune_trace::Recorder;

use crate::ProxyProtocol;
use crate::anytls::AnyTlsConnector;
use crate::error::ProxyProtocolError;
use crate::hysteria2::Hysteria2Connector;
use crate::options::DialerOptions;
use crate::reality::RealityConnector;
use crate::shadowsocks::ShadowSocksConnector;
use crate::trojan::TrojanConnector;

/// Unified proxy protocol dialer.
#[derive(Debug, Clone)]
pub enum ProxyDialer {
    ShadowSocks(ShadowSocksConnector),
    Trojan(TrojanConnector),
    AnyTls(AnyTlsConnector),
    Hysteria2(Hysteria2Connector),
    Reality(RealityConnector),
}

impl ProxyDialer {
    /// Builds a proxy dialer from a protocol link URI.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, ProxyProtocolError> {
        let link = link.trim();
        let Some((scheme, _)) = link.split_once("://") else {
            return Err(ProxyProtocolError::UnsupportedLink(format!(
                "{link:?} has no scheme"
            )));
        };

        if scheme.eq_ignore_ascii_case("ss") || scheme.eq_ignore_ascii_case("shadowsocks") {
            let connector = ShadowSocksConnector::from_link(link, options)?;
            return Ok(Self::ShadowSocks(connector));
        }
        if scheme.eq_ignore_ascii_case("trojan") || scheme.eq_ignore_ascii_case("trojan-go") {
            let connector = TrojanConnector::from_link(link, options)?;
            return Ok(Self::Trojan(connector));
        }
        if scheme.eq_ignore_ascii_case("anytls") {
            let connector = AnyTlsConnector::from_link(link, options)?;
            return Ok(Self::AnyTls(connector));
        }
        if scheme.eq_ignore_ascii_case("hysteria2") || scheme.eq_ignore_ascii_case("hy2") {
            let connector = Hysteria2Connector::from_link(link, options)?;
            return Ok(Self::Hysteria2(connector));
        }
        if scheme.eq_ignore_ascii_case("vless") {
            let connector = RealityConnector::from_link(link, options)?;
            return Ok(Self::Reality(connector));
        }

        Err(ProxyProtocolError::UnsupportedLink(format!(
            "unsupported proxy protocol scheme {scheme:?}"
        )))
    }

    /// Builds a proxy dialer from a typed `NodeEndpoint`.
    pub fn from_node(
        endpoint: &daer_config::NodeEndpoint,
        options: DialerOptions,
    ) -> Result<Self, ProxyProtocolError> {
        match endpoint {
            daer_config::NodeEndpoint::Shadowsocks(n) => {
                let connector =
                    ShadowSocksConnector::new(&n.server, n.port, &n.method, &n.password, options)?;
                Ok(Self::ShadowSocks(connector))
            }
            daer_config::NodeEndpoint::Trojan(n) => {
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
            daer_config::NodeEndpoint::AnyTls(n) => {
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
            daer_config::NodeEndpoint::Hysteria2(n) => {
                let connector = Hysteria2Connector::new(
                    crate::hysteria2::connector::Hysteria2Params {
                        server: &n.server,
                        port: n.port,
                        password: &n.password,
                        sni: n.sni.as_deref(),
                        allow_insecure: n.allow_insecure,
                        up_mbps: n.up_mbps,
                        down_mbps: n.down_mbps,
                        obfs: n.obfs.as_deref(),
                    },
                    options,
                )?;
                Ok(Self::Hysteria2(connector))
            }
            daer_config::NodeEndpoint::Vless(n) => {
                let reality = n.reality.as_ref().ok_or_else(|| {
                    ProxyProtocolError::UnsupportedLink(
                        "vless node requires [node.reality]".to_owned(),
                    )
                })?;
                let connector = RealityConnector::new(
                    crate::reality::connector::RealityEndpointParams {
                        server: &n.server,
                        port: n.port,
                        uuid: &n.uuid,
                        flow: n.flow.as_deref(),
                        sni: &reality.sni,
                        public_key: &reality.public_key,
                        short_id: reality.short_id.as_deref(),
                        fingerprint: reality.fingerprint.as_deref(),
                        alpn: &reality.alpn,
                    },
                    options,
                )?;
                Ok(Self::Reality(connector))
            }
            _ => Err(ProxyProtocolError::UnsupportedLink(
                "not a supported proxy protocol endpoint".to_owned(),
            )),
        }
    }

    /// The protocol variant this dialer executes.
    #[must_use]
    pub fn protocol(&self) -> ProxyProtocol {
        match self {
            Self::ShadowSocks(_) => ProxyProtocol::ShadowSocks,
            Self::Trojan(_) => ProxyProtocol::Trojan,
            Self::AnyTls(_) => ProxyProtocol::AnyTls,
            Self::Hysteria2(_) => ProxyProtocol::Hysteria2,
            Self::Reality(_) => ProxyProtocol::Reality,
        }
    }

    /// Connects to `authority` (`host:port`) using default recorder.
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
            Self::Reality(c) => c.connect(authority, recorder).await,
        }
    }

    /// Returns the shared datagram connector if supported by this protocol.
    #[must_use]
    pub fn datagram_connector(&self) -> Option<Arc<dyn DatagramConnector>> {
        match self {
            Self::ShadowSocks(_) => None,
            Self::Trojan(_) => None,
            Self::AnyTls(c) => Some(c.datagram_connector()),
            Self::Hysteria2(c) => Some(c.datagram_connector()),
            Self::Reality(_) => None,
        }
    }
}
