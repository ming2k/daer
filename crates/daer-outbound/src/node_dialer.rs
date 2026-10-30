// SPDX-License-Identifier: AGPL-3.0-only

//! Transport dialers for one node: direct, SOCKS5 or HTTP CONNECT.
//!
//! The proxy handshakes are netune's `ProxyConnector`; this module only decides
//! which one a node link asks for and applies daer's socket options.
//!
//! Supported schemes:
//!
//! * `direct` (or an empty link)
//! * `socks5://[user:pass@]host:port` (also `socks5h://`, `socks://`)
//! * `http://[user:pass@]host:port`
//! * `ss://…` (shadowsocks AEAD; see [`crate::shadowsocks`])
//! * `trojan://…` (see [`crate::trojan`])
//!
//! `https://` is rejected: it means TLS *to the proxy*, and netune's HTTP
//! CONNECT connector reaches the proxy over plaintext. Silently downgrading
//! would put proxy credentials on the wire in clear text.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune::{
    Connector, DatagramConnector, Established, Proxy, ProxyConnector, SocketConfig,
    Socks5DatagramConnector, Target, TcpConnector, UdpConnector,
};
use netune_trace::Recorder;

use crate::anytls::AnyTlsConnector;
use crate::error::OutboundError;
use crate::hysteria2::Hysteria2Connector;
use crate::property::Protocol;
use crate::reality::connector::RealityConnector;
use crate::shadowsocks::ShadowSocksConnector;
use crate::trojan::TrojanConnector;

/// Socket options and deadlines shared by every node dialer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialerOptions {
    /// `SO_MARK`, applied before `connect(2)`.
    pub so_mark: Option<u32>,
    pub timeout: Duration,
    /// `[global.tls] profile`: a netune preset name, used by every outbound that rides netune's
    /// TLS stack (`trojan`, and any future TLS-based connector).
    ///
    /// Carried here rather than read per connector because the profile is a property of the
    /// *deployment*: one daemon presents one ClientHello identity, and two nodes of the same
    /// deployment disagreeing about it would be a fingerprint leak in its own right.
    ///
    /// `None` keeps netune's default identity. A name that is not a registered preset is a
    /// **load-time** error (`DialerOptions::with_tls_profile`), because a silently different
    /// ClientHello defeats the point of configuring one.
    pub tls_profile: Option<&'static str>,
    /// `[global.tls] fragment`: slice a handshake daer owns. Only a REALITY session qualifies,
    /// because a `trojan://` node's ClientHello is written by netune inside its own connector.
    pub fragment: Option<crate::fragment::Fragment>,
}

impl DialerOptions {
    pub fn new(so_mark: Option<u32>, timeout: Duration) -> Self {
        Self {
            so_mark,
            timeout,
            tls_profile: None,
            fragment: None,
        }
    }

    /// Sets the ClientHello fragmentation plan.
    #[must_use]
    pub fn with_fragment(mut self, fragment: Option<crate::fragment::Fragment>) -> Self {
        self.fragment = fragment;
        self
    }

    /// Sets the TLS fingerprint profile, resolving it against netune's registry.
    ///
    /// # Errors
    ///
    /// Returns the name and the accepted set when it is not a registered preset, so a typo is a
    /// load-time error that lists the alternatives rather than a handshake that fails on the wire
    /// for a reason no log attributes to the profile.
    pub fn with_tls_profile(mut self, name: &str) -> Result<Self, OutboundError> {
        let Some(preset) = crate::Preset::by_name(name) else {
            let known: Vec<&str> = crate::Preset::all()
                .iter()
                .map(|preset| preset.name())
                .collect();
            return Err(OutboundError::UnsupportedLink(format!(
                "global.tls.profile = {name:?} is not a netune TLS preset; the registered names \
                 are {known:?}"
            )));
        };
        self.tls_profile = Some(preset.name());
        Ok(self)
    }

    /// The socket options this dialer would apply.
    ///
    /// Public because a datagram leg has to be configured identically: a mark or a
    /// buffer size that applied to one transport and not the other would make the
    /// two legs of the same proxy behave differently.
    #[must_use]
    pub fn socket_config(self) -> SocketConfig {
        match self.so_mark {
            Some(mark) => SocketConfig::default().with_mark(mark),
            None => SocketConfig::default(),
        }
    }
}

/// A node's transport.
pub enum NodeDialer {
    Direct(DirectTransport),
    Proxy(ProxyTransport),
    ShadowSocks(ShadowSocksTransport),
    Trojan(TrojanTransport),
    AnyTls(AnyTlsTransport),
    Hysteria2(Hysteria2Transport),
    Reality(RealityTransport),
}

impl fmt::Debug for NodeDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(dialer) => f.debug_tuple("Direct").field(dialer).finish(),
            Self::Proxy(dialer) => f.debug_tuple("Proxy").field(dialer).finish(),
            Self::ShadowSocks(dialer) => f.debug_tuple("ShadowSocks").field(dialer).finish(),
            Self::Trojan(dialer) => f.debug_tuple("Trojan").field(dialer).finish(),
            Self::AnyTls(dialer) => f.debug_tuple("AnyTls").field(dialer).finish(),
            Self::Hysteria2(dialer) => f.debug_tuple("Hysteria2").field(dialer).finish(),
            Self::Reality(dialer) => f.debug_tuple("Reality").field(dialer).finish(),
        }
    }
}

/// The first hop's scheme when `link` is a chain, or `None` for a single link.
///
/// A chain is spelled `scheme://… -> scheme://…`. The separator is looked for
/// outside the link's authority so a `->` inside a query string cannot be mistaken
/// for one — but a link that contains the separator anywhere in its path or query
/// is far more likely to be a chain than a coincidence, so the check is deliberately
/// conservative: any top-level ` -> ` between two scheme prefixes counts.
fn chain_head_scheme(link: &str) -> Option<&str> {
    let (head, rest) = link.split_once("->")?;
    // Both sides must look like a link for this to be a chain rather than a literal.
    if !rest.contains("://") {
        return None;
    }
    head.split_once("://").map(|(scheme, _)| scheme)
}

impl NodeDialer {
    /// Builds the transport directly from a typed configuration [`daer_config::Node`].
    pub fn from_node(
        node: &daer_config::Node,
        options: DialerOptions,
    ) -> Result<Self, OutboundError> {
        match &node.endpoint {
            daer_config::NodeEndpoint::Direct(_) => Ok(Self::Direct(DirectTransport::new(options))),
            daer_config::NodeEndpoint::Socks5(n) => {
                let link = n.to_link();
                let proxy = Proxy::parse(&link)
                    .map_err(|e| OutboundError::UnsupportedLink(e.to_string()))?;
                Ok(Self::Proxy(ProxyTransport::new(proxy, options)))
            }
            daer_config::NodeEndpoint::Http(n) => {
                let link = n.to_link();
                let proxy = Proxy::parse(&link)
                    .map_err(|e| OutboundError::UnsupportedLink(e.to_string()))?;
                Ok(Self::Proxy(ProxyTransport::new(proxy, options)))
            }
            daer_config::NodeEndpoint::Shadowsocks(n) => {
                let connector =
                    ShadowSocksConnector::new(&n.server, n.port, &n.method, &n.password, options)?;
                Ok(Self::ShadowSocks(ShadowSocksTransport { connector }))
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
                Ok(Self::Trojan(TrojanTransport { connector }))
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
                Ok(Self::AnyTls(AnyTlsTransport { connector }))
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
                Ok(Self::Hysteria2(Hysteria2Transport { connector }))
            }
            daer_config::NodeEndpoint::Vless(n) => {
                let reality = n.reality.as_ref().ok_or_else(|| {
                    OutboundError::UnsupportedLink("vless node requires [node.reality]".to_owned())
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
                Ok(Self::Reality(RealityTransport { connector }))
            }
            daer_config::NodeEndpoint::Unsupported { scheme, .. } => Err(
                OutboundError::UnsupportedLink(format!("unsupported protocol {scheme:?}")),
            ),
        }
    }

    /// Builds the transport a node link describes.
    ///
    /// # Chains
    ///
    /// A link may name a chain (`a -> b`), and this build does not implement one.
    /// That is rejected **loudly** rather than silently truncated to its first hop:
    /// an operator who writes `socks5://a -> socks5://b` and gets a working
    /// connection believes traffic takes two hops when it takes one, and that
    /// misbelief is a traffic-analysis and blame-attribution error that no log
    /// would ever reveal.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, OutboundError> {
        let link = link.trim();
        if link.is_empty() || link == "direct" {
            return Ok(Self::Direct(DirectTransport::new(options)));
        }

        if let Some(scheme) = chain_head_scheme(link) {
            return Err(OutboundError::UnsupportedLink(format!(
                "chained links (`a -> b`) are not implemented; {scheme:?} is the first hop \
                 of a chain this build would otherwise silently ignore"
            )));
        }

        let Some((scheme, _)) = link.split_once("://") else {
            return Err(OutboundError::UnsupportedLink(format!(
                "{link:?} has no scheme"
            )));
        };

        // Protocols with their own handshake get their own connector: none of them is a
        // CONNECT-style proxy, so routing them through netune's `Proxy` would misread the
        // link.
        if scheme.eq_ignore_ascii_case("ss") || scheme.eq_ignore_ascii_case("shadowsocks") {
            let connector = ShadowSocksConnector::from_link(link, options)?;
            return Ok(Self::ShadowSocks(ShadowSocksTransport { connector }));
        }
        if scheme.eq_ignore_ascii_case("trojan") || scheme.eq_ignore_ascii_case("trojan-go") {
            let connector = TrojanConnector::from_link(link, options)?;
            return Ok(Self::Trojan(TrojanTransport { connector }));
        }
        if scheme.eq_ignore_ascii_case("anytls") {
            let connector = AnyTlsConnector::from_link(link, options)?;
            return Ok(Self::AnyTls(AnyTlsTransport { connector }));
        }
        if scheme.eq_ignore_ascii_case("hysteria2") || scheme.eq_ignore_ascii_case("hy2") {
            let connector = Hysteria2Connector::from_link(link, options)?;
            return Ok(Self::Hysteria2(Hysteria2Transport { connector }));
        }
        // `vless://` is REALITY-only in this build. A plain `security=tls` vless link is
        // refused by `RealityConnector::from_link` with that reason rather than being sent
        // somewhere it would not work.
        if scheme.eq_ignore_ascii_case("vless") {
            let connector = RealityConnector::from_link(link, options)?;
            return Ok(Self::Reality(RealityTransport { connector }));
        }

        let (link_clean, _fragment) = match link.split_once('#') {
            Some((before, frag)) => (before, Some(frag)),
            None => (link, None),
        };

        let normalized = match scheme.to_ascii_lowercase().as_str() {
            "socks" | "socks5" | "socks5h" => {
                format!("socks5://{}", &link_clean[scheme.len() + 3..])
            }
            "http" => link_clean.to_owned(),
            "https" => {
                return Err(OutboundError::UnsupportedLink(
                    "https proxies (TLS to the proxy) are not supported yet; \
                     use http:// or socks5://"
                        .to_owned(),
                ));
            }
            other => {
                return Err(OutboundError::UnsupportedLink(format!(
                    "unsupported protocol {other:?}"
                )));
            }
        };

        let proxy = Proxy::parse(&normalized)
            .map_err(|error| OutboundError::UnsupportedLink(error.to_string()))?;
        Ok(Self::Proxy(ProxyTransport::new(proxy, options)))
    }

    /// Opens a TCP connection to `authority` (`host:port`).
    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        match self {
            Self::Direct(dialer) => dialer.connect(authority).await,
            Self::Proxy(dialer) => dialer.connect(authority).await,
            Self::ShadowSocks(dialer) => dialer.connect(authority).await,
            Self::Trojan(dialer) => dialer.connect(authority).await,
            Self::AnyTls(dialer) => dialer.connect(authority).await,
            Self::Hysteria2(dialer) => dialer.connect(authority).await,
            Self::Reality(dialer) => dialer.connect(authority).await,
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            Self::Direct(_) => Protocol::Direct,
            Self::Proxy(dialer) => dialer.protocol(),
            Self::ShadowSocks(_) => Protocol::ShadowSocks,
            Self::Trojan(_) => Protocol::Trojan,
            Self::AnyTls(_) => Protocol::AnyTls,
            Self::Hysteria2(_) => Protocol::Hysteria2,
            Self::Reality(_) => Protocol::Reality,
        }
    }

    /// A short identity for diagnostics.
    ///
    /// The routing generation reports which node a flow was sent to; that needs a name,
    /// not the transport.
    #[must_use]
    pub fn describe(&self) -> Protocol {
        self.protocol()
    }

    /// The datagram connector for this node, or `None` when this build cannot
    /// carry datagrams through it.
    ///
    /// Returning `Option` rather than a connector that fails on first use keeps the
    /// limitation at the decision point: a UDP flow routed to a node that cannot
    /// carry it must be refused *before* a session is opened, otherwise the client
    /// sees a silent black hole instead of an error.
    ///
    /// What is supported, and why:
    ///
    /// * **direct** — netune's [`UdpConnector`], which has no protocol of its own.
    /// * **socks5** — `Socks5DatagramConnector`. The destination must be a literal
    ///   address; a domain is refused by the connector with a reason rather than
    ///   resolved locally (see netune ADR-0008).
    ///
    /// What is not, and why it is not merely unimplemented:
    ///
    /// * **shadowsocks** — the AEAD stream construction has no datagram framing
    ///   here; the UDP form is a separate encapsulation, not a flag on the stream.
    /// * **trojan** — Trojan's UDP framing rides the same TCP tunnel and is another
    ///   packet format to implement.
    /// * **http/https** — `CONNECT` tunnels TCP only; there is no UDP associate to
    ///   expose.
    ///
    /// [`UdpConnector`]: netune::UdpConnector
    #[must_use]
    pub fn datagram(&self) -> Option<Arc<dyn DatagramConnector>> {
        match self {
            Self::Direct(dialer) => Some(Arc::new(dialer.datagram_connector())),
            Self::Proxy(dialer) => dialer.datagram_connector(),
            Self::Reality(dialer) => Some(dialer.datagram_connector()),
            Self::Trojan(dialer) => Some(dialer.datagram_connector()),
            Self::AnyTls(dialer) => Some(dialer.datagram_connector()),
            Self::Hysteria2(dialer) => Some(dialer.datagram_connector()),
            Self::ShadowSocks(dialer) => Some(dialer.datagram_connector()),
        }
    }
}

/// A Hysteria 2 node.
pub struct Hysteria2Transport {
    connector: Hysteria2Connector,
}

impl fmt::Debug for Hysteria2Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2Transport")
            .field("server", &self.connector.server())
            .field("server_name", &self.connector.server_name())
            .finish()
    }
}

impl Hysteria2Transport {
    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));
        self.connector.connect(authority, &recorder).await
    }

    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        self.connector.datagram_connector()
    }
}

/// An AnyTLS node.
pub struct AnyTlsTransport {
    connector: AnyTlsConnector,
}

impl fmt::Debug for AnyTlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyTlsTransport")
            .field("server", &self.connector.server())
            .field("server_name", &self.connector.server_name())
            .finish()
    }
}

impl AnyTlsTransport {
    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));
        self.connector.connect(authority, &recorder).await
    }

    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        self.connector.datagram_connector()
    }
}

/// A Trojan node.
pub struct TrojanTransport {
    connector: TrojanConnector,
}

impl fmt::Debug for TrojanTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanTransport")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl TrojanTransport {
    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));
        self.connector.connect(authority, &recorder).await
    }

    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        self.connector.datagram_connector()
    }
}

/// A REALITY node.
pub struct RealityTransport {
    connector: RealityConnector,
}

impl fmt::Debug for RealityTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityTransport")
            .field("server", &self.connector.link().server())
            .field("impersonating", &self.connector.link().server_name())
            .finish()
    }
}

impl RealityTransport {
    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));
        self.connector.connect(authority, &recorder).await
    }

    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        self.connector.datagram_connector()
    }
}

/// A shadowsocks node.
pub struct ShadowSocksTransport {
    connector: ShadowSocksConnector,
}

impl fmt::Debug for ShadowSocksTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowSocksTransport")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl ShadowSocksTransport {
    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));
        self.connector.connect(authority, &recorder).await
    }

    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        self.connector.datagram_connector()
    }
}

pub struct DirectTransport {
    connector: TcpConnector,
    timeout: Duration,
    /// Kept so the datagram leg is configured exactly like the stream leg; a mark
    /// that applied to TCP but not UDP would let a proxy capture its own traffic.
    socket_config: SocketConfig,
}

impl fmt::Debug for DirectTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectTransport")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl DirectTransport {
    pub fn new(options: DialerOptions) -> Self {
        Self {
            connector: TcpConnector::new()
                .with_socket_config(options.socket_config())
                .with_connect_timeout(Some(options.timeout)),
            timeout: options.timeout,
            socket_config: options.socket_config(),
        }
    }

    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        let target = Target::plain(authority);
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));
        tokio::time::timeout(self.timeout, self.connector.connect(&target, &recorder))
            .await
            .map_err(|_| OutboundError::Timeout)?
            .map_err(|error| OutboundError::Connect(error.to_string()))
    }

    /// The datagram twin of [`Self::connect`]: same socket configuration, so
    /// `SO_MARK` travels with it and a direct datagram flow is not captured by the
    /// proxy's own routing rules.
    fn datagram_connector(&self) -> UdpConnector {
        UdpConnector::new()
            .with_socket_config(self.socket_config.clone())
            .with_connect_timeout(Some(self.timeout))
    }
}

pub struct ProxyTransport {
    connector: ProxyConnector<TcpConnector>,
    protocol: Protocol,
    timeout: Duration,
    /// Kept so a `socks5` node can also open a UDP associate. `None` for an HTTP
    /// proxy, which has no datagram form: `CONNECT` tunnels TCP only.
    proxy: Option<Proxy>,
}

impl fmt::Debug for ProxyTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyTransport")
            .field("protocol", &self.protocol)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl ProxyTransport {
    fn new(proxy: Proxy, options: DialerOptions) -> Self {
        let protocol = match &proxy {
            Proxy::Http { .. } => Protocol::Http,
            Proxy::Socks5 { .. } => Protocol::Socks5,
        };
        let inner = TcpConnector::new()
            .with_socket_config(options.socket_config())
            .with_connect_timeout(Some(options.timeout));
        // Only SOCKS5 has a UDP associate; an HTTP proxy's `CONNECT` is TCP-only,
        // so the field stays `None` and `datagram()` answers honestly.
        let datagram_proxy = match &proxy {
            Proxy::Socks5 { .. } => Some(proxy.clone()),
            Proxy::Http { .. } => None,
        };
        Self {
            connector: ProxyConnector::new(inner, proxy),
            protocol,
            timeout: options.timeout,
            proxy: datagram_proxy,
        }
    }

    /// The SOCKS5 UDP associate for this node, if the proxy has one.
    fn datagram_connector(&self) -> Option<Arc<dyn DatagramConnector>> {
        let proxy = self.proxy.clone()?;
        let inner = TcpConnector::new().with_connect_timeout(Some(self.timeout));
        let connector = Socks5DatagramConnector::new(inner, proxy).ok()?;
        Some(Arc::new(connector))
    }

    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        let target = Target::plain(authority);
        let recorder = Arc::new(Mutex::new(Recorder::start(128)));
        tokio::time::timeout(self.timeout, self.connector.connect(&target, &recorder))
            .await
            .map_err(|_| OutboundError::Timeout)?
            .map_err(|error| OutboundError::Connect(error.to_string()))
    }

    fn protocol(&self) -> Protocol {
        self.protocol.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn options() -> DialerOptions {
        DialerOptions::new(None, Duration::from_secs(2))
    }

    /// A minimal SOCKS5 server: no-auth greeting, one CONNECT, then an echo.
    async fn socks5_echo(listener: TcpListener) {
        let (mut stream, _) = listener.accept().await.expect("accepts");
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await.expect("greeting");
        assert_eq!(greeting[0], 0x05);
        let mut methods = vec![0u8; greeting[1] as usize];
        stream.read_exact(&mut methods).await.expect("methods");
        stream.write_all(&[0x05, 0x00]).await.expect("method");

        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.expect("request");
        assert_eq!(request[0], 0x05);
        assert_eq!(request[1], 0x01, "CONNECT expected");
        match request[3] {
            0x01 => {
                let mut address = [0u8; 4];
                stream.read_exact(&mut address).await.expect("ipv4");
            }
            0x03 => {
                let mut length = [0u8; 1];
                stream.read_exact(&mut length).await.expect("len");
                let mut name = vec![0u8; length[0] as usize];
                stream.read_exact(&mut name).await.expect("domain");
                assert_eq!(name, b"example.com");
            }
            0x04 => {
                let mut address = [0u8; 16];
                stream.read_exact(&mut address).await.expect("ipv6");
            }
            other => panic!("unexpected address type {other}"),
        }
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.expect("port");
        assert_eq!(u16::from_be_bytes(port), 80);

        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("reply");

        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.expect("payload");
        stream.write_all(&payload).await.expect("echo");
    }

    /// A minimal HTTP proxy: one CONNECT, then an echo.
    async fn http_connect_echo(listener: TcpListener) {
        let (mut stream, _) = listener.accept().await.expect("accepts");
        let mut request = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.expect("request byte");
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert!(request.starts_with("connect example.com:80 "), "{request}");
        // base64("u:p") is "dTpw"; the request was lowercased above.
        assert!(
            request.contains("proxy-authorization: basic dtpw"),
            "missing credentials: {request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .expect("reply");

        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.expect("payload");
        stream.write_all(&payload).await.expect("echo");
    }

    async fn echo_through(dialer: &NodeDialer) {
        let mut established = dialer.connect("example.com:80").await.expect("connects");
        established
            .stream
            .write_all(b"hello")
            .await
            .expect("writes");
        let mut echoed = [0u8; 5];
        established
            .stream
            .read_exact(&mut echoed)
            .await
            .expect("reads");
        assert_eq!(&echoed, b"hello");
    }

    #[tokio::test]
    async fn dials_through_socks5() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(socks5_echo(listener));

        let dialer = NodeDialer::from_link(&format!("socks5://127.0.0.1:{port}"), options())
            .expect("builds");
        assert_eq!(dialer.protocol(), Protocol::Socks5);
        echo_through(&dialer).await;
        server.await.expect("server");
    }

    #[tokio::test]
    async fn dials_through_socks5_alias() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(socks5_echo(listener));

        let dialer =
            NodeDialer::from_link(&format!("socks://127.0.0.1:{port}"), options()).expect("builds");
        echo_through(&dialer).await;
        server.await.expect("server");
    }

    #[tokio::test]
    async fn dials_through_http_connect_with_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(http_connect_echo(listener));

        let dialer = NodeDialer::from_link(&format!("http://u:p@127.0.0.1:{port}"), options())
            .expect("builds");
        assert_eq!(dialer.protocol(), Protocol::Http);
        echo_through(&dialer).await;
        server.await.expect("server");
    }

    #[test]
    fn direct_and_empty_links_use_the_direct_transport() {
        assert!(matches!(
            NodeDialer::from_link("", options()),
            Ok(NodeDialer::Direct(_))
        ));
        assert!(matches!(
            NodeDialer::from_link("direct", options()),
            Ok(NodeDialer::Direct(_))
        ));
    }

    #[test]
    fn a_chain_is_rejected_rather_than_truncated_to_its_first_hop() {
        // The dangerous failure mode: accepting the chain and silently using only
        // the first hop, so an operator's traffic model is wrong and no log says so.
        let error = NodeDialer::from_link(
            "socks5://127.0.0.1:1080 -> socks5://127.0.0.1:1081",
            options(),
        )
        .expect_err("a chain must not build");
        let OutboundError::UnsupportedLink(message) = &error else {
            panic!("expected UnsupportedLink, got {error:?}");
        };
        assert!(message.contains("chained links"), "{message}");
        assert!(
            message.contains("socks5"),
            "the error must name the hop it refused to drop: {message}"
        );
    }

    #[test]
    fn an_arrow_inside_a_query_is_not_a_chain() {
        // `->` appears in real link parameters; only a second `scheme://` makes a
        // chain, so an ordinary link must still parse.
        let dialer = NodeDialer::from_link("socks5://127.0.0.1:1080?label=a->b", options());
        assert!(dialer.is_ok(), "{dialer:?}");
    }

    #[test]
    fn rejects_unsupported_links_loudly() {
        // `https` would put proxy credentials on the wire in clear text.
        let error =
            NodeDialer::from_link("https://127.0.0.1:8443", options()).expect_err("must fail");
        assert!(matches!(error, OutboundError::UnsupportedLink(_)));
        assert!(error.to_string().contains("not supported yet"), "{error}");

        let error = NodeDialer::from_link("vmess://xyz", options()).expect_err("must fail");
        assert!(
            error.to_string().contains("unsupported protocol"),
            "{error}"
        );

        let error = NodeDialer::from_link("127.0.0.1:1080", options()).expect_err("must fail");
        assert!(error.to_string().contains("no scheme"), "{error}");
    }
}
