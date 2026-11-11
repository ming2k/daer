// SPDX-License-Identifier: AGPL-3.0-only

//! Transport dialers for one node: direct, SOCKS5, HTTP CONNECT, or proxy protocols.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use daer_proxy_protocols::ProxyDialer;
pub use daer_proxy_protocols::options::DialerOptions;
use netune::{
    Connector, DatagramConnector, Established, Proxy, ProxyConnector, SocketConfig,
    Socks5DatagramConnector, Target, TcpConnector, UdpConnector,
};
use netune_trace::TraceCollector;

use crate::error::OutboundError;
use crate::property::Protocol;

/// A node's transport.
pub enum NodeDialer {
    Direct(DirectTransport),
    Proxy(ProxyTransport),
    Protocol(ProxyDialer),
}

impl fmt::Debug for NodeDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(dialer) => f.debug_tuple("Direct").field(dialer).finish(),
            Self::Proxy(dialer) => f.debug_tuple("Proxy").field(dialer).finish(),
            Self::Protocol(dialer) => f.debug_tuple("Protocol").field(dialer).finish(),
        }
    }
}

/// The first hop's scheme when `link` is a chain, or `None` for a single link.
fn chain_head_scheme(link: &str) -> Option<&str> {
    let (head, rest) = link.split_once("->")?;
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
            daer_config::NodeEndpoint::Unsupported { scheme, .. } => Err(
                OutboundError::UnsupportedLink(format!("unsupported protocol {scheme:?}")),
            ),
            endpoint => {
                let dialer = ProxyDialer::from_node(endpoint, options)?;
                Ok(Self::Protocol(dialer))
            }
        }
    }

    /// Builds the transport a node link describes.
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

        if scheme.eq_ignore_ascii_case("ss")
            || scheme.eq_ignore_ascii_case("shadowsocks")
            || scheme.eq_ignore_ascii_case("trojan")
            || scheme.eq_ignore_ascii_case("trojan-go")
            || scheme.eq_ignore_ascii_case("anytls")
            || scheme.eq_ignore_ascii_case("hysteria2")
            || scheme.eq_ignore_ascii_case("hy2")
            || scheme.eq_ignore_ascii_case("vless")
        {
            let dialer = ProxyDialer::from_link(link, options)?;
            return Ok(Self::Protocol(dialer));
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

    /// Opens a TCP connection to `authority` (`host:port`) without observing it.
    ///
    /// `TraceCollector::disabled()` is the netune `Observation::Off` cold path:
    /// no event is recorded and no sink is installed. A dial that nobody
    /// measures must not fill an event ring nobody reads.
    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        self.connect_with_collector(authority, &TraceCollector::disabled())
            .await
    }

    /// Opens a TCP connection, recording the attempt into `collector`.
    ///
    /// This is the seam an observer uses: netune emits its DNS/TCP/TLS phases
    /// into the collector, and the caller can derive them instead of timing the
    /// whole dial with a wall clock.
    pub async fn connect_with_collector(
        &self,
        authority: &str,
        collector: &TraceCollector,
    ) -> Result<Established, OutboundError> {
        match self {
            Self::Direct(dialer) => dialer.connect_with_collector(authority, collector).await,
            Self::Proxy(dialer) => dialer.connect_with_collector(authority, collector).await,
            Self::Protocol(dialer) => {
                Ok(dialer.connect_with_collector(authority, collector).await?)
            }
        }
    }

    #[must_use]
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::Direct(_) => Protocol::Direct,
            Self::Proxy(dialer) => dialer.protocol(),
            Self::Protocol(dialer) => dialer.protocol().into(),
        }
    }

    /// A short identity for diagnostics.
    #[must_use]
    pub fn describe(&self) -> Protocol {
        self.protocol()
    }

    /// The datagram connector for this node, or `None` when this build cannot
    /// carry datagrams through it.
    #[must_use]
    pub fn datagram(&self) -> Option<Arc<dyn DatagramConnector>> {
        match self {
            Self::Direct(dialer) => Some(Arc::new(dialer.datagram_connector())),
            Self::Proxy(dialer) => dialer.datagram_connector(),
            Self::Protocol(dialer) => dialer.datagram_connector(),
        }
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
        self.connect_with_collector(authority, &TraceCollector::disabled())
            .await
    }

    pub async fn connect_with_collector(
        &self,
        authority: &str,
        collector: &TraceCollector,
    ) -> Result<Established, OutboundError> {
        let target = Target::plain(authority);
        tokio::time::timeout(self.timeout, self.connector.connect(&target, collector))
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
    pub fn new(proxy: Proxy, options: DialerOptions) -> Self {
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
        self.connect_with_collector(authority, &TraceCollector::disabled())
            .await
    }

    pub async fn connect_with_collector(
        &self,
        authority: &str,
        collector: &TraceCollector,
    ) -> Result<Established, OutboundError> {
        let target = Target::plain(authority);
        tokio::time::timeout(self.timeout, self.connector.connect(&target, collector))
            .await
            .map_err(|_| OutboundError::Timeout)?
            .map_err(|error| OutboundError::Connect(error.to_string()))
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn options() -> DialerOptions {
        DialerOptions::new(None, Duration::from_secs(1))
    }

    async fn socks5_echo(listener: TcpListener) {
        let (mut stream, _) = listener.accept().await.expect("accept");

        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).await.expect("greeting");
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        stream
            .write_all(&[0x05, 0x00])
            .await
            .expect("method chosen");

        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.expect("request head");
        assert_eq!(&request[..3], &[0x05, 0x01, 0x00]);
        assert_eq!(request[3], 0x03);

        let mut domain_len = [0u8; 1];
        stream
            .read_exact(&mut domain_len)
            .await
            .expect("domain len");
        let mut domain = vec![0u8; domain_len[0] as usize];
        stream.read_exact(&mut domain).await.expect("domain");
        assert_eq!(&domain, b"example.com");

        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.expect("port");
        assert_eq!(u16::from_be_bytes(port), 80);

        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
            .await
            .expect("reply");

        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.expect("payload");
        stream.write_all(&payload).await.expect("echo");
    }

    async fn http_connect_echo(listener: TcpListener) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut head = [0u8; 256];
        let n = stream.read(&mut head).await.expect("read connect");
        let request = std::str::from_utf8(&head[..n]).expect("ascii");
        assert!(request.starts_with("CONNECT example.com:80 HTTP/1.1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dTpw\r\n"));

        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .expect("established");

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
        let dialer = NodeDialer::from_link("socks5://127.0.0.1:1080?label=a->b", options());
        assert!(dialer.is_ok(), "{dialer:?}");
    }

    #[test]
    fn rejects_unsupported_links_loudly() {
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
