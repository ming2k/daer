// SPDX-License-Identifier: AGPL-3.0-only

//! Transport dialers for one node: direct, SOCKS5, HTTP CONNECT, or proxy protocols.

use std::fmt;
use std::sync::Arc;

use daer_proxy_protocols::ProxyDialer;
pub use daer_proxy_protocols::options::DialerOptions;
use daer_proxy_protocols::server::{ServerConnector, ServerDialer};
use netune::{
    Connector, DatagramConnector, Established, Proxy, ProxyConnector, Socks5DatagramConnector,
};
use netune_trace::TraceCollector;

use crate::error::OutboundError;
use crate::property::Protocol;

/// One selectable outbound node, optionally carried by another node.
///
/// The transport is what speaks the node's protocol; `detour` is the outbound that opens the
/// stream to this node's *server*. Keeping the chain beside the transport rather than folding
/// it into the transport is what lets `daer route` and the health scheduler name both hops
/// (ADR-0044).
pub struct NodeDialer {
    label: String,
    transport: NodeTransport,
    detour: Option<Arc<NodeDialer>>,
}

enum NodeTransport {
    Proxy(ProxyTransport),
    Protocol(ProxyDialer),
}

impl fmt::Debug for NodeDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeDialer")
            .field("label", &self.label)
            .field("transport", &self.transport)
            .field("detour", &self.detour.as_ref().map(|inner| inner.label()))
            .finish()
    }
}

impl fmt::Debug for NodeTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proxy(dialer) => f.debug_tuple("Proxy").field(dialer).finish(),
            Self::Protocol(dialer) => f.debug_tuple("Protocol").field(dialer).finish(),
        }
    }
}

/// A link's diagnostic label, with credentials and query parameters removed.
///
/// `Debug` on a [`NodeDialer`] must never print a password. A node built from configuration
/// already has a name or a `host:port` default; a node built from a link gets this instead of
/// the raw string.
fn safe_link_label(link: &str) -> String {
    let Some((scheme, rest)) = link.split_once("://") else {
        return link.to_owned();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{scheme}://{host}")
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
        let label = node.label();
        let transport = match &node.endpoint {
            daer_config::NodeEndpoint::Socks5(n) => {
                let link = n.to_link();
                let proxy = Proxy::parse(&link)
                    .map_err(|e| OutboundError::UnsupportedLink(e.to_string()))?;
                NodeTransport::Proxy(ProxyTransport::new(proxy, options))
            }
            daer_config::NodeEndpoint::Http(n) => {
                let link = n.to_link();
                let proxy = Proxy::parse(&link)
                    .map_err(|e| OutboundError::UnsupportedLink(e.to_string()))?;
                NodeTransport::Proxy(ProxyTransport::new(proxy, options))
            }
            daer_config::NodeEndpoint::Unsupported { scheme, .. } => Err(
                OutboundError::UnsupportedLink(format!("unsupported protocol {scheme:?}")),
            )?,
            endpoint => {
                let dialer = ProxyDialer::from_node(endpoint, options)?;
                NodeTransport::Protocol(dialer)
            }
        };
        Ok(Self {
            label,
            transport,
            detour: None,
        })
    }

    /// Builds the transport a node link describes.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, OutboundError> {
        let link = link.trim();
        let label = safe_link_label(link);
        if link.is_empty() || link == "direct" || link.starts_with("direct://") {
            return Err(OutboundError::UnsupportedLink(
                "`direct` is a routing verdict, not a node link".to_owned(),
            ));
        }

        if let Some(scheme) = chain_head_scheme(link) {
            return Err(OutboundError::UnsupportedLink(format!(
                "chained links (`a -> b`) are not implemented; use a `[[node]]` with `detour = \"<name>\"`; {scheme:?} is the first hop of a chain this build would otherwise silently ignore"
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
            return Ok(Self {
                label,
                transport: NodeTransport::Protocol(dialer),
                detour: None,
            });
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
        Ok(Self {
            label,
            transport: NodeTransport::Proxy(ProxyTransport::new(proxy, options)),
            detour: None,
        })
    }

    /// Attaches the outbound that carries this node's server leg.
    ///
    /// The caller has already injected the matching [`ServerDialer`] into the options; this
    /// field is the diagnostic/health view of the same edge, and the two are set together by
    /// [`crate::NodeGraph`].
    #[must_use]
    pub(crate) fn with_detour(mut self, detour: Arc<NodeDialer>) -> Self {
        self.detour = Some(detour);
        self
    }

    /// The immediate inner outbound, when this node is a detour hop.
    #[must_use]
    pub fn detour(&self) -> Option<&Arc<NodeDialer>> {
        self.detour.as_ref()
    }

    /// This node's configured label (its name, or its default name).
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
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
        match &self.transport {
            NodeTransport::Proxy(dialer) => {
                dialer.connect_with_collector(authority, collector).await
            }
            NodeTransport::Protocol(dialer) => {
                Ok(dialer.connect_with_collector(authority, collector).await?)
            }
        }
    }

    /// Opens the bare stream to this node's server, before the protocol handshake.
    ///
    /// A health probe of a detoured node must test the *chain* to the node's own server, not
    /// the final internet target and not a direct socket that would report the outer server
    /// unreachable while the chain is fine (ADR-0044).
    pub async fn probe_server(
        &self,
        collector: &TraceCollector,
    ) -> Result<Established, OutboundError> {
        match &self.transport {
            NodeTransport::Proxy(dialer) => dialer.connect_server(collector).await,
            NodeTransport::Protocol(dialer) => Ok(dialer.connect_server(collector).await?),
        }
    }

    #[must_use]
    pub fn protocol(&self) -> Protocol {
        match &self.transport {
            NodeTransport::Proxy(dialer) => dialer.protocol(),
            NodeTransport::Protocol(dialer) => dialer.protocol().into(),
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
        match &self.transport {
            NodeTransport::Proxy(dialer) => dialer.datagram_connector(),
            NodeTransport::Protocol(dialer) => dialer.datagram_connector(),
        }
    }
}

/// Makes an outbound node usable as another node's server leg.
///
/// This is the only place a chain edge becomes code. The outer protocol asks for its server
/// stream, this adapter asks the inner node for a stream to that server, and the inner node's
/// own detour (if any) applies recursively — the configuration validation has already proven
/// the graph is acyclic (ADR-0044).
#[derive(Clone)]
pub(crate) struct NodeServerDialer {
    node: Arc<NodeDialer>,
}

impl NodeServerDialer {
    #[must_use]
    pub fn new(node: Arc<NodeDialer>) -> Self {
        Self { node }
    }
}

impl fmt::Debug for NodeServerDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeServerDialer")
            .field("node", &self.node.label())
            .finish()
    }
}

impl ServerDialer for NodeServerDialer {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a TraceCollector,
    ) -> daer_proxy_protocols::server::ServerFuture<'a> {
        let node = Arc::clone(&self.node);
        Box::pin(async move {
            node.connect_with_collector(authority, recorder)
                .await
                .map_err(|error| match error {
                    OutboundError::Timeout => daer_proxy_protocols::ProxyProtocolError::Timeout,
                    other => daer_proxy_protocols::ProxyProtocolError::Connect(other.to_string()),
                })
        })
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramConnector>> {
        self.node.datagram()
    }

    fn is_direct(&self) -> bool {
        false
    }

    fn route_shape(&self) -> Option<String> {
        Some(format!("detour:{}", self.node.label()))
    }
}

pub struct ProxyTransport {
    connector: ProxyConnector<ServerConnector>,
    base: Arc<dyn ServerDialer>,
    server: String,
    protocol: Protocol,
    /// `None` when the node cannot carry datagrams. A SOCKS5 UDP associate is a session with
    /// the proxy server itself; when the server is reached through a detour, the associate's
    /// datagrams would still take the local UDP path and silently bypass the chain. Refusing
    /// is the honest answer (ADR-0044).
    datagram: Option<Arc<dyn DatagramConnector>>,
}

impl fmt::Debug for ProxyTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyTransport")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl ProxyTransport {
    pub fn new(proxy: Proxy, options: DialerOptions) -> Self {
        let protocol = match &proxy {
            Proxy::Http { .. } => Protocol::Http,
            Proxy::Socks5 { .. } => Protocol::Socks5,
        };
        // Only SOCKS5 has a UDP associate; an HTTP proxy's `CONNECT` is TCP-only.
        // A detoured SOCKS5 node keeps TCP but reports no datagram support, because the
        // associate would otherwise send packets directly to a server reached through a chain.
        let datagram: Option<Arc<dyn DatagramConnector>> =
            match (&proxy, options.base().is_direct()) {
                (Proxy::Socks5 { .. }, true) => {
                    let inner = ServerConnector::new(options.base().clone());
                    Socks5DatagramConnector::new(inner, proxy.clone())
                        .ok()
                        .map(|connector| Arc::new(connector) as Arc<dyn DatagramConnector>)
                }
                _ => None,
            };
        let base = options.base().clone();
        let server = match &proxy {
            Proxy::Http { authority, .. } | Proxy::Socks5 { authority, .. } => authority.clone(),
        };
        Self {
            connector: ProxyConnector::new(ServerConnector::new(Arc::clone(&base)), proxy),
            base,
            server,
            protocol,
            datagram,
        }
    }

    fn datagram_connector(&self) -> Option<Arc<dyn DatagramConnector>> {
        self.datagram.clone()
    }

    async fn connect_server(
        &self,
        collector: &TraceCollector,
    ) -> Result<Established, OutboundError> {
        self.base
            .connect(&self.server, collector)
            .await
            .map_err(OutboundError::from)
    }

    pub async fn connect_with_collector(
        &self,
        authority: &str,
        collector: &TraceCollector,
    ) -> Result<Established, OutboundError> {
        let target = netune::Target::plain(authority);
        self.connector
            .connect(&target, collector)
            .await
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
    fn direct_links_are_routing_verdicts_not_node_links() {
        for link in ["", "direct", "direct://local"] {
            let error = NodeDialer::from_link(link, options()).expect_err("must fail");
            assert!(
                error.to_string().contains("routing verdict"),
                "{link:?}: {error}"
            );
        }
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

    #[test]
    fn a_link_label_never_prints_credentials() {
        let dialer =
            NodeDialer::from_link("http://user:secret@127.0.0.1:8080", options()).expect("builds");
        let rendered = format!("{dialer:?}");
        assert!(!rendered.contains("user"), "{rendered}");
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(rendered.contains("127.0.0.1:8080"), "{rendered}");
    }
}
