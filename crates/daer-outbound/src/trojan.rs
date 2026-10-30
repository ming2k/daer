// SPDX-License-Identifier: AGPL-3.0-only

//! Trojan: a password-authenticated session inside TLS to the node.
//!
//! # The protocol
//!
//! ```text
//!   [hex(SHA224(password)) | CRLF]          56 bytes, plaintext *inside* TLS
//!   [CMD(1)] [ATYP(1)] [address] [CRLF]     CMD 1 = CONNECT
//!   [payload …]                             the tunnel, from here on raw bytes
//! ```
//!
//! There is no encryption of its own: the security is the TLS session, and the password is
//! only an admission check. That shapes every decision below.
//!
//! # Why TLS is not optional here
//!
//! Trojan has no confidentiality of its own, so a `trojan://` node that fell back to
//! plaintext would put the password and the whole session on the wire in clear text. This
//! module never constructs a plaintext connector: the only way to reach it is through
//! [`netune::TlsConnector`], and the target always carries a server name.
//!
//! # What the protocol deliberately leaks, and what this refuses to do
//!
//! The handshake is length-prefixed by a fixed-size header, so a passive observer learns the
//! shape of the first flight. Trojan's answer is to look like HTTPS — which is why the node is
//! reached with a TLS fingerprint profile (see `[global.tls] profile`) rather than with
//! rustls' default identity. This module does not invent a padding scheme or a fake HTTP
//! request: an unauthenticated wrong guess about what a server expects is worse than a
//! consistent identity, and the identity is what netune is for.
//!
//! # Fallback
//!
//! A real Trojan server answers an unauthenticated probe with an HTTP response so it looks
//! like a web server. This client treats that as a failed handshake and reports it — it does
//! not try to impersonate a browser to the same node, because a client that speaks two
//! protocols to one endpoint has to be told which one is real, and that is a decision, not a
//! default.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune::{
    Connector, DatagramConnector, DatagramTransport, Established, EstablishedDatagrams, NetError,
    SocketConfig, Target, TcpConnector, TlsConnector,
};
use netune_trace::Recorder;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::OutboundError;
use crate::node_dialer::DialerOptions;
use crate::shadowsocks::connector::{encode_address, split_authority};

/// The command byte for a TCP session.
const CMD_CONNECT: u8 = 0x01;
/// The command byte for a UDP association.
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// The request header a Trojan client sends for one UDP session.
pub fn request_header_udp(authority: &str) -> Result<Vec<u8>, String> {
    let (host, port) = split_authority(authority)?;
    let mut out = Vec::with_capacity(64);
    out.push(CMD_UDP_ASSOCIATE);
    out.extend_from_slice(&encode_address(host, port)?);
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// A parsed `trojan://` link.
///
/// ```text
///   trojan://password@host:port?sni=example.com#tag
/// ```
///
/// Every link carries a **password** and a **server**; `sni` is optional and defaults to the
/// server's host name, which is what a node serving one domain wants and what an operator
/// with a fronted node must override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    password: String,
    pub server: String,
    /// The name presented in the TLS handshake.
    pub server_name: String,
    pub tag: Option<String>,
    /// Whether the link said `allowInsecure=1`.
    pub allow_insecure: bool,
}

impl Link {
    /// Parses a `trojan://` link.
    ///
    /// # Errors
    ///
    /// Returns a message naming what is wrong: a missing password, a missing server, a server
    /// without a port, or a TLS name that is neither present nor derivable.
    pub fn parse(link: &str) -> Result<Self, String> {
        let body = link
            .strip_prefix("trojan://")
            .ok_or_else(|| format!("{link:?} does not start with trojan://"))?;

        // Order matters: the fragment is last, then the query, then the authority.
        let (body, tag) = match body.split_once('#') {
            Some((body, tag)) => (body, Some(tag.to_owned())),
            None => (body, None),
        };
        let (authority, query) = match body.split_once('?') {
            Some((authority, query)) => (authority, query),
            None => (body, ""),
        };
        let (password, server) = authority.rsplit_once('@').ok_or_else(|| {
            format!("trojan:// link {link:?} has no `password@server`; a password is required")
        })?;
        if password.is_empty() {
            return Err("trojan:// link has an empty password".to_owned());
        }

        let (host, port) = split_authority(server)?;
        if port == 0 {
            return Err("trojan:// link has port 0".to_owned());
        }

        let mut server_name = None;
        let mut allow_insecure = false;
        let mut peer = None;
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = match pair.split_once('=') {
                Some(pair) => pair,
                None => continue,
            };
            match key {
                "sni" | "peer" => {
                    if value.is_empty() {
                        return Err(format!("trojan:// link has an empty {key}"));
                    }
                    server_name = Some(value.to_owned());
                }
                "allowInsecure" | "allow_insecure" => {
                    allow_insecure = matches!(value, "1" | "true" | "yes");
                }
                // Unknown parameters are not an error: panels add them freely and a strict
                // parser would lock operators out of their own subscriptions. They are
                // ignored rather than guessed at.
                _ => {}
            }
            if key == "peer" {
                peer = Some(value.to_owned());
            }
        }
        // `peer=` is the older spelling of `sni=`; it does not override an explicit sni.
        let server_name = server_name
            .or(peer)
            // The server's host is the name a certificate for that node will carry. Using the
            // address would fail verification, so a link with neither `sni` nor a hostname is
            // rejected below rather than at handshake time.
            .unwrap_or_else(|| host.to_owned());
        if server_name.parse::<std::net::IpAddr>().is_ok() {
            return Err(format!(
                "trojan:// link {link:?} needs `?sni=…`: a TLS certificate cannot be verified \
                 against the bare address {server_name}"
            ));
        }

        Ok(Self {
            password: password.to_owned(),
            server: server.to_owned(),
            server_name,
            tag,
            allow_insecure,
        })
    }

    /// The 56-byte credential: hex of SHA-224 of the password, then CRLF.
    ///
    /// Lowercase hex, because that is what servers compare and what every implementation
    /// writes.
    #[must_use]
    pub fn credential(&self) -> Vec<u8> {
        let digest = Sha224::digest(self.password.as_bytes());
        let mut out = Vec::with_capacity(58);
        for byte in digest {
            out.extend_from_slice(format!("{byte:02x}").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

impl fmt::Display for Link {
    /// Renders the link without the password.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "trojan://***@{}", self.server)?;
        if self.server_name != self.server.split(':').next().unwrap_or(&self.server) {
            write!(f, "?sni={}", self.server_name)?;
        }
        if let Some(tag) = &self.tag {
            write!(f, "#{tag}")?;
        }
        Ok(())
    }
}

/// The request header a Trojan client sends for one TCP session.
///
/// # Errors
///
/// Returns a message for a target that cannot be encoded (empty host, port 0).
pub fn request_header(authority: &str) -> Result<Vec<u8>, String> {
    let (host, port) = split_authority(authority)?;
    let mut out = Vec::with_capacity(64);
    out.push(CMD_CONNECT);
    out.extend_from_slice(&encode_address(host, port)?);
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// A Trojan node.
#[derive(Clone)]
pub struct TrojanConnector {
    link: Link,
    /// The TLS stack, from netune. Trojan has no confidentiality of its own, so this is not
    /// optional and there is no plaintext constructor.
    tls: Arc<TlsConnector<TcpConnector>>,
    timeout: Duration,
    /// `global.tls.profile`, applied per `Target` because netune selects the ClientHello
    /// identity there rather than on the connector.
    tls_profile: Option<&'static str>,
}

impl fmt::Debug for TrojanConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanConnector")
            .field("link", &self.link)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl TrojanConnector {
    /// Builds a connector from a `trojan://` link.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundError::UnsupportedLink`] when the link does not parse, and
    /// [`OutboundError::Connect`] when the TLS profile cannot be built (a certificate store
    /// that cannot be read is a system problem, not a link problem).
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, OutboundError> {
        let parsed = Link::parse(link).map_err(OutboundError::UnsupportedLink)?;

        let socket = match options.so_mark {
            Some(mark) => SocketConfig::default().with_mark(mark),
            None => SocketConfig::default(),
        };
        let tcp = TcpConnector::new()
            .with_socket_config(socket)
            .with_connect_timeout(Some(options.timeout));

        // The platform trust store, not a pinned set: a node's certificate is verified like any
        // other HTTPS endpoint. A node with a self-signed certificate must be fronted by a real
        // one, which is what Trojan servers do anyway.
        let tls = TlsConnector::platform(tcp)
            .map_err(|error| OutboundError::Connect(error.to_string()))?;

        Ok(Self {
            link: parsed,
            tls: Arc::new(tls),
            timeout: options.timeout,
            // `global.tls.profile`: the ClientHello this deployment presents. Netune selects it
            // per `Target`, so it is carried here and attached at dial time. It used to be
            // accepted by the schema and never applied, so an operator who chose a profile got
            // netune's default identity with no way to tell (ADR-0006).
            tls_profile: options.tls_profile,
        })
    }

    /// The node's server address.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.link.server
    }

    /// The TLS name presented for this node.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.link.server_name
    }

    /// Opens a session to `authority` (`host:port`).
    ///
    /// # Errors
    ///
    /// Returns [`OutboundError`] for a bad target, a failed TLS handshake, or a failed header
    /// write. The handshake failure carries the TLS error, because "certificate expired" and
    /// "node refused the password" are the two things an operator needs to tell apart.
    pub async fn connect(
        &self,
        authority: &str,
        recorder: &Arc<Mutex<netune_trace::Recorder>>,
    ) -> Result<Established, OutboundError> {
        let header = request_header(authority).map_err(OutboundError::UnsupportedLink)?;
        let credential = self.link.credential();

        // TLS to the node: the target carries the *node's* address and the name to verify,
        // which is exactly what `Target::tls` exists for.
        let target = Target::tls(&self.link.server, &self.link.server_name);
        let target = match self.tls_profile {
            Some(profile) => target.with_tls_profile(profile),
            None => target,
        };
        let established = tokio::time::timeout(self.timeout, self.tls.connect(&target, recorder))
            .await
            .map_err(|_| OutboundError::Timeout)?
            .map_err(|error| OutboundError::Connect(error.to_string()))?;

        let mut stream = established.stream;
        // Credential and request go in one write: a server that sees the credential alone may
        // wait for the header, and two writes would add a round trip to every connection.
        let mut first_flight = Vec::with_capacity(credential.len() + header.len());
        first_flight.extend_from_slice(&credential);
        first_flight.extend_from_slice(&header);
        stream
            .write_all(&first_flight)
            .await
            .map_err(|error| OutboundError::Connect(error.to_string()))?;

        Ok(Established {
            stream,
            local_port: established.local_port,
            socket: established.socket,
            alpn: established.alpn,
        })
    }

    /// Returns a [`DatagramConnector`] that carries UDP over this Trojan node.
    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        Arc::new(TrojanDatagramConnector::new(self.clone()))
    }

    /// Opens a Trojan datagram session to `authority` (`host:port`).
    pub async fn connect_datagram(
        &self,
        authority: &str,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<EstablishedDatagrams, NetError> {
        let (host, port) = split_authority(authority).map_err(NetError::Protocol)?;
        let addr_bytes = encode_address(host, port).map_err(NetError::Protocol)?;
        let header = request_header_udp(authority).map_err(NetError::Protocol)?;
        let credential = self.link.credential();

        let target = Target::tls(&self.link.server, &self.link.server_name);
        let target = match self.tls_profile {
            Some(profile) => target.with_tls_profile(profile),
            None => target,
        };
        let established = tokio::time::timeout(self.timeout, self.tls.connect(&target, recorder))
            .await
            .map_err(|_| NetError::Connect(format!("timeout connecting to {}", self.link.server)))?
            .map_err(|error| NetError::Connect(error.to_string()))?;

        let mut stream = established.stream;
        let mut first_flight = Vec::with_capacity(credential.len() + header.len());
        first_flight.extend_from_slice(&credential);
        first_flight.extend_from_slice(&header);
        stream
            .write_all(&first_flight)
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;

        let (read, write) = tokio::io::split(stream);
        let session = TrojanDatagramSession::new(read, write, addr_bytes);
        Ok(EstablishedDatagrams {
            datagrams: Box::new(session),
            local_port: established.local_port,
        })
    }
}

/// A datagram session over a Trojan TLS connection.
pub struct TrojanDatagramSession<R, W> {
    reader: tokio::sync::Mutex<R>,
    writer: tokio::sync::Mutex<W>,
    target_addr: Vec<u8>,
}

impl<R, W> fmt::Debug for TrojanDatagramSession<R, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanDatagramSession")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for TrojanDatagramConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanDatagramConnector")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl<R, W> TrojanDatagramSession<R, W> {
    pub fn new(reader: R, writer: W, target_addr: Vec<u8>) -> Self {
        Self {
            reader: tokio::sync::Mutex::new(reader),
            writer: tokio::sync::Mutex::new(writer),
            target_addr,
        }
    }
}

impl<R, W> DatagramTransport for TrojanDatagramSession<R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<usize, std::io::Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut writer = self.writer.lock().await;
            let len = u16::try_from(payload.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "datagram exceeds u16::MAX",
                )
            })?;
            writer.write_all(&self.target_addr).await?;
            writer.write_all(&len.to_be_bytes()).await?;
            writer.write_all(b"\r\n").await?;
            writer.write_all(payload).await?;
            writer.flush().await?;
            Ok(payload.len())
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<usize, std::io::Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;
            // Read address header: ATYP
            let mut atyp = [0u8; 1];
            reader.read_exact(&mut atyp).await?;
            match atyp[0] {
                1 => {
                    // IPv4: 4 bytes IP + 2 bytes port
                    let mut skip = [0u8; 6];
                    reader.read_exact(&mut skip).await?;
                }
                4 => {
                    // IPv6: 16 bytes IP + 2 bytes port
                    let mut skip = [0u8; 18];
                    reader.read_exact(&mut skip).await?;
                }
                3 => {
                    // Domain: 1 byte len + domain bytes + 2 bytes port
                    let mut dlen = [0u8; 1];
                    reader.read_exact(&mut dlen).await?;
                    let mut skip = vec![0u8; dlen[0] as usize + 2];
                    reader.read_exact(&mut skip).await?;
                }
                other => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid trojan atyp: {other}"),
                    ));
                }
            }

            // Read 2 bytes length
            let mut len_bytes = [0u8; 2];
            reader.read_exact(&mut len_bytes).await?;
            let len = u16::from_be_bytes(len_bytes) as usize;

            // Read 2 bytes CRLF
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await?;

            let buf_len = buffer.len();
            if len > buf_len {
                reader.read_exact(&mut buffer[..buf_len]).await?;
                let mut discard = vec![0u8; len - buf_len];
                reader.read_exact(&mut discard).await?;
                Ok(buf_len)
            } else {
                reader.read_exact(&mut buffer[..len]).await?;
                Ok(len)
            }
        })
    }

    fn max_datagram_size(&self) -> usize {
        65507
    }
}

/// A connector establishing datagram sessions over Trojan.
#[derive(Clone)]
pub struct TrojanDatagramConnector {
    connector: TrojanConnector,
}

impl TrojanDatagramConnector {
    #[must_use]
    pub const fn new(connector: TrojanConnector) -> Self {
        Self { connector }
    }
}

impl DatagramConnector for TrojanDatagramConnector {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a Arc<Mutex<Recorder>>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>,
    > {
        let connector = self.connector.clone();
        let authority = authority.to_owned();
        let recorder = Arc::clone(recorder);
        Box::pin(async move { connector.connect_datagram(&authority, &recorder).await })
    }
}

/// True when a link is a Trojan link.
#[must_use]
pub fn is_trojan(link: &str) -> bool {
    link.trim_start().starts_with("trojan://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_link_parses_and_derives_the_tls_name() {
        let link = Link::parse("trojan://pw@node.example.com:443").expect("parses");
        assert_eq!(link.server, "node.example.com:443");
        assert_eq!(
            link.server_name, "node.example.com",
            "the host is the certificate name"
        );
        assert_eq!(link.tag, None);
        assert!(!link.allow_insecure);
    }

    #[test]
    fn sni_overrides_the_derived_name() {
        let link =
            Link::parse("trojan://pw@1.2.3.4:443?sni=fronted.example.com#hk").expect("parses");
        assert_eq!(link.server, "1.2.3.4:443");
        assert_eq!(link.server_name, "fronted.example.com");
        assert_eq!(link.tag.as_deref(), Some("hk"));
    }

    #[test]
    fn the_older_peer_parameter_is_accepted() {
        let link = Link::parse("trojan://pw@1.2.3.4:443?peer=old.example.com").expect("parses");
        assert_eq!(link.server_name, "old.example.com");
    }

    #[test]
    fn sni_wins_over_peer_when_both_are_present() {
        let link = Link::parse("trojan://pw@1.2.3.4:443?peer=old.example.com&sni=new.example.com")
            .expect("parses");
        assert_eq!(link.server_name, "new.example.com");
    }

    #[test]
    fn a_bare_ip_without_sni_is_rejected_with_the_reason() {
        // A certificate cannot be verified against an address, so failing here is better than
        // failing at handshake time with an opaque TLS error.
        let error = Link::parse("trojan://pw@1.2.3.4:443").expect_err("must reject");
        assert!(error.contains("needs `?sni=…`"), "{error}");
        assert!(error.contains("cannot be verified"), "{error}");
    }

    #[test]
    fn the_credential_is_lowercase_hex_sha224_plus_crlf() {
        let link = Link::parse("trojan://password@node.example.com:443").expect("parses");
        let credential = link.credential();
        assert_eq!(credential.len(), 58, "56 hex characters plus CRLF");
        assert!(credential.ends_with(b"\r\n"));
        let text = std::str::from_utf8(&credential[..56]).expect("ascii");
        assert!(
            text.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lowercase hex: {text}"
        );
        // Pinned so a change to the digest would be caught here rather than by a server.
        assert_eq!(text, format!("{:x}", Sha224::digest(b"password")));
    }

    #[test]
    fn the_credential_differs_per_password() {
        let a = Link::parse("trojan://a@node.example.com:1").expect("parses");
        let b = Link::parse("trojan://b@node.example.com:1").expect("parses");
        assert_ne!(a.credential(), b.credential());
    }

    #[test]
    fn the_request_header_carries_the_target() {
        let header = request_header("example.com:443").expect("encodes");
        assert_eq!(header[0], CMD_CONNECT);
        assert_eq!(header[1], 3, "ATYP domain");
        assert_eq!(header[2], 11, "example.com");
        assert_eq!(&header[3..14], b"example.com");
        assert_eq!(&header[14..16], &443u16.to_be_bytes());
        assert_eq!(&header[16..], b"\r\n");
    }

    #[test]
    fn the_request_header_encodes_ip_targets() {
        let header = request_header("1.2.3.4:80").expect("encodes");
        assert_eq!(header[1], 1, "ATYP ipv4");
        assert_eq!(&header[2..6], &[1, 2, 3, 4]);
    }

    #[test]
    fn broken_links_name_the_broken_part() {
        let cases = [
            ("http://x", "does not start with trojan://"),
            ("trojan://node.example.com:443", "no `password@server`"),
            ("trojan://@node.example.com:443", "empty password"),
            ("trojan://pw@node.example.com", "has no port"),
        ];
        for (link, expected) in cases {
            let error = Link::parse(link).expect_err("must reject");
            assert!(
                error.contains(expected),
                "{link}: expected {expected:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn unknown_query_parameters_are_ignored() {
        // Panels add parameters freely; a strict parser would lock an operator out of their own
        // subscription for a reason that does not affect the connection.
        let link =
            Link::parse("trojan://pw@node.example.com:443?type=ws&host=x&path=/y").expect("parses");
        assert_eq!(link.server_name, "node.example.com");
    }

    #[test]
    fn the_link_renders_without_the_password() {
        let link =
            Link::parse("trojan://secret@1.2.3.4:443?sni=front.example.com#hk").expect("parses");
        let rendered = link.to_string();
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(rendered.contains("front.example.com"), "{rendered}");
        assert!(rendered.contains("#hk"), "{rendered}");
    }

    #[test]
    fn link_detection_is_prefix_based() {
        assert!(is_trojan("trojan://x"));
        assert!(!is_trojan("ss://x"));
    }
}
