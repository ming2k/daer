// SPDX-License-Identifier: AGPL-3.0-only

//! The REALITY connector: a `vless://…?security=reality` link, end to end.
//!
//! # The shape
//!
//! ```text
//!   link  ──▶ RealityConnector ──▶ Tls13Connection ──▶ VLESS request ──▶ tunnel
//!                  │                    │
//!                  │                    └── owns the handshake, because rustls
//!                  │                        cannot write `legacy_session_id`
//!                  └── the ONLY constructor: a `security=reality` link
//! ```
//!
//! See [ADR-0010](../../../docs/adr/0010-reality-client-ownership.md).
//!
//! # Why this module is the only door
//!
//! `Tls13Connection` is `pub(crate)` and has no public constructor. The only way to obtain
//! one is [`RealityConnector::from_link`], which requires `security=reality` in a
//! `vless://` link. There is therefore no configuration, routing decision or other code
//! path that can reach the TLS 1.3 client — the scope decision in the ADR is enforced by
//! the type system rather than by review.
//!
//! # What a link must carry
//!
//! | Parameter | Meaning | Default |
//! | --- | --- | --- |
//! | `pbk` | server's X25519 public key, base64url | **required** |
//! | `sid` | short-id, up to 8 bytes, hex | empty |
//! | `sni` | impersonated site | the server's host |
//! | `fp` | TLS fingerprint the node expects | **required** (see below) |
//! | `flow` | `xtls-rprx-vision` | Vision framing ([`super::vision`]) |
//!
//! `fp` is required rather than defaulted. A REALITY ClientHello that presents the wrong
//! fingerprint fails on the wire with no diagnostic a log can attribute to the cause, so it
//! is a configuration error and it is reported as one at load.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune::{
    Connector, DatagramConnector, DatagramTransport, Established, EstablishedDatagrams, NetError,
    Target, TcpConnector,
};
use netune_trace::Recorder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::tls13::RealityAuth;
use super::tls13::stream::{HandshakeError, Tls13Connection};
use crate::error::OutboundError;
use crate::node_dialer::DialerOptions;

/// The one flow this build implements. The string is the wire spelling a subscription uses.
const FLOW_VISION: &str = "xtls-rprx-vision";

/// A parsed `vless://…?security=reality` link.
#[derive(Clone)]
pub struct Link {
    /// The user id (UUID) that authenticates the session to the node.
    user_id: String,
    /// `host:port` of the node.
    server: String,
    /// The name presented in SNI: the *impersonated* site, not the node's name.
    server_name: String,
    /// The server's X25519 public key.
    public_key: [u8; 32],
    /// REALITY short-id.
    short_id: Vec<u8>,
    /// The fingerprint the node expects, recorded so a diagnostic can name it.
    fingerprint: String,
    /// Whether the inner stream is Vision-framed (`?flow=xtls-rprx-vision`).
    vision: bool,
    /// ALPN protocols to offer in the handshake, from `?alpn=`.
    ///
    /// A REALITY node forwards an unauthenticated flow to the impersonated site, so the
    /// handshake has to look like that site's. Offering an ALPN the site does not speak is
    /// one of the ways a flow fails to blend in.
    alpn: Vec<Vec<u8>>,
    tag: String,
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The user id is a credential and the public key identifies the node; neither is
        // printed. The tag and the impersonated name are what a reader needs.
        f.debug_struct("Link")
            .field("server", &self.server)
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl Link {
    /// Parses a REALITY link.
    ///
    /// # Errors
    ///
    /// Returns a message naming the missing or malformed part. Every one of these is a
    /// configuration error an operator can fix, so each is reported by name rather than as
    /// "invalid link".
    pub fn parse(link: &str) -> Result<Self, String> {
        let rest = link
            .strip_prefix("vless://")
            .ok_or_else(|| format!("{link:?} is not a vless:// link"))?;

        // user_id @ host:port ? query # tag
        let (user_id, rest) = rest
            .split_once('@')
            .ok_or_else(|| "vless:// link has no `user@host` part".to_owned())?;
        if user_id.is_empty() {
            return Err("vless:// link has an empty user id".to_owned());
        }

        // `authority[?query][#fragment]`. The fragment starts at the first `#` and runs to
        // the end, so a `#` inside it is data rather than a second fragment.
        let (before_fragment, fragment) = match rest.split_once('#') {
            Some((before, fragment)) => (before, Some(fragment)),
            None => (rest, None),
        };
        let (authority, query) = match before_fragment.split_once('?') {
            Some((authority, query)) => (authority, Some(query)),
            None => (before_fragment, None),
        };
        let query = query.unwrap_or("");

        let (host, port) = split_authority(authority)?;
        if port == 0 {
            return Err("vless:// link has port 0".to_owned());
        }
        let server = format!("{host}:{port}");

        let mut security = None;
        let mut public_key = None;
        let mut short_id = Vec::new();
        let mut server_name = None;
        let mut fingerprint = None;
        let mut flow = None;
        let mut kind = None;
        let mut alpn = None;

        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = match pair.split_once('=') {
                Some(pair) => pair,
                None => continue,
            };
            let value = percent_decode(value)?;
            match key {
                "security" => security = Some(value),
                "pbk" => public_key = Some(value),
                "sid" => short_id = decode_short_id(&value)?,
                "sni" | "peer" => server_name = Some(value),
                "fp" => fingerprint = Some(value),
                "flow" => flow = Some(value),
                "type" => kind = Some(value),
                "alpn" => alpn = Some(value),
                // Unknown parameters are not an error: panels add them freely and a strict
                // parser would lock operators out of their own subscriptions.
                _ => {}
            }
        }

        match security.as_deref() {
            Some("reality") => {}
            Some(other) => {
                return Err(format!(
                    "vless:// link has security={other}; this connector only serves \
                     security=reality"
                ));
            }
            None => {
                return Err(
                    "vless:// link has no `security=reality`; a plain vless node is a \
                     different connector"
                        .to_owned(),
                );
            }
        }

        // `flow` selects the inner framing. Vision is the only one this build speaks; a node
        // whose user is configured for it **rejects** a client that omits it, so the two are
        // not interchangeable and an unknown flow is refused rather than ignored.
        let vision = match flow.as_deref() {
            None | Some("") | Some("none") => false,
            Some(FLOW_VISION) => true,
            Some(other) => {
                return Err(format!(
                    "vless:// link asks for flow={other}; this build implements only \
                     {FLOW_VISION:?}"
                ));
            }
        };

        // Only raw TCP inside TLS is implemented. A transport that wraps the stream
        // (`ws`, `grpc`, `h2`, `xhttp`) is a different framing layer, and silently ignoring
        // it would produce a session that connects and then sends nonsense.
        match kind.as_deref() {
            None | Some("") | Some("tcp") | Some("raw") | Some("none") => {}
            Some(other) => {
                return Err(format!(
                    "vless:// link asks for type={other}; only a raw TCP session is \
                     implemented (REALITY over ws/grpc is a separate framing layer)"
                ));
            }
        }

        let public_key = public_key.ok_or_else(|| {
            "vless:// REALITY link has no `pbk`; the server's public key is what the tag \
             is derived from, and without it no handshake can be attempted"
                .to_owned()
        })?;
        let public_key = decode_public_key(&public_key)?;

        let fingerprint = fingerprint.ok_or_else(|| {
            "vless:// REALITY link has no `fp`; a REALITY ClientHello must present the \
             fingerprint the node expects. Defaulting it would fail on the wire with no \
             log able to attribute the cause"
                .to_owned()
        })?;

        let server_name = server_name.unwrap_or_else(|| host.to_owned());
        if server_name.parse::<std::net::IpAddr>().is_ok() {
            return Err(format!(
                "vless:// REALITY link needs `?sni=…`: SNI names the site being \
                 impersonated, and {server_name} is an address"
            ));
        }

        let tag = fragment
            .map(percent_decode)
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            user_id: user_id.to_owned(),
            server,
            server_name,
            public_key,
            short_id,
            fingerprint,
            alpn: parse_alpn(alpn.as_deref())?,
            vision,
            tag,
        })
    }

    /// The node's address, for diagnostics.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The impersonated site, for diagnostics.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The fingerprint the node expects, for diagnostics.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The REALITY tag for the current time.
    fn auth(&self) -> Result<RealityAuth, String> {
        RealityAuth::new(
            &self.public_key,
            &self.short_id,
            std::time::SystemTime::now(),
        )
    }

    /// The VLESS request header.
    ///
    /// ```text
    ///   [version(1)=0] [uuid(16)] [addon_len(1)=0] [CMD(1)=1] [port(2)] [ATYP(1)] [addr] [payload…]
    /// ```
    fn request_header(&self, authority: &str) -> Result<Vec<u8>, String> {
        let uuid = parse_uuid(&self.user_id)?;
        let (host, port) = split_authority(authority)?;

        // The addons field is a length-prefixed protobuf `Addons { Flow = 1 }`. Declaring
        // the flow here is what makes the server accept the session: a node whose user is
        // configured for Vision refuses a client that leaves this empty.
        let addons = if self.vision {
            let mut protobuf = Vec::with_capacity(2 + FLOW_VISION.len());
            protobuf.push(0x0a); // field 1, wire type 2 (length-delimited)
            protobuf.push(FLOW_VISION.len() as u8);
            protobuf.extend_from_slice(FLOW_VISION.as_bytes());
            protobuf
        } else {
            Vec::new()
        };

        let mut header = Vec::with_capacity(1 + 16 + 1 + addons.len() + 1 + 2 + 1 + host.len());
        header.push(0); // version
        header.extend_from_slice(&uuid);
        header.push(addons.len() as u8);
        header.extend_from_slice(&addons);
        header.push(0x01); // CMD: TCP
        // VLESS builds its address parser with `protocol.PortThenAddress()`, so the layout
        // is `port(2) || atyp(1) || address`. `encode_address` is the shadowsocks form —
        // `atyp || address || port` — and appending it here wrote the port twice, which
        // shifted every following field by two bytes. The node then read our address
        // starting one byte late and dialled the resulting garbage: the lab inbound logged
        // `accepted tcp:[b65:7861:...]:80`.
        header.extend_from_slice(&port.to_be_bytes());
        // VLESS address types are its own: 1 = IPv4, 2 = domain, 3 = IPv6. Shadowsocks
        // numbers them differently (1 = IPv4, 3 = domain, 4 = IPv6), so the constant is
        // written here rather than borrowed from `shadowsocks::atyp`.
        const VLESS_ATYP_DOMAIN: u8 = 2;
        header.push(VLESS_ATYP_DOMAIN);
        header.push(
            u8::try_from(host.len())
                .map_err(|_| format!("destination host {host:?} is longer than 255 bytes"))?,
        );
        header.extend_from_slice(host.as_bytes());
        Ok(header)
    }

    /// The VLESS request header for UDP.
    pub fn request_header_udp(&self, authority: &str) -> Result<Vec<u8>, String> {
        let uuid = parse_uuid(&self.user_id)?;
        let (host, port) = split_authority(authority)?;

        let mut header = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + host.len());
        header.push(0); // version
        header.extend_from_slice(&uuid);
        header.push(0); // addons length = 0 (no flow for UDP)
        header.push(0x02); // CMD: UDP (0x02)
        header.extend_from_slice(&port.to_be_bytes());
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    header.push(1); // ATYP IPv4
                    header.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    header.push(3); // ATYP IPv6
                    header.extend_from_slice(&v6.octets());
                }
            }
        } else {
            header.push(2); // ATYP Domain
            header.push(
                u8::try_from(host.len())
                    .map_err(|_| format!("destination host {host:?} is longer than 255 bytes"))?,
            );
            header.extend_from_slice(host.as_bytes());
        }
        Ok(header)
    }
}

/// The REALITY connector.
#[derive(Clone)]
pub struct RealityConnector {
    link: Link,
    tcp: TcpConnector,
    timeout: Duration,
    /// `[global.tls] fragment`, or `None` to send the ClientHello in one write.
    fragment: Option<crate::fragment::Fragment>,
}

impl fmt::Debug for RealityConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityConnector")
            .field("link", &self.link)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl RealityConnector {
    /// Builds a connector from a `vless://security=reality` link.
    ///
    /// This is the **only** constructor of a REALITY session, which is what keeps the
    /// TLS 1.3 client unreachable from anywhere else.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundError::UnsupportedLink`] when the link does not parse or asks for
    /// a feature this build does not implement.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, OutboundError> {
        let parsed = Link::parse(link).map_err(OutboundError::UnsupportedLink)?;
        Ok(Self {
            link: parsed,
            tcp: TcpConnector::new()
                .with_connect_timeout(Some(options.timeout))
                .with_socket_config(options.socket_config()),
            timeout: options.timeout,
            fragment: options.fragment,
        })
    }

    /// The parsed link, for diagnostics.
    #[must_use]
    pub const fn link(&self) -> &Link {
        &self.link
    }

    /// Opens a REALITY session to `authority` (`host:port`).
    ///
    /// # Errors
    ///
    /// Returns [`OutboundError::Timeout`] when the deadline passes, and
    /// [`OutboundError::Connect`] for a TLS or handshake failure, carrying the reason.
    pub async fn connect(
        &self,
        authority: &str,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<Established, OutboundError> {
        let header = self
            .link
            .request_header(authority)
            .map_err(OutboundError::UnsupportedLink)?;
        let auth = self.link.auth().map_err(OutboundError::UnsupportedLink)?;

        // The TCP leg is netune's, so `SO_MARK` is applied before the SYN exactly like
        // every other dial. Only the TLS handshake above it is ours.
        let target = Target::plain(self.link.server.clone());
        let tcp = self
            .tcp
            .connect(&target, recorder)
            .await
            .map_err(|error| OutboundError::Connect(error.to_string()))?;
        let local_port = tcp.local_port;

        // `[global.tls] fragment`: slice the ClientHello so no single TCP segment carries the
        // pattern a middlebox matches. Applied here because a REALITY handshake is daer's own
        // (ADR-0010), which is the only place the setting can mean what it says.
        //
        // The two arms run the *whole* remaining exchange through one generic helper rather than
        // returning a `Tls13Connection<S>`: `S` differs between them, so an arm that only
        // handshaked would give the two branches different types.
        let uuid = parse_uuid(&self.link.user_id).map_err(OutboundError::UnsupportedLink)?;
        match self.fragment {
            Some(fragment) => {
                let stream = crate::fragment::FragmentingIo::new(tcp.stream, fragment);
                self.run(stream, &auth, &header, uuid, local_port).await
            }
            None => self.run(tcp.stream, &auth, &header, uuid, local_port).await,
        }
    }

    /// Runs the handshake and the VLESS exchange over `stream`.
    ///
    /// Generic over the stream so the caller can hand it either the bare TCP socket or the same
    /// socket wrapped in a [`FragmentingIo`](crate::fragment::FragmentingIo): the two cases have
    /// different types, and boxing them would need a trait object this crate does not control.
    async fn run<S>(
        &self,
        stream: S,
        auth: &RealityAuth,
        header: &[u8],
        uuid: [u8; 16],
        local_port: Option<u16>,
    ) -> Result<Established, OutboundError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let mut stream = self.handshake(stream, auth).await.map_err(|error| {
            OutboundError::Connect(format!(
                "REALITY handshake with {} (impersonating {}) failed: {error}",
                self.link.server, self.link.server_name
            ))
        })?;

        if std::env::var_os("DAER_HDR_TRACE").is_some() {
            eprintln!("vless header {} bytes: {:02x?}", header.len(), header);
        }
        if std::env::var_os("DAER_HDR_TRACE").is_some() {
            eprintln!("vless header {} bytes: {:02x?}", header.len(), header);
        }
        if self.link.vision {
            // The uplink is `header (unframed) || opening block || payload`, and the split
            // matters: the header must NOT go through the Vision writer, or it is framed and
            // the peer reads block bytes as a VLESS version.
            //
            // `tests/vision_lab.rs` pins the byte layout against a real `xray run` inbound:
            // the server logs `Xtls Unpadding new block, content 0 padding 900 command 0`
            // followed by `content N padding 0 command 1`, which is exactly the shape below.
            // Header and opening block go out as **one** write. The inbound reads its
            // first TCP segment into a single buffer (`firstLen`) and decodes the VLESS
            // header from *that*; with the header alone it gets `firstLen = 52`, decodes the
            // address correctly, and then reads the Vision stream from a socket that has no
            // block waiting yet — the lab server logged `firstLen = 52` followed by a reset.
            //
            // The reference produces this shape by writing the request header into a
            // buffered writer and wrapping that writer in a VisionWriter before the first
            // flush, so both land in the same segment.
            let mut stream = crate::reality::vision::VisionStream::new_answering(stream, uuid);
            let opening = stream.opening_block();
            let mut flight = Vec::with_capacity(header.len() + opening.len());
            flight.extend_from_slice(header);
            flight.extend_from_slice(&opening);
            // `write_through` writes `flight` verbatim: the header must not be framed, and
            // the opening block already is.
            if let Err(error) = stream.write_through(&flight).await {
                return Err(OutboundError::Connect(format!(
                    "write the VLESS request to {}: {error}",
                    self.link.server
                )));
            }
            if let Err(error) = stream.flush().await {
                return Err(OutboundError::Connect(format!(
                    "flush the VLESS request to {}: {error}",
                    self.link.server
                )));
            }
            let (read, write) = tokio::io::split(stream);
            return Ok(Established {
                stream: Box::new(SplitStream { read, write }),
                local_port,
                socket: None,
                alpn: None,
            });
        }

        // The VLESS header rides the first application record, so the node sees one
        // flight rather than two.
        if let Err(error) = stream.write_all(header).await {
            return Err(OutboundError::Connect(format!(
                "write the VLESS request to {}: {error}",
                self.link.server
            )));
        }

        let (read, write) = tokio::io::split(stream);
        Ok(Established {
            stream: Box::new(SplitStream { read, write }),
            local_port,
            socket: None,
            alpn: None,
        })
    }

    /// One TLS 1.3 handshake, with the deadline and the error the caller reports.
    async fn handshake<S>(
        &self,
        stream: S,
        auth: &RealityAuth,
    ) -> Result<Tls13Connection<S>, HandshakeError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match tokio::time::timeout(
            self.timeout,
            Tls13Connection::handshake(stream, &self.link.server_name, auth, &self.link.alpn),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(HandshakeError(format!(
                "no answer from {} within {:?}",
                self.link.server, self.timeout
            ))),
        }
    }

    /// Returns a [`DatagramConnector`] that carries UDP over this REALITY node.
    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        Arc::new(RealityDatagramConnector::new(self.clone()))
    }

    /// Opens a REALITY datagram session to `authority` (`host:port`).
    pub async fn connect_datagram(
        &self,
        authority: &str,
        recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<EstablishedDatagrams, NetError> {
        let header = self
            .link
            .request_header_udp(authority)
            .map_err(NetError::Protocol)?;
        let auth = self.link.auth().map_err(NetError::Protocol)?;

        let target = Target::plain(self.link.server.clone());
        let tcp = self
            .tcp
            .connect(&target, recorder)
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;
        let local_port = tcp.local_port;

        let mut stream = self
            .handshake(tcp.stream, &auth)
            .await
            .map_err(|error| NetError::Connect(format!("REALITY handshake failed: {error}")))?;

        stream
            .write_all(&header)
            .await
            .map_err(|e| NetError::Connect(format!("write VLESS UDP request header: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| NetError::Connect(format!("flush VLESS UDP request header: {e}")))?;

        let (r, w) = tokio::io::split(stream);
        let session = VlessDatagramSession::new(r, w);
        Ok(EstablishedDatagrams {
            datagrams: Box::new(session),
            local_port,
        })
    }
}

/// A datagram session over a VLESS stream.
pub struct VlessDatagramSession<R, W> {
    reader: tokio::sync::Mutex<VlessReader<R>>,
    writer: tokio::sync::Mutex<W>,
}

struct VlessReader<R> {
    stream: R,
    header_read: bool,
}

impl<R, W> fmt::Debug for VlessDatagramSession<R, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessDatagramSession")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RealityDatagramConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityDatagramConnector")
            .field("server", &self.connector.link().server())
            .finish()
    }
}

impl<R, W> VlessDatagramSession<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: tokio::sync::Mutex::new(VlessReader {
                stream: reader,
                header_read: false,
            }),
            writer: tokio::sync::Mutex::new(writer),
        }
    }
}

impl<R, W> DatagramTransport for VlessDatagramSession<R, W>
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
            writer.write_all(&len.to_be_bytes()).await?;
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
            if !reader.header_read {
                let mut resp_header = [0u8; 2];
                reader.stream.read_exact(&mut resp_header).await?;
                let addons_len = resp_header[1] as usize;
                if addons_len > 0 {
                    let mut addons = vec![0u8; addons_len];
                    reader.stream.read_exact(&mut addons).await?;
                }
                reader.header_read = true;
            }

            let mut len_bytes = [0u8; 2];
            reader.stream.read_exact(&mut len_bytes).await?;
            let len = u16::from_be_bytes(len_bytes) as usize;

            let buf_len = buffer.len();
            if len > buf_len {
                reader.stream.read_exact(&mut buffer[..buf_len]).await?;
                let remaining = len - buf_len;
                let mut discard = vec![0u8; remaining];
                reader.stream.read_exact(&mut discard).await?;
                Ok(buf_len)
            } else {
                reader.stream.read_exact(&mut buffer[..len]).await?;
                Ok(len)
            }
        })
    }

    fn max_datagram_size(&self) -> usize {
        65507
    }
}

/// A connector establishing datagram sessions over REALITY + VLESS.
#[derive(Clone)]
pub struct RealityDatagramConnector {
    connector: RealityConnector,
}

impl RealityDatagramConnector {
    #[must_use]
    pub const fn new(connector: RealityConnector) -> Self {
        Self { connector }
    }
}

impl DatagramConnector for RealityDatagramConnector {
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

/// A `Transport` over the split halves of a handshaken tunnel.
///
/// `tokio::io::split` is used rather than a `Sync`-by-lock wrapper: the relay reads and
/// writes from two tasks, and a lock around the whole stream would serialize them. The
/// inner type is a parameter because a Vision session wraps the TLS connection, and the
/// relay must not know which it got.
struct SplitStream<S> {
    read: tokio::io::ReadHalf<S>,
    write: tokio::io::WriteHalf<S>,
}

impl<S: tokio::io::AsyncRead> tokio::io::AsyncRead for SplitStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite> tokio::io::AsyncWrite for SplitStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

// ── Link helpers ────────────────────────────────────────────────────────────

/// Splits `host:port`, tolerating `[v6]:port`.
fn split_authority(authority: &str) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| format!("{authority:?} has an unclosed `[`"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| format!("{authority:?} has no port"))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("{authority:?} has an invalid port"))?;
        return Ok((host.to_owned(), port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("{authority:?} is not host:port"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("{authority:?} has an invalid port"))?;
    Ok((host.to_owned(), port))
}

/// Splits a `?alpn=h2,http/1.1` value into the protocol list the handshake offers.
///
/// An empty or absent value means "offer none", which is what a REALITY node that
/// forwards to a plain HTTPS site expects. A malformed entry is an error rather than a
/// silent drop: an ALPN the site does not speak changes what the flow looks like.
fn parse_alpn(text: Option<&str>) -> Result<Vec<Vec<u8>>, String> {
    let Some(text) = text else {
        return Ok(Vec::new());
    };
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|entry| {
            if entry.is_empty() || entry.len() > 255 {
                return Err(format!("alpn entry {entry:?} is empty or over 255 bytes"));
            }
            Ok(entry.as_bytes().to_vec())
        })
        .collect()
}

/// Decodes a base64url public key, with or without padding.
fn decode_public_key(text: &str) -> Result<[u8; 32], String> {
    let bytes = crate::subscription::decode_base64(text)
        .ok_or_else(|| format!("pbk {text:?} is not base64"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "pbk decodes to {} bytes; an X25519 public key is 32",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Decodes a short-id, which panels write as hex but sometimes as base64.
fn decode_short_id(text: &str) -> Result<Vec<u8>, String> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if text.len().is_multiple_of(2)
        && text.chars().all(|ch| ch.is_ascii_hexdigit())
        && let Ok(bytes) = (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16))
            .collect::<Result<Vec<_>, _>>()
    {
        return Ok(bytes);
    }
    // Fall back to base64 for a panel that wrote it that way.
    crate::subscription::decode_base64(text)
        .ok_or_else(|| format!("sid {text:?} is neither hex nor base64"))
}

/// Parses a UUID into its 16 bytes.
fn parse_uuid(text: &str) -> Result<[u8; 16], String> {
    let compact: String = text.chars().filter(|ch| *ch != '-').collect();
    if compact.len() != 32 {
        return Err(format!(
            "user id {text:?} is not a UUID ({} hex digits, need 32)",
            compact.len()
        ));
    }
    let mut out = [0u8; 16];
    for (index, chunk) in compact.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| "user id is not ASCII".to_owned())?;
        out[index] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("user id {text:?} is not hex"))?;
    }
    Ok(out)
}

/// Decodes `%XX` escapes.
fn percent_decode(text: &str) -> Result<String, String> {
    if !text.contains('%') {
        return Ok(text.to_owned());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .ok_or_else(|| format!("{text:?} has a truncated escape"))?;
            let hex = std::str::from_utf8(hex).map_err(|_| "escape is not ASCII".to_owned())?;
            out.push(
                u8::from_str_radix(hex, 16).map_err(|_| format!("{text:?} has a bad escape"))?,
            );
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("{text:?} is not UTF-8 after decoding"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";

    fn link(query: &str) -> String {
        format!("vless://11111111-2222-3333-4444-555555555555@node.example.com:443?{query}#tokyo")
    }

    #[test]
    fn a_complete_reality_link_parses() {
        let parsed = Link::parse(&link(&format!(
            "security=reality&pbk={PUBLIC_KEY}&sid=0123abcd&sni=www.microsoft.com&fp=chrome"
        )))
        .expect("parses");
        assert_eq!(parsed.server, "node.example.com:443");
        assert_eq!(parsed.server_name, "www.microsoft.com");
        assert_eq!(parsed.fingerprint, "chrome");
        assert_eq!(parsed.short_id, vec![0x01, 0x23, 0xab, 0xcd]);
        assert_eq!(parsed.tag, "tokyo");
    }

    #[test]
    fn a_link_without_pbk_is_refused_by_name() {
        let error = Link::parse(&link("security=reality&fp=chrome")).expect_err("must fail");
        assert!(error.contains("pbk"), "{error}");
    }

    #[test]
    fn a_link_without_fp_is_refused_rather_than_defaulted() {
        // The failure this prevents: a handshake that fails on the wire for a reason no
        // log can attribute to the fingerprint.
        let error = Link::parse(&link(&format!("security=reality&pbk={PUBLIC_KEY}")))
            .expect_err("must fail");
        assert!(error.contains("fp"), "{error}");
        assert!(error.contains("fingerprint"), "{error}");
    }

    #[test]
    fn a_vision_flow_is_understood_and_declared_in_the_addons() {
        // A node whose user is configured for Vision refuses a client that omits it, so the
        // flow has to reach the wire — not merely be tolerated by the parser.
        let parsed = Link::parse(&link(&format!(
            "security=reality&pbk={PUBLIC_KEY}&fp=chrome&flow=xtls-rprx-vision"
        )))
        .expect("parses");
        assert!(parsed.vision);

        let header = parsed.request_header("example.com:443").expect("builds");
        assert_eq!(header[17], 2 + FLOW_VISION.len() as u8, "addons length");
        assert_eq!(header[18], 0x0a, "protobuf field 1, length-delimited");
        assert_eq!(header[19], FLOW_VISION.len() as u8);
        assert_eq!(&header[20..20 + FLOW_VISION.len()], FLOW_VISION.as_bytes());
    }

    #[test]
    fn a_flowless_link_declares_no_addons() {
        let parsed = Link::parse(&link(&format!(
            "security=reality&pbk={PUBLIC_KEY}&fp=chrome"
        )))
        .expect("parses");
        assert!(!parsed.vision);
        let header = parsed.request_header("example.com:443").expect("builds");
        assert_eq!(header[17], 0, "an empty addons length");
        assert_eq!(header[18], 0x01, "CMD follows immediately");
    }

    #[test]
    fn an_unknown_flow_is_refused_by_name() {
        // Vision and "no flow" are not interchangeable, so a third value cannot be guessed.
        let error = Link::parse(&link(&format!(
            "security=reality&pbk={PUBLIC_KEY}&fp=chrome&flow=xtls-rprx-direct"
        )))
        .expect_err("must fail");
        assert!(error.contains("xtls-rprx-direct"), "{error}");
        assert!(error.contains(FLOW_VISION), "{error}");
    }

    #[test]
    fn a_wrapping_transport_is_refused_rather_than_ignored() {
        // Ignoring `type=ws` would connect and then send nonsense.
        let error = Link::parse(&link(&format!(
            "security=reality&pbk={PUBLIC_KEY}&fp=chrome&type=ws"
        )))
        .expect_err("must fail");
        assert!(error.contains("ws"), "{error}");
    }

    #[test]
    fn a_plain_vless_link_is_not_this_connector() {
        let error = Link::parse(&link("security=tls&sni=a.example")).expect_err("must fail");
        assert!(error.contains("security=reality"), "{error}");
    }

    #[test]
    fn an_ip_sni_is_refused() {
        let error = Link::parse(&link(&format!(
            "security=reality&pbk={PUBLIC_KEY}&fp=chrome&sni=1.2.3.4"
        )))
        .expect_err("must fail");
        assert!(error.contains("sni"), "{error}");
    }

    #[test]
    fn a_uuid_is_parsed_into_sixteen_bytes() {
        let uuid = parse_uuid("11111111-2222-3333-4444-555555555555").expect("parses");
        assert_eq!(uuid[0], 0x11);
        assert_eq!(uuid[15], 0x55);
        assert!(parse_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn a_public_key_must_decode_to_32_bytes() {
        assert!(decode_public_key(PUBLIC_KEY).is_ok());
        assert!(decode_public_key("AAAA").is_err());
        assert!(decode_public_key("!!!").is_err());
    }

    #[test]
    fn a_short_id_accepts_hex_and_base64() {
        assert_eq!(decode_short_id("abcd").expect("hex"), vec![0xab, 0xcd]);
        assert_eq!(decode_short_id("").expect("empty"), Vec::<u8>::new());
        assert!(decode_short_id("q80").is_ok(), "base64 falls through");
    }

    #[test]
    fn percent_escapes_in_a_tag_are_decoded() {
        // `link()` already appends `#tokyo`; the escape has to sit in that fragment.
        let parsed = Link::parse(&format!(
            "vless://11111111-2222-3333-4444-555555555555@node.example.com:443\
             ?security=reality&pbk={PUBLIC_KEY}&fp=chrome#my%20node"
        ))
        .expect("parses");
        assert_eq!(parsed.tag, "my node");
    }

    #[test]
    fn the_request_header_is_vless_shaped() {
        let parsed = Link::parse(&link(&format!(
            "security=reality&pbk={PUBLIC_KEY}&fp=chrome"
        )))
        .expect("parses");
        let header = parsed.request_header("example.com:443").expect("builds");

        // version(1) uuid(16) addons_len(1) cmd(1) port(2) atyp(1) len(1) host
        assert_eq!(header[0], 0, "version");
        assert_eq!(header[17], 0, "addon length");
        assert_eq!(header[18], 0x01, "CMD is TCP");
        // VLESS builds its address parser with `PortThenAddress`, so the port precedes the
        // address. Writing the shadowsocks form (`atyp || addr || port`) instead put the port
        // in twice and shifted every later field by two bytes: the node then dialled a
        // garbage address and the session died after a successful handshake.
        assert_eq!(&header[19..21], &443u16.to_be_bytes(), "port comes first");
        assert_eq!(
            header[21], 2,
            "ATYP is a domain (VLESS numbers it 2, not 3)"
        );
        assert_eq!(header[22], 11, "domain length");
        assert_eq!(&header[23..], b"example.com", "and the host is last");
        assert_eq!(header.len(), 23 + 11, "nothing follows the host");
    }

    #[test]
    fn the_debug_output_names_the_impersonated_site_not_the_credential() {
        let parsed = Link::parse(&link(&format!(
            "security=reality&pbk={PUBLIC_KEY}&sni=www.microsoft.com&fp=chrome"
        )))
        .expect("parses");
        let rendered = format!("{parsed:?}");
        assert!(rendered.contains("www.microsoft.com"), "{rendered}");
        assert!(rendered.contains("chrome"), "{rendered}");
        assert!(
            !rendered.contains("11111111-2222"),
            "the user id must not be printed: {rendered}"
        );
    }

    #[test]
    fn only_a_reality_link_constructs_a_connector() {
        // The scope decision, asserted: a plain vless link cannot reach the TLS 1.3 client.
        assert!(
            RealityConnector::from_link(
                &link("security=tls&sni=a.example"),
                DialerOptions::new(None, Duration::from_secs(1)),
            )
            .is_err()
        );
        assert!(
            RealityConnector::from_link(
                &link(&format!("security=reality&pbk={PUBLIC_KEY}&fp=chrome")),
                DialerOptions::new(None, Duration::from_secs(1)),
            )
            .is_ok()
        );
    }
}
