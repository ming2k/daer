// SPDX-License-Identifier: AGPL-3.0-only

//! The VLESS connector: ADR-0028's layer composition, in one place.
//!
//! ```text
//!   dial ──▶ Transport (tcp | ws)          ──▶ byte stream
//!         ──▶ Security  (none | tls | reality) ──▶ opaque stream
//!         ──▶ request header                ──▶ the node knows where to dial
//!         ──▶ Flow      (none | vision)     ──▶ padded stream
//! ```
//!
//! # Why the header and the opening Vision block go out as one write
//!
//! The node reads its first TCP segment into a single buffer and decodes the VLESS header
//! from *that*. A client that writes the 52-byte header alone gets `firstLen = 52`, a
//! correctly decoded address, and then a reset — the Vision stream it tries to read from has
//! no block waiting yet. The reference produces the combined shape by writing the request
//! header into a buffered writer and wrapping that writer in a `VisionWriter` before the
//! first flush, so both land in one segment. This does the same thing explicitly.
//!
//! # UDP
//!
//! A UDP flow is a separate session whose payload is `[len 2][datagram]` framed
//! (`MultiLengthPacketWriter` in the reference). Vision does not apply: the reference refuses
//! a `RequestCommandUDP` under `xtls-rprx-vision` at the inbound, and its outbound rewrites a
//! Vision UDP flow into XUDP instead. daer takes the first branch — a Vision node's UDP is
//! refused with that reason rather than silently sent in a shape the node will drop.

use std::sync::Arc;
use std::time::Duration;

use netune::{
    DatagramConnector, DatagramTransport, Established, EstablishedDatagrams, NetError, Transport,
};
use netune_trace::TraceCollector;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::error::ProxyProtocolError;
use crate::options::DialerOptions;
use crate::security::{Opaque, Security};
use crate::server::ServerDialer;
use crate::transport::TransportLayer;
use crate::vless::response::ResponseHeaderStream;
use crate::vless::vision::VisionStream;
use crate::vless::{Command, Flow, Request, encode_request, parse_uuid};

/// A VLESS node, with its layers already resolved.
#[derive(Clone)]
pub struct VlessConnector {
    /// `host:port` of the node.
    server: String,
    /// The host without the port, for SNI and for a WebSocket `Host`.
    host: String,
    parsed_uuid: [u8; 16],
    flow: Flow,
    security: Security,
    transport: TransportLayer,
    base: Arc<dyn ServerDialer>,
    timeout: Duration,
    fragment: Option<crate::fragment::Fragment>,
}

impl std::fmt::Debug for VlessConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The uuid is a credential and the REALITY public key identifies the node; neither
        // is printed. The layers and the address are what a reader needs.
        f.debug_struct("VlessConnector")
            .field("server", &self.server)
            .field("security", &self.security.kind())
            .field("transport", &self.transport.kind())
            .field("flow", &self.flow.as_str())
            .finish_non_exhaustive()
    }
}

/// Typed parameters for a VLESS node.
#[derive(Debug, Clone)]
pub struct VlessParams<'a> {
    pub server: &'a str,
    pub port: u16,
    pub uuid: &'a str,
    pub flow: Flow,
    pub security: Security,
    pub transport: TransportLayer,
}

impl VlessConnector {
    /// Builds a connector from typed parameters.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyProtocolError::UnsupportedLink`] when the uuid is malformed or the flow
    /// is illegal on the chosen security layer — both are load-time facts, and neither is
    /// recoverable at connect time.
    pub fn new(
        params: VlessParams<'_>,
        options: DialerOptions,
    ) -> Result<Self, ProxyProtocolError> {
        let parsed_uuid = parse_uuid(params.uuid).map_err(ProxyProtocolError::UnsupportedLink)?;
        if params.flow.is_vision() && !params.security.can_splice() {
            return Err(ProxyProtocolError::UnsupportedLink(format!(
                "flow = {:?} needs a security layer with a record layer to splice; a plaintext \
                 node cannot use Vision (the reference refuses it too: \"XTLS only supports TLS \
                 and REALITY directly for now\")",
                params.flow.as_str()
            )));
        }
        // Vision splices the record layer, so TLS or REALITY has to be the thing *directly* under
        // the protocol. A `ws`-wrapped connection is neither `*tls.Conn` nor `*reality.UConn` in
        // the reference, and `inbound.go` answers exactly that error — so this combination is
        // refused here rather than at the node, where it would look like a rejected credential.
        if params.flow.is_vision() && !matches!(params.transport, TransportLayer::Tcp) {
            return Err(ProxyProtocolError::UnsupportedLink(format!(
                "flow = {:?} needs TLS or REALITY directly under the protocol, but \
                 transport.type = \"{}\" wraps the record layer (the reference refuses this: \
                 \"XTLS only supports TLS and REALITY directly for now\")",
                params.flow.as_str(),
                params.transport.kind()
            )));
        }
        Ok(Self {
            server: format!("{}:{}", params.server, params.port),
            host: params.server.to_owned(),
            parsed_uuid,
            flow: params.flow,
            security: params.security,
            transport: params.transport,
            base: options.base().clone(),
            timeout: options.timeout,
            fragment: options.fragment,
        })
    }

    /// The node's address, for diagnostics.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The flow this node declares.
    #[must_use]
    pub const fn flow(&self) -> Flow {
        self.flow
    }

    /// The security layer this node applies.
    #[must_use]
    pub const fn security(&self) -> &Security {
        &self.security
    }

    /// Opens a VLESS session to `authority` (`host:port`).
    pub async fn connect(
        &self,
        authority: &str,
        recorder: &TraceCollector,
    ) -> Result<Established, ProxyProtocolError> {
        let header = encode_request(&Request {
            uuid: self.parsed_uuid,
            command: Command::Tcp,
            flow: self.flow,
            authority,
        })?;

        let (opaque, local_port) = self.open_stream(recorder).await?;
        let alpn_protocol = opaque.alpn_protocol.clone();
        let alpn = alpn_protocol
            .as_deref()
            .map(|name| netune_trace::Alpn::from_name(Some(name)));
        let stream = self.write_head(opaque, &header).await.map_err(|error| {
            ProxyProtocolError::Connect(format!(
                "write the VLESS request to {}: {error}",
                self.server
            ))
        })?;

        Ok(Established {
            stream,
            local_port,
            socket: None,
            alpn,
            alpn_protocol,
        })
    }

    /// Writes the request head through the opaque stream, applying the flow to the payload.
    async fn write_head(
        &self,
        opaque: Opaque,
        header: &[u8],
    ) -> std::io::Result<Box<dyn Transport>> {
        let Opaque {
            stream,
            raw_read,
            alpn: _,
            alpn_protocol: _,
        } = opaque;

        // The node precedes its payload with `version || addon_len || addons`, and the reference
        // consumes that header in `DecodeResponseHeader` before handing the connection to the body
        // decoder. A layer rather than an eager read, because a node may wait for the request
        // payload before answering at all (`vless::response`).
        let stream: Box<dyn Transport> = Box::new(ResponseHeaderStream::new(stream));

        if !self.flow.is_vision() {
            let mut stream = stream;
            stream.write_all(header).await?;
            stream.flush().await?;
            return Ok(stream);
        }

        // Wrap so Vision sees the record layer it may have to switch off. The wrapper is not
        // split: a `ReadHalf` would give the switch no way back to the layer underneath, and
        // a downlink `Direct` has to reach it.
        let mut stream = VisionStream::new_answering(stream, self.parsed_uuid, raw_read);
        let opening = stream.opening_block();
        let mut flight = Vec::with_capacity(header.len() + opening.len());
        flight.extend_from_slice(header);
        flight.extend_from_slice(&opening);
        // `write_through` writes verbatim: the header is not a Vision block, and the opening
        // block already is one. Framing them again makes the peer read block bytes as a
        // VLESS version.
        stream.write_through(&flight).await?;
        stream.flush().await?;
        Ok(Box::new(stream))
    }

    /// Dials, upgrades the transport, and applies the security layer.
    async fn open_stream(
        &self,
        recorder: &TraceCollector,
    ) -> Result<(Opaque, Option<u16>), ProxyProtocolError> {
        let established = self
            .base
            .connect(&self.server, recorder)
            .await
            .map_err(|error| match error {
                ProxyProtocolError::Timeout => ProxyProtocolError::Timeout,
                other => ProxyProtocolError::Connect(other.to_string()),
            })?;
        let local_port = established.local_port;

        // ADR-0028's order is security **then** transport, which is the opposite of what the
        // configuration names suggest: `network = "ws"` with `security = "tls"` is `wss://`, so
        // the upgrade request travels inside the tunnel. A node that receives a plaintext `GET`
        // answers `HTTP/1.0 400 Bad Request` (Go's TLS listener's reply to a non-TLS first
        // record), which is exactly what `tests/layer_matrix.rs` caught.
        //
        // REALITY's ClientHello is the only handshake daer writes, so `fragment` can only be
        // honoured on that layer — and it has to slice the *socket*, which is why it wraps the
        // stream before the security layer sees it.
        let opaque = match (&self.fragment, &self.security) {
            (Some(fragment), Security::Reality(_)) => {
                let stream = crate::fragment::FragmentingIo::new(established.stream, *fragment);
                self.security
                    .wrap(stream, &self.host, recorder, self.timeout)
                    .await?
            }
            _ => {
                self.security
                    .wrap(established.stream, &self.host, recorder, self.timeout)
                    .await?
            }
        };

        // The transport sits above: a `ws` upgrade is HTTP inside the secured stream.
        let raw_read = opaque.raw_read;
        let stream = self
            .transport
            .wrap(
                opaque.stream,
                &self.host,
                self.security.sni_hint(),
                recorder,
                self.timeout,
            )
            .await?;
        Ok((
            Opaque {
                stream,
                raw_read,
                alpn: opaque.alpn,
                alpn_protocol: opaque.alpn_protocol,
            },
            local_port,
        ))
    }

    /// Opens the bare TCP stream to this VLESS server, before the protocol handshake.
    pub async fn connect_server(
        &self,
        recorder: &TraceCollector,
    ) -> Result<Established, ProxyProtocolError> {
        self.base.connect(&self.server, recorder).await
    }

    /// Returns a [`DatagramConnector`] that carries UDP over this VLESS node.
    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        Arc::new(VlessDatagramConnector::new(self.clone()))
    }

    /// Opens a VLESS UDP session.
    ///
    /// # Errors
    ///
    /// Refuses a Vision node's UDP with that reason: the reference closes the flow rather
    /// than send a shape the node drops.
    pub async fn connect_datagram(
        &self,
        authority: &str,
        recorder: &TraceCollector,
    ) -> Result<EstablishedDatagrams, NetError> {
        if self.flow.is_vision() {
            return Err(NetError::Protocol(format!(
                "node {} declares flow = {:?}: the reference refuses UDP under \
                 xtls-rprx-vision (it rewrites the flow to XUDP instead, which daer does not \
                 implement). Use flow = \"none\" for a node that must carry UDP, or declare \
                 flow = \"xtls-rprx-vision-udp443\" if the node is configured for it",
                self.server,
                self.flow.as_str()
            )));
        }

        let header = encode_request(&Request {
            uuid: self.parsed_uuid,
            command: Command::Udp,
            flow: Flow::None,
            authority,
        })
        .map_err(|error| NetError::Protocol(error.to_string()))?;

        let (opaque, local_port) = self
            .open_stream(recorder)
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;
        let mut stream = opaque.stream;
        stream
            .write_all(&header)
            .await
            .map_err(|error| NetError::Connect(format!("write VLESS UDP header: {error}")))?;
        stream
            .flush()
            .await
            .map_err(|error| NetError::Connect(format!("flush VLESS UDP header: {error}")))?;

        // The response header (`version || addon_len || addons`) precedes the first datagram,
        // so it is consumed once rather than by every `recv`.
        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|error| NetError::Connect(format!("read VLESS response header: {error}")))?;
        if response[0] != 0 {
            return Err(NetError::Protocol(format!(
                "VLESS response version {} is not 0",
                response[0]
            )));
        }
        if response[1] > 0 {
            let mut addons = vec![0u8; response[1] as usize];
            stream.read_exact(&mut addons).await.map_err(|error| {
                NetError::Connect(format!("read VLESS response addons: {error}"))
            })?;
        }

        Ok(EstablishedDatagrams {
            datagrams: Box::new(VlessDatagramSession::new(stream)),
            local_port,
        })
    }
}

/// The datagram connector a [`VlessConnector`] hands to the relay.
pub struct VlessDatagramConnector {
    connector: VlessConnector,
}

impl VlessDatagramConnector {
    #[must_use]
    pub const fn new(connector: VlessConnector) -> Self {
        Self { connector }
    }
}

impl std::fmt::Debug for VlessDatagramConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessDatagramConnector")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl DatagramConnector for VlessDatagramConnector {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a TraceCollector,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>,
    > {
        let connector = self.connector.clone();
        let authority = authority.to_owned();
        Box::pin(async move { connector.connect_datagram(&authority, recorder).await })
    }
}

/// A UDP session over a VLESS stream: `[len 2][payload]` in each direction.
pub struct VlessDatagramSession {
    stream: tokio::sync::Mutex<Box<dyn Transport>>,
}

impl std::fmt::Debug for VlessDatagramSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessDatagramSession")
            .finish_non_exhaustive()
    }
}

impl VlessDatagramSession {
    #[must_use]
    pub fn new(stream: Box<dyn Transport>) -> Self {
        Self {
            stream: tokio::sync::Mutex::new(stream),
        }
    }
}

impl DatagramTransport for VlessDatagramSession {
    fn max_datagram_size(&self) -> usize {
        // `MultiLengthPacketWriter` skips anything whose `length + 2 > buf.Size`, and the
        // reference's `buf.Size` is 8192.
        8190
    }

    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<usize, std::io::Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            let length = u16::try_from(payload.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "a VLESS datagram cannot exceed 65535 bytes",
                )
            })?;
            let mut stream = self.stream.lock().await;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(payload).await?;
            stream.flush().await?;
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
            let mut stream = self.stream.lock().await;
            let mut length_bytes = [0u8; 2];
            stream.read_exact(&mut length_bytes).await?;
            let length = u16::from_be_bytes(length_bytes) as usize;
            if length <= buffer.len() {
                stream.read_exact(&mut buffer[..length]).await?;
                return Ok(length);
            }
            // Drain the surplus so the stream stays framed, then report: returning a
            // truncated datagram would corrupt the caller's view of the flow, and returning
            // `length` would claim bytes that were never written.
            let keep = buffer.len();
            stream.read_exact(&mut buffer[..keep]).await?;
            let mut discard = vec![0u8; length - keep];
            stream.read_exact(&mut discard).await?;
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "a VLESS datagram of {length} bytes does not fit a {keep} byte buffer; it \
                     was discarded"
                ),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vision_on_a_plaintext_node_is_refused_with_the_references_reason() {
        // Accepting this would produce a session that authenticates and then deadlocks, so
        // it is refused at construction — which is load time for every real caller.
        let error = VlessConnector::new(
            VlessParams {
                server: "node.example.com",
                port: 443,
                uuid: "df4af3d0-030e-4062-baa6-eb9dd45298ef",
                flow: Flow::Vision,
                security: Security::None,
                transport: TransportLayer::Tcp,
            },
            DialerOptions::new(None, Duration::from_secs(1)),
        )
        .expect_err("vision needs a record layer");
        assert!(error.to_string().contains("record layer"), "{error}");
    }

    #[test]
    fn a_malformed_uuid_is_a_load_error() {
        let error = VlessConnector::new(
            VlessParams {
                server: "node.example.com",
                port: 443,
                uuid: "not-a-uuid",
                flow: Flow::None,
                security: Security::None,
                transport: TransportLayer::Tcp,
            },
            DialerOptions::new(None, Duration::from_secs(1)),
        )
        .expect_err("uuid must parse");
        assert!(error.to_string().contains("UUID"), "{error}");
    }

    #[test]
    fn the_debug_rendering_names_the_layers_and_not_the_credential() {
        let connector = VlessConnector::new(
            VlessParams {
                server: "node.example.com",
                port: 443,
                uuid: "df4af3d0-030e-4062-baa6-eb9dd45298ef",
                flow: Flow::Vision,
                security: Security::Tls(crate::security::tls::TlsParams {
                    server_name: Some("cdn.example.com".to_owned()),
                    allow_insecure: false,
                    alpn: Vec::new(),
                    fingerprint: None,
                }),
                transport: TransportLayer::Tcp,
            },
            DialerOptions::new(None, Duration::from_secs(1)),
        )
        .expect("builds");
        let rendered = format!("{connector:?}");
        assert!(rendered.contains("tls"), "{rendered}");
        assert!(rendered.contains("xtls-rprx-vision"), "{rendered}");
        assert!(
            !rendered.contains("df4af3d0"),
            "the uuid is a credential: {rendered}"
        );
    }
}
