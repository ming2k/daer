// SPDX-License-Identifier: AGPL-3.0-only

//! The VMess connector: ADR-0028's composition for ADR-0030's protocol.
//!
//! ```text
//!   dial ──▶ Transport (tcp | ws)          ──▶ byte stream
//!         ──▶ Security  (none | tls)           ──▶ opaque stream
//!         ──▶ AuthID + sealed request header   ──▶ the node accepts the session
//!         ──▶ response header                  ──▶ the node's reply is authenticated
//!         ──▶ chunk stream / packet stream     ──▶ the tunnel
//! ```
//!
//! # The two planes
//!
//! A TCP flow is `TransferTypeStream`: the payload is a chunk stream, and a write of N bytes may
//! become several chunks. A UDP flow is `TransferTypePacket`: **one chunk is one datagram**, so
//! the reader returns one chunk per call and the writer emits one chunk per datagram. Getting
//! that backwards makes a UDP flow that silently coalesces packets, which is how a DNS resolver
//! ends up answering the wrong query.
//!
//! # Mux
//!
//! `RequestCommandMux` (`v1.mux.cool`) is not implemented. The reference uses it for XUDP, for
//! multiplexing many flows over one connection, and for Vision-bound UDP; daer speaks none of
//! that, and the reference's own UDP path without mux is a `RequestCommandUDP` with packet
//! transfer — which is what this does. A node that *requires* mux cannot be used, and the
//! connector says so rather than sending a request the node answers with a mux handshake this
//! side cannot parse.

use std::sync::Arc;
use std::time::Duration;

use netune::{DatagramConnector, Established, EstablishedDatagrams, NetError, Transport};
use netune_trace::TraceCollector;
use tokio::io::AsyncWriteExt;

use crate::error::ProxyProtocolError;
use crate::options::DialerOptions;
use crate::security::{Opaque, Security};
use crate::server::ServerDialer;
use crate::transport::TransportLayer;
use crate::vmess::aead::{create_auth_id, seal_header};
use crate::vmess::chunk::{Cipher, SizeMode};
use crate::vmess::header::{self, Command, Session};
use crate::vmess::kdf::cmd_key;
use crate::vmess::response::ResponseHeaderStream;
use crate::vmess::stream::{ChunkStream, PacketStream};

/// A VMess node, with its layers already resolved.
#[derive(Clone)]
pub struct VmessConnector {
    server: String,
    host: String,
    cmd_key: [u8; 16],
    cipher: Cipher,
    /// The options byte the request declares.
    options: u8,
    security: Security,
    transport: TransportLayer,
    base: Arc<dyn ServerDialer>,
    timeout: Duration,
    /// The reference's `NoTerminationSignal` account flag (`vmess`'s `no-termination-signal`).
    termination_signal: bool,
}

impl std::fmt::Debug for VmessConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The `cmdKey` is derived from the uuid and is a credential; the layers and the address
        // are what a reader needs.
        f.debug_struct("VmessConnector")
            .field("server", &self.server)
            .field("security", &self.security.kind())
            .field("transport", &self.transport.kind())
            .field(
                "cipher",
                &match self.cipher {
                    Cipher::Aes128Gcm => "aes-128-gcm",
                    Cipher::Chacha20Poly1305 => "chacha20-poly1305",
                },
            )
            .finish_non_exhaustive()
    }
}

/// Typed parameters for a VMess node.
#[derive(Debug, Clone)]
pub struct VmessParams<'a> {
    pub server: &'a str,
    pub port: u16,
    pub uuid: &'a str,
    pub cipher: daer_config::VmessCipher,
    pub authenticated_length: bool,
    pub no_termination_signal: bool,
    pub security: Security,
    pub transport: TransportLayer,
}

impl VmessConnector {
    /// Builds a connector from typed parameters.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyProtocolError::UnsupportedLink`] when the uuid is malformed, when the
    /// cipher does not match the chosen security layer, or when REALITY is asked for — VMess has
    /// no REALITY client in the reference either (ADR-0030).
    pub fn new(
        params: VmessParams<'_>,
        options: DialerOptions,
    ) -> Result<Self, ProxyProtocolError> {
        let uuid =
            crate::vless::parse_uuid(params.uuid).map_err(ProxyProtocolError::UnsupportedLink)?;
        if matches!(params.security, Security::Reality(_)) {
            return Err(ProxyProtocolError::UnsupportedLink(
                "vmess.security.type = \"reality\" is not a combination the reference implements; \
                 REALITY authenticates a vless flow"
                    .to_owned(),
            ));
        }

        let cipher = match params.cipher {
            daer_config::VmessCipher::Auto => match header::Security::auto() {
                header::Security::Aes128Gcm => Cipher::Aes128Gcm,
                header::Security::Chacha20Poly1305 => Cipher::Chacha20Poly1305,
            },
            daer_config::VmessCipher::Aes128Gcm => Cipher::Aes128Gcm,
            daer_config::VmessCipher::Chacha20Poly1305 => Cipher::Chacha20Poly1305,
        };

        // `RequestOptionChunkStream` is always set, because the body is always chunked: a VMess
        // stream without it is the legacy unframed format, which daer does not speak.
        let mut option = header::option::CHUNK_STREAM;
        // `shouldEnablePadding`: the reference enables chunk masking for both AEAD ciphers, and
        // global padding only when masking is on.
        option |= header::option::CHUNK_MASKING;
        option |= header::option::GLOBAL_PADDING;
        if params.authenticated_length {
            option |= header::option::AUTHENTICATED_LENGTH;
        }

        Ok(Self {
            server: format!("{}:{}", params.server, params.port),
            host: params.server.to_owned(),
            cmd_key: cmd_key(&uuid),
            cipher,
            options: option,
            security: params.security,
            transport: params.transport,
            base: options.base().clone(),
            timeout: options.timeout,
            termination_signal: !params.no_termination_signal,
        })
    }

    /// The node's address, for diagnostics.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The security layer this node applies.
    #[must_use]
    pub const fn security(&self) -> &Security {
        &self.security
    }

    /// Opens a VMess TCP session to `authority` (`host:port`).
    pub async fn connect(
        &self,
        authority: &str,
        recorder: &TraceCollector,
    ) -> Result<Established, ProxyProtocolError> {
        let (stream, session, local_port, alpn, alpn_protocol) =
            self.open(authority, Command::Tcp, recorder).await?;
        // The response header is consumed on the first read, not here: the node buffers it until
        // the *target* produces data, so an eager read deadlocks a caller that has not sent its
        // payload yet (`vmess::response`).
        let stream: Box<dyn Transport> = Box::new(ChunkStream::new(
            Box::new(ResponseHeaderStream::new(stream, session.clone())),
            self.cipher,
            session.body_key,
            session.body_iv,
            SizeMode::from_options(self.options),
            self.options,
            self.termination_signal,
        ));
        Ok(Established {
            stream,
            local_port,
            socket: None,
            alpn,
            alpn_protocol,
        })
    }

    /// Opens the bare TCP stream to this VMess server, before the protocol handshake.
    pub async fn connect_server(
        &self,
        recorder: &TraceCollector,
    ) -> Result<Established, ProxyProtocolError> {
        self.base.connect(&self.server, recorder).await
    }

    /// Returns a [`DatagramConnector`] that carries UDP over this VMess node.
    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        Arc::new(VmessDatagramConnector::new(self.clone()))
    }

    /// Opens a VMess UDP session.
    ///
    /// One chunk is one datagram (`TransferTypePacket`), so the session's `send` seals one chunk
    /// per datagram and `recv` opens one chunk per call.
    pub async fn connect_datagram(
        &self,
        authority: &str,
        recorder: &TraceCollector,
    ) -> Result<EstablishedDatagrams, NetError> {
        let (stream, session, local_port, _alpn, _alpn_protocol) = self
            .open(authority, Command::Udp, recorder)
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;

        let packets = PacketStream::new(
            Box::new(ResponseHeaderStream::new(stream, session.clone())),
            self.cipher,
            session.body_key,
            session.body_iv,
            SizeMode::from_options(self.options),
            self.options,
        );
        Ok(EstablishedDatagrams {
            datagrams: Box::new(packets),
            local_port,
        })
    }

    /// Dials, applies the layers, and writes the sealed request header.
    async fn open(
        &self,
        authority: &str,
        command: Command,
        recorder: &TraceCollector,
    ) -> Result<
        (
            BoundedStream,
            Session,
            Option<u16>,
            Option<netune_trace::Alpn>,
            Option<Vec<u8>>,
        ),
        ProxyProtocolError,
    > {
        let session = Session::new();
        let security = match self.cipher {
            Cipher::Aes128Gcm => header::Security::Aes128Gcm,
            Cipher::Chacha20Poly1305 => header::Security::Chacha20Poly1305,
        };
        let plain = header::encode_request(&header::Request {
            session: &session,
            command,
            security,
            option: self.options,
            authority,
        })
        .map_err(ProxyProtocolError::UnsupportedLink)?;

        let auth_id = create_auth_id(&self.cmd_key, unix_now(), random_four());
        let nonce = random_eight();
        let sealed = seal_header(&self.cmd_key, &plain, auth_id, nonce);

        let (opaque, local_port) = self.open_stream(recorder).await?;
        let alpn_protocol = opaque.alpn_protocol.clone();
        let alpn = alpn_protocol
            .as_deref()
            .map(|name| netune_trace::Alpn::from_name(Some(name)));
        let mut stream: BoundedStream = opaque.stream;
        stream.write_all(&sealed).await.map_err(|error| {
            ProxyProtocolError::Connect(format!(
                "write the VMess request to {}: {error}",
                self.server
            ))
        })?;
        stream.flush().await.map_err(|error| {
            ProxyProtocolError::Connect(format!(
                "flush the VMess request to {}: {error}",
                self.server
            ))
        })?;
        Ok((stream, session, local_port, alpn, alpn_protocol))
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

        // `tls.fragment` slices a handshake daer writes. VMess over plain TLS rides
        // netune's rustls handshake, which daer cannot slice, and VMess has no REALITY layer at
        // all — so the setting cannot be honoured here. `DialerOptions::fragment` is documented
        // as applying only to a layer whose ClientHello daer owns, and the daemon reports which
        // nodes those are rather than half-applying the setting (`fragment.rs`'s module note).
        let opaque = self
            .security
            .wrap(established.stream, &self.host, recorder, self.timeout)
            .await?;

        // Security then transport (ADR-0028): a `ws` upgrade is HTTP inside the secured stream.
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
}

/// The dialled stream, boxed so the protocol layers above it name one type.
///
/// It used to carry a per-read deadline; that moved out when the response header became lazy
/// (`vmess::response`). An eager read needed a deadline of its own because it was the one place the
/// connector *waited* for the node; now the only bounded wait is the connect, which
/// `TcpConnector::with_connect_timeout` already applies, and a caller's own deadline governs the
/// rest — which is the right place for it, since only the caller knows how long a reply should take.
type BoundedStream = Box<dyn Transport>;

/// `SystemTime::now()` as a Unix timestamp.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn random_four() -> [u8; 4] {
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).expect("the OS provides entropy");
    random
}

fn random_eight() -> [u8; 8] {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).expect("the OS provides entropy");
    random
}

/// The datagram connector a [`VmessConnector`] hands to the relay.
pub struct VmessDatagramConnector {
    connector: VmessConnector,
}

impl VmessDatagramConnector {
    #[must_use]
    pub const fn new(connector: VmessConnector) -> Self {
        Self { connector }
    }
}

impl std::fmt::Debug for VmessDatagramConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessDatagramConnector")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl DatagramConnector for VmessDatagramConnector {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> DialerOptions {
        DialerOptions::new(None, Duration::from_secs(1))
    }

    fn params<'a>(uuid: &'a str) -> VmessParams<'a> {
        VmessParams {
            server: "node.example.com",
            port: 443,
            uuid,
            cipher: daer_config::VmessCipher::Auto,
            authenticated_length: false,
            no_termination_signal: false,
            security: Security::None,
            transport: TransportLayer::Tcp,
        }
    }

    #[test]
    fn reality_under_vmess_is_refused_because_the_reference_has_no_such_client() {
        // REALITY authenticates a VLESS flow; a VMess node configured with it does not exist.
        let public_key =
            crate::reality::decode_public_key("9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E")
                .expect("valid key");
        let error = VmessConnector::new(
            VmessParams {
                security: Security::Reality(crate::security::reality::RealitySecurity::new(
                    crate::security::reality::RealityParams {
                        server_name: "www.apple.com".to_owned(),
                        public_key,
                        short_id: Vec::new(),
                        alpn: Vec::new(),
                    },
                )),
                ..params("df4af3d0-030e-4062-baa6-eb9dd45298ef")
            },
            options(),
        )
        .expect_err("vmess has no reality client");
        assert!(error.to_string().contains("reality"), "{error}");
    }

    #[test]
    fn a_malformed_uuid_is_a_load_error() {
        let error =
            VmessConnector::new(params("not-a-uuid"), options()).expect_err("uuid must parse");
        assert!(error.to_string().contains("UUID"), "{error}");
    }

    #[test]
    fn the_request_options_always_chunk_and_mask() {
        // `shouldEnablePadding`: both AEAD ciphers get chunk masking, and global padding follows
        // it. A stream without masking is legal but produces fixed-size packets, which is the
        // signature the option exists to remove.
        let connector =
            VmessConnector::new(params("df4af3d0-030e-4062-baa6-eb9dd45298ef"), options())
                .expect("builds");
        assert_ne!(connector.options & header::option::CHUNK_STREAM, 0);
        assert_ne!(connector.options & header::option::CHUNK_MASKING, 0);
        assert_ne!(connector.options & header::option::GLOBAL_PADDING, 0);
        assert_eq!(
            connector.options & header::option::AUTHENTICATED_LENGTH,
            0,
            "authenticated length is a wire change the server must also have"
        );

        // And it is settable, because a node that needs it will not connect without it.
        let connector = VmessConnector::new(
            VmessParams {
                authenticated_length: true,
                ..params("df4af3d0-030e-4062-baa6-eb9dd45298ef")
            },
            options(),
        )
        .expect("builds");
        assert_ne!(connector.options & header::option::AUTHENTICATED_LENGTH, 0);
    }

    #[test]
    fn no_termination_signal_reaches_the_stream() {
        // The key is in the schema, so it has to mean something (ADR-0006). It decides whether
        // `shutdown` writes the terminating zero-length chunk, which is the one place a client and
        // a server must agree on *absence* — a mismatch shows up as a node logging a truncated
        // request rather than as a failed connection.
        let connector =
            VmessConnector::new(params("df4af3d0-030e-4062-baa6-eb9dd45298ef"), options())
                .expect("builds");
        assert!(connector.termination_signal, "the default is to send it");

        let connector = VmessConnector::new(
            VmessParams {
                no_termination_signal: true,
                ..params("df4af3d0-030e-4062-baa6-eb9dd45298ef")
            },
            options(),
        )
        .expect("builds");
        assert!(!connector.termination_signal);
    }

    #[test]
    fn the_debug_rendering_names_the_layers_and_not_the_credential() {
        let connector = VmessConnector::new(
            VmessParams {
                cipher: daer_config::VmessCipher::Aes128Gcm,
                ..params("df4af3d0-030e-4062-baa6-eb9dd45298ef")
            },
            options(),
        )
        .expect("builds");
        let rendered = format!("{connector:?}");
        assert!(rendered.contains("aes-128-gcm"), "{rendered}");
        assert!(rendered.contains("none"), "{rendered}");
        assert!(!rendered.contains("df4af3d0"), "{rendered}");
    }
}
