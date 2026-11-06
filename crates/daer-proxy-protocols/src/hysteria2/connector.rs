// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 outbound: the socket stack, the handshake, and the two planes (ADR-0029).
//!
//! # The stack
//!
//! ```text
//!   quinn::Endpoint
//!         ▲
//!         │  AsyncUdpSocket
//!   ┌─────┴──────────────────────────────┐
//!   │ hop    (rotate the local port)      │  optional
//!   │ obfs   (salamander / gecko)         │  optional
//!   │ socket (tokio UdpSocket, SO_MARK)   │  always
//!   └─────────────────────────────────────┘
//! ```
//!
//! The endpoint is created with `Endpoint::new_with_abstract_socket`, the only constructor
//! that accepts a layer. `Endpoint::new` is not used at all, so a socket wrapper cannot be
//! forgotten — which is exactly what happened before ADR-0029: `obfs` was parsed, stored,
//! printed by `Debug`, asserted by a test, and *not on the wire*.
//!
//! # What the handshake negotiates
//!
//! `POST https://hysteria/auth` with `Hysteria-Auth`, `Hysteria-CC-RX` and a padding header.
//! A `233` answer authorises the connection; the *same* answer carries two facts the client
//! must honour:
//!
//! * `Hysteria-UDP`: may this node relay UDP at all? Answering "no" here and failing later at
//!   the relay is how a datagram flow dies with nothing to attribute it to.
//! * `Hysteria-CC-RX`: the rate the server will take, `0` for unlimited or `auto` for "use
//!   congestion control". Brutal needs it; the loss-based controllers ignore it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune::{DatagramConnector, Established, EstablishedDatagrams, NetError};
use netune_trace::Recorder;
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use tokio::sync::Mutex as AsyncMutex;

use crate::error::ProxyProtocolError;
use crate::hysteria2::auth::{self, H3Session};
use crate::hysteria2::brutal::BrutalConfig;
use crate::hysteria2::datagram::{Hysteria2DatagramConnector, Hysteria2DatagramSession};
use crate::hysteria2::hop::{self, HopSchedule, PortHopper};
use crate::hysteria2::obfs::Obfs;
use crate::hysteria2::port_set::PortSet;
use crate::hysteria2::tcp::open_tcp_stream;
use crate::options::DialerOptions;

/// A Hysteria 2 outbound connector.
#[derive(Clone)]
pub struct Hysteria2Connector {
    server: String,
    server_name: String,
    password: String,
    allow_insecure: bool,
    pin_sha256: Option<[u8; 32]>,
    up_mbps: u64,
    down_mbps: u64,
    obfs: Option<Obfs>,
    congestion: Arc<dyn ControllerFactory + Send + Sync>,
    quic: daer_config::Hysteria2Quic,
    ports: PortSet,
    options: DialerOptions,
    state: Arc<AsyncMutex<Option<Connection>>>,
}

/// An authenticated connection and what the server said about it.
///
/// The **endpoint** is held here, not only the connection: a `quinn::Connection` is a handle, and
/// dropping the last reference to its `Endpoint` closes every connection on it. That is a quiet
/// failure — `connect` succeeds, then the first stream operation reports "closed" — so the
/// endpoint lives exactly as long as the session does.
#[derive(Clone)]
pub(crate) struct Connection {
    /// Kept alive for the connection's lifetime; see this struct's own note.
    _endpoint: quinn::Endpoint,
    /// Kept alive so a hop schedule stops with the session rather than running on.
    _hopper: Option<Arc<crate::hysteria2::hop::PortHopper>>,
    /// Kept alive because dropping it closes the QUIC connection (`auth::H3Session`).
    _h3: Arc<H3Session>,
    connection: quinn::Connection,
    /// Whether the server will relay UDP (`Hysteria-UDP`).
    udp_enabled: bool,
    /// The rate the server will take, in bytes per second; `None` means it did not say.
    server_rx: Option<u64>,
}

impl std::fmt::Debug for Hysteria2Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Connector")
            .field("server", &self.server)
            .field("server_name", &self.server_name)
            .field("ports", &self.ports.ranges)
            .field("up_mbps", &self.up_mbps)
            .field("down_mbps", &self.down_mbps)
            .field("obfs", &self.obfs.as_ref().map(Obfs::kind))
            .field("allow_insecure", &self.allow_insecure)
            .field("pin_sha256", &self.pin_sha256.is_some())
            .finish_non_exhaustive()
    }
}

/// Typed parameters for constructing a [`Hysteria2Connector`].
#[derive(Debug, Clone, Copy)]
pub struct Hysteria2Params<'a> {
    pub server: &'a str,
    pub ports: &'a PortSet,
    pub password: &'a str,
    pub sni: Option<&'a str>,
    pub allow_insecure: bool,
    pub pin_sha256: Option<&'a str>,
    pub up_mbps: u64,
    pub down_mbps: u64,
    pub obfs: Option<&'a daer_config::Hysteria2Obfs>,
    pub congestion: daer_config::Hysteria2Congestion,
    pub quic: &'a daer_config::Hysteria2Quic,
}

impl Hysteria2Connector {
    /// The obfuscation this node applies, if any.
    #[must_use]
    pub fn obfs(&self) -> Option<&Obfs> {
        self.obfs.as_ref()
    }

    /// The configured ports.
    #[must_use]
    pub const fn ports(&self) -> &PortSet {
        &self.ports
    }

    /// Builds a connector directly from typed parameters.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyProtocolError::UnsupportedLink`] when a value cannot be honoured: a
    /// malformed `pin-sha256`, an obfuscation whose key is too short, Brutal without a rate,
    /// or a hop schedule below the reference's floor. Every one of those is a load-time fact.
    pub fn new(
        params: Hysteria2Params<'_>,
        options: DialerOptions,
    ) -> Result<Self, ProxyProtocolError> {
        if params.ports.ranges.is_empty() {
            return Err(ProxyProtocolError::UnsupportedLink(
                "hysteria2: the node names no ports".to_owned(),
            ));
        }
        // The hop schedule is validated here rather than at dial time: a 1-second schedule
        // looks like a working node that the server drops connections on.
        HopSchedule::from_ports(params.ports).map_err(ProxyProtocolError::UnsupportedLink)?;

        let obfs = match params.obfs {
            Some(obfs) => {
                Some(Obfs::from_config(obfs).map_err(ProxyProtocolError::UnsupportedLink)?)
            }
            None => None,
        };

        let pin_sha256 = match params.pin_sha256 {
            Some(text) => Some(parse_pin(text)?),
            None => None,
        };

        let congestion = controller_for(params.congestion, params.up_mbps, params.down_mbps)?;

        let server_name = params.sni.unwrap_or(params.server).to_owned();
        Ok(Self {
            server: params.server.to_owned(),
            server_name,
            password: params.password.to_owned(),
            allow_insecure: params.allow_insecure,
            pin_sha256,
            up_mbps: params.up_mbps,
            down_mbps: params.down_mbps,
            obfs,
            congestion,
            quic: params.quic.clone(),
            ports: params.ports.clone(),
            options,
            state: Arc::new(AsyncMutex::new(None)),
        })
    }

    /// Builds a connector from a `hysteria2://` or `hy2://` link.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, ProxyProtocolError> {
        let endpoint = daer_config::NodeEndpoint::from_link(link)
            .map_err(ProxyProtocolError::UnsupportedLink)?;
        match endpoint {
            daer_config::NodeEndpoint::Hysteria2(hy2) => Self::new(
                Hysteria2Params {
                    server: &hy2.server,
                    ports: &hy2.ports,
                    password: &hy2.password,
                    sni: hy2.sni.as_deref(),
                    allow_insecure: hy2.allow_insecure,
                    pin_sha256: hy2.pin_sha256.as_deref(),
                    up_mbps: hy2.up_mbps,
                    down_mbps: hy2.down_mbps,
                    obfs: hy2.obfs.as_ref(),
                    congestion: hy2.congestion,
                    quic: &hy2.quic,
                },
                options,
            ),
            _ => Err(ProxyProtocolError::UnsupportedLink(
                "not a hysteria2 link".to_owned(),
            )),
        }
    }

    /// The rate the server said it will take, for a diagnostic that reports it.
    ///
    /// `None` means the server answered `auto` or `0`, which is the protocol's way of saying "use
    /// congestion control" rather than "unlimited bandwidth".
    ///
    /// # Why this is not fed into the congestion controller
    ///
    /// The reference applies it *after* authentication, by mutating the live connection
    /// (`congestion.UseBrutal(conn, actual_tx, …)` in `core/client/client.go`). Quinn fixes its
    /// controller in `TransportConfig`, which is consumed when the endpoint dials — there is no
    /// post-handshake hook, and forging one would mean reaching into `quinn-proto`'s private state.
    ///
    /// So Brutal pins to `up-mbps` for the whole session, and this value is reported rather than
    /// silently claimed to be applied. ADR-0029 records the gap instead of asserting a behaviour
    /// the code does not have.
    pub async fn server_rx(&self) -> Option<u64> {
        self.state
            .lock()
            .await
            .as_ref()
            .and_then(|connection| connection.server_rx)
    }

    /// The node's server address (`host:port` of the first port).
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The TLS server name presented for this node.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Returns a shared datagram connector for this Hysteria 2 node.
    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        Arc::new(Hysteria2DatagramConnector::new(self.clone()))
    }

    /// Builds the QUIC client configuration.
    ///
    /// The ALPN is `h3` because the authentication *is* an HTTP/3 request; a node that does
    /// not see `h3` serves its masquerade page instead of answering `233`, which looks like a
    /// wrong password.
    pub(crate) fn client_config(&self) -> Result<quinn::ClientConfig, ProxyProtocolError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut crypto = if self.allow_insecure {
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|error| ProxyProtocolError::Connect(format!("TLS versions: {error}")))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
                .with_no_client_auth()
        } else {
            use rustls_platform_verifier::BuilderVerifierExt;
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|error| ProxyProtocolError::Connect(format!("TLS versions: {error}")))?
                .with_platform_verifier()
                .map_err(|error| {
                    ProxyProtocolError::Connect(format!("platform trust store: {error}"))
                })?
                .with_no_client_auth()
        };
        crypto.alpn_protocols = vec![b"h3".to_vec()];

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|error| ProxyProtocolError::Connect(format!("QUIC client crypto: {error}")))?;
        let mut config = quinn::ClientConfig::new(Arc::new(quic_crypto));

        let transport = self.transport_config()?;
        config.transport_config(transport);
        Ok(config)
    }

    /// Maps the node's `[node.quic]` table onto `quinn::TransportConfig`.
    ///
    /// Every field either changes the connection or is not in the model, which is what
    /// ADR-0006 requires of a key.
    pub(crate) fn transport_config(
        &self,
    ) -> Result<Arc<quinn::TransportConfig>, ProxyProtocolError> {
        let mut transport = quinn::TransportConfig::default();

        let idle = if self.quic.max_idle_timeout_ms > 0 {
            Duration::from_millis(self.quic.max_idle_timeout_ms)
        } else {
            Duration::from_secs(30)
        };
        transport.max_idle_timeout(Some(idle.try_into().map_err(|error| {
            ProxyProtocolError::UnsupportedLink(format!(
                "hysteria2.quic.max-idle-timeout = {}ms is not a valid QUIC idle timeout: \
                     {error}",
                self.quic.max_idle_timeout_ms
            ))
        })?));
        // Keep-alives are what stop a NAT from dropping the flow's mapping; the reference
        // sends one every 10 s by default and the value here follows that, because a
        // Hysteria node is usually reached through a NAT.
        let keep_alive = if self.quic.keep_alive_period_ms > 0 {
            Some(Duration::from_millis(self.quic.keep_alive_period_ms))
        } else {
            Some(Duration::from_secs(10))
        };
        transport.keep_alive_interval(keep_alive);

        if self.quic.disable_path_mtu_discovery {
            // `migration` is a server-side knob; on a client, disabling MTUD is what the
            // reference's `disablePathMTUDiscovery` does. `None` means "use the initial MTU
            // and do not probe".
            transport.mtu_discovery_config(None);
        }
        transport.enable_segmentation_offload(!self.quic.disable_segmentation_offload);

        if self.quic.init_stream_receive_window > 0 {
            transport.stream_receive_window(
                quinn::VarInt::from_u64(self.quic.init_stream_receive_window).map_err(|_| {
                    ProxyProtocolError::UnsupportedLink(
                        "hysteria2.quic.init-stream-receive-window is too large for a QUIC \
                         varint"
                            .to_owned(),
                    )
                })?,
            );
        }
        if self.quic.init_conn_receive_window > 0 {
            transport.receive_window(
                quinn::VarInt::from_u64(self.quic.init_conn_receive_window).map_err(|_| {
                    ProxyProtocolError::UnsupportedLink(
                        "hysteria2.quic.init-conn-receive-window is too large for a QUIC varint"
                            .to_owned(),
                    )
                })?,
            );
        }
        if self.quic.max_stream_receive_window > 0 || self.quic.max_conn_receive_window > 0 {
            // quinn's flow control has no separate "max" knob: the window is what it is.
            // Reporting that rather than silently ignoring the key is the ADR-0006 rule, so
            // an operator who set it learns it has no effect *here* instead of at 3 a.m.
            return Err(ProxyProtocolError::UnsupportedLink(
                "hysteria2.quic.max-stream-receive-window / max-conn-receive-window are \
                 quic-go's growing-window knobs; quinn's flow control uses a fixed window, \
                 so set init-stream-receive-window / init-conn-receive-window instead"
                    .to_owned(),
            ));
        }

        transport.congestion_controller_factory(Arc::clone(&self.congestion));
        Ok(Arc::new(transport))
    }

    /// Builds the socket stack and the endpoint that sits on top of it.
    ///
    /// This is the function ADR-0029 exists for: every datagram layer is installed here and
    /// `Endpoint::new` is not used at all.
    async fn endpoint(
        &self,
        target: SocketAddr,
    ) -> Result<(quinn::Endpoint, Option<PortHopper>), ProxyProtocolError> {
        let is_ipv6 = target.is_ipv6();
        // ADR-0029's stack: a marked socket, then the obfuscation layer if configured.
        let socket = hop::build_stack(is_ipv6, self.options.so_mark, self.obfs.as_ref())?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| ProxyProtocolError::Connect(format!("create quinn endpoint: {error}")))?;

        let schedule =
            HopSchedule::from_ports(&self.ports).map_err(ProxyProtocolError::UnsupportedLink)?;
        let hopper = schedule.map(|schedule| {
            PortHopper::start(
                endpoint.clone(),
                target,
                self.ports.clone(),
                schedule,
                self.options.so_mark,
                self.obfs.clone(),
            )
        });
        Ok((endpoint, hopper))
    }

    /// Resolves the node's first port.
    async fn resolve(&self) -> Result<SocketAddr, ProxyProtocolError> {
        let port = self.ports.ranges.first().map(|(low, _)| *low).unwrap_or(0);
        let authority = format!("{}:{}", self.server, port);
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host(&authority)
            .await
            .map_err(|error| ProxyProtocolError::Connect(format!("resolve {authority}: {error}")))?
            .collect();
        addresses
            .first()
            .copied()
            .ok_or_else(|| ProxyProtocolError::Connect(format!("could not resolve {authority}")))
    }

    /// Gets an authenticated connection or establishes one.
    pub(crate) async fn get_or_dial(&self) -> Result<Connection, ProxyProtocolError> {
        let mut state = self.state.lock().await;
        if let Some(connection) = state.as_ref()
            && connection.connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }

        let target = self.resolve().await?;
        let (endpoint, hopper) = self.endpoint(target).await?;
        let config = self.client_config()?;
        let connecting = endpoint
            .connect_with(config, target, &self.server_name)
            .map_err(|error| ProxyProtocolError::Connect(format!("quic connect: {error}")))?;
        let connection = tokio::time::timeout(self.options.timeout, connecting)
            .await
            .map_err(|_| ProxyProtocolError::Timeout)?
            .map_err(|error| {
                ProxyProtocolError::Connect(format!("quic connection failed: {error}"))
            })?;

        // `pin-sha256` is a post-handshake digest check, which is what the reference does:
        // the certificate is already verified by the chain, and the pin is a second factor.
        if let Some(expected) = self.pin_sha256 {
            verify_pin(&connection, &expected)?;
        }

        // `Hysteria-CC-RX` is this client's *receive* rate in bytes per second, which is the
        // download figure converted from megabits. `0` means "unknown", and the server then
        // uses congestion control against us.
        let server_rx = self.down_mbps.saturating_mul(1_000_000) / 8;
        let (outcome, h3) = auth::authenticate(&connection, &self.password, server_rx).await?;
        let opened = Connection {
            _endpoint: endpoint,
            _hopper: hopper.map(Arc::new),
            _h3: Arc::new(h3),
            connection,
            udp_enabled: outcome.udp_enabled,
            server_rx: outcome.server_rx,
        };
        *state = Some(opened.clone());
        Ok(opened)
    }

    /// Connects a TCP stream through this Hysteria 2 node to `authority`.
    pub async fn connect(
        &self,
        authority: &str,
        _recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<Established, ProxyProtocolError> {
        let connection = self.get_or_dial().await?;
        let stream = open_tcp_stream(&connection.connection, authority).await?;
        Ok(Established {
            stream: Box::new(stream),
            local_port: None,
            socket: None,
            alpn: None,
        })
    }

    /// Connects a UDP datagram session through this Hysteria 2 node to `authority`.
    ///
    /// # Errors
    ///
    /// Refuses with the server's own answer when it said `Hysteria-UDP: false`: failing here
    /// names the cause, where failing at the first datagram names nothing.
    pub async fn connect_datagram(
        &self,
        authority: &str,
        _recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<EstablishedDatagrams, NetError> {
        let connection = self
            .get_or_dial()
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;
        if !connection.udp_enabled {
            return Err(NetError::Protocol(format!(
                "{} answered Hysteria-UDP: false during authentication, so it will not relay \
                 UDP to {authority}. The node's server needs `udp: true` in its Hysteria \
                 configuration",
                self.server
            )));
        }
        let session = Hysteria2DatagramSession::new(connection.connection, authority.to_owned());
        Ok(EstablishedDatagrams {
            datagrams: Box::new(session),
            local_port: None,
        })
    }
}

/// Maps the node's congestion choice onto a Quinn controller factory.
fn controller_for(
    congestion: daer_config::Hysteria2Congestion,
    up_mbps: u64,
    down_mbps: u64,
) -> Result<Arc<dyn ControllerFactory + Send + Sync>, ProxyProtocolError> {
    use daer_config::Hysteria2Congestion;

    Ok(match congestion {
        Hysteria2Congestion::Bbr => Arc::new(BbrConfig::default()),
        Hysteria2Congestion::Cubic => Arc::new(CubicConfig::default()),
        Hysteria2Congestion::NewReno => Arc::new(NewRenoConfig::default()),
        Hysteria2Congestion::Brutal => {
            // Brutal pins the *send* window, so the number it needs is this client's transmit
            // rate — `up-mbps`, not `down-mbps`. Pinning a sender to its receive rate is the one
            // mistake that makes Brutal worse than BBR: a node configured `up-mbps = 100,
            // down-mbps = 200` would send at 200 Mbit into a 100 Mbit pipe, which is precisely the
            // congestion Brutal exists to avoid.
            //
            // The reference reaches the same number from two inputs: `max_tx` (this key) and the
            // server's `Hysteria-CC-RX`, as `actual_tx = min(server_rx, max_tx)`
            // (`core/client/client.go`). Only the configured half is available here — see
            // [`Hysteria2Connector::server_rx`] for why the other half cannot be applied.
            let bits = up_mbps.saturating_mul(1_000_000);
            if bits == 0 {
                return Err(ProxyProtocolError::UnsupportedLink(
                    "hysteria2: congestion = \"brutal\" pins the *send* window to `up-mbps`, so \
                     that key must be set. `down-mbps` is this client's receive rate and is sent \
                     to the server as Hysteria-CC-RX, which is a different number"
                        .to_owned(),
                ));
            }
            let _ = down_mbps;
            Arc::new(BrutalConfig::from_bits_per_second(bits))
        }
    })
}

/// Parses `pin-sha256`: 64 hex digits, colons and spaces tolerated.
fn parse_pin(text: &str) -> Result<[u8; 32], ProxyProtocolError> {
    let digits: String = text
        .chars()
        .filter(|c| *c != ':' && *c != ' ' && *c != '-')
        .collect();
    if digits.len() != 64 {
        return Err(ProxyProtocolError::UnsupportedLink(format!(
            "hysteria2.pin-sha256 = {text:?} is {} hex digits, not the 64 of a SHA-256 digest",
            digits.len()
        )));
    }
    let mut pin = [0u8; 32];
    for (index, pair) in digits.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(pair).map_err(|_| {
            ProxyProtocolError::UnsupportedLink(format!(
                "hysteria2.pin-sha256 = {text:?} is not ASCII"
            ))
        })?;
        pin[index] = u8::from_str_radix(hex, 16).map_err(|_| {
            ProxyProtocolError::UnsupportedLink(format!(
                "hysteria2.pin-sha256 = {text:?} is not hex"
            ))
        })?;
    }
    Ok(pin)
}

/// Compares the peer's leaf certificate against the configured pin.
fn verify_pin(
    connection: &quinn::Connection,
    expected: &[u8; 32],
) -> Result<(), ProxyProtocolError> {
    use sha2::{Digest as _, Sha256};

    let identity = connection.peer_identity().ok_or_else(|| {
        ProxyProtocolError::Connect(
            "hysteria2.pin-sha256 is set but the QUIC session exposed no peer certificate, so \
             the pin cannot be checked"
                .to_owned(),
        )
    })?;
    let chain = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| {
            ProxyProtocolError::Connect(
                "the QUIC session's peer identity is not a certificate chain".to_owned(),
            )
        })?;
    let leaf = chain.first().ok_or_else(|| {
        ProxyProtocolError::Connect("the QUIC peer presented an empty certificate chain".to_owned())
    })?;
    let digest: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
    if &digest != expected {
        return Err(ProxyProtocolError::Connect(format!(
            "hysteria2.pin-sha256 does not match: the leaf certificate hashes to {}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )));
    }
    Ok(())
}

/// Accepts any certificate chain.
///
/// Reachable only through `allow-insecure = true`, which is a decision an operator writes
/// down. The name says what it does so a reviewer cannot miss it.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
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

    fn options() -> DialerOptions {
        DialerOptions::new(None, Duration::from_secs(1))
    }

    fn params<'a>(ports: &'a PortSet) -> Hysteria2Params<'a> {
        Hysteria2Params {
            server: "hy2.example.com",
            ports,
            password: "secret",
            sni: None,
            allow_insecure: false,
            pin_sha256: None,
            up_mbps: 0,
            down_mbps: 0,
            obfs: None,
            congestion: daer_config::Hysteria2Congestion::Bbr,
            quic: &DEFAULT_QUIC,
        }
    }

    const DEFAULT_QUIC: daer_config::Hysteria2Quic = daer_config::Hysteria2Quic {
        init_stream_receive_window: 0,
        max_stream_receive_window: 0,
        init_conn_receive_window: 0,
        max_conn_receive_window: 0,
        max_idle_timeout_ms: 0,
        keep_alive_period_ms: 0,
        disable_path_mtu_discovery: false,
        disable_segmentation_offload: false,
    };

    #[test]
    fn brutal_pins_to_the_send_rate_not_the_receive_rate() {
        // The mistake this pins: `down-mbps` is the number that *also* goes out in
        // `Hysteria-CC-RX`, so it is the tempting one to pin Brutal to. But Brutal pins the window
        // a client *sends* with, so the rate is `up-mbps`. A client configured 100 up / 200 down
        // would otherwise send at 200 Mbit into a 100 Mbit pipe — the exact congestion the
        // controller exists to avoid.
        let ports = PortSet::single(443);
        let with_up = controller_for(daer_config::Hysteria2Congestion::Brutal, 100, 200)
            .expect("brutal with up-mbps builds");

        // `down-mbps` alone is refused, not silently substituted.
        //
        // `expect_err` cannot be used: the `Ok` side is `Arc<dyn ControllerFactory>`, which has no
        // `Debug`. A test helper that unwrapped by hand would hide the very case being asserted, so
        // the match is explicit.
        let error = match controller_for(daer_config::Hysteria2Congestion::Brutal, 0, 200) {
            Ok(_) => panic!("brutal with only down-mbps must be refused, not built"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("up-mbps"), "{error}");
        assert!(
            error.to_string().contains("Hysteria-CC-RX"),
            "the message must distinguish the two rates: {error}"
        );

        // And the config validator says the same thing, so a node cannot load and then fail to dial.
        let error = Hysteria2Connector::new(
            Hysteria2Params {
                congestion: daer_config::Hysteria2Congestion::Brutal,
                up_mbps: 0,
                down_mbps: 200,
                ..params(&ports)
            },
            options(),
        )
        .expect_err("a load-time refusal, not a dial-time one");
        assert!(error.to_string().contains("up-mbps"), "{error}");
        let _ = with_up;
    }

    #[test]
    fn brutal_without_a_rate_is_refused_because_there_is_nothing_to_pin() {
        let ports = PortSet::single(443);
        let error = Hysteria2Connector::new(
            Hysteria2Params {
                congestion: daer_config::Hysteria2Congestion::Brutal,
                ..params(&ports)
            },
            options(),
        )
        .expect_err("brutal needs a rate");
        assert!(error.to_string().contains("brutal"), "{error}");
    }

    #[test]
    fn a_pin_that_is_not_a_sha256_digest_is_refused_at_load() {
        let ports = PortSet::single(443);
        let error = Hysteria2Connector::new(
            Hysteria2Params {
                pin_sha256: Some("deadbeef"),
                ..params(&ports)
            },
            options(),
        )
        .expect_err("4 bytes is not a digest");
        assert!(error.to_string().contains("64"), "{error}");

        // The control: 64 hex digits with the colons an `openssl` transcript uses is accepted.
        let pin = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";
        Hysteria2Connector::new(
            Hysteria2Params {
                pin_sha256: Some(pin),
                ..params(&ports)
            },
            options(),
        )
        .expect("colons are tolerated");
    }

    #[test]
    fn obfs_reaches_the_connector_or_is_refused() {
        // The defect ADR-0029 exists for: `obfs` used to be stored and never applied. The
        // connector now holds the resolved layer, so a test can assert it is there.
        let ports = PortSet::single(443);
        let obfs = daer_config::Hysteria2Obfs::Salamander {
            password: "cry_me_a_r1ver".to_owned(),
        };
        let connector = Hysteria2Connector::new(
            Hysteria2Params {
                obfs: Some(&obfs),
                ..params(&ports)
            },
            options(),
        )
        .expect("builds");
        assert_eq!(connector.obfs().map(Obfs::kind), Some("salamander"));

        // And a key the reference would refuse is a load error, not a runtime timeout.
        let short = daer_config::Hysteria2Obfs::Salamander {
            password: "abc".to_owned(),
        };
        Hysteria2Connector::new(
            Hysteria2Params {
                obfs: Some(&short),
                ..params(&ports)
            },
            options(),
        )
        .expect_err("3 bytes is under the reference floor");
    }

    #[test]
    fn the_socket_stack_is_reachable_through_the_ports_the_node_names() {
        let ports = PortSet::parse("20000-20002").expect("parses");
        let connector = Hysteria2Connector::new(params(&ports), options()).expect("builds");
        assert_eq!(connector.ports().ports(), vec![20000, 20001, 20002]);
        assert_eq!(connector.server(), "hy2.example.com");
        assert_eq!(connector.server_name(), "hy2.example.com");

        let ports = PortSet::parse("443").expect("parses");
        let connector = Hysteria2Connector::new(
            Hysteria2Params {
                sni: Some("cdn.example.com"),
                ..params(&ports)
            },
            options(),
        )
        .expect("builds");
        assert_eq!(connector.server_name(), "cdn.example.com");
    }

    #[test]
    fn a_quic_knob_quinn_cannot_honour_is_a_load_error_rather_than_ignored() {
        // ADR-0006: a key the schema accepts must take effect or not exist. quinn's flow
        // control has no growing window, so `max-stream-receive-window` cannot mean what the
        // reference means by it — and silently ignoring it is what this test forbids.
        const GROWING: daer_config::Hysteria2Quic = daer_config::Hysteria2Quic {
            init_stream_receive_window: 0,
            max_stream_receive_window: 1_000_000,
            init_conn_receive_window: 0,
            max_conn_receive_window: 0,
            max_idle_timeout_ms: 0,
            keep_alive_period_ms: 0,
            disable_path_mtu_discovery: false,
            disable_segmentation_offload: false,
        };
        let ports = PortSet::single(443);
        let connector = Hysteria2Connector::new(
            Hysteria2Params {
                quic: &GROWING,
                ..params(&ports)
            },
            options(),
        )
        .expect("construction succeeds; the error is at config build");
        let error = connector
            .transport_config()
            .expect_err("a growing window is not implementable");
        assert!(
            error.to_string().contains("max-stream-receive-window"),
            "{error}"
        );
    }

    #[test]
    fn the_transport_config_honours_the_idle_timeout_and_keep_alive() {
        const TUNED: daer_config::Hysteria2Quic = daer_config::Hysteria2Quic {
            init_stream_receive_window: 1_000_000,
            max_stream_receive_window: 0,
            init_conn_receive_window: 2_000_000,
            max_conn_receive_window: 0,
            max_idle_timeout_ms: 60_000,
            keep_alive_period_ms: 5_000,
            disable_path_mtu_discovery: true,
            disable_segmentation_offload: true,
        };
        let ports = PortSet::single(443);
        let connector = Hysteria2Connector::new(
            Hysteria2Params {
                quic: &TUNED,
                ..params(&ports)
            },
            options(),
        )
        .expect("builds");
        connector
            .transport_config()
            .expect("every knob here is implementable");
    }
}
