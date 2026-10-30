// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 outbound connector over QUIC with socket mark support.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use netune::{DatagramConnector, Established, EstablishedDatagrams, NetError};
use netune_trace::Recorder;
use tokio::sync::Mutex;

use crate::error::OutboundError;
use crate::hysteria2::datagram::{Hysteria2DatagramConnector, Hysteria2DatagramSession};
use crate::hysteria2::tcp::open_tcp_stream;
use crate::node_dialer::DialerOptions;

/// A Hysteria 2 outbound connector.
#[derive(Clone)]
pub struct Hysteria2Connector {
    server: String,
    server_name: String,
    password: String,
    allow_insecure: bool,
    up_mbps: u64,
    down_mbps: u64,
    obfs: Option<String>,
    options: DialerOptions,
    active_conn: Arc<Mutex<Option<quinn::Connection>>>,
}

impl fmt::Debug for Hysteria2Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2Connector")
            .field("server", &self.server)
            .field("server_name", &self.server_name)
            .field("up_mbps", &self.up_mbps)
            .field("down_mbps", &self.down_mbps)
            .field("obfs", &self.obfs)
            .field("allow_insecure", &self.allow_insecure)
            .finish_non_exhaustive()
    }
}

/// Typed parameters for constructing a [`Hysteria2Connector`].
#[derive(Debug, Clone, Copy)]
pub struct Hysteria2Params<'a> {
    pub server: &'a str,
    pub port: u16,
    pub password: &'a str,
    pub sni: Option<&'a str>,
    pub allow_insecure: bool,
    pub up_mbps: u64,
    pub down_mbps: u64,
    pub obfs: Option<&'a str>,
}

impl Hysteria2Connector {
    /// Obfuscation password if configured.
    #[must_use]
    pub fn obfs(&self) -> Option<&str> {
        self.obfs.as_deref()
    }

    /// Builds a connector directly from typed parameters.
    pub fn new(params: Hysteria2Params<'_>, options: DialerOptions) -> Result<Self, OutboundError> {
        let server_name = params.sni.unwrap_or(params.server).to_owned();
        Ok(Self {
            server: format!("{}:{}", params.server, params.port),
            server_name,
            password: params.password.to_owned(),
            allow_insecure: params.allow_insecure,
            up_mbps: params.up_mbps,
            down_mbps: params.down_mbps,
            obfs: params.obfs.map(str::to_owned),
            options,
            active_conn: Arc::new(Mutex::new(None)),
        })
    }

    /// Builds a connector from a `hysteria2://` or `hy2://` link.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, OutboundError> {
        let structured =
            daer_config::NodeEndpoint::from_link(link).map_err(OutboundError::UnsupportedLink)?;
        let hy2 = match structured {
            daer_config::NodeEndpoint::Hysteria2(n) => n,
            _ => {
                return Err(OutboundError::UnsupportedLink(
                    "not a hysteria2 link".to_owned(),
                ));
            }
        };

        Self::new(
            Hysteria2Params {
                server: &hy2.server,
                port: hy2.port,
                password: &hy2.password,
                sni: hy2.sni.as_deref(),
                allow_insecure: hy2.allow_insecure,
                up_mbps: hy2.up_mbps,
                down_mbps: hy2.down_mbps,
                obfs: hy2.obfs.as_deref(),
            },
            options,
        )
    }

    /// The node's server address (`host:port`).
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

    /// Creates a QUIC client configuration with ALPN `h3`.
    fn make_client_config(allow_insecure: bool) -> Result<quinn::ClientConfig, OutboundError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_crypto = if allow_insecure {
            #[derive(Debug)]
            struct NoVerify;
            impl rustls::client::danger::ServerCertVerifier for NoVerify {
                fn verify_server_cert(
                    &self,
                    _end_entity: &rustls::pki_types::CertificateDer<'_>,
                    _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                    _server_name: &rustls::pki_types::ServerName<'_>,
                    _ocsp_response: &[u8],
                    _now: rustls::pki_types::UnixTime,
                ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error>
                {
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                }
                fn verify_tls12_signature(
                    &self,
                    _message: &[u8],
                    _cert: &rustls::pki_types::CertificateDer<'_>,
                    _dss: &rustls::DigitallySignedStruct,
                ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
                {
                    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
                }
                fn verify_tls13_signature(
                    &self,
                    _message: &[u8],
                    _cert: &rustls::pki_types::CertificateDer<'_>,
                    _dss: &rustls::DigitallySignedStruct,
                ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
                {
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
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| OutboundError::Connect(e.to_string()))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth()
        } else {
            use rustls_platform_verifier::BuilderVerifierExt;
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| OutboundError::Connect(e.to_string()))?
                .with_platform_verifier()
                .map_err(|e| OutboundError::Connect(e.to_string()))?
                .with_no_client_auth()
        };

        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic_client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|e| OutboundError::Connect(format!("quic client crypto: {e}")))?;

        let mut config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        config.transport_config(Arc::new(transport));

        Ok(config)
    }

    /// Creates an endpoint bound with `SO_MARK` before connect/bind.
    fn make_endpoint(
        so_mark: Option<u32>,
        is_ipv6: bool,
    ) -> Result<quinn::Endpoint, OutboundError> {
        let socket = socket2::Socket::new(
            if is_ipv6 {
                socket2::Domain::IPV6
            } else {
                socket2::Domain::IPV4
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|e| OutboundError::Connect(format!("create udp socket: {e}")))?;

        if let Some(mark) = so_mark {
            socket
                .set_mark(mark)
                .map_err(|e| OutboundError::Connect(format!("set so_mark {mark}: {e}")))?;
        }

        let bind_addr: SocketAddr = if is_ipv6 {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        socket
            .bind(&bind_addr.into())
            .map_err(|e| OutboundError::Connect(format!("bind udp socket: {e}")))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| OutboundError::Connect(format!("set nonblocking: {e}")))?;

        let std_sock: std::net::UdpSocket = socket.into();
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std_sock,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| OutboundError::Connect(format!("create quinn endpoint: {e}")))
    }

    /// Gets an active QUIC connection or establishes and authenticates a new one.
    pub async fn get_or_dial(&self) -> Result<quinn::Connection, OutboundError> {
        let mut active = self.active_conn.lock().await;
        if let Some(conn) = &*active
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }

        // Resolve destination address
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&self.server)
            .await
            .map_err(|e| OutboundError::Connect(format!("resolve {}: {e}", self.server)))?
            .collect();
        let target_addr = addrs
            .first()
            .ok_or_else(|| OutboundError::Connect(format!("could not resolve {}", self.server)))?;

        // Create socket with so_mark
        let endpoint = Self::make_endpoint(self.options.so_mark, target_addr.is_ipv6())?;

        // Client config
        let client_config = Self::make_client_config(self.allow_insecure)?;

        let connecting = endpoint
            .connect_with(client_config, *target_addr, &self.server_name)
            .map_err(|e| OutboundError::Connect(format!("quic connect: {e}")))?;

        let conn = tokio::time::timeout(self.options.timeout, connecting)
            .await
            .map_err(|_| OutboundError::Timeout)?
            .map_err(|e| OutboundError::Connect(format!("quic connection failed: {e}")))?;

        // Authenticate via HTTP/3
        let rx_bps = self.down_mbps * 1_000_000 / 8;
        crate::hysteria2::auth::authenticate(&conn, &self.password, rx_bps).await?;

        *active = Some(conn.clone());
        Ok(conn)
    }

    /// Connects a TCP stream through this Hysteria 2 node to `authority`.
    pub async fn connect(
        &self,
        authority: &str,
        _recorder: &Arc<std::sync::Mutex<Recorder>>,
    ) -> Result<Established, OutboundError> {
        let conn = self.get_or_dial().await?;
        let bi_stream = open_tcp_stream(&conn, authority).await?;

        Ok(Established {
            stream: Box::new(bi_stream),
            local_port: None,
            socket: None,
            alpn: None,
        })
    }

    /// Connects a UDP datagram session through this Hysteria 2 node to `authority`.
    pub async fn connect_datagram(
        &self,
        authority: &str,
        _recorder: &Arc<std::sync::Mutex<Recorder>>,
    ) -> Result<EstablishedDatagrams, NetError> {
        let conn = self
            .get_or_dial()
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?;

        let datagram_session = Hysteria2DatagramSession::new(conn, authority.to_owned(), 1);

        Ok(EstablishedDatagrams {
            datagrams: Box::new(datagram_session),
            local_port: None,
        })
    }
}
