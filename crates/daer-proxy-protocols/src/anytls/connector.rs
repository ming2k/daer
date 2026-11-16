// SPDX-License-Identifier: AGPL-3.0-only

//! AnyTLS connector managing persistent TLS sessions and virtual stream multiplexing.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use netune::{DatagramConnector, Established, EstablishedDatagrams, NetError, TlsProfile};
use netune_trace::TraceCollector;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::anytls::auth::send_authentication;
use crate::anytls::datagram::{AnyTlsDatagramConnector, AnyTlsDatagramSession, UOT_MAGIC_ADDRESS};
use crate::anytls::session::AnyTlsSession;
use crate::error::ProxyProtocolError;
use crate::options::DialerOptions;
use crate::server::ServerDialer;
use crate::shadowsocks::connector::{encode_address, split_authority};

/// An AnyTLS outbound connector.
#[derive(Clone)]
pub struct AnyTlsConnector {
    server: String,
    server_name: String,
    password: String,
    allow_insecure: bool,
    idle_sessions: usize,
    timeout: Duration,
    base: Arc<dyn ServerDialer>,
    tls_profile: TlsProfile,
    sessions: Arc<Mutex<Vec<Arc<AnyTlsSession>>>>,
}

impl fmt::Debug for AnyTlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyTlsConnector")
            .field("server", &self.server)
            .field("server_name", &self.server_name)
            .field("idle_sessions", &self.idle_sessions)
            .field("allow_insecure", &self.allow_insecure)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl AnyTlsConnector {
    /// Builds a connector directly from typed parameters.
    pub fn new(
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        allow_insecure: bool,
        idle_sessions: usize,
        options: DialerOptions,
    ) -> Result<Self, ProxyProtocolError> {
        let server_name = sni.unwrap_or(server).to_owned();
        let tls_profile = crate::security::tls::resolve_profile(options.tls_profile)?;

        Ok(Self {
            server: format!("{server}:{port}"),
            server_name,
            password: password.to_owned(),
            allow_insecure,
            idle_sessions: idle_sessions.max(1),
            timeout: options.timeout,
            base: options.base().clone(),
            tls_profile,
            sessions: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Builds a connector from an `anytls://` link.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, ProxyProtocolError> {
        let structured = daer_config::NodeEndpoint::from_link(link)
            .map_err(ProxyProtocolError::UnsupportedLink)?;
        let anytls = match structured {
            daer_config::NodeEndpoint::AnyTls(n) => n,
            _ => {
                return Err(ProxyProtocolError::UnsupportedLink(
                    "not an anytls link".to_owned(),
                ));
            }
        };

        Self::new(
            &anytls.server,
            anytls.port,
            &anytls.password,
            anytls.tls.sni.as_deref(),
            anytls.tls.allow_insecure,
            anytls.idle_sessions,
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

    /// Opens the bare TCP stream to this AnyTLS server, before TLS and authentication.
    pub async fn connect_server(
        &self,
        recorder: &TraceCollector,
    ) -> Result<Established, ProxyProtocolError> {
        self.connect_server_within(recorder, Instant::now() + self.timeout)
            .await
    }

    /// Opens the bare TCP stream to this AnyTLS server within `deadline`.
    pub async fn connect_server_within(
        &self,
        recorder: &TraceCollector,
        deadline: Instant,
    ) -> Result<Established, ProxyProtocolError> {
        self.base
            .connect_within(&self.server, recorder, deadline)
            .await
    }

    /// Returns a shared datagram connector for this AnyTLS node.
    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        Arc::new(AnyTlsDatagramConnector::new(self.clone()))
    }

    /// Retrieves an active session from the pool or establishes a new authenticated session.
    pub async fn get_or_dial_session(
        &self,
        recorder: &TraceCollector,
    ) -> Result<Arc<AnyTlsSession>, ProxyProtocolError> {
        self.get_or_dial_session_within(recorder, Instant::now() + self.timeout)
            .await
    }

    /// Retrieves an active session from the pool or establishes a new authenticated session within `deadline`.
    pub async fn get_or_dial_session_within(
        &self,
        recorder: &TraceCollector,
        deadline: Instant,
    ) -> Result<Arc<AnyTlsSession>, ProxyProtocolError> {
        let remaining = ProxyProtocolError::remaining_until(
            deadline,
            daer_observe::DialStage::Handshake,
            &self.server,
        )?;
        let mut pool = tokio::time::timeout_at(deadline, self.sessions.lock())
            .await
            .map_err(|_| {
                ProxyProtocolError::timeout(
                    daer_observe::DialStage::Handshake,
                    format!(
                        "AnyTLS session dial to {} exceeded {} ms",
                        self.server,
                        remaining.as_millis()
                    ),
                )
            })?;

        // Cull dead sessions
        pool.retain(|s| !s.is_closed());

        // Return first healthy session
        if let Some(existing) = pool.first() {
            return Ok(Arc::clone(existing));
        }

        let tcp_established = self
            .base
            .connect_within(&self.server, recorder, deadline)
            .await?;
        let established = crate::security::tls::wrap_profile(
            tcp_established.stream,
            &self.tls_profile,
            &self.server_name,
            self.allow_insecure,
            recorder,
            deadline,
        )
        .await?;

        let alpn_protocol = established.alpn_protocol;
        let mut stream = established.stream;

        let remaining = ProxyProtocolError::remaining_until(
            deadline,
            daer_observe::DialStage::Handshake,
            &self.server,
        )?;
        // Perform AnyTLS client authentication flight
        tokio::time::timeout(
            remaining,
            send_authentication(&mut stream, &self.password, 0),
        )
        .await
        .map_err(|_| {
            ProxyProtocolError::timeout(
                daer_observe::DialStage::Handshake,
                format!(
                    "AnyTLS authentication with {} exceeded {} ms",
                    self.server,
                    remaining.as_millis()
                ),
            )
        })?
        .map_err(|error| {
            ProxyProtocolError::handshake(format!(
                "AnyTLS authentication with {}: {error}",
                self.server
            ))
        })?;

        let session = AnyTlsSession::new(stream, alpn_protocol);
        pool.push(Arc::clone(&session));

        Ok(session)
    }

    /// Connects a TCP stream through this AnyTLS node to `authority`.
    pub async fn connect(
        &self,
        authority: &str,
        recorder: &TraceCollector,
    ) -> Result<Established, ProxyProtocolError> {
        self.connect_within(authority, recorder, Instant::now() + self.timeout)
            .await
    }

    /// Connects a TCP stream through this AnyTLS node to `authority` within `deadline`.
    pub async fn connect_within(
        &self,
        authority: &str,
        recorder: &TraceCollector,
        deadline: Instant,
    ) -> Result<Established, ProxyProtocolError> {
        let session = self.get_or_dial_session_within(recorder, deadline).await?;
        let virtual_stream = session.open_stream_within(authority, deadline).await?;
        let alpn_protocol = session.alpn_protocol().map(<[u8]>::to_vec);
        let alpn = alpn_protocol
            .as_deref()
            .map(|name| netune_trace::Alpn::from_name(Some(name)));

        Ok(Established::new(Box::new(virtual_stream)).with_alpn(alpn, alpn_protocol))
    }

    /// Connects a UDP datagram session through this AnyTLS node to `authority`.
    pub async fn connect_datagram(
        &self,
        authority: &str,
        recorder: &TraceCollector,
    ) -> Result<EstablishedDatagrams, NetError> {
        let deadline = Instant::now() + self.timeout;
        let session = self
            .get_or_dial_session_within(recorder, deadline)
            .await
            .map_err(|error| error.into_net_error(&self.server))?;

        // Open UoT tunnel stream
        let stream = session
            .open_stream_within(UOT_MAGIC_ADDRESS, deadline)
            .await
            .map_err(|error| error.into_net_error(&self.server))?;

        let (host, port) = split_authority(authority).map_err(NetError::Protocol)?;
        let target_addr = encode_address(host, port).map_err(NetError::Protocol)?;

        let (read, write) = tokio::io::split(stream);
        let datagram_session = AnyTlsDatagramSession::new(read, write, target_addr);

        Ok(EstablishedDatagrams {
            datagrams: Box::new(datagram_session),
            local_port: None,
        })
    }
}
