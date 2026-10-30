// SPDX-License-Identifier: AGPL-3.0-only

//! AnyTLS connector managing persistent TLS sessions and virtual stream multiplexing.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use netune::{
    Connector, DatagramConnector, Established, EstablishedDatagrams, NetError, SocketConfig,
    Target, TcpConnector, TlsConnector,
};
use netune_trace::Recorder;
use tokio::sync::Mutex;

use crate::anytls::auth::send_authentication;
use crate::anytls::datagram::{AnyTlsDatagramConnector, AnyTlsDatagramSession, UOT_MAGIC_ADDRESS};
use crate::anytls::session::AnyTlsSession;
use crate::error::OutboundError;
use crate::node_dialer::DialerOptions;
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
    tls_profile: Option<&'static str>,
    tls: Arc<TlsConnector<TcpConnector>>,
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
    ) -> Result<Self, OutboundError> {
        let server_name = sni.unwrap_or(server).to_owned();
        let socket = match options.so_mark {
            Some(mark) => SocketConfig::default().with_mark(mark),
            None => SocketConfig::default(),
        };
        let tcp = TcpConnector::new()
            .with_socket_config(socket)
            .with_connect_timeout(Some(options.timeout));
        let tls = TlsConnector::platform(tcp)
            .map_err(|error| OutboundError::Connect(error.to_string()))?;

        Ok(Self {
            server: format!("{server}:{port}"),
            server_name,
            password: password.to_owned(),
            allow_insecure,
            idle_sessions: idle_sessions.max(1),
            timeout: options.timeout,
            tls_profile: options.tls_profile,
            tls: Arc::new(tls),
            sessions: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Builds a connector from an `anytls://` link.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, OutboundError> {
        let structured =
            daer_config::NodeEndpoint::from_link(link).map_err(OutboundError::UnsupportedLink)?;
        let anytls = match structured {
            daer_config::NodeEndpoint::AnyTls(n) => n,
            _ => {
                return Err(OutboundError::UnsupportedLink(
                    "not an anytls link".to_owned(),
                ));
            }
        };

        Self::new(
            &anytls.server,
            anytls.port,
            &anytls.password,
            anytls.sni.as_deref(),
            anytls.allow_insecure,
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

    /// Returns a shared datagram connector for this AnyTLS node.
    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        Arc::new(AnyTlsDatagramConnector::new(self.clone()))
    }

    /// Retrieves an active session from the pool or establishes a new authenticated session.
    pub async fn get_or_dial_session(
        &self,
        recorder: &Arc<std::sync::Mutex<Recorder>>,
    ) -> Result<Arc<AnyTlsSession>, OutboundError> {
        let mut pool = self.sessions.lock().await;

        // Cull dead sessions
        pool.retain(|s| !s.is_closed());

        // Return first healthy session
        if let Some(existing) = pool.first() {
            return Ok(Arc::clone(existing));
        }

        // Establish new session over TLS
        let target = Target::tls(&self.server, &self.server_name);
        let target = match self.tls_profile {
            Some(profile) => target.with_tls_profile(profile),
            None => target,
        };

        let established = tokio::time::timeout(self.timeout, self.tls.connect(&target, recorder))
            .await
            .map_err(|_| OutboundError::Timeout)?
            .map_err(|error| OutboundError::Connect(error.to_string()))?;

        let mut stream = established.stream;

        // Perform AnyTLS client authentication flight
        send_authentication(&mut stream, &self.password, 0)
            .await
            .map_err(|error| OutboundError::Connect(error.to_string()))?;

        let session = AnyTlsSession::new(stream);
        pool.push(Arc::clone(&session));

        Ok(session)
    }

    /// Connects a TCP stream through this AnyTLS node to `authority`.
    pub async fn connect(
        &self,
        authority: &str,
        recorder: &Arc<std::sync::Mutex<Recorder>>,
    ) -> Result<Established, OutboundError> {
        let session = self.get_or_dial_session(recorder).await?;
        let virtual_stream = session.open_stream(authority).await?;

        Ok(Established {
            stream: Box::new(virtual_stream),
            local_port: None,
            socket: None,
            alpn: None,
        })
    }

    /// Connects a UDP datagram session through this AnyTLS node to `authority`.
    pub async fn connect_datagram(
        &self,
        authority: &str,
        recorder: &Arc<std::sync::Mutex<Recorder>>,
    ) -> Result<EstablishedDatagrams, NetError> {
        let session = self
            .get_or_dial_session(recorder)
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?;

        // Open UoT tunnel stream
        let stream = session
            .open_stream(UOT_MAGIC_ADDRESS)
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?;

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
