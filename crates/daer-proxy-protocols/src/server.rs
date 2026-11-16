// SPDX-License-Identifier: AGPL-3.0-only

//! The byte stream to a node's own server.
//!
//! # Why this seam exists
//!
//! Every proxy protocol has two different destinations:
//!
//! * the **server** (`server:port` from the node), which terminates the protocol;
//! * the **target** (`host:port` from the flow), which is encoded in the protocol payload.
//!
//! Before this module the first destination was welded to `netune::TcpConnector` inside each
//! connector. That made an outbound chain impossible: there was no place to say "open this
//! stream through another outbound". [`ServerDialer`] is that place. A connector asks it for
//! the stream to its server and keeps naming the final target in its own header, so an outer
//! node over an inner node is exactly `outer protocol` over `inner outbound` (ADR-0044).
//!
//! The default implementation is still a direct `TcpConnector`; a chain is a different
//! implementation of the same trait, not a second protocol path.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use netune::{
    Connector, DatagramConnector, Established, NetError, SocketConfig, Target, TcpConnector,
    UdpConnector,
};
use netune_trace::TraceCollector;

use crate::error::ProxyProtocolError;

/// A boxed future, so [`ServerDialer`] stays object-safe.
///
/// `netune::Connector` uses `impl Future` in its method signature and is therefore not
/// dyn-compatible. daer needs a trait object here because the chain depth is decided by the
/// configuration, not by the type system.
pub type ServerFuture<'a> =
    Pin<Box<dyn std::future::Future<Output = Result<Established, ProxyProtocolError>> + Send + 'a>>;

/// Opens the stream to one proxy server, and the datagram session to it when the protocol has
/// a datagram form.
///
/// Implementations must apply `SO_MARK` before `connect(2)` (or before the first datagram);
/// [`crate::server::DirectServerDialer`] does, and an outbound chain delegates to the inner
/// node, which applies its own mark exactly once.
pub trait ServerDialer: fmt::Debug + Send + Sync {
    /// Opens a TCP stream to `authority` (`host:port`).
    fn connect<'a>(&'a self, authority: &'a str, recorder: &'a TraceCollector) -> ServerFuture<'a>;

    /// Opens a TCP stream to `authority` (`host:port`) before `deadline`.
    fn connect_within<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a TraceCollector,
        deadline: tokio::time::Instant,
    ) -> ServerFuture<'a> {
        Box::pin(async move {
            let Ok(remaining) = ProxyProtocolError::remaining_until(
                deadline,
                daer_observe::DialStage::Tcp,
                authority,
            ) else {
                return Err(ProxyProtocolError::timeout(
                    daer_observe::DialStage::Tcp,
                    format!("tcp connect to {authority}: dial deadline expired"),
                ));
            };
            tokio::time::timeout(remaining, self.connect(authority, recorder))
                .await
                .map_err(|_| {
                    ProxyProtocolError::timeout(
                        daer_observe::DialStage::Tcp,
                        format!(
                            "tcp connect to {authority} exceeded {} ms",
                            remaining.as_millis()
                        ),
                    )
                })?
        })
    }

    /// The datagram connector to this server, when this dialer can carry datagrams.
    ///
    /// A protocol whose UDP is carried *inside* its own stream does not use this; it is for
    /// the `direct` transport and for an outbound chain used as a transparent delegate.
    fn datagram(&self) -> Option<Arc<dyn DatagramConnector>> {
        None
    }

    /// Whether this dialer is the default direct transport.
    ///
    /// Hysteria 2 is QUIC over UDP, so its own server leg cannot be injected through a TCP
    /// dialer. The constructor asks this question and refuses the combination by name instead
    /// of accepting a detour that would silently connect directly.
    fn is_direct(&self) -> bool {
        false
    }

    /// A stable description of the route, when it is not direct.
    fn route_shape(&self) -> Option<String> {
        None
    }
}

/// The default server dialer: a direct netune TCP connector with daer's socket options.
#[derive(Debug, Clone)]
pub struct DirectServerDialer {
    connector: TcpConnector,
    unbounded_connector: TcpConnector,
    socket_config: SocketConfig,
    so_mark: Option<u32>,
    timeout: Duration,
}

pub(crate) fn build_socket_config(
    so_mark: Option<u32>,
    tcp_keepalive: Option<Duration>,
) -> SocketConfig {
    let mut socket_config = SocketConfig::default();
    if let Some(mark) = so_mark {
        socket_config = socket_config.with_mark(mark);
    }
    if let Some(idle) = tcp_keepalive {
        socket_config = socket_config.with_keepalive(idle);
    }
    socket_config
}

impl DirectServerDialer {
    #[must_use]
    pub fn new(so_mark: Option<u32>, timeout: Duration) -> Self {
        Self::new_with_keepalive(so_mark, timeout, None)
    }

    #[must_use]
    pub fn new_with_keepalive(
        so_mark: Option<u32>,
        timeout: Duration,
        tcp_keepalive: Option<Duration>,
    ) -> Self {
        let socket_config = build_socket_config(so_mark, tcp_keepalive);
        let unbounded = TcpConnector::new().with_socket_config(socket_config.clone());
        Self {
            connector: unbounded.clone().with_connect_timeout(Some(timeout)),
            unbounded_connector: unbounded.with_connect_timeout(None),
            socket_config,
            so_mark,
            timeout,
        }
    }

    /// Configures or clears TCP `SO_KEEPALIVE` on outbound connections.
    #[must_use]
    pub fn with_tcp_keepalive(self, tcp_keepalive: Option<Duration>) -> Self {
        Self::new_with_keepalive(self.so_mark, self.timeout, tcp_keepalive)
    }
}

impl ServerDialer for DirectServerDialer {
    fn connect<'a>(&'a self, authority: &'a str, recorder: &'a TraceCollector) -> ServerFuture<'a> {
        Box::pin(async move {
            let target = Target::plain(authority);
            self.connector
                .connect(&target, recorder)
                .await
                .map_err(|error| ProxyProtocolError::from_net_error(&error))
        })
    }

    fn connect_within<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a TraceCollector,
        deadline: tokio::time::Instant,
    ) -> ServerFuture<'a> {
        Box::pin(async move {
            let remaining = ProxyProtocolError::remaining_until(
                deadline,
                daer_observe::DialStage::Tcp,
                authority,
            )?;
            let target = Target::plain(authority);
            self.unbounded_connector
                .clone()
                .with_connect_timeout(Some(remaining))
                .connect(&target, recorder)
                .await
                .map_err(|error| ProxyProtocolError::from_net_error(&error))
        })
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramConnector>> {
        Some(Arc::new(
            UdpConnector::new()
                .with_socket_config(self.socket_config.clone())
                .with_connect_timeout(Some(self.timeout)),
        ))
    }

    fn is_direct(&self) -> bool {
        true
    }
}

/// Adapts a [`ServerDialer`] to netune's generic [`Connector`] interface.
///
/// `TlsRouterConnector<C>` and `ProxyConnector<C>` are generic over a netune connector. They consume
/// this adapter when their inner leg is a daer server dialer, which is what lets Trojan,
/// AnyTLS, SOCKS5 and HTTP participate in a chain without a second TLS or CONNECT
/// implementation.
#[derive(Debug, Clone)]
pub struct ServerConnector {
    dialer: Arc<dyn ServerDialer>,
    deadline: Option<tokio::time::Instant>,
}

impl ServerConnector {
    #[must_use]
    pub fn new(dialer: Arc<dyn ServerDialer>) -> Self {
        Self {
            dialer,
            deadline: None,
        }
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: tokio::time::Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }
}

impl Connector for ServerConnector {
    fn socket_shape(&self) -> Option<String> {
        None
    }

    fn route_shape(&self) -> Option<String> {
        self.dialer.route_shape()
    }

    async fn connect(
        &self,
        target: &Target,
        recorder: &TraceCollector,
    ) -> Result<Established, NetError> {
        let result = match self.deadline {
            Some(deadline) => {
                self.dialer
                    .connect_within(&target.authority, recorder, deadline)
                    .await
            }
            None => self.dialer.connect(&target.authority, recorder).await,
        };
        result.map_err(|error| error.into_net_error(&target.authority))
    }
}
