// SPDX-License-Identifier: AGPL-3.0-only

//! The direct dialer: a plain TCP connection with daer's socket options.
//!
//! `SO_MARK` is applied before `connect(2)` through netune's pre-connect path,
//! so the SYN already carries the mark the eBPF program uses to recognise
//! daer-originated traffic. Without it, daer's own connections to a node would be
//! routed by its own rules.

use std::fmt;
use std::time::Duration;

use netune::{Connector, Established, Target, TcpConnector};
use netune_trace::TraceCollector;

use crate::error::OutboundError;
use crate::node_dialer::DialerOptions;

pub struct DirectDialer {
    connector: TcpConnector,
    so_mark: Option<u32>,
    timeout: Duration,
    tcp_keepalive: Option<Duration>,
}

impl fmt::Debug for DirectDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectDialer")
            .field("timeout", &self.timeout)
            .field("tcp_keepalive", &self.tcp_keepalive)
            .finish_non_exhaustive()
    }
}

impl DirectDialer {
    pub fn new(so_mark: Option<u32>, timeout: Duration) -> Self {
        Self::new_with_keepalive(so_mark, timeout, None)
    }

    /// Configures TCP `SO_KEEPALIVE` idle timeout on direct egress sockets.
    #[must_use]
    pub fn with_tcp_keepalive(self, tcp_keepalive: Option<Duration>) -> Self {
        Self::new_with_keepalive(self.so_mark, self.timeout, tcp_keepalive)
    }

    fn new_with_keepalive(
        so_mark: Option<u32>,
        timeout: Duration,
        tcp_keepalive: Option<Duration>,
    ) -> Self {
        let socket_config = DialerOptions::socket_config_for(so_mark, tcp_keepalive);
        Self {
            connector: TcpConnector::new()
                .with_socket_config(socket_config)
                .with_connect_timeout(Some(timeout)),
            so_mark,
            timeout,
            tcp_keepalive,
        }
    }

    /// Opens a TCP connection to `authority` (`host:port`).
    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        let target = Target::plain(authority);
        let recorder = TraceCollector::disabled();
        self.connector
            .connect(&target, &recorder)
            .await
            .map_err(|error| OutboundError::from_net_error(&error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connects_to_a_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

        let dialer = DirectDialer::new(None, Duration::from_secs(2));
        let established = dialer.connect(&addr.to_string()).await.expect("connects");
        assert!(established.local_port.is_some());
        drop(established);

        tokio::time::timeout(Duration::from_secs(1), accept)
            .await
            .expect("accept completes")
            .expect("accept task")
            .expect("accept");
    }

    #[tokio::test]
    async fn reports_a_refused_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        let dialer = DirectDialer::new(None, Duration::from_millis(500));
        let error = match dialer.connect(&addr.to_string()).await {
            Ok(_) => panic!("a closed port must not connect"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            OutboundError::Connect { .. } | OutboundError::Timeout { .. }
        ));
    }

    #[tokio::test]
    async fn a_mark_is_either_applied_or_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

        let dialer = DirectDialer::new(Some(1), Duration::from_secs(2));
        match dialer.connect(&addr.to_string()).await {
            Ok(established) => {
                drop(established);
                accept.abort();
            }
            Err(OutboundError::Connect { detail, .. }) => {
                // Unprivileged runners cannot set SO_MARK; anything else is a
                // regression in the pre-connect path.
                assert!(
                    detail.contains("permitted") || detail.contains("Operation not permitted"),
                    "unexpected error: {detail}"
                );
                accept.abort();
            }
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn tcp_keepalive_option_connects_and_toggles() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

        let dialer = DirectDialer::new(None, Duration::from_secs(2))
            .with_tcp_keepalive(Some(Duration::from_secs(15)));
        let established = dialer.connect(&addr.to_string()).await.expect("connects");
        drop(established);
        accept.await.expect("task").expect("accept");

        let opts_with = DialerOptions::new(None, Duration::from_secs(2))
            .with_tcp_keepalive(Some(Duration::from_secs(15)));
        let opts_without =
            DialerOptions::new(None, Duration::from_secs(2)).with_tcp_keepalive(None);
        assert_eq!(opts_with.tcp_keepalive, Some(Duration::from_secs(15)));
        assert_eq!(opts_without.tcp_keepalive, None);
    }
}
