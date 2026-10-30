// SPDX-License-Identifier: AGPL-3.0-only

//! The direct dialer: a plain TCP connection with daer's socket options.
//!
//! `SO_MARK` is applied before `connect(2)` through netune's pre-connect path,
//! so the SYN already carries the mark the eBPF program uses to recognise
//! daer-originated traffic. Without it, daer's own connections to a node would be
//! routed by its own rules.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune::{Connector, Established, SocketConfig, Target, TcpConnector};
use netune_trace::Recorder;

use crate::error::OutboundError;

pub struct DirectDialer {
    connector: TcpConnector,
    timeout: Duration,
}

impl fmt::Debug for DirectDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectDialer")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl DirectDialer {
    pub fn new(so_mark: Option<u32>, timeout: Duration) -> Self {
        let mut socket_config = SocketConfig::default();
        if let Some(mark) = so_mark {
            socket_config = socket_config.with_mark(mark);
        }
        Self {
            connector: TcpConnector::new()
                .with_socket_config(socket_config)
                .with_connect_timeout(Some(timeout)),
            timeout,
        }
    }

    /// Opens a TCP connection to `authority` (`host:port`).
    pub async fn connect(&self, authority: &str) -> Result<Established, OutboundError> {
        let target = Target::plain(authority);
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));
        tokio::time::timeout(self.timeout, self.connector.connect(&target, &recorder))
            .await
            .map_err(|_| OutboundError::Timeout)?
            .map_err(|error| OutboundError::Connect(error.to_string()))
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
            OutboundError::Connect(_) | OutboundError::Timeout
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
            Err(OutboundError::Connect(message)) => {
                // Unprivileged runners cannot set SO_MARK; anything else is a
                // regression in the pre-connect path.
                assert!(
                    message.contains("permitted") || message.contains("Operation not permitted"),
                    "unexpected error: {message}"
                );
                accept.abort();
            }
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
