// SPDX-License-Identifier: AGPL-3.0-only

//! Test doubles for the two decider traits.
//!
//! Compiled only for this crate's own tests. A data-path test must not need a routing
//! configuration, a proxy protocol or a network stack: what it is asserting is that a
//! rejected flow closes one connection, that a reply reaches the peer that asked, that an
//! idle session is reaped. A routing decision is an input to those, not the subject.

use std::net::SocketAddr;
use std::sync::Arc;

use netune::{SocketConfig, UdpConnector};

use daer_observe::{DialFailure, DialStage, diagnostic::codes};

use crate::error::RelayError;
use crate::inbound::FlowFacts;
use crate::relay::datagram::{DatagramLeg, DatagramRouter, OpenDatagram};

/// A datagram router that answers `direct` for everything.
///
/// Reports no known domain and opens a plain [`UdpConnector`] session to the literal
/// destination, which is exactly what the control plane does for a `direct` verdict.
#[derive(Debug)]
pub struct DirectRouter;

impl DatagramRouter for DirectRouter {
    fn known_domain(&self, _destination: SocketAddr) -> Option<String> {
        None
    }

    fn open_datagram<'a>(&'a self, facts: FlowFacts, _domain: Option<&'a str>) -> OpenDatagram<'a> {
        Box::pin(async move {
            let connector: Arc<dyn netune::DatagramConnector> =
                Arc::new(UdpConnector::new().with_socket_config(SocketConfig::default()));
            Ok(DatagramLeg {
                target: facts.destination.to_string(),
                connector,
            })
        })
    }
}

/// A datagram router that refuses every flow, for the negative control.
#[derive(Debug)]
pub struct RefusingRouter(pub &'static str);

impl DatagramRouter for RefusingRouter {
    fn known_domain(&self, _destination: SocketAddr) -> Option<String> {
        None
    }

    fn open_datagram<'a>(
        &'a self,
        _facts: FlowFacts,
        _domain: Option<&'a str>,
    ) -> OpenDatagram<'a> {
        let reason = self.0;
        Box::pin(async move {
            Err::<DatagramLeg, DialFailure>(DialFailure::new(
                DialStage::Policy,
                codes::RELAY_DIAL_NO_NODE,
                reason,
            ))
        })
    }
}

/// A `Decide` double that dials one fixed echo address, optionally rejecting instead.
#[derive(Debug)]
pub struct EchoDecide {
    /// The address every flow is sent to.
    pub upstream: SocketAddr,
    /// When true, every flow is refused as if it were not redirected.
    pub reject: bool,
}

impl crate::serve::Decide for EchoDecide {
    type Upstream = tokio::net::TcpStream;
    type Future<'a> = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Upstream, RelayError>> + Send + 'a>,
    >;

    fn decide<'a>(&'a self, flow: &'a crate::inbound::tcp::Accepted) -> Self::Future<'a> {
        let upstream = self.upstream;
        let reject = self.reject;
        let destination = flow.destination;
        Box::pin(async move {
            if reject {
                return Err(RelayError::Rejected(crate::error::Reject::Blocked {
                    destination,
                }));
            }
            tokio::net::TcpStream::connect(upstream)
                .await
                .map_err(RelayError::Relay)
        })
    }
}
