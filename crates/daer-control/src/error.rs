// SPDX-License-Identifier: AGPL-3.0-only

//! Why a TCP byte stream was rejected before it reached the proxy.

use std::fmt;
use std::io;
use std::net::SocketAddr;

use daer_outbound::OutboundError;

/// The reason an accepted connection is not eligible for proxying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// The original destination *is* the transparent port itself: someone
    /// connected to the port directly instead of being redirected into it. That
    /// traffic has no destination to reach, and answering it would turn the
    /// transparent port into a service.
    SelfConnect { destination: std::net::SocketAddr },
    /// A routing rule matched `block`: the flow is dropped on purpose.
    Blocked { destination: std::net::SocketAddr },
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfConnect { destination } => write!(
                f,
                "connection to the transparent port itself ({destination}); \
                 not a redirected flow"
            ),
            Self::Blocked { destination } => {
                write!(f, "blocked by a routing rule: {destination}")
            }
        }
    }
}

impl std::error::Error for Reject {}

/// Errors raised while accepting or relaying.
#[derive(Debug)]
pub enum IngressError {
    /// A socket could not be created, configured or bound.
    Socket(io::Error),
    /// `accept(2)` failed in a way that ends the loop.
    Accept(io::Error),
    /// The connection was not produced by the datapath.
    Rejected(Reject),
    /// Relaying bytes between the two halves failed.
    Relay(io::Error),
    /// The outbound leg could not be opened.
    Dial {
        destination: SocketAddr,
        source: OutboundError,
    },
}

impl fmt::Display for IngressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(error) => write!(f, "transparent listener: {error}"),
            Self::Accept(error) => write!(f, "accept failed: {error}"),
            Self::Rejected(reject) => write!(f, "{reject}"),
            Self::Relay(error) => write!(f, "relay failed: {error}"),
            Self::Dial {
                destination,
                source,
            } => write!(f, "cannot reach {destination}: {source}"),
        }
    }
}

impl std::error::Error for IngressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(error) | Self::Accept(error) | Self::Relay(error) => Some(error),
            Self::Dial { source, .. } => Some(source),
            Self::Rejected(reject) => Some(reject),
        }
    }
}

impl From<Reject> for IngressError {
    fn from(reject: Reject) -> Self {
        Self::Rejected(reject)
    }
}
