// SPDX-License-Identifier: AGPL-3.0-only

//! Why a flow was refused, and which half of the relay failed.

use std::fmt;
use std::io;
use std::net::SocketAddr;

pub use daer_observe::DialFailure;

/// The reason an accepted flow is not eligible for proxying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// A routing rule matched `block`: the flow is dropped on purpose.
    Blocked { destination: SocketAddr },
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked { destination } => {
                write!(f, "blocked by a routing rule: {destination}")
            }
        }
    }
}

impl std::error::Error for Reject {}

/// Errors raised while accepting, deciding or relaying.
#[derive(Debug)]
pub enum RelayError {
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
        failure: DialFailure,
    },
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(error) => write!(f, "transparent listener: {error}"),
            Self::Accept(error) => write!(f, "accept failed: {error}"),
            Self::Rejected(reject) => write!(f, "{reject}"),
            Self::Relay(error) => write!(f, "relay failed: {error}"),
            Self::Dial {
                destination,
                failure,
            } => write!(f, "cannot reach {destination}: {failure}"),
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(error) | Self::Accept(error) | Self::Relay(error) => Some(error),
            Self::Rejected(reject) => Some(reject),
            Self::Dial { failure, .. } => Some(failure),
        }
    }
}

impl From<Reject> for RelayError {
    fn from(reject: Reject) -> Self {
        Self::Rejected(reject)
    }
}
