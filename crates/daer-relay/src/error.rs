// SPDX-License-Identifier: AGPL-3.0-only

//! Why a flow was refused, and which half of the relay failed.

use std::fmt;
use std::io;
use std::net::SocketAddr;

/// The reason an accepted flow is not eligible for proxying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// The original destination *is* the transparent port itself: someone
    /// connected to the port directly instead of being redirected into it. That
    /// traffic has no destination to reach, and answering it would turn the
    /// transparent port into a service.
    SelfConnect { destination: SocketAddr },
    /// A routing rule matched `block`: the flow is dropped on purpose.
    Blocked { destination: SocketAddr },
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

/// Why an outbound leg could not be opened.
///
/// Deliberately a string: this crate owns no routing policy and therefore has no
/// vocabulary for *why* a decision refused — the decider does. Copying a foreign
/// error enum here would make every new selection failure a change to the data path,
/// which is exactly the coupling this crate exists to avoid.
pub type DialFailure = String;

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
        reason: DialFailure,
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
                reason,
            } => write!(f, "cannot reach {destination}: {reason}"),
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(error) | Self::Accept(error) | Self::Relay(error) => Some(error),
            Self::Rejected(reject) => Some(reject),
            Self::Dial { .. } => None,
        }
    }
}

impl From<Reject> for RelayError {
    fn from(reject: Reject) -> Self {
        Self::Rejected(reject)
    }
}
