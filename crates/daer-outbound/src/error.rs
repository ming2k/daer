// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use daer_observe::{DialFailure, DialStage, ErrorCode, diagnostic::codes};
use daer_proxy_protocols::ProxyProtocolError;
use netune::NetError;

use crate::alive::DialerId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundError {
    /// The connection attempt did not finish within its deadline.
    Timeout {
        stage: DialStage,
        detail: String,
    },
    /// The transport or handshake failed; stage and code come from netune / protocol layers.
    Connect {
        stage: DialStage,
        code: ErrorCode,
        detail: String,
    },
    UnknownDialer(DialerId),
    UnsupportedLink(String),
    /// A rule or fallback named a group that this configuration does not declare.
    UnknownElection(String),
    /// The group has no node that can be selected (empty, or all marked dead).
    NoElectableNode(String),
    /// The node is reachable but this build cannot carry datagrams through it.
    ///
    /// Distinct from [`Self::UnsupportedLink`]: the link parsed, the node works for
    /// TCP, and only the datagram leg is missing. Reporting it as an unsupported
    /// link would send an operator looking for a typo in a link that is correct.
    NoDatagramSupport(String),
    /// A `detour` names a node name that does not exist.
    UnknownDetour {
        node: String,
        detour: String,
    },
    /// The detour graph contains a cycle.
    DetourCycle(String),
    /// The detour target exists but this build cannot turn it into a dialer.
    ///
    /// Kept distinct from [`Self::UnsupportedLink`] so a group builder never skips a node that
    /// an operator explicitly asked to chain: an unsupported *target* is a broken chain, not an
    /// unselectable leaf.
    DetourBroken {
        node: String,
        detour: String,
        reason: String,
    },
    /// Two nodes declare the same name, so a detour reference is ambiguous.
    DuplicateNodeName(String),
}

impl OutboundError {
    /// Constructs a deadline-expiry error for `stage`.
    #[must_use]
    pub fn timeout(stage: DialStage, detail: impl Into<String>) -> Self {
        Self::Timeout {
            stage,
            detail: detail.into(),
        }
    }

    /// Constructs a structured transport/handshake error.
    #[must_use]
    pub fn connect(stage: DialStage, code: ErrorCode, detail: impl Into<String>) -> Self {
        Self::Connect {
            stage,
            code,
            detail: detail.into(),
        }
    }

    /// Constructs a DNS failure.
    #[must_use]
    pub fn dns(detail: impl Into<String>) -> Self {
        Self::connect(DialStage::Dns, codes::RELAY_DIAL_CONNECT, detail)
    }

    /// Constructs a TCP/UDP transport failure.
    #[must_use]
    pub fn tcp(detail: impl Into<String>) -> Self {
        Self::connect(DialStage::Tcp, codes::RELAY_DIAL_CONNECT, detail)
    }

    /// Constructs a proxy handshake failure.
    #[must_use]
    pub fn handshake(detail: impl Into<String>) -> Self {
        Self::connect(DialStage::Handshake, codes::RELAY_DIAL_HANDSHAKE, detail)
    }

    /// Translates a [`NetError`] without flattening its stage, timeout status, or cause.
    #[must_use]
    pub fn from_net_error(error: &NetError) -> Self {
        ProxyProtocolError::from_net_error(error).into()
    }

    /// Converts this error into [`ProxyProtocolError`] across recursive detour hops.
    #[must_use]
    pub fn into_proxy_error(&self) -> ProxyProtocolError {
        match self {
            Self::Timeout { stage, detail } => ProxyProtocolError::timeout(*stage, detail.clone()),
            Self::Connect {
                stage,
                code,
                detail,
            } => ProxyProtocolError::connect(*stage, *code, detail.clone()),
            Self::UnsupportedLink(msg) => ProxyProtocolError::UnsupportedLink(msg.clone()),
            other => {
                let failure = DialFailure::from(other.clone());
                ProxyProtocolError::connect(failure.stage, failure.code, failure.detail)
            }
        }
    }

    /// Human-readable error detail.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Timeout { detail, .. }
            | Self::Connect { detail, .. }
            | Self::UnsupportedLink(detail) => detail.clone(),
            other => other.to_string(),
        }
    }

    /// Whether this failure represents a transport/node health issue (timeout, connect/TLS/handshake)
    /// vs a local policy/configuration error.
    #[must_use]
    pub const fn is_transient_dial_failure(&self) -> bool {
        matches!(self, Self::Timeout { .. } | Self::Connect { .. })
    }
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout { stage, detail } => write!(f, "{stage} dial timed out: {detail}"),
            Self::Connect {
                stage,
                code,
                detail,
            } => write!(f, "{stage} dial failed ({code}): {detail}"),
            Self::UnknownDialer(id) => {
                write!(f, "dialer {:?} is not a candidate of this election", id)
            }
            Self::UnsupportedLink(message) => write!(f, "unsupported node link: {message}"),
            Self::UnknownElection(name) => {
                write!(f, "election {name:?} is not declared in this configuration")
            }
            Self::NoElectableNode(name) => write!(
                f,
                "election {name:?} has no electable node (empty input, or none alive)"
            ),
            Self::NoDatagramSupport(name) => {
                write!(f, "node {name:?} cannot carry datagrams in this build")
            }
            Self::UnknownDetour { node, detour } => write!(
                f,
                "node {node:?} detours through {detour:?}, but no node declares that name"
            ),
            Self::DetourCycle(chain) => write!(f, "detour cycle: {chain}"),
            Self::DetourBroken {
                node,
                detour,
                reason,
            } => write!(
                f,
                "node {node:?} detours through {detour:?}, which cannot be built: {reason}"
            ),
            Self::DuplicateNodeName(name) => {
                write!(
                    f,
                    "duplicate node name {name:?}; a detour must name exactly one node"
                )
            }
        }
    }
}

impl std::error::Error for OutboundError {}

/// Maps an outbound failure into the relay's neutral diagnostic vocabulary.
///
/// This is the seam that keeps `daer-relay` free of routing/outbound types while preserving
/// the stage and stable code all the way to the flow event and the incident bundle.
impl From<OutboundError> for DialFailure {
    fn from(error: OutboundError) -> Self {
        let (stage, code, detail, timeout) = match error {
            OutboundError::Timeout { stage, detail } => {
                (stage, codes::RELAY_DIAL_TIMEOUT, detail, true)
            }
            OutboundError::Connect {
                stage,
                code,
                detail,
            } => (stage, code, detail, false),
            OutboundError::UnknownDialer(id) => (
                DialStage::Policy,
                codes::RELAY_DIAL_NO_NODE,
                format!("dialer {id:?} is not in this group"),
                false,
            ),
            OutboundError::UnsupportedLink(message) => (
                DialStage::Policy,
                codes::RELAY_DIAL_UNSUPPORTED,
                message,
                false,
            ),
            OutboundError::UnknownElection(name) => (
                DialStage::Policy,
                codes::RELAY_DIAL_UNKNOWN_ELECTION,
                format!("election {name:?} is not declared in this configuration"),
                false,
            ),
            OutboundError::NoElectableNode(name) => (
                DialStage::Policy,
                codes::RELAY_DIAL_NO_NODE,
                format!("election {name:?} has no electable node"),
                false,
            ),
            OutboundError::NoDatagramSupport(name) => (
                DialStage::Policy,
                codes::RELAY_DIAL_NO_DATAGRAM,
                format!("node {name:?} cannot carry datagrams in this build"),
                false,
            ),
            OutboundError::UnknownDetour { node, detour } => (
                DialStage::Policy,
                codes::RELAY_DIAL_UNSUPPORTED,
                format!("node {node:?} detours through {detour:?}, but no node declares that name"),
                false,
            ),
            OutboundError::DetourCycle(chain) => (
                DialStage::Policy,
                codes::RELAY_DIAL_UNSUPPORTED,
                format!("detour cycle: {chain}"),
                false,
            ),
            OutboundError::DetourBroken {
                node,
                detour,
                reason,
            } => (
                DialStage::Policy,
                codes::RELAY_DIAL_UNSUPPORTED,
                format!(
                    "node {node:?} detours through {detour:?}, which cannot be built: {reason}"
                ),
                false,
            ),
            OutboundError::DuplicateNodeName(name) => (
                DialStage::Policy,
                codes::RELAY_DIAL_UNSUPPORTED,
                format!("duplicate node name {name:?}; a detour must name exactly one node"),
                false,
            ),
        };
        DialFailure::new(stage, code, detail).timed_out(timeout)
    }
}

impl From<ProxyProtocolError> for OutboundError {
    fn from(err: ProxyProtocolError) -> Self {
        match err {
            ProxyProtocolError::Timeout { stage, detail } => Self::Timeout { stage, detail },
            ProxyProtocolError::Connect {
                stage,
                code,
                detail,
            } => Self::Connect {
                stage,
                code,
                detail,
            },
            ProxyProtocolError::UnsupportedLink(msg) => Self::UnsupportedLink(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_transport_failures_are_transient() {
        assert!(OutboundError::timeout(DialStage::Tcp, "deadline").is_transient_dial_failure());
        assert!(
            OutboundError::connect(DialStage::Tls, codes::RELAY_DIAL_TLS, "handshake")
                .is_transient_dial_failure()
        );
        assert!(!OutboundError::UnsupportedLink("bad link".to_owned()).is_transient_dial_failure());
        assert!(!OutboundError::NoElectableNode("proxy".to_owned()).is_transient_dial_failure());
    }
}
