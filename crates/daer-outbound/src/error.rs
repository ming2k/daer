// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::time::Duration;

use daer_observe::{DialFailure, DialStage, diagnostic::codes};

use crate::alive::DialerId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundError {
    /// The connection attempt did not finish within its deadline.
    Timeout,
    /// The transport failed; the message comes from netune.
    Connect(String),
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

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("outbound dial timed out"),
            Self::Connect(message) => write!(f, "outbound dial failed: {message}"),
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
            OutboundError::Timeout => (
                DialStage::Tcp,
                codes::RELAY_DIAL_TIMEOUT,
                "outbound dial timed out".to_owned(),
                true,
            ),
            OutboundError::Connect(message) => {
                (DialStage::Tcp, codes::RELAY_DIAL_CONNECT, message, false)
            }
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
        DialFailure {
            stage,
            code,
            detail,
            elapsed: Duration::ZERO,
            timeout,
        }
    }
}

impl From<daer_proxy_protocols::ProxyProtocolError> for OutboundError {
    fn from(err: daer_proxy_protocols::ProxyProtocolError) -> Self {
        match err {
            daer_proxy_protocols::ProxyProtocolError::Timeout => Self::Timeout,
            daer_proxy_protocols::ProxyProtocolError::Connect(msg) => Self::Connect(msg),
            daer_proxy_protocols::ProxyProtocolError::UnsupportedLink(msg) => {
                Self::UnsupportedLink(msg)
            }
        }
    }
}
