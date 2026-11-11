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
    FixedIndexOutOfRange {
        index: usize,
        count: usize,
    },
    UnsupportedLink(String),
    /// A rule or fallback named a group that this configuration does not declare.
    UnknownGroup(String),
    /// The group has no node that can be selected (empty, or all marked dead).
    NoAliveNode(String),
    /// The node is reachable but this build cannot carry datagrams through it.
    ///
    /// Distinct from [`Self::UnsupportedLink`]: the link parsed, the node works for
    /// TCP, and only the datagram leg is missing. Reporting it as an unsupported
    /// link would send an operator looking for a typo in a link that is correct.
    NoDatagramSupport(String),
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("outbound dial timed out"),
            Self::Connect(message) => write!(f, "outbound dial failed: {message}"),
            Self::UnknownDialer(id) => write!(f, "dialer {:?} is not in this group", id),
            Self::FixedIndexOutOfRange { index, count } => write!(
                f,
                "selected dialer index {index} is out of range (the group has {count} dialer(s))"
            ),
            Self::UnsupportedLink(message) => write!(f, "unsupported node link: {message}"),
            Self::UnknownGroup(name) => {
                write!(f, "group {name:?} is not declared in this configuration")
            }
            Self::NoAliveNode(name) => write!(
                f,
                "group {name:?} has no selectable node (empty after filters, or none alive)"
            ),
            Self::NoDatagramSupport(name) => {
                write!(f, "node {name:?} cannot carry datagrams in this build")
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
            OutboundError::FixedIndexOutOfRange { index, count } => (
                DialStage::Policy,
                codes::RELAY_DIAL_NO_NODE,
                format!(
                    "selected dialer index {index} is out of range (the group has {count} dialer(s))"
                ),
                false,
            ),
            OutboundError::UnsupportedLink(message) => (
                DialStage::Policy,
                codes::RELAY_DIAL_UNSUPPORTED,
                message,
                false,
            ),
            OutboundError::UnknownGroup(name) => (
                DialStage::Policy,
                codes::RELAY_DIAL_UNKNOWN_GROUP,
                format!("group {name:?} is not declared in this configuration"),
                false,
            ),
            OutboundError::NoAliveNode(name) => (
                DialStage::Policy,
                codes::RELAY_DIAL_NO_NODE,
                format!("group {name:?} has no selectable node"),
                false,
            ),
            OutboundError::NoDatagramSupport(name) => (
                DialStage::Policy,
                codes::RELAY_DIAL_NO_DATAGRAM,
                format!("node {name:?} cannot carry datagrams in this build"),
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
