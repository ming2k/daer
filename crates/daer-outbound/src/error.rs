// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

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
