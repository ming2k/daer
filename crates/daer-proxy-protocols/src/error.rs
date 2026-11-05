// SPDX-License-Identifier: AGPL-3.0-only

/// Errors returned by proxy protocol connectors and parsers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyProtocolError {
    /// The connection attempt did not finish within its deadline.
    #[error("protocol dial timed out")]
    Timeout,
    /// The protocol transport or handshake failed.
    #[error("protocol dial failed: {0}")]
    Connect(String),
    /// A link, URI or configuration parameter is unsupported or malformed.
    #[error("unsupported protocol link: {0}")]
    UnsupportedLink(String),
}
