// SPDX-License-Identifier: AGPL-3.0-only

//! Machine-readable failure identity.
//!
//! A `String` reason is a sentence for a human; it is not something a collector can group, an
//! incident record can link, or a test can assert. `ErrorCode` is the stable identity, and
//! [`Diagnostic`] is the trait a layer implements to name it without importing another layer's
//! policy vocabulary.

use std::fmt;
use std::time::Duration;

/// A stable, dotted failure code.
///
/// Codes are part of the diagnostic contract. Renaming one is a breaking change for incident
/// records, dashboards and runbooks; add a new code instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ErrorCode(&'static str);

impl ErrorCode {
    /// Declares a code.
    ///
    /// The constructor is `const` so codes can live as associated constants and be checked for
    /// uniqueness by a test.
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self(code)
    }

    /// The dotted spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// The stable codes this build can emit.
///
/// This is intentionally a flat module rather than an enum: an error code is a value that can
/// cross a crate boundary without making the receiver depend on the sender's error enum. A
/// test asserts every code is unique and non-empty.
pub mod codes {
    use super::ErrorCode;

    pub const CONFIG_INVALID: ErrorCode = ErrorCode::new("daer.config.invalid");
    pub const CONFIG_UNREADABLE: ErrorCode = ErrorCode::new("daer.config.unreadable");
    pub const GENERATION_INVALID: ErrorCode = ErrorCode::new("daer.generation.invalid");
    pub const DATAPATH_ATTACH_FAILED: ErrorCode = ErrorCode::new("daer.datapath.attach_failed");
    pub const DATAPATH_OBJECT_MISSING: ErrorCode = ErrorCode::new("daer.datapath.object_missing");
    pub const DATAPATH_CLEANUP_FAILED: ErrorCode = ErrorCode::new("daer.datapath.cleanup_failed");
    pub const NETNS_SETUP_FAILED: ErrorCode = ErrorCode::new("daer.netns.setup_failed");
    pub const RELAY_ACCEPT_RESOURCE: ErrorCode = ErrorCode::new("daer.relay.accept_resource");
    pub const RELAY_SOCKET: ErrorCode = ErrorCode::new("daer.relay.socket");
    pub const RELAY_SPLICE: ErrorCode = ErrorCode::new("daer.relay.splice");
    pub const RELAY_DIAL_TIMEOUT: ErrorCode = ErrorCode::new("daer.relay.dial_timeout");
    pub const RELAY_DIAL_CONNECT: ErrorCode = ErrorCode::new("daer.relay.dial_connect");
    pub const RELAY_DIAL_TLS: ErrorCode = ErrorCode::new("daer.relay.dial_tls");
    pub const RELAY_DIAL_HANDSHAKE: ErrorCode = ErrorCode::new("daer.relay.dial_handshake");
    pub const RELAY_DIAL_NO_NODE: ErrorCode = ErrorCode::new("daer.relay.dial_no_node");
    pub const RELAY_DIAL_UNSUPPORTED: ErrorCode = ErrorCode::new("daer.relay.dial_unsupported");
    pub const RELAY_DIAL_UNKNOWN_GROUP: ErrorCode = ErrorCode::new("daer.relay.dial_unknown_group");
    pub const RELAY_DIAL_NO_DATAGRAM: ErrorCode = ErrorCode::new("daer.relay.dial_no_datagram");
    pub const DNS_UPSTREAM_TIMEOUT: ErrorCode = ErrorCode::new("daer.dns.upstream_timeout");
    pub const DNS_UPSTREAM_CONNECT: ErrorCode = ErrorCode::new("daer.dns.upstream_connect");
    pub const DNS_UPSTREAM_PROTOCOL: ErrorCode = ErrorCode::new("daer.dns.upstream_protocol");
    pub const DNS_UPSTREAM_UNSUPPORTED: ErrorCode = ErrorCode::new("daer.dns.upstream_unsupported");
    pub const PROVIDER_FETCH: ErrorCode = ErrorCode::new("daer.provider.fetch");
    pub const PROVIDER_INVALID: ErrorCode = ErrorCode::new("daer.provider.invalid");
    pub const SUBSCRIPTION_FETCH: ErrorCode = ErrorCode::new("daer.subscription.fetch");
    pub const SUBSCRIPTION_INVALID: ErrorCode = ErrorCode::new("daer.subscription.invalid");
    pub const PROTOCOL_ALERT: ErrorCode = ErrorCode::new("daer.protocol.alert");
    pub const PROTOCOL_FRAMING: ErrorCode = ErrorCode::new("daer.protocol.framing");
    pub const INTERNAL: ErrorCode = ErrorCode::new("daer.internal");
}

/// A diagnosable error: a stable code, an optional remediation, and the human chain.
pub trait Diagnostic: std::error::Error {
    /// The stable identity of this failure.
    fn code(&self) -> ErrorCode;

    /// What an operator should do, when there is an action. `None` means "report and attach the
    /// bundle"; a wrong action is worse than no action.
    fn remediation(&self) -> Option<&'static str> {
        None
    }
}

/// The stage of a dial that failed.
///
/// This is neutral: `daer-relay` can carry it without importing routing, outbound or protocol
/// vocabulary, and `daer-control` maps its typed errors into it at the seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DialStage {
    /// A name that the node or authority needed did not resolve.
    Dns,
    /// The TCP connection did not open.
    Tcp,
    /// The TLS handshake did not complete.
    Tls,
    /// The proxy protocol handshake did not complete.
    Handshake,
    /// The decision itself refused the flow (no group, no alive node, no datagram support).
    Policy,
}

impl DialStage {
    /// The stable spelling used in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Handshake => "handshake",
            Self::Policy => "policy",
        }
    }
}

impl fmt::Display for DialStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failed outbound leg, carried across the relay boundary without a policy type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialFailure {
    /// Where the attempt stopped.
    pub stage: DialStage,
    /// The stable failure identity.
    pub code: ErrorCode,
    /// The sanitized human detail.
    pub detail: String,
    /// How long the attempt took before it failed.
    pub elapsed: Duration,
    /// Whether the failure was a deadline.
    pub timeout: bool,
}

impl DialFailure {
    /// Builds a failure.
    #[must_use]
    pub fn new(stage: DialStage, code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            stage,
            code,
            // A transport error can embed a user-supplied URL. The type cannot make the
            // string safe, so the constructor removes URI-shaped tokens before the value can
            // reach an event or a bundle.
            detail: crate::redact::redact_text(&detail.into()),
            elapsed: Duration::ZERO,
            timeout: false,
        }
    }

    /// Records the elapsed time.
    #[must_use]
    pub const fn with_elapsed(mut self, elapsed: Duration) -> Self {
        self.elapsed = elapsed;
        self
    }

    /// Marks the failure as a deadline.
    #[must_use]
    pub const fn timed_out(mut self, timeout: bool) -> Self {
        self.timeout = timeout;
        self
    }
}

impl fmt::Display for DialFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed at {}: {}", self.code, self.stage, self.detail)
    }
}

impl std::error::Error for DialFailure {}

impl Diagnostic for DialFailure {
    fn code(&self) -> ErrorCode {
        self.code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_code_is_unique_and_namespaced() {
        let all = [
            codes::CONFIG_INVALID,
            codes::CONFIG_UNREADABLE,
            codes::GENERATION_INVALID,
            codes::DATAPATH_ATTACH_FAILED,
            codes::DATAPATH_OBJECT_MISSING,
            codes::DATAPATH_CLEANUP_FAILED,
            codes::NETNS_SETUP_FAILED,
            codes::RELAY_ACCEPT_RESOURCE,
            codes::RELAY_SOCKET,
            codes::RELAY_SPLICE,
            codes::RELAY_DIAL_TIMEOUT,
            codes::RELAY_DIAL_CONNECT,
            codes::RELAY_DIAL_TLS,
            codes::RELAY_DIAL_HANDSHAKE,
            codes::RELAY_DIAL_NO_NODE,
            codes::RELAY_DIAL_UNSUPPORTED,
            codes::RELAY_DIAL_UNKNOWN_GROUP,
            codes::RELAY_DIAL_NO_DATAGRAM,
            codes::DNS_UPSTREAM_TIMEOUT,
            codes::DNS_UPSTREAM_CONNECT,
            codes::DNS_UPSTREAM_PROTOCOL,
            codes::DNS_UPSTREAM_UNSUPPORTED,
            codes::PROVIDER_FETCH,
            codes::PROVIDER_INVALID,
            codes::SUBSCRIPTION_FETCH,
            codes::SUBSCRIPTION_INVALID,
            codes::PROTOCOL_ALERT,
            codes::PROTOCOL_FRAMING,
            codes::INTERNAL,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for code in all {
            assert!(code.as_str().starts_with("daer."), "{code}");
            assert!(
                code.as_str()
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
                "{code} is not a stable dotted code"
            );
            assert!(seen.insert(code), "duplicate error code: {code}");
        }
    }

    #[test]
    fn a_dial_failure_redacts_a_uri_in_its_detail() {
        let failure = DialFailure::new(
            DialStage::Tcp,
            codes::RELAY_DIAL_CONNECT,
            "connect to ss://aes-256-gcm:hunter2@host:443 failed",
        );
        assert!(!failure.detail.contains("hunter2"), "{failure:?}");
        assert!(failure.detail.contains("<redacted>"), "{failure:?}");
    }

    #[test]
    fn a_dial_failure_displays_its_stage_and_code() {
        let failure = DialFailure::new(
            DialStage::Tls,
            codes::RELAY_DIAL_TLS,
            "certificate verify failed",
        );
        let rendered = failure.to_string();
        assert!(rendered.contains("daer.relay.dial_tls"), "{rendered}");
        assert!(rendered.contains("tls"), "{rendered}");
    }
}
