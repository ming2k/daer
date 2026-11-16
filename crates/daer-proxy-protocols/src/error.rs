// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use daer_observe::{DialStage, ErrorCode, diagnostic::codes};
use netune::{ConnectError, ConnectErrorKind, NetError, ResolveError, ResolveErrorKind};
use netune_trace::DiagnosticPhase;
use tokio::time::Instant;

/// Errors returned by proxy protocol connectors and parsers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyProtocolError {
    /// The connection attempt did not finish within its deadline.
    #[error("{stage} timed out: {detail}")]
    Timeout { stage: DialStage, detail: String },
    /// The protocol transport or handshake failed.
    #[error("{stage} failed ({code}): {detail}")]
    Connect {
        stage: DialStage,
        code: ErrorCode,
        detail: String,
    },
    /// A link, URI or configuration parameter is unsupported or malformed.
    #[error("unsupported protocol link: {0}")]
    UnsupportedLink(String),
}

impl ProxyProtocolError {
    /// Constructs a deadline-expiry error for `stage`.
    #[must_use]
    pub fn timeout(stage: DialStage, detail: impl Into<String>) -> Self {
        Self::Timeout {
            stage,
            detail: detail.into(),
        }
    }

    /// Constructs a transport/protocol failure with explicit `stage` and `code`.
    #[must_use]
    pub fn connect(stage: DialStage, code: ErrorCode, detail: impl Into<String>) -> Self {
        Self::Connect {
            stage,
            code,
            detail: detail.into(),
        }
    }

    /// Constructs a DNS resolution failure.
    #[must_use]
    pub fn dns(detail: impl Into<String>) -> Self {
        Self::connect(DialStage::Dns, codes::RELAY_DIAL_CONNECT, detail)
    }

    /// Constructs a TCP/UDP socket-layer failure.
    #[must_use]
    pub fn tcp(detail: impl Into<String>) -> Self {
        Self::connect(DialStage::Tcp, codes::RELAY_DIAL_CONNECT, detail)
    }

    /// Constructs a TLS/REALITY handshake or certificate verification failure.
    #[must_use]
    pub fn tls(detail: impl Into<String>) -> Self {
        Self::connect(DialStage::Tls, codes::RELAY_DIAL_TLS, detail)
    }

    /// Constructs a proxy protocol or transport upgrade handshake failure.
    #[must_use]
    pub fn handshake(detail: impl Into<String>) -> Self {
        Self::connect(DialStage::Handshake, codes::RELAY_DIAL_HANDSHAKE, detail)
    }

    /// The dial stage where this error occurred.
    #[must_use]
    pub const fn stage(&self) -> DialStage {
        match self {
            Self::Timeout { stage, .. } | Self::Connect { stage, .. } => *stage,
            Self::UnsupportedLink(_) => DialStage::Policy,
        }
    }

    /// The stable machine-readable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Timeout { .. } => codes::RELAY_DIAL_TIMEOUT,
            Self::Connect { code, .. } => *code,
            Self::UnsupportedLink(_) => codes::RELAY_DIAL_UNSUPPORTED,
        }
    }

    /// Human-readable error detail without losing context across conversions.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Timeout { detail, .. }
            | Self::Connect { detail, .. }
            | Self::UnsupportedLink(detail) => detail,
        }
    }

    /// Whether the failure was caused by a timeout.
    #[must_use]
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }

    /// Returns the remaining time until `deadline`, or a typed [`Self::Timeout`] for `stage`.
    pub fn remaining_until(
        deadline: Instant,
        stage: DialStage,
        peer: &str,
    ) -> Result<Duration, Self> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Self::timeout(
                stage,
                format!("{stage} for {peer}: dial deadline expired"),
            ));
        }
        Ok(remaining)
    }

    /// Translates a [`NetError`] without flattening its stage, timeout status, or cause.
    #[must_use]
    pub fn from_net_error(error: &NetError) -> Self {
        match error {
            NetError::Resolve(err) => {
                if err.is_timeout() {
                    Self::timeout(DialStage::Dns, err.to_string())
                } else {
                    Self::dns(err.to_string())
                }
            }
            NetError::Connect(err) => {
                let stage = stage_from_phase(err.phase);
                if err.is_timeout() {
                    return Self::timeout(stage, err.to_string());
                }
                match err.kind {
                    ConnectErrorKind::Tls => Self::tls(err.to_string()),
                    ConnectErrorKind::Proxy => Self::handshake(err.to_string()),
                    ConnectErrorKind::Protocol => Self::connect(
                        if stage == DialStage::Tcp {
                            DialStage::Handshake
                        } else {
                            stage
                        },
                        if stage == DialStage::Tls {
                            codes::RELAY_DIAL_TLS
                        } else {
                            codes::RELAY_DIAL_HANDSHAKE
                        },
                        err.to_string(),
                    ),
                    ConnectErrorKind::Config => Self::connect(
                        if stage == DialStage::Dns {
                            DialStage::Dns
                        } else {
                            DialStage::Policy
                        },
                        codes::RELAY_DIAL_UNSUPPORTED,
                        err.to_string(),
                    ),
                    ConnectErrorKind::Io(_) | ConnectErrorKind::Timeout => {
                        Self::connect(stage, default_code_for_stage(stage), err.to_string())
                    }
                    _ => Self::connect(stage, default_code_for_stage(stage), err.to_string()),
                }
            }
            NetError::Io(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                Self::timeout(DialStage::Tcp, err.to_string())
            }
            NetError::Io(err) => Self::tcp(err.to_string()),
            NetError::Protocol(msg) | NetError::RetryableProtocol(msg) => Self::handshake(msg),
            NetError::Http(err) => Self::handshake(err.to_string()),
            NetError::Security(msg) => {
                Self::connect(DialStage::Policy, codes::RELAY_DIAL_CONNECT, msg)
            }
            NetError::UnsupportedEncoding(msg) | NetError::Decode(msg) => Self::handshake(msg),
            NetError::TooManyRedirects(count) => {
                Self::handshake(format!("too many redirects ({count})"))
            }
            NetError::Timeout {
                phase,
                waiting_for,
                limit,
            } => Self::timeout(
                stage_from_phase(*phase),
                format!(
                    "timed out waiting for {waiting_for} after {} ms",
                    limit.as_millis()
                ),
            ),
            _ => Self::handshake(error.to_string()),
        }
    }

    /// Converts this error into a structured [`NetError`] so `netune` connectors wrapping a
    /// [`crate::server::ServerConnector`] preserve stage and timeout classification.
    #[must_use]
    pub fn into_net_error(&self, peer: &str) -> NetError {
        match self {
            Self::Timeout { stage, detail } => match stage {
                DialStage::Dns => {
                    NetError::Resolve(ResolveError::new(ResolveErrorKind::Timeout, peer, detail))
                }
                other => NetError::Connect(
                    ConnectError::new(phase_for_stage(*other), ConnectErrorKind::Timeout, detail)
                        .with_peer(peer),
                ),
            },
            Self::Connect { stage, detail, .. } => match stage {
                DialStage::Dns => {
                    NetError::Resolve(ResolveError::new(ResolveErrorKind::Failed, peer, detail))
                }
                DialStage::Tcp => NetError::Connect(
                    ConnectError::new(
                        DiagnosticPhase::Tcp,
                        ConnectErrorKind::Io(std::io::ErrorKind::Other),
                        detail,
                    )
                    .with_peer(peer),
                ),
                DialStage::Tls => NetError::Connect(ConnectError::tls(peer, detail)),
                DialStage::Handshake => NetError::Connect(ConnectError::proxy(peer, detail)),
                DialStage::Policy => NetError::Connect(
                    ConnectError::config(DiagnosticPhase::Dispatch, detail).with_peer(peer),
                ),
            },
            Self::UnsupportedLink(detail) => NetError::Connect(
                ConnectError::config(DiagnosticPhase::Dispatch, detail).with_peer(peer),
            ),
        }
    }
}

/// Maps a netune diagnostic phase onto daer's dial stage taxonomy.
#[must_use]
pub const fn stage_from_phase(phase: DiagnosticPhase) -> DialStage {
    match phase {
        DiagnosticPhase::Dns => DialStage::Dns,
        DiagnosticPhase::Tls => DialStage::Tls,
        DiagnosticPhase::Proxy
        | DiagnosticPhase::Http1
        | DiagnosticPhase::Http2
        | DiagnosticPhase::Http3
        | DiagnosticPhase::WebSocket
        | DiagnosticPhase::Request
        | DiagnosticPhase::Response => DialStage::Handshake,
        DiagnosticPhase::Dispatch
        | DiagnosticPhase::Tcp
        | DiagnosticPhase::Pool
        | DiagnosticPhase::Quic
        | DiagnosticPhase::Server
        | DiagnosticPhase::Listener
        | DiagnosticPhase::Drain
        | DiagnosticPhase::Sink
        | DiagnosticPhase::Trace
        | DiagnosticPhase::Unknown => DialStage::Tcp,
        // A future netune phase is a protocol phase until proven otherwise.
        _ => DialStage::Handshake,
    }
}

#[must_use]
const fn phase_for_stage(stage: DialStage) -> DiagnosticPhase {
    match stage {
        DialStage::Dns => DiagnosticPhase::Dns,
        DialStage::Tcp => DiagnosticPhase::Tcp,
        DialStage::Tls => DiagnosticPhase::Tls,
        DialStage::Handshake => DiagnosticPhase::Proxy,
        DialStage::Policy => DiagnosticPhase::Dispatch,
    }
}

#[must_use]
const fn default_code_for_stage(stage: DialStage) -> ErrorCode {
    match stage {
        DialStage::Dns | DialStage::Tcp => codes::RELAY_DIAL_CONNECT,
        DialStage::Tls => codes::RELAY_DIAL_TLS,
        DialStage::Handshake => codes::RELAY_DIAL_HANDSHAKE,
        DialStage::Policy => codes::RELAY_DIAL_UNSUPPORTED,
    }
}
