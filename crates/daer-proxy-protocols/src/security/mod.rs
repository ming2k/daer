// SPDX-License-Identifier: AGPL-3.0-only

//! The security layer: what makes a byte stream opaque (ADR-0028).
//!
//! # Why this is its own layer
//!
//! A security layer owns a handshake, a certificate policy and an ALPN offer. It knows
//! nothing about the protocol above it, and the protocol above it knows nothing about which
//! security layer it is riding on. Before ADR-0028 the crate had no such seam: REALITY was a
//! *kind of VLESS*, so a standard-TLS VLESS node was unreachable, and the next security
//! layer would have had to be bolted onto a second protocol.
//!
//! ```text
//!   tcp ──▶ [none] ──────────────────────▶ plaintext stream
//!       ──▶ [tls]  ── netune TLS ───────▶ opaque stream
//!       ──▶ [reality] ─ daer TLS 1.3 ───▶ opaque stream
//! ```
//!
//! # The one capability that is not `AsyncRead + AsyncWrite`
//!
//! XTLS Vision stops framing once the inner stream reveals itself, and on the downlink a
//! node may answer with `Direct`, which means "the rest of this connection is the inner
//! protocol's records, unmodified — stop decrypting". A security layer that cannot be told
//! that reads ciphertext as plaintext and dies with `the record was altered`.
//!
//! So [`Opaque`] carries a **raw-read switch** next to the stream rather than hiding it
//! behind a trait method. A trait with a no-op default would have to be implemented for
//! every transport (`Box<dyn Transport>`, `WsStream<S>`, `TlsStream<S>`, the REALITY
//! connection) and overlap with the `RealityStream` wrapper that is the only type that has
//! anything to switch; a `Option<Arc<AtomicBool>>` says the same thing without the
//! coherence problem, and it is also what `Tls13Connection` already exposes internally.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use netune::Transport;
use netune_trace::TraceCollector;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::ProxyProtocolError;

pub mod reality;
pub mod tls;

/// An opaque stream, plus the switch Vision may need.
pub struct Opaque {
    pub stream: Box<dyn Transport>,
    /// Set by a security layer whose record layer can be bypassed. `None` means "there is
    /// nothing to switch off", which is the truth for `none` and for TLS: rustls has no
    /// splice path here, so a `Direct` from the peer is only ever sent in response to a
    /// client that could splice.
    pub raw_read: Option<Arc<AtomicBool>>,
    /// The ALPN the peer selected, when the security layer had one to report.
    pub alpn: Option<String>,
    /// Raw negotiated ALPN bytes, preserved for a protocol that uses a name netune's
    /// trace enum does not classify.
    pub alpn_protocol: Option<Vec<u8>>,
}

impl std::fmt::Debug for Opaque {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opaque")
            .field("alpn", &self.alpn)
            .field("raw_read", &self.raw_read.is_some())
            .finish()
    }
}

impl Opaque {
    /// A plain stream with nothing to switch off.
    #[must_use]
    pub fn plain(stream: Box<dyn Transport>) -> Self {
        Self {
            stream,
            raw_read: None,
            alpn: None,
            alpn_protocol: None,
        }
    }
}

/// The security layer of a node (ADR-0028).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Security {
    /// No handshake: the protocol speaks over the transport directly.
    #[default]
    None,
    /// Ordinary TLS, verified against the platform trust store unless the node says
    /// otherwise.
    Tls(tls::TlsParams),
    /// REALITY: a tag in `legacy_session_id` authenticates the flow (ADR-0010).
    Reality(reality::RealitySecurity),
}

impl Security {
    /// The name a log or a diagnostic uses.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls(_) => "tls",
            Self::Reality(_) => "reality",
        }
    }

    /// Whether `flow = xtls-rprx-vision` is a legal choice on this layer.
    ///
    /// The reference rejects it on a plaintext outer stream — `inbound.go` says "XTLS only
    /// supports TLS and REALITY directly for now" — because the whole point of Vision is to
    /// splice a record layer. The check lives here so both the config validator and the
    /// connector ask the same question.
    #[must_use]
    pub const fn can_splice(&self) -> bool {
        matches!(self, Self::Tls(_) | Self::Reality(_))
    }

    /// The SNI this layer will present, when it has one.
    ///
    /// The transport layer needs it: a `ws` upgrade's `Host` defaults to the SNI, because a
    /// CDN-fronted node routes by name while its address is an IP literal.
    #[must_use]
    pub fn sni_hint(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Tls(params) => params.server_name.as_deref(),
            Self::Reality(security) => Some(security.server_name()),
        }
    }

    /// Wraps `stream` in this layer.
    ///
    /// `node_host` is the node's own hostname, used when the layer names no SNI of its own.
    /// `recorder` is passed to netune's TLS handshake so the phase is observable on the same
    /// trace as the DNS/TCP legs that produced the stream.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyProtocolError::Connect`] for a handshake failure and
    /// [`ProxyProtocolError::Timeout`] when the deadline passes; both carry the reason.
    pub async fn wrap<S>(
        &self,
        stream: S,
        node_host: &str,
        recorder: &TraceCollector,
        timeout: Duration,
    ) -> Result<Opaque, ProxyProtocolError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        match self {
            Self::None => Ok(Opaque::plain(Box::new(stream))),
            Self::Tls(params) => tls::wrap(stream, params, node_host, recorder, timeout).await,
            Self::Reality(security) => security.wrap(stream, timeout).await,
        }
    }
}

/// A shared, lazily built rustls provider, so every TLS security layer in the process
/// handshakes with the same crypto backend.
pub(crate) fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}
