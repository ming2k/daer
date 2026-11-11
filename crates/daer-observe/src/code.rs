// SPDX-License-Identifier: AGPL-3.0-only

//! Event severity and the generated catalog re-exports.

pub use crate::generated::EventCode;

/// The severity a catalog event is allowed to use.
///
/// The catalog declares it. A call site picks the macro that matches; `cargo xtask events
/// --check` compares the two. The distinction is load-bearing: a client-visible failure may
/// not be emitted at `debug`, because the shipped default is `info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// A promised contract is broken; the process cannot continue or first-generation build
    /// failed.
    Error,
    /// A client-visible failure or degraded capability while the service continues.
    Warn,
    /// Lifecycle and state transition.
    Info,
    /// Per-flow success or decision detail.
    Debug,
    /// Per-query/per-packet internals, opt-in.
    Trace,
}

impl Severity {
    /// The lower-case spelling used in the catalog and the generated reference.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
