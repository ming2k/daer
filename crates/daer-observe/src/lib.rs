// SPDX-License-Identifier: AGPL-3.0-only

//! The daer diagnostic plane (ADR-0040).
//!
//! # Why this crate exists
//!
//! Before this crate, a diagnostic was a `tracing` call with a formatted message. The message
//! was the contract: the docs grepped it, the e2e scripts grepped it, and a rename silently
//! broke an operator's runbook. There was no correlation ID, no severity policy, no catalog,
//! no counter/rate rule, and no way to say "this event is a client-visible failure".
//!
//! `daer-observe` turns that into a typed interface:
//!
//! * [`EventCode`] is the stable contract, generated from `events.toml`;
//! * [`Severity`] is declared by the catalog, not chosen at the call site;
//! * [`FlowId`], [`QueryId`], [`ProbeId`] and [`RefreshId`] carry causality;
//! * [`Diagnostic`] and [`ErrorCode`] carry a machine-readable failure identity;
//! * [`Secret`] and [`RedactedLink`] make a credential leak a type error rather than a review
//!   miss.
//!
//! # The macro firewall
//!
//! Only this crate and `daer-cli` may depend on `tracing`. Every other crate uses
//! [`debug!`], [`info!`], [`warn!`], [`error!`] or [`trace!`] and supplies an [`EventCode`].
//! A raw `tracing::warn!` in a library is a build failure, not a style preference.
//!
//! ```ignore
//! use daer_observe::{EventCode, warn};
//!
//! warn!(
//!     EventCode::FlowDialFailed,
//!     flow_id = %flow.id,
//!     generation = flow.generation,
//!     stage = %failure.stage,
//!     "flow dial failed"
//! );
//! ```
//!
//! The generated event module lives in [`generated`]; `cargo xtask events --check` is the
//! mechanism that keeps it in sync with the catalog.

pub mod counters;
pub mod diagnostic;
pub mod ids;
pub mod redact;

mod code;
#[rustfmt::skip]
pub mod generated;

pub use code::{EventCode, Severity};
pub use diagnostic::{Diagnostic, DialFailure, DialStage, ErrorCode};
pub use ids::{FlowId, Ids, ProbeId, QueryId, RefreshId, RunId};
pub use redact::{RedactedLink, Secret};

/// Re-export used by the macros. Not part of the public API.
#[doc(hidden)]
pub use tracing as __tracing;

/// Emits a `trace` event with a catalog code.
#[macro_export]
macro_rules! trace {
    ($code:expr, $($args:tt)*) => {
        $crate::__event!(trace, $code, $($args)*)
    };
}

/// Emits a `debug` event with a catalog code.
#[macro_export]
macro_rules! debug {
    ($code:expr, $($args:tt)*) => {
        $crate::__event!(debug, $code, $($args)*)
    };
}

/// Emits an `info` event with a catalog code.
#[macro_export]
macro_rules! info {
    ($code:expr, $($args:tt)*) => {
        $crate::__event!(info, $code, $($args)*)
    };
}

/// Emits a `warn` event with a catalog code.
#[macro_export]
macro_rules! warn {
    ($code:expr, $($args:tt)*) => {
        $crate::__event!(warn, $code, $($args)*)
    };
}

/// Emits an `error` event with a catalog code.
#[macro_export]
macro_rules! error {
    ($code:expr, $($args:tt)*) => {
        $crate::__event!(error, $code, $($args)*)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __event {
    ($level:ident, $code:expr, $($args:tt)*) => {{
        let __daer_code = $code;
        $crate::__tracing::$level!(
            event = __daer_code.as_str(),
            code = __daer_code.as_str(),
            $($args)*
        );
        $crate::counters::record(__daer_code);
    }};
}
