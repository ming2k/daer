// SPDX-License-Identifier: AGPL-3.0-only

//! Correlation identifiers.
//!
//! IDs are created at the boundary that owns the thing — ingress accept, DNS receive, health
//! sweep, provider refresh — and carried in the type from there on. They are not reconstructed
//! from log fields, and they are not optional when the event is about a specific flow/query.
//!
//! A `RunId` is random per process so a `flow_id` from yesterday's journal cannot be mistaken
//! for one from today's. The rest are process-local counters.

use std::fmt;

macro_rules! id_type {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Builds an ID from a raw value.
            ///
            /// # Panics
            ///
            /// Panics on `0`: zero is the "unset" sentinel and must never be emitted.
            #[must_use]
            pub const fn new(value: u64) -> Self {
                assert!(value != 0, concat!(stringify!($name), " must not be zero"));
                Self(value)
            }

            /// The raw value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "{:016x}"), self.0)
            }
        }
    };
}

id_type!(RunId, "r", "The process run this event belongs to.");
id_type!(FlowId, "f", "One accepted TCP flow or one UDP session.");
id_type!(QueryId, "q", "One DNS query received by the server.");
id_type!(ProbeId, "p", "One health-probe result.");
id_type!(RefreshId, "x", "One provider refresh attempt.");

/// Allocates IDs for one daemon run.
///
/// A single counter is shared across kinds: an ID cannot collide with another kind, and the
/// ordering is globally meaningful within a run.
#[derive(Debug)]
pub struct Ids {
    run: RunId,
    next: std::sync::atomic::AtomicU64,
}

impl Ids {
    /// Creates an allocator with a random `RunId`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_run(RunId::new(fastrand::u64(1..=u64::MAX)))
    }

    /// Creates an allocator with an explicit run id, for tests and incident replay.
    #[must_use]
    pub fn with_run(run: RunId) -> Self {
        Self {
            run,
            next: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// The run id every event from this process carries.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run
    }

    fn next(&self) -> u64 {
        self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Allocates a flow/session id.
    #[must_use]
    pub fn flow(&self) -> FlowId {
        FlowId::new(self.next())
    }

    /// Allocates a DNS query id.
    #[must_use]
    pub fn query(&self) -> QueryId {
        QueryId::new(self.next())
    }

    /// Allocates a health-probe id.
    #[must_use]
    pub fn probe(&self) -> ProbeId {
        ProbeId::new(self.next())
    }

    /// Allocates a provider-refresh id.
    #[must_use]
    pub fn refresh(&self) -> RefreshId {
        RefreshId::new(self.next())
    }
}

impl Default for Ids {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_human_readable() {
        let ids = Ids::with_run(RunId::new(7));
        let a = ids.flow();
        let b = ids.flow();
        assert_ne!(a, b);
        assert_eq!(a.to_string(), "f0000000000000001");
        assert_eq!(ids.run_id().to_string(), "r0000000000000007");
    }

    #[test]
    #[should_panic(expected = "FlowId must not be zero")]
    fn zero_is_not_an_id() {
        let _ = FlowId::new(0);
    }
}
