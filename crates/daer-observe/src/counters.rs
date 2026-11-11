// SPDX-License-Identifier: AGPL-3.0-only

//! Exact event counters.
//!
//! A `warn`/`error` event is sampled in the log and exact in the counter. The catalog declares
//! the counter name; this module is the process-wide sink the event macro increments. It is a
//! `Mutex<BTreeMap>` rather than a generated atomic table because only failure events have a
//! counter and their volume is bounded by the rate-limit policy; the per-flow `debug` path
//! never touches it.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use crate::EventCode;

fn counters() -> &'static Mutex<BTreeMap<&'static str, u64>> {
    static COUNTERS: OnceLock<Mutex<BTreeMap<&'static str, u64>>> = OnceLock::new();
    COUNTERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Increments the counter attached to `code`, if it has one.
///
/// Called by the event macro after the tracing event. It is deliberately infallible: a
/// poisoned counter lock must not hide the event that was just emitted.
pub fn record(code: EventCode) {
    let Some(name) = code.counter() else {
        return;
    };
    let mut map = counters().lock().unwrap_or_else(|error| error.into_inner());
    *map.entry(name).or_insert(0) += 1;
}

/// A point-in-time snapshot of every counter this process has incremented.
#[must_use]
pub fn snapshot() -> BTreeMap<String, u64> {
    counters()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .map(|(name, value)| ((*name).to_owned(), *value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_event_increments_its_catalog_counter() {
        let name = EventCode::FlowDialFailed
            .counter()
            .expect("the catalog gives this event a counter");
        let before = snapshot().get(name).copied().unwrap_or(0);
        record(EventCode::FlowDialFailed);
        let after = snapshot().get(name).copied().unwrap_or(0);
        assert_eq!(after, before + 1);
    }

    #[test]
    fn the_event_macro_increments_the_catalog_counter() {
        // A different event from the direct-record test: the counter map is process-wide, and
        // tests run in parallel. Sharing one code would make this test observe the other's
        // increment and fail for a reason unrelated to the macro.
        let name = EventCode::FlowRelayFailed
            .counter()
            .expect("the catalog gives this event a counter");
        let before = snapshot().get(name).copied().unwrap_or(0);
        crate::warn!(
            EventCode::FlowRelayFailed,
            flow_id = %crate::FlowId::new(1),
            "macro counter test"
        );
        let after = snapshot().get(name).copied().unwrap_or(0);
        assert_eq!(after, before + 1);
    }

    #[test]
    fn a_debug_event_without_a_counter_is_a_no_op() {
        assert!(EventCode::FlowAccepted.counter().is_none());
        record(EventCode::FlowAccepted);
        assert!(!snapshot().contains_key(""));
    }
}
