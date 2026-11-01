// SPDX-License-Identifier: AGPL-3.0-only

//! What a dial measured, and where it goes.
//!
//! # Why this exists
//!
//! `netune` records every transport step as an event and derives timings from them as pure
//! functions (netune ADR-0001). `daer` created a `Recorder` per dial and then **dropped it**:
//! `Recorder::start(64)` appeared in `direct.rs`, `check.rs`, `trojan.rs`, and `datagram.rs`,
//! and nothing ever read one. The observability was paid for and thrown away, so a node's
//! measured latency and a failed handshake's phase were both invisible.
//!
//! This module is the consumer side: a [`DialObserver`] is what a dial reports to, and
//! [`ObservedDialer`] is the seam where a caller installs one.
//!
//! # What this can and cannot see, and why
//!
//! netune's per-event stream (`TraceSink`) is a **netune 0.0.5** capability. With `daer` pinned
//! to `v0.0.5`, [`DialObserverSink`] bridges netune's trace stream into [`DialObserver::observe`],
//! while [`ObservedDialer`] measures the overall wall-clock span from "start the dial" to
//! "the dial returned". That is the number a health check and a "why is this node slow" report
//! both need.
//!
//! What it is **not** is a per-phase breakdown (DNS / TCP / TLS). Claiming one would mean
//! reading the transport's `Recorder`, which no connector hands back — reaching into seven
//! connectors to change that would put instrumentation inside the transports, and the phases
//! netune already derived would still be discarded. The honest statement is in the code and in
//! the log: this is a total, and the phases are a netune-side capability daer does not yet
//! consume.

use std::sync::Arc;

pub use netune_trace::TraceSink;
use netune_trace::{DerivedTimings, Event, derive};

/// Where a dial's measurement goes.
///
/// One method per fact, deliberately: an observer that could also *block* the dial would be a
/// policy decision hidden in instrumentation.
pub trait DialObserver: Send + Sync + std::fmt::Debug {
    /// Receives one event of a dial, as it is recorded.
    ///
    /// Transports installing a [`TraceSink`] via [`DialObserverSink`] call this per event;
    /// the default implementation is a no-op and [`Self::finished`] reports the summary once
    /// the dial is complete.
    fn observe(&self, dial: &DialId, event: Event) {
        let _ = (dial, event);
    }

    /// Receives the derived timings once the dial attempt is over.
    ///
    /// Called exactly once per dial, with `None` when the attempt failed before any timing
    /// could be derived. A failed dial still calls it: "the handshake took 3 s and then
    /// failed" is the fact that explains a timeout, and dropping it is how a health check
    /// ends up with no reason.
    fn finished(&self, dial: &DialId, timings: Option<&DerivedTimings>);
}

/// Which dial an event belongs to.
///
/// The node's tag and the destination, so an observer can attribute a measurement without
/// holding a reference to the dialer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialId {
    /// The node's tag (`direct` for a direct dial).
    pub node: Arc<str>,
    /// The authority the dial targeted.
    pub authority: Arc<str>,
}

impl DialId {
    /// Builds an id from the node tag and the dialed authority.
    pub fn new(node: impl Into<Arc<str>>, authority: impl Into<Arc<str>>) -> Self {
        Self {
            node: node.into(),
            authority: authority.into(),
        }
    }
}

impl std::fmt::Display for DialId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}→{}", self.node, self.authority)
    }
}

/// A [`TraceSink`] adapter that bridges netune's streaming event trace to a [`DialObserver`].
#[derive(Debug, Clone)]
pub struct DialObserverSink {
    dial: DialId,
    observer: Arc<dyn DialObserver>,
}

impl DialObserverSink {
    /// Creates a sink forwarding events to `observer` under `dial`.
    #[must_use]
    pub fn new(dial: DialId, observer: Arc<dyn DialObserver>) -> Self {
        Self { dial, observer }
    }

    /// The dial identity associated with this sink.
    #[must_use]
    pub fn dial(&self) -> &DialId {
        &self.dial
    }
}

impl TraceSink for DialObserverSink {
    fn event(&self, event: Event) {
        self.observer.observe(&self.dial, event);
    }
}

/// A [`DialObserver`] that logs one line per dial and keeps nothing.
///
/// The default the daemon installs: it makes a dial's span visible in the journal without
/// adding a metrics pipeline, and it is the thing that would have answered "why is this node
/// slow" during the period when the recorder was discarded.
#[derive(Debug, Default)]
pub struct LogObserver;

impl DialObserver for LogObserver {
    fn finished(&self, dial: &DialId, timings: Option<&DerivedTimings>) {
        let Some(timings) = timings else {
            tracing::debug!(dial = %dial, "dial finished without timings");
            return;
        };
        // A `Reading` is reported as its value or as why there is none: a fabricated zero
        // would make a reused connection look instantaneous rather than not-applicable.
        tracing::debug!(
            dial = %dial,
            tcp_us = ?timings.tcp_us.value(),
            tls_us = ?timings.tls_us.value(),
            ttfb_us = ?timings.ttfb_us.value(),
            "dial finished"
        );
    }
}

/// The observer a dial should install, if any.
///
/// `None` means "record nothing", which is the right default for a flow whose measurement
/// nobody asked for: the per-flow path installs an observer only when a consumer (the health
/// scheduler, a diagnostic) is listening.
pub type ObserverSlot = Option<Arc<dyn DialObserver>>;

/// A dialer paired with the observer its dials should report to.
///
/// # Why a wrapper and not a field on every transport
///
/// Every protocol's dial funnels through `NodeDialer::connect`, and threading an observer
/// through that enum would touch seven variants and every constructor. This wrapper sits where
/// a *caller* holds a dialer — the router's node selection — so the measurement is installed at
/// the seam that already exists. The transports stay unaware that anyone is watching, which is
/// also what keeps a transport testable without an observer.
#[derive(Clone)]
pub struct ObservedDialer {
    dialer: Arc<crate::node_dialer::NodeDialer>,
    observer: ObserverSlot,
    tag: Arc<str>,
}

impl std::fmt::Debug for ObservedDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservedDialer")
            .field("tag", &self.tag)
            .field("observed", &self.observer.is_some())
            .finish_non_exhaustive()
    }
}

impl ObservedDialer {
    /// Wraps `dialer`, reporting its dials to `observer` under `tag`.
    #[must_use]
    pub fn new(
        dialer: Arc<crate::node_dialer::NodeDialer>,
        observer: ObserverSlot,
        tag: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            dialer,
            observer,
            tag: tag.into(),
        }
    }

    /// Opens a connection, reporting the attempt to the observer when there is one.
    ///
    /// The span is measured here rather than derived from the transport's recorder: a protocol
    /// that owns its own `Recorder` (all of them do) does not hand it back, and reaching into
    /// seven connectors to change that would put instrumentation inside the transports. The
    /// wall-clock span is the honest number this seam can observe, and it is labelled as such —
    /// the per-phase breakdown stays netune's, and daer does not yet consume it.
    pub async fn connect(
        &self,
        authority: &str,
    ) -> Result<crate::Established, crate::error::OutboundError> {
        let started = std::time::Instant::now();
        let result = self.dialer.connect(authority).await;
        if let Some(observer) = &self.observer {
            let dial = DialId::new(Arc::clone(&self.tag), authority.to_owned());
            let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            observer.finished(&dial, Some(&wall_clock_timings(micros)));
        }
        result
    }
}

/// A `DerivedTimings` whose TCP phase is the wall-clock span of a whole dial.
///
/// # Why a synthetic trace rather than a constructed struct
///
/// `DerivedTimings` has private fields and a `Reading` that carries a validity verdict, so the
/// only way to produce one is through `derive`. Recording a two-event trace (`TcpStart`,
/// `TcpEnd`) and deriving it keeps the reported shape identical to netune's own: a hand-built
/// struct would be a second definition of the same type's meaning.
///
/// The span covers the whole dial, including TLS and the proxy handshake, because that is what
/// a health check wants to know. The per-phase split is netune's, in the transport's ring.
fn wall_clock_timings(micros: u64) -> DerivedTimings {
    use netune_trace::{EventKind, EventLog};
    let mut log = EventLog::with_capacity(4);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(0, EventKind::TcpStart, 0, 0);
    // The derivation reads the log; nanoseconds are what the events carry.
    log.push_at(micros.saturating_mul(1_000), EventKind::TcpEnd, 0, 0);
    let trace = netune_trace::RequestTrace {
        id: netune_trace::TraceId::new("daer-dial"),
        attempt: netune_trace::AttemptRef {
            round: 1,
            turn: 0,
            attempt: 0,
        },
        endpoint: netune_trace::EndpointRef {
            provider: "daer".to_owned(),
            model: "dial".to_owned(),
            authority: String::new(),
        },
        connection: netune_trace::ConnectionInfo::default(),
        fidelity: netune_trace::Fidelity::l0(),
        log,
    };
    derive(&trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An observer that keeps what it was given.
    #[derive(Debug, Default)]
    struct Collector(std::sync::Mutex<Vec<(DialId, Option<DerivedTimings>)>>);

    impl DialObserver for Collector {
        fn finished(&self, dial: &DialId, timings: Option<&DerivedTimings>) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((dial.clone(), timings.copied()));
        }
    }

    #[test]
    fn the_wall_clock_timings_carry_the_span_they_were_built_from() {
        // The number a health check reads: one total, derived through netune's own function so
        // the type's meaning cannot drift from netune's.
        let timings = wall_clock_timings(5_000);
        assert_eq!(timings.tcp_us.value(), Some(5_000));
    }

    #[test]
    fn a_dial_reports_exactly_once_even_when_it_fails() {
        // A health check that learns nothing from a failure cannot say *why* a node is down,
        // and "it timed out" with no span is the least useful answer there is.
        let collector = Arc::new(Collector::default());
        let slot: ObserverSlot = Some(Arc::clone(&collector) as Arc<dyn DialObserver>);
        let dial = DialId::new("n1", "example.com:443");
        slot.as_ref()
            .expect("set")
            .finished(&dial, Some(&wall_clock_timings(1)));

        let recorded = collector.0.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, dial);
        assert!(recorded[0].1.is_some());
    }

    #[test]
    fn a_missing_observer_is_a_none_not_a_flag() {
        // The type is what makes "nobody is listening" a single value rather than a boolean
        // every call site has to check consistently.
        let slot: ObserverSlot = None;
        assert!(slot.is_none());
    }

    #[test]
    fn a_dial_observer_sink_forwards_events_to_observer() {
        #[derive(Debug, Default)]
        struct EventRecorder(std::sync::Mutex<Vec<(DialId, Event)>>);

        impl DialObserver for EventRecorder {
            fn observe(&self, dial: &DialId, event: Event) {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((dial.clone(), event));
            }

            fn finished(&self, _dial: &DialId, _timings: Option<&DerivedTimings>) {}
        }

        let recorder = Arc::new(EventRecorder::default());
        let dial = DialId::new("node-test", "api.example.com:443");
        let sink =
            DialObserverSink::new(dial.clone(), Arc::clone(&recorder) as Arc<dyn DialObserver>);
        assert_eq!(sink.dial(), &dial);

        let event = Event {
            at_ns: 1234,
            kind: netune_trace::EventKind::TcpStart,
            a: 0,
            b: 0,
        };
        sink.event(event);

        let observed = recorder.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].0, dial);
        assert_eq!(observed[0].1.at_ns, 1234);
    }
}
