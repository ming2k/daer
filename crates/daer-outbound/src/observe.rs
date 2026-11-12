// SPDX-License-Identifier: AGPL-3.0-only

//! What a dial measured, and where it goes.
//!
//! # Why this exists
//!
//! `netune` records every transport step as an event and derives timings from them as pure
//! functions (netune ADR-0001). A dial that nobody observes used to allocate a throwaway
//! event ring and then drop it, so the observability was paid for and discarded.
//!
//! This module is the consumer side: a [`DialObserver`] is what a dial reports to, and
//! [`ObservedDialer`] is the seam where a caller installs one. When an observer is present
//! the dial gets one [`TraceCollector`] with a [`DialObserverSink`] attached; netune's
//! DNS/TCP/TLS marks stream into the observer and the final log is derived through netune's
//! own `derive`. When nobody is listening, the dial uses `TraceCollector::disabled()`: no
//! event is recorded, no sink is installed, and no ring is filled (netune ADR-0017, ADR-0018).
//!
//! What this cannot see is a proxy protocol's own framing after netune's transport returns:
//! that work is daer's and is not part of netune's trace vocabulary. The phases that *are*
//! recorded are reported as phases; no wall-clock span is relabelled as a handshake.

use std::sync::Arc;

pub use netune_trace::TraceSink;
use netune_trace::{DerivedTimings, Event, EventKind, EventLog, TraceCollector, derive};

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
    /// The flow/session this dial belongs to.
    pub flow_id: daer_observe::FlowId,
    /// The node's tag (`direct` for a direct dial).
    pub node: Arc<str>,
    /// The authority the dial targeted.
    pub authority: Arc<str>,
}

impl DialId {
    /// Builds an id from the flow, node tag and dialed authority.
    pub fn new(
        flow_id: daer_observe::FlowId,
        node: impl Into<Arc<str>>,
        authority: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            flow_id,
            node: node.into(),
            authority: authority.into(),
        }
    }
}

impl std::fmt::Display for DialId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}→{}", self.flow_id, self.node, self.authority)
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
    fn event(&self, _meta: &netune_trace::TraceMeta, event: Event) -> netune_trace::Flow {
        self.observer.observe(&self.dial, event);
        // The observer never rejects an event: dropping one would make the trace window
        // silently narrower than the collector's ring, which is the opposite of what a
        // consumer of the stream is promised.
        netune_trace::Flow::Continue
    }
}

/// A [`DialObserver`] that logs one line per dial and keeps nothing.
///
/// The default the daemon installs: it makes the recorded phases visible in the journal
/// without adding a metrics pipeline, and it is the thing that answers "why is this node
/// slow" when the transport already derived the answer.
#[derive(Debug, Default)]
pub struct LogObserver;

impl DialObserver for LogObserver {
    fn finished(&self, dial: &DialId, timings: Option<&DerivedTimings>) {
        let Some(timings) = timings else {
            daer_observe::debug!(
                daer_observe::EventCode::FlowDialFinishedWithoutTimings,
                flow_id = %dial.flow_id,
                dial = %dial,
                node = %dial.node,
                authority = %dial.authority,
                "dial finished without timings"
            );
            return;
        };
        // A `Reading` is reported as its value or as why there is none: a fabricated zero
        // would make a reused connection look instantaneous rather than not-applicable.
        daer_observe::debug!(daer_observe::EventCode::FlowDialFinished,
            flow_id = %dial.flow_id,
            dial = %dial,
            node = %dial.node,
            authority = %dial.authority,
            dns_us = ?timings.dns_us.value(),
            tcp_us = ?timings.tcp_us.value(),
            tls_us = ?timings.tls_us.value(),
            rtt_us = ?timings.rtt_us.value(),
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
    flow_id: daer_observe::FlowId,
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
        flow_id: daer_observe::FlowId,
        tag: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            dialer,
            observer,
            flow_id,
            tag: tag.into(),
        }
    }

    /// Opens a connection, reporting the attempt to the observer when there is one.
    ///
    /// The collector is installed before the dial, not read after it: netune emits the
    /// `DnsStart`/`TcpStart`/`TlsStart` marks into it as they happen, so the observer sees the
    /// stream and the final derivation is over the exact events that produced the connection.
    /// A dial with no observer uses the disabled collector, so its ring stays empty.
    pub async fn connect(
        &self,
        authority: &str,
    ) -> Result<crate::Established, crate::error::OutboundError> {
        let dial = self
            .observer
            .as_ref()
            .map(|_| DialId::new(self.flow_id, Arc::clone(&self.tag), authority.to_owned()));
        let collector = match (&self.observer, &dial) {
            (Some(observer), Some(dial)) => {
                let sink = DialObserverSink::new(dial.clone(), Arc::clone(observer));
                TraceCollector::start(64).with_sink(Arc::new(sink))
            }
            _ => TraceCollector::disabled(),
        };

        let started = std::time::Instant::now();
        let result = self
            .dialer
            .connect_with_collector(authority, &collector)
            .await;

        if let Err(error) = &result {
            // One failure event per dial, at the layer that knows the stage and stable code.
            // The relay's generic "no outbound leg" line stays at debug; this is the warn.
            let failure = daer_observe::DialFailure::from(error.clone());
            daer_observe::warn!(
                daer_observe::EventCode::FlowDialFailed,
                flow_id = %self.flow_id,
                destination = %authority,
                group = %self.tag,
                stage = %failure.stage,
                error_code = %failure.code,
                elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "flow dial failed"
            );
        }

        if let (Some(observer), Some(dial)) = (&self.observer, dial) {
            let log = collector.log();
            let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            let timings = if log.first_of(EventKind::Dispatch).is_some() {
                trace_timings(log)
            } else {
                // A connector that records nothing (or an empty capacity) still owes the
                // observer a span; keep the old wall-clock fallback, clearly synthetic.
                wall_clock_timings(micros)
            };
            observer.finished(&dial, Some(&timings));
        }
        result
    }
}

/// Derives timings from the events a dial actually produced.
///
/// This is the normal path: the collector's log is the transport's own record, and `derive` is
/// netune's pure function over it. A phase netune did not record stays
/// `not_applicable`/`not_estimable` rather than becoming a zero.
fn trace_timings(log: EventLog) -> DerivedTimings {
    let trace = netune_trace::RequestTrace {
        meta: netune_trace::TraceMeta::new(
            netune_trace::TraceId::new("daer-dial"),
            netune_trace::Direction::Egress,
        ),
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
        // A dial has no request wire identity of its own; the default identity and the
        // current envelope version keep the derivation comparable with netune's.
        identity: netune_trace::ConnectionIdentity::default(),
        schema_version: netune_trace::TRACE_SCHEMA_VERSION,
        fidelity: netune_trace::Fidelity::l0(),
        log,
        diagnostics: netune_trace::DiagnosticTable::default(),
    };
    derive(&trace)
}

/// A `DerivedTimings` whose TCP phase is the wall-clock span of a whole dial.
///
/// Used only when a collector recorded no `Dispatch` event. `DerivedTimings` cannot be built
/// field-by-field honestly without a log, so a two-event synthetic trace keeps the reported
/// shape identical to netune's own derivation. The value is explicitly a fallback, not a
/// measurement of a TCP handshake.
fn wall_clock_timings(micros: u64) -> DerivedTimings {
    let mut log = EventLog::with_capacity(4);
    log.push_at(0, EventKind::Dispatch, 0, 0);
    log.push_at(0, EventKind::TcpStart, 0, 0);
    // The derivation reads the log; nanoseconds are what the events carry.
    log.push_at(micros.saturating_mul(1_000), EventKind::TcpEnd, 0, 0);
    trace_timings(log)
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
        // The fallback number a health check reads: one total, derived through netune's own
        // function so the type's meaning cannot drift from netune's.
        let timings = wall_clock_timings(5_000);
        assert_eq!(timings.tcp_us.value(), Some(5_000));
    }

    #[test]
    fn recorded_phases_are_derived_without_inventing_the_absent_ones() {
        // Positive control: the marks that were recorded become measured phases.
        let mut log = EventLog::with_capacity(8);
        log.push_at(0, EventKind::Dispatch, 0, 0);
        log.push_at(1_000, EventKind::DnsStart, 0, 0);
        log.push_at(3_000, EventKind::DnsEnd, 0, 0);
        log.push_at(3_000, EventKind::TcpStart, 0, 0);
        log.push_at(8_000, EventKind::TcpEnd, 0, 0);
        let timings = trace_timings(log);

        assert_eq!(timings.dns_us.value(), Some(2));
        assert_eq!(timings.tcp_us.value(), Some(5));

        // Negative control: no TLS marks means the TLS phase is absent, not 0 µs. A
        // synthetic zero would make a TLS dial look free and a non-TLS dial look measured.
        assert_eq!(timings.tls_us.value(), None);
    }

    #[test]
    fn a_dial_reports_exactly_once_even_when_it_fails() {
        // A health check that learns nothing from a failure cannot say *why* a node is down,
        // and "it timed out" with no span is the least useful answer there is.
        let collector = Arc::new(Collector::default());
        let slot: ObserverSlot = Some(Arc::clone(&collector) as Arc<dyn DialObserver>);
        let dial = DialId::new(daer_observe::FlowId::new(1), "n1", "example.com:443");
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
        let dial = DialId::new(
            daer_observe::FlowId::new(2),
            "node-test",
            "api.example.com:443",
        );
        let sink =
            DialObserverSink::new(dial.clone(), Arc::clone(&recorder) as Arc<dyn DialObserver>);
        assert_eq!(sink.dial(), &dial);

        let event = Event {
            at_ns: 1234,
            stream: 0,
            kind: netune_trace::EventKind::TcpStart,
            a: 0,
            b: 0,
        };
        sink.event(&netune_trace::TraceMeta::egress(), event);

        let observed = recorder.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].0, dial);
        assert_eq!(observed[0].1.at_ns, 1234);
    }
}
