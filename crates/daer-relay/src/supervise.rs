// SPDX-License-Identifier: AGPL-3.0-only

//! Flow ownership, so a reload cannot drop a connection.
//!
//! # The problem this exists to solve
//!
//! An accept loop that owns its flows ties two unrelated lifetimes together: how
//! long the *listener* runs, and how long *connections* last. Stopping the loop to
//! swap a configuration would then tear down every live connection, which makes
//! "reload without dropping traffic" impossible by construction.
//!
//! The fix is to move ownership of the flows out of the loop: [`Supervisor::spawn`]
//! starts each flow as an independent task and tracks it, and
//! [`Supervisor::drain`] waits for all of them to finish. The loop can then be
//! stopped and replaced while its flows keep relaying.
//!
//! ```text
//!   accept loop (generation N)   ──spawn──▶ flow ─┐
//!   accept loop (generation N+1) ──spawn──▶ flow ─┼──▶ Supervisor (shared)
//!   accept loop stopped ──────────────────────────┘        │
//!                                                          └─ drain() waits here
//! ```
//!
//! # Why a counter and a `Notify`, and why that is not a lost wakeup
//!
//! The count answers "how many", `Notify` answers "when zero". Two details make that
//! correct rather than nearly correct:
//!
//! * a waiter **registers before it checks** the count (`Notified::enable`), so a
//!   flow that finishes in between cannot slip past a waiter that has not yet
//!   subscribed;
//! * the last flow **broadcasts** (`notify_waiters`) instead of waking one waiter.
//!   A stored permit would be consumed by whichever `drain` happened to be waiting,
//!   leaving a second one asleep forever; a broadcast wakes all of them, and each
//!   re-checks the count and returns when it is zero.
//!
//! A channel or a condvar would express the same thing with more machinery and the
//! same two obligations.
//!
//! # Panic accounting
//!
//! Each flow runs under a [`FlowGuard`]. Finishing normally sets a flag; if the guard
//! drops without it, the task ended abnormally. That is recorded as `panicked`.
//! A drop cannot distinguish a panic from a cancellation, so this deliberately counts
//! both — during shutdown the counter stops being read, and claiming a finer
//! distinction would be claiming something the code does not know.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::sync::Notify;

use crate::relay::Relayed;
use crate::serve::Metrics;

/// Owns every in-flight flow.
///
/// Cheap to clone (one `Arc`), so the accept loop, the reload path and the shutdown
/// path all name the same supervisor, and the counters describe the *service* rather
/// than one loop generation.
#[derive(Debug, Clone)]
pub struct Supervisor {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    flows: AtomicUsize,
    /// Set once graceful shutdown begins so task abortions from `runtime.shutdown_timeout`
    /// do not pollute abnormal-end metrics or warning logs.
    shutting_down: AtomicBool,
    /// Notified when `flows` reaches zero.
    idle: Notify,
    metrics: Metrics,
}

impl Supervisor {
    /// Creates a supervisor with fresh counters.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                flows: AtomicUsize::new(0),
                shutting_down: AtomicBool::new(false),
                idle: Notify::new(),
                metrics: Metrics::default(),
            }),
        }
    }

    /// Marks the supervisor as entering graceful shutdown.
    ///
    /// Flows cancelled by executor teardown after a bounded drain are expected
    /// shutdown aborts rather than unexpected crashes; this suppresses
    /// `flow.abnormal_end` warnings and counters for non-panicking unwinds.
    pub fn begin_shutdown(&self) {
        self.inner.shutting_down.store(true, Ordering::Release);
    }

    /// Whether [`Self::begin_shutdown`] has been called on this supervisor.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::Acquire)
    }

    /// The live counters.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }

    /// A clone of the supervisor, for a task that outlives the borrow.
    ///
    /// Sharing the supervisor shares its counters, which is the point: the counters
    /// describe the service, so they must survive a reload.
    #[must_use]
    pub fn handle(&self) -> Self {
        self.clone()
    }

    /// Runs `flow` as an independent task and tracks it until it ends.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime: there is then no executor to run
    /// the flow on. That is a wiring mistake, not a runtime condition.
    pub fn spawn<F>(&self, flow: F)
    where
        F: Future<Output = Relayed> + Send + 'static,
    {
        self.spawn_inner(None, flow);
    }

    /// Runs a flow as an independent task and attributes an abnormal end to `flow_id`.
    ///
    /// The data path uses this form. A plain [`Self::spawn`] is kept for test doubles that
    /// deliberately do not have a flow context; it still counts the abnormal end but cannot
    /// name it.
    pub fn spawn_tracked<F>(&self, flow_id: daer_observe::FlowId, flow: F)
    where
        F: Future<Output = Relayed> + Send + 'static,
    {
        self.spawn_inner(Some(flow_id), flow);
    }

    fn spawn_inner<F>(&self, flow_id: Option<daer_observe::FlowId>, flow: F)
    where
        F: Future<Output = Relayed> + Send + 'static,
    {
        self.inner.flows.fetch_add(1, Ordering::AcqRel);
        let guard = FlowGuard {
            inner: Arc::clone(&self.inner),
            flow_id,
            completed: false,
        };
        tokio::spawn(async move {
            let mut guard = guard;
            let relayed = flow.await;
            // Reaching here means the task body ran to completion; the flag is what
            // separates a finished flow from one that ended abnormally.
            guard.completed = true;
            relayed
        });
    }

    /// Number of flows currently running.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.inner.flows.load(Ordering::Acquire)
    }

    /// Waits until every tracked flow has ended.
    ///
    /// Returns immediately when nothing is in flight, so a reload with no live
    /// connection does not wait at all. Safe to call from several tasks at once:
    /// every waiter is woken by the broadcast and each returns on its own re-check.
    pub async fn drain(&self) {
        loop {
            // Register *before* reading the count. Without this ordering a flow that
            // ends between the check and the `await` would notify nobody, and this
            // task would sleep until an unrelated flow ended — or forever.
            let idle = self.inner.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();

            if self.in_flight() == 0 {
                return;
            }
            idle.await;
        }
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

/// Attributes one flow's end to the counters.
#[derive(Debug)]
struct FlowGuard {
    inner: Arc<Inner>,
    flow_id: Option<daer_observe::FlowId>,
    completed: bool,
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        if !self.completed {
            if self.inner.shutting_down.load(Ordering::Acquire) && !std::thread::panicking() {
                if let Some(flow_id) = self.flow_id {
                    daer_observe::debug!(
                        daer_observe::EventCode::FlowShutdownAborted,
                        flow_id = %flow_id,
                        "flow task aborted during shutdown"
                    );
                }
            } else {
                // A join error, a panic, or an unexpected cancellation: all of them are
                // "this flow did not finish its work", and all of them are worth counting.
                self.inner.metrics.record_abnormal_end();
                if let Some(flow_id) = self.flow_id {
                    daer_observe::warn!(
                        daer_observe::EventCode::FlowAbnormalEnd,
                        flow_id = %flow_id,
                        "flow task ended abnormally"
                    );
                }
            }
        }
        if self.inner.flows.fetch_sub(1, Ordering::AcqRel) == 1 {
            // The last flow: wake every waiter. A single permit would be taken by one
            // of them, stranding any other `drain` that is also waiting.
            self.inner.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn an_idle_supervisor_reports_nothing_in_flight() {
        let supervisor = Supervisor::new();
        assert_eq!(supervisor.in_flight(), 0);
    }

    #[tokio::test]
    async fn drain_returns_immediately_when_idle() {
        let supervisor = Supervisor::new();
        tokio::time::timeout(Duration::from_secs(1), supervisor.drain())
            .await
            .expect("an idle drain must not wait");
    }

    #[tokio::test]
    async fn drain_waits_for_every_flow() {
        let supervisor = Supervisor::new();
        for _ in 0..4 {
            supervisor.spawn(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Relayed::default()
            });
        }
        assert_eq!(supervisor.in_flight(), 4);

        tokio::time::timeout(Duration::from_secs(5), supervisor.drain())
            .await
            .expect("drain must finish");
        assert_eq!(supervisor.in_flight(), 0);
    }

    #[tokio::test]
    async fn every_waiter_is_woken_by_the_last_flow() {
        // Two drainers, one last flow. With a single stored permit the second one
        // would wait forever; the broadcast is what makes this pass.
        let supervisor = Supervisor::new();
        supervisor.spawn(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Relayed::default()
        });

        let first = supervisor.clone();
        let second = supervisor.clone();
        let (a, b) = tokio::join!(
            async move {
                tokio::time::timeout(Duration::from_secs(5), first.drain())
                    .await
                    .expect("first drainer")
            },
            async move {
                tokio::time::timeout(Duration::from_secs(5), second.drain())
                    .await
                    .expect("second drainer must not wait forever")
            }
        );
        assert_eq!(supervisor.in_flight(), 0);
        let _ = (a, b);
    }

    #[tokio::test]
    async fn a_flow_that_ends_before_the_drain_still_lets_it_return() {
        // The register-before-check ordering: the notification happens while no one
        // is subscribed, and `drain` must still observe the zero count.
        let supervisor = Supervisor::new();
        supervisor.spawn(async { Relayed::default() });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(supervisor.in_flight(), 0);

        tokio::time::timeout(Duration::from_secs(2), supervisor.drain())
            .await
            .expect("drain after completion must not hang");
    }

    #[tokio::test]
    async fn the_supervisor_is_reusable_after_a_drain() {
        let supervisor = Supervisor::new();
        supervisor.spawn(async { Relayed::default() });
        supervisor.drain().await;

        supervisor.spawn(async { Relayed::default() });
        assert_eq!(supervisor.in_flight(), 1);
        supervisor.drain().await;
        assert_eq!(supervisor.in_flight(), 0);
    }

    #[tokio::test]
    async fn counters_are_shared_by_every_handle() {
        let supervisor = Supervisor::new();
        let handle = supervisor.handle();
        handle.spawn(async { Relayed::default() });
        supervisor.drain().await;
        // One service, one set of counters: the handle did not create its own.
        assert_eq!(supervisor.metrics().snapshot(), handle.metrics().snapshot());
    }

    #[test]
    fn graceful_shutdown_suppresses_abnormal_end_for_aborted_flow() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let supervisor = Supervisor::new();
        rt.block_on(async {
            supervisor.spawn_tracked(daer_observe::FlowId::new(1), std::future::pending());
            tokio::task::yield_now().await;
        });
        assert_eq!(supervisor.in_flight(), 1);
        supervisor.begin_shutdown();
        assert!(supervisor.is_shutting_down());
        rt.shutdown_timeout(Duration::from_millis(10));

        assert_eq!(
            supervisor.in_flight(),
            0,
            "aborted flow guard must decrement in-flight count on shutdown"
        );
        assert_eq!(
            supervisor.metrics().snapshot().panicked,
            0,
            "expected cancellation after begin_shutdown() must not inflate panicked"
        );
    }

    #[test]
    fn non_shutdown_cancellation_still_records_abnormal_end() {
        // Falsifier for graceful_shutdown_suppresses_abnormal_end_for_aborted_flow:
        // without begin_shutdown(), aborting an in-flight task is still unexpected.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let supervisor = Supervisor::new();
        rt.block_on(async {
            supervisor.spawn_tracked(daer_observe::FlowId::new(2), std::future::pending());
            tokio::task::yield_now().await;
        });
        assert!(!supervisor.is_shutting_down());
        rt.shutdown_timeout(Duration::from_millis(10));

        assert_eq!(supervisor.in_flight(), 0);
        assert_eq!(supervisor.metrics().snapshot().panicked, 1);
    }

    #[test]
    fn panic_during_shutdown_still_records_abnormal_end() {
        // Falsifier for `!std::thread::panicking()`: even after begin_shutdown(),
        // a genuine task panic unwinds as an abnormal end and is still counted.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let supervisor = Supervisor::new();
        rt.block_on(async {
            supervisor.begin_shutdown();
            supervisor.spawn_tracked(daer_observe::FlowId::new(3), async {
                panic!("intentional test panic during shutdown");
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        rt.shutdown_timeout(Duration::from_millis(10));

        assert_eq!(supervisor.in_flight(), 0);
        assert_eq!(supervisor.metrics().snapshot().panicked, 1);
    }
}
