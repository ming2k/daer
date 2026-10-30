// SPDX-License-Identifier: AGPL-3.0-only

//! Control plane and transparent-proxy data path.
//!
//! # Where a packet goes
//!
//! ```text
//!   client ──▶ tc hook ──▶ ["route this flow?"] ──yes──▶ tproxy port
//!                  │                                        │
//!                  └──no──▶ kernel stack (direct)            ▼
//!                                                    daer-control::inbound
//!                                                           │
//!                                    routing decision ──────┤
//!                                                           ▼
//!                                              daer-outbound (netune transport)
//! ```
//!
//! The kernel program has already decided *whether* to redirect. Everything here
//! answers *where to* and *which bytes*: [`inbound`] accepts the redirected flow
//! and recovers its destination, [`decide::Router`] turns it into a verdict and
//! opens the other leg, and [`relay`] splices the two together under [`serve`].
//!
//! # Reload
//!
//! Accepting and relaying have separate lifetimes, deliberately. A generation is
//! immutable and published by one atomic swap ([`generation`]); the flows it started
//! are owned by a [`supervise::Supervisor`], not by the accept loop. A reload
//! therefore:
//!
//! 1. builds and validates the next generation (a failure publishes nothing),
//! 2. binds the new listener **while the old one is still accepting**
//!    (`SO_REUSEPORT`, see [`inbound::bind_shared`]),
//! 3. starts the new accept loop, then stops the old one,
//! 4. leaves every live flow relaying on the generation it arrived under.
//!
//! `tests/handover.rs` asserts each of those, including one connection crossing
//! eight generations and the port never going unbound.
//!
//! # What is not here yet
//!
//! Interface and namespace setup (`daer0`/`daer0peer`, tc attach), UDP sessions,
//! connection-state bookkeeping and the event ring. `tests/handover.rs` covers the
//! userland half of a reload; what remains is the kernel side of it — publishing a
//! routing epoch into the maps — which needs privileges this environment does not
//! have.
//!
//! # Design rules
//!
//! * **No lock crosses an `.await`.** A flow owns its state.
//! * **Cancellation is dropping.** A relay ends when its future is dropped, so
//!   there is no shutdown flag to observe and no task to leak.
//! * **The kernel is the authority on destinations.** The original destination is
//!   the accepted socket's peer address; it is never guessed or re-derived.
//! * **Nothing is swallowed.** A socket option that cannot be set is an error, not
//!   a warning: a listener without `IP_TRANSPARENT` silently accepts nothing.
//! * **The loop is testable without privileges.** [`serve`](serve::serve) takes
//!   traits for "accept" and "decide", so the accept loop's failure modes (a
//!   rejected flow, fd exhaustion, a panicking handler) are covered by tests that
//!   run as an ordinary user.
//!
//! # Reporting
//!
//! Every hop has one place that reports it, so a question has exactly one place to
//! look. The field names are stable — they are what a log query filters on.
//!
//! | Question | Where | Level | Fields |
//! | --- | --- | --- | --- |
//! | Which configuration is serving? | [`generation::Generations::new`] | `info` | `generation rules groups nodes build_ms` |
//! | What did a reload do? | [`generation::Generations::reload`] | `info` | `generation previous rules groups nodes routing_changed build_ms` |
//! | Why did a reload fail? | [`generation::Generations::reload`] | `error` | `generation serving error` — the running generation is untouched |
//! | Why did *this* flow go there? | [`decide::Router::resolve`] | `debug` | `generation source destination rule outbound mark must` |
//! | Which node was picked? | [`decide::Router::resolve`] | `trace` | `group node protocol` |
//! | What happened to the bytes? | [`serve::serve`] | `debug` | `destination to_upstream to_client elapsed_ms` |
//! | Why was a flow dropped? | [`serve::serve`] | `debug` | `reject` |
//! | Are we out of file descriptors? | [`serve::serve`] | `warn` | `error` (then a backoff, never a teardown) |
//! | Is anything leaking? | [`serve::Metrics::snapshot`] | on demand | `accepted rejected failed exhausted panicked` |
//! | Is a reload safe to finish? | [`supervise::Supervisor::in_flight`] | on demand | count of live flows |
//! | Did stopping a loop drop traffic? | [`serve::serve`] | `info` | `in_flight` — the flows keep running |
//!
//! Counters answer "how much", logs answer "which one": a flow that behaved
//! unexpectedly is a `debug` line with a destination and a rule number, reproducible
//! offline through [`decide::Router::verdict_for`].

pub mod daemon;
pub mod datagram;
pub mod datapath;
pub mod decide;
pub mod error;
pub mod generation;
pub mod health;
pub mod inbound;
pub mod ingress_udp;
pub mod load;
pub mod relay;
pub mod serve;
pub mod sniff;
pub mod subscription;
pub mod supervise;

pub use daemon::{
    BindError, Daemon, DatapathSettings, DatapathStatus, detect_wan_interface, listen_address,
    resolve_interfaces,
};
pub use datagram::{
    DatagramService, DatagramSnapshot, DatagramStats, RelayOptions, serve_datagrams,
};
pub use datapath::{DEVICE, DatapathError, PEER, ensure_device_pair, peer_mac};
pub use decide::{Explanation, NodeIdentity, Router, RouterOptions, Verdict};
pub use error::{IngressError, Reject};
pub use generation::{Generation, GenerationId, Generations, ReloadError, ReloadReport};
pub use health::{
    ProbeFailure, ProbeResult, ProbeTarget, Scheduler, has_measurable_nodes,
    policy_needs_measurement, spawn as spawn_health_scheduler,
};
pub use inbound::{Accepted, TransparentListener, bind_shared, is_self_connect, unmap};
pub use ingress_udp::{Datagram, DatagramIngress, TransparentDatagramListener};
pub use load::{
    Resolved, group_mentions_node, load_resolved, load_resolved_with, warn_about_empty_groups,
};
pub use relay::{Relayed, splice};
pub use serve::{
    Decide, Ingress, Metrics, ServeStats, ShutdownReason, Stopped, is_resource_exhausted,
    serve as serve_ingress, serve_with_datagrams,
};
pub use sniff::{Outcome, Unnamed, sniff_stream};
pub use subscription::{
    Resolution, cache_directory, resolve_subscriptions, resolve_subscriptions_with,
};
pub use supervise::Supervisor;
