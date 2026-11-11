// SPDX-License-Identifier: AGPL-3.0-only

//! The routing and outbound scheduling plane: what a flow is, and where it goes.
//!
//! # This crate decides; `daer-relay` carries
//!
//! ```text
//!   client ──▶ tc hook ──▶ ["route this flow?"] ──yes──▶ tproxy port
//!                  │                                        │
//!                  └──no──▶ kernel stack (direct)            ▼
//!                                                    daer-relay::inbound
//!                                                           │
//!                                          ┌────────────────┘
//!                                          ▼
//!                         daer-control::decide::Router  (this crate)
//!                                          │
//!                          ┌───────────────┴───────────────┐
//!                          ▼                               ▼
//!                 daer-outbound group             daer-proxy-protocols node
//!                          │
//!                          ▼
//!                  daer-relay::relay::splice / serve_datagrams
//! ```
//!
//! Accepting a redirected flow, splicing two streams, keying a UDP session and reaping an
//! idle peer are `daer-relay`'s. Everything that answers *which outbound, which node, and
//! why* is here: the compiled routing program, the node groups with their measured state,
//! the health scheduler that fills that state, subscription and rule-provider resolution,
//! and the sniffing that turns a peeked ClientHello into a name a rule can match.
//!
//! # Why the split is where it is
//!
//! The two halves change for different reasons. The data path changes when a socket option
//! or a session invariant is wrong; this crate changes when a routing concept, a selection
//! policy or a configuration key is added. Keeping them apart means adding a protocol or a
//! policy rule does not recompile or re-review the accept loop, and the accept loop's tests
//! do not need a routing configuration to run.
//!
//! # Reload
//!
//! A generation is immutable and published by one atomic swap ([`generation`]); the flows
//! it started are owned by a [`daer_relay::Supervisor`], not by the accept loop. A reload:
//!
//! 1. builds and validates the next generation (a failure publishes nothing),
//! 2. swaps the generation behind the already-bound listener,
//! 3. leaves every live flow relaying on the generation it arrived under.
//!
//! The production listener is deliberately not reusable (`SO_REUSEPORT` would let the
//! kernel choose a different socket than the one `bpf_sk_assign` named); the separate
//! `bind_shared` helper and `tests/handover.rs` exercise the accept-loop handover shape on
//! a plain socket.
//!
//! # Reporting
//!
//! | Question | Where | Level | Fields |
//! | --- | --- | --- | --- |
//! | Which configuration is serving? | [`generation::Generations::new`] | `info` | `generation rules groups nodes build_ms` |
//! | What did a reload do? | [`generation::Generations::reload`] | `info` | `generation previous rules groups nodes routing_changed build_ms` |
//! | Why did a reload fail? | [`generation::Generations::reload`] | `error` | `generation serving error` — the running generation is untouched |
//! | Why did *this* flow go there? | [`decide::Router::resolve`] | `debug` | `generation source destination rule outbound mark must` |
//! | Which node was picked? | [`decide::Router::resolve`] | `trace` | `group node protocol` |
//! | What did the bytes do? | [`daer_relay::serve`] | `debug` | `destination to_upstream to_client elapsed_ms` |
//!
//! Counters answer "how much", logs answer "which one": a flow that behaved unexpectedly is
//! a `debug` line with a destination and a rule number, reproducible offline through
//! [`decide::Router::verdict_for`].

pub mod daemon;
pub mod datapath;
pub mod decide;
pub mod generation;
pub mod health;
pub mod load;
pub mod netns;
pub mod rule_provider;
pub mod sniff;
pub mod subscription;

pub use daemon::{
    BindError, Daemon, DatapathSettings, DatapathStatus, detect_wan_interface, listen_address,
    resolve_interfaces,
};
pub use datapath::{DEVICE, DatapathError, PEER, peer_mac};
pub use decide::{Explanation, NodeIdentity, Router, RouterOptions, Verdict};
pub use generation::{Generation, GenerationId, Generations, ReloadError, ReloadReport};
pub use health::{
    ProbeFailure, ProbeResult, ProbeTarget, Scheduler, has_measurable_nodes,
    policy_needs_measurement, spawn as spawn_health_scheduler,
};
pub use load::{
    Resolved, group_mentions_node, load_resolved, load_resolved_with, warn_about_empty_groups,
};
pub use netns::{INGRESS_NETNS, IngressNamespace, PreparedIngress};
pub use rule_provider::{
    ProviderSchedule, ProviderScheduleEntry, RefreshOutcome, RefreshedProvider,
    ResolvedRuleProvider, RuleProviderResolution, refresh_rule_provider, resolve_rule_providers,
    resolve_rule_providers_with,
};
pub use sniff::{Outcome, Unnamed, sniff_stream};
pub use subscription::{
    Resolution, cache_directory, resolve_subscriptions, resolve_subscriptions_with,
};
