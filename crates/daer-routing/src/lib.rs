// SPDX-License-Identifier: AGPL-3.0-only

//! Routing policy for daer.
//!
//! Replaces `component/routing` (and the userspace half of
//! `control/routing_matcher_*`). The pipeline is:
//!
//! ```text
//! config rules -> optimizers -> RulesBuilder -> MatchSink -> match sets
//!                                                              |
//!                                    userspace evaluator  <----+
//!                                    kernel matcher      <----+  (daer-control)
//! ```
//!
//! A [`MatchSink`] decides what a match set *is*: [`RecordingSink`] keeps the
//! operands so [`matcher::evaluate`] can replay the kernel's decision loop in
//! userspace, and [`kernel::compile`] encodes the same list into the datapath's
//! `struct match_set` table (ADR-0005). Two backends over one lowering is what
//! keeps them from drifting: a change to how rules lower has to keep both in
//! agreement, or `tests/kernel_policy.rs` fails.

mod builder;
pub mod drb;
mod error;
mod identity;
mod ipset;
mod matcher;
mod optimizer;
mod outbound;
mod program;
mod values;

pub mod domain;
pub mod explain;
pub mod kernel;

pub use builder::{MatchSink, RecordingSink, RulesBuilder, ValidationSink};
/// The builtin outbound names, re-exported from `daer-common` so a caller that compares an
/// outbound name spells it once: `outbound_name::DIRECT` in a comparison and in the list
/// `is_builtin_outbound` consults cannot drift apart the way two string literals can.
pub use daer_common::consts::outbound_name;
pub use domain::{DomainTable, SuffixScope, validate_patterns};
pub use drb::{DRB_MAGIC, DRB_VERSION, DrbError, DrbSet, DrbSummary, RuleProviderPool};
pub use error::RoutingError;
pub use explain::{PredicateTrace, RuleTrace, Trace, explain};
pub use identity::{PolicyEpoch, PolicyIdentity, hash_normalized_program};
pub use ipset::{IpIndex, MAX_PREFIXES};
pub use kernel::{DeferReason, OutboundIds, Policy};
pub use matcher::{
    Hit, MatchFacts, MatchSet, MatchValue, RoutingResult, evaluate, first_hit, intern_outbound,
    matches_value,
};
pub use optimizer::{
    DeduplicateParamsOptimizer, RulesOptimizer, SortFunctionsOptimizer, apply_optimizers,
};
pub use outbound::{
    BUILTIN_OUTBOUNDS, CONTROL_PLANE_ROUTING, LOGICAL_AND, LOGICAL_OR, MUST_RULES, MatchTarget,
    Outbound, is_builtin_outbound,
};
pub use program::NormalizedProgram;
pub use values::{IpVersionMask, L4ProtoMask, ProcessName, TASK_COMM_LEN};

pub use daer_common::net::{MacAddr, PortRange};
pub use ipnet::IpNet;
