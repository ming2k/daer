// SPDX-License-Identifier: AGPL-3.0-only

//! Turning a flow into a verdict, and a verdict into a connection.
//!
//! This is the seam the whole data path exists for:
//!
//! ```text
//! Accepted { source, destination }
//!         │
//!         ▼  MatchFacts (addresses, ports, l4proto; domain/pname/mac unknown here)
//!   routing program (compiled once, immutable, shared by every flow)
//!         │
//!         ▼  Outbound { name, mark, must }
//!   direct ──▶ DirectDialer
//!   block  ──▶ the flow is dropped
//!   election ──▶ ElectionRuntime::select ──▶ NodeDialer for the elected node
//!         │
//!         ▼  Upstream stream, handed back to the relay
//! ```
//!
//! # What a TCP flow knows, and what it does not
//!
//! A redirected TCP flow gives the matcher four things: source address, source
//! port, destination address and destination port, plus `TCP`. The domain fact is
//! acquired by [`crate::domain::DomainResolver`] (Fake-IP, DNS snooper, or the
//! explicit `[routing.sniff]` fallback). The client's process name, the DSCP field
//! and the source MAC live in the kernel's connection state. Facts that are not
//! available are supplied as "unknown" (`None`/zero) rather than guessed, so a rule
//! that depends on them cannot match by accident.
//!
//! # Why the groups are built once
//!
//! Compiling the program and assembling the groups is work per configuration
//! generation, not per packet. [`Router::new`] does it once; a reload builds
//! another `Router` and swaps the pointer, which is why nothing here takes a lock:
//! a flow's whole view of the configuration is the `&self` it was created under.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

/// `IPPROTO_TCP`, the datapath's `l4proto` for a stream flow.
const IPPROTO_TCP: u8 = 6;
/// `IPPROTO_UDP`, the datapath's `l4proto` for a datagram flow.
const IPPROTO_UDP: u8 = 17;
use std::sync::Arc;
use std::time::Duration;

use daer_config::{Config, ElectionKind, OutboundKind, ProbeSettings};
use daer_outbound::{
    Dialer, DialerId, DialerOptions, DirectDialer, ElectionRuntime, FilterSet, NodeDialer,
    NodeGraph, NotifyOutcome, OutboundError, Property, Protocol, Security, UdpConnector, Upstream,
};
use daer_primitives::net::MacAddr;

use daer_relay::relay::DatagramLeg;
use daer_relay::{Accepted, FlowFacts, RelayError};
use daer_routing::{
    DeduplicateParamsOptimizer, MatchFacts, MatchSet, NormalizedProgram, Outbound, RecordingSink,
    RoutingError, RulesBuilder, SortFunctionsOptimizer, Trace, first_hit,
};
use daer_routing::{L4ProtoMask, ProcessName};

use serde::Serialize;

use crate::domain::{DomainOutcome, DomainPlan, DomainResolver, DomainSource};
use crate::election::ElectionOverrides;
use crate::generation::GenerationId;

/// What the routing program decided for one flow.
///
/// `rule` is what makes a decision explainable after the fact: "this flow went to
/// `proxy`" is only actionable together with *which* rule sent it there, or that
/// the fallback did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub outbound: Outbound,
    /// Index of the matching rule, or `None` when the fallback applied.
    pub rule: Option<usize>,
}

impl Verdict {
    /// `rule 7`, or `fallback`.
    #[must_use]
    pub fn describe(&self) -> String {
        self.rule
            .map_or_else(|| "fallback".to_owned(), |rule| format!("rule {rule}"))
    }
}

/// One selectable node, described for a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeIdentity {
    /// The resource pool this node belongs to. Empty for a node-only election.
    pub group: String,
    /// The election that selected this node. Empty for a resource-catalog row.
    pub election: String,
    pub node: String,
    pub protocol: Protocol,
    pub security: Security,
    /// Whether the node is used for UDP as well as TCP.
    pub udp: bool,
    pub subscription_name: String,
    /// The node that carries this node's server leg, when it is a detour hop.
    pub detour: Option<String>,
    /// The election that currently elects this node, when one does.
    pub elected_by: Option<String>,
    /// Cached health of this node from that election.
    pub health: Option<ElectionHealth>,
}

/// One resource pool and the elections that consume it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupIdentity {
    pub name: String,
    pub candidates: Vec<String>,
    pub elections: Vec<String>,
}

/// One election and its current result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElectionIdentity {
    pub name: String,
    /// `group:<name>` or `node:<name>`.
    pub input: String,
    pub kind: ElectionKind,
    /// The scheduled probe, or `None` for a manual election (never probed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeSettings>,
    pub candidates: usize,
    /// The node pinned by `daer elect`, if any.
    pub pinned: Option<String>,
    /// The node the election would return for the next flow.
    pub effective: Option<String>,
    /// Cached health of the effective node, when it has been measured.
    pub health: Option<ElectionHealth>,
}

/// The cached liveness of one elected node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElectionHealth {
    pub alive: bool,
    pub latency_us: Option<u64>,
}

impl NodeIdentity {
    /// Compatibility accessor for the subscription name.
    #[must_use]
    pub fn subscription_tag(&self) -> &str {
        &self.subscription_name
    }

    /// The name of the subscription this node belongs to, or `""`.
    #[must_use]
    pub fn subscription_name(&self) -> &str {
        &self.subscription_name
    }

    /// A one-line description, safe to log: it names the cipher or the TLS name, never a secret.
    #[must_use]
    pub fn describe(&self) -> String {
        let owner = if self.election.is_empty() {
            self.group.clone()
        } else if self.group.is_empty() {
            self.election.clone()
        } else {
            format!("{}:{}", self.election, self.group)
        };
        format!(
            "{}: {} [{} | {}]{}{}{}",
            owner,
            self.node,
            self.protocol.as_str(),
            self.security.describe(),
            if self.udp { " udp" } else { "" },
            if self.subscription_name.is_empty() {
                String::new()
            } else {
                format!(" sub={}", self.subscription_name)
            },
            self.detour
                .as_ref()
                .map_or_else(String::new, |detour| format!(" detour={detour}"))
        )
    }
}

/// A routing decision rendered for a human, with the rule text that produced it.
///
/// This is the data behind `daer route explain`: the same numbers the live path
/// logs, plus the rule as the operator wrote it. Reporting only the outbound would
/// leave "why?" unanswered, and reporting only an index would leave "which rule?"
/// unanswered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub generation: GenerationId,
    /// The matching rule's index, or `None` for the fallback.
    pub rule: Option<usize>,
    /// The rule's stable name, or `None` for the fallback.
    pub rule_name: Option<String>,
    /// The rule as the engine evaluated it.
    ///
    /// The optimizer sorts predicates and parameters inside the rule, so this is
    /// the text that actually fired. Rule order and rule identity are never
    /// rewritten.
    pub rule_text: String,
    pub outbound: Outbound,
    /// Elections the flow could have gone to, for a rule that did not match.
    pub elections: Vec<String>,
    /// Per-rule, per-predicate detail.
    ///
    /// Carried in the explanation rather than fetched separately: the two must
    /// describe the same evaluation, and making them one value is how that is
    /// guaranteed.
    pub trace: daer_routing::Trace,
    /// The node the verdict would select, when it names a group.
    ///
    /// `None` for `direct` and `block`, which select no node. Present here because "which node
    /// and how is it protected" is part of the same answer as "which rule fired".
    pub selected: Option<NodeIdentity>,
}

impl Explanation {
    /// True when this verdict can actually carry the flow somewhere.
    ///
    /// `block` cannot by definition, and a group with no selectable node cannot
    /// either — the difference between the two is *why*, and both are failures of
    /// the same question: does this flow have a destination that exists? A
    /// diagnostic that calls an empty group a success makes its own exit status
    /// meaningless.
    #[must_use]
    pub fn outbound_is_actionable(&self) -> bool {
        match self.outbound.kind {
            OutboundKind::Block => false,
            OutboundKind::Direct => true,
            // An election is actionable only when it actually selected a node.
            OutboundKind::Election => self.selected.is_some(),
        }
    }
}

impl fmt::Display for Explanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} → {}  [{}]",
            self.source, self.destination, self.generation
        )?;
        match &self.rule_name {
            Some(name) => writeln!(f, "  decided by : rule {name:?}: {}", self.rule_text)?,
            None => writeln!(f, "  decided by : {}", self.rule_text)?,
        }
        write!(
            f,
            "  outbound   : {} (mark {})",
            self.outbound.name, self.outbound.mark
        )?;
        if self.outbound.must {
            write!(f, " must")?;
        }
        if let Some(selected) = &self.selected {
            write!(f, "\n  node       : {}", selected.describe())?;
        }
        Ok(())
    }
}

/// What the router needs besides the configuration.
#[derive(Debug, Clone, Default)]
pub struct RouterOptions {
    /// The socket mark to put on daer's own outbound sockets.
    ///
    /// # Why this is a process option, not configuration
    ///
    /// `SO_MARK` needs `CAP_NET_ADMIN`, so the value cannot come from a file: an
    /// unprivileged run (`--no-datapath`, a container probe, the test suite) must dial
    /// without a mark or every dial fails, and a privileged run **must** dial with one or
    /// the proxy captures its own traffic.
    ///
    /// The value itself is an internal loop-evasion identity. A privileged run uses
    /// [`daer_primitives::consts::DEFAULT_SOCKET_MARK`]; `--no-datapath` and diagnostics pass
    /// `None`. `Some(mark)` exists for tests and future privileged callers that need a
    /// different identity; `None` means no mark, never "read it from configuration".
    ///
    /// That is not hypothetical. With the mark absent, `daer`'s own connection to an
    /// origin matches the same `tproxy` rule as a client's, is redirected back into the
    /// listener, and the result is an unbounded loop: the end-to-end test observed
    /// **17,134** accepted flows for a single client request before the mark was threaded
    /// through. The process knows which case it is in (it either attached a datapath or it
    /// did not), so it decides once, here, and the generation carries the answer.
    pub so_mark: Option<u32>,
    /// Synthetic Fake-IP allocation pool (ADR-0012).
    pub fake_ip: Option<Arc<daer_dns::FakeIpPool>>,
    /// Observational DNS Snooper for Real-IP mode (ADR-0011).
    pub dns_snooper: Option<Arc<daer_dns::DnsSnooper>>,
    /// The datapath's per-flow facts, when a datapath is attached.
    ///
    /// `None` is the honest state for `--no-datapath`, the diagnostics, and every test: the
    /// router then matches on addresses and the acquired domain only, and a rule needing a MAC,
    /// a DSCP, or a process name does not match by accident.
    pub kernel_observer: Option<Arc<dyn KernelObserver>>,
    /// Where a dial's measurement goes.
    ///
    /// `None` records only the transport's own ring, which nothing reads. The daemon installs
    /// [`daer_outbound::LogObserver`] so a dial's span reaches the journal; a diagnostic or a
    /// test leaves it unset.
    pub dial_observer: daer_outbound::ObserverSlot,
    /// Pre-loaded rule provider pool (ADR-0014).
    pub rule_providers: Option<Arc<daer_routing::RuleProviderPool>>,
    /// Runtime election overrides, shared by every generation.
    pub overrides: Arc<ElectionOverrides>,
}

impl RouterOptions {
    /// The defaults: no override, no datapath facts, no dial observer.
    ///
    /// A caller that has a configuration *file* uses [`Self::for_config`] instead, because the
    /// rules of a file are resolved relative to that file's directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The defaults, with the configuration's own directory recorded.
    ///
    /// `config` is accepted rather than ignored: a caller reading a file passes its path so a
    /// relative `[[rule-set]] path` resolves beside it, and the signature is the place
    /// that requirement is visible.
    #[must_use]
    pub fn for_config(config: impl AsRef<std::path::Path>) -> Self {
        let config = config.as_ref();
        debug_assert!(
            config.parent().is_some(),
            "a configuration path always has a parent"
        );
        Self::default()
    }

    /// Supplies the preloaded rule provider pool.
    #[must_use]
    pub fn with_rule_providers(
        mut self,
        providers: Option<Arc<daer_routing::RuleProviderPool>>,
    ) -> Self {
        self.rule_providers = providers;
        self
    }

    /// Supplies the shared runtime election overrides.
    #[must_use]
    pub fn with_overrides(mut self, overrides: Arc<ElectionOverrides>) -> Self {
        self.overrides = overrides;
        self
    }

    /// Overrides the synthetic Fake-IP pool.
    #[must_use]
    pub fn with_fake_ip(mut self, fake_ip: Option<Arc<daer_dns::FakeIpPool>>) -> Self {
        self.fake_ip = fake_ip;
        self
    }

    /// Overrides the DNS snooper.
    #[must_use]
    pub fn with_dns_snooper(mut self, dns_snooper: Option<Arc<daer_dns::DnsSnooper>>) -> Self {
        self.dns_snooper = dns_snooper;
        self
    }

    /// Supplies the datapath's per-flow facts.
    #[must_use]
    pub fn with_kernel_observer(mut self, observer: Option<Arc<dyn KernelObserver>>) -> Self {
        self.kernel_observer = observer;
        self
    }

    /// Supplies the destination for dial measurements.
    #[must_use]
    pub fn with_dial_observer(mut self, observer: daer_outbound::ObserverSlot) -> Self {
        self.dial_observer = observer;
        self
    }

    /// Forces the socket mark daer's own dials carry.
    ///
    /// `Some(mark)` marks every daer socket; `None` disables marking (an unprivileged
    /// run, a diagnostic, or the test suite). The configuration cannot set this value.
    #[must_use]
    pub fn with_socket_mark(mut self, mark: Option<u32>) -> Self {
        self.so_mark = mark;
        self
    }

    /// The mark this generation's dialers apply.
    fn effective_so_mark(&self) -> Option<u32> {
        self.so_mark
    }
}

/// The routing program plus every outbound it can name.
#[derive(Debug)]
pub struct Router {
    /// Which generation this router serves. Every flow log carries it, so a log
    /// slice is self-explaining: which configuration made this decision.
    generation: GenerationId,
    /// How this generation obtains a domain, and whether payload inspection is
    /// allowed. Built once from the lowered policy so TCP, UDP and diagnostics agree.
    domain: DomainResolver,
    /// Kept so a generation can report the *semantic* identity of its routing
    /// policy: "did the reload change where traffic goes?" is a different question
    /// from "did the file change?".
    program: NormalizedProgram,
    matches: Vec<MatchSet>,
    /// Where a flow goes when no rule matches. Never absent: a configuration
    /// always has a fallback, which is what makes "unmatched" a value and not an
    /// error.
    fallback: Outbound,
    direct: DirectDialer,
    /// The datagram twin of `direct`. Kept beside it so a UDP flow to a `direct`
    /// outbound does not have to build a connector per packet.
    datagram_direct: UdpConnector,
    /// Elections live behind a lock because a probe mutates a candidate's measured
    /// state while flows read it to elect. A group is only a candidate set and is
    /// immutable after the generation is built.
    elections: std::sync::RwLock<HashMap<String, ElectionRoute>>,
    /// Every resource pool, including pools no election consumes.
    groups: HashMap<String, GroupResource>,
    /// Node names, indexed like `config.node`.
    node_names: Vec<String>,
    /// Every node resource, grouped by the pools that contain it, for diagnostics.
    node_catalog: Vec<NodeIdentity>,
    /// Runtime `daer elect` overrides, shared across generations.
    overrides: Arc<ElectionOverrides>,
    /// The datapath's per-flow facts, when one is attached.
    kernel_observer: Option<Arc<dyn KernelObserver>>,
    /// Where a dial's measurement goes.
    dial_observer: daer_outbound::ObserverSlot,
    /// The mark every socket daer creates carries, including health probes.
    so_mark: Option<u32>,
    /// Non-fatal compile warnings, so a reload report and a snapshot can carry them.
    warnings: Vec<String>,
}

impl Router {
    /// Compiles a configuration into a router.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError`] for an invalid rule, a fallback or rule target that
    /// names an outbound that does not exist, or a group whose policy or filters do
    /// not compile. Everything that can be rejected statically is rejected here, at
    /// the configuration generation, not per flow.
    pub fn new(
        config: &Config,
        generation: GenerationId,
        options: &RouterOptions,
    ) -> Result<Self, RoutingError> {
        // A detour is a DAG, not a runtime recursion. Validate it before anything lowers or
        // builds; a diagnostic that skips the graph check would disagree with the daemon about
        // whether the configuration is runnable (ADR-0006, ADR-0044).
        daer_config::validate::validate_chain_graph(config)
            .map_err(|error| RoutingError::new(error.to_string()))?;

        // `geoip:` / `geosite:` are gone with the Protobuf reader (ADR-0014/ADR-0015): a rule
        // names a `rule-set(...)`, and the set is a compiled `.drb`. There is no
        // optimizer here that could resurrect the retired format.
        let program = NormalizedProgram::new(
            &config.routing.rule,
            config.routing.default.clone(),
            &[&SortFunctionsOptimizer, &DeduplicateParamsOptimizer],
        )?;

        // The mark daer's own dials carry. It is a process option because `SO_MARK` needs
        // `CAP_NET_ADMIN`: an unprivileged run must not mark, and a privileged one must
        // (see `RouterOptions::so_mark` for the loop it prevents).
        let so_mark = options.effective_so_mark();
        let dialer_options = {
            let options = DialerOptions::new(so_mark, DEFAULT_DIAL_TIMEOUT);
            // `tls.profile`: unknown names are a load-time error. A silently defaulted
            // profile is a ClientHello the operator did not choose, and the handshake that fails
            // because of it reports nothing that points at the profile.
            let options = match &config.tls.profile {
                Some(name) => options
                    .with_tls_profile(name)
                    .map_err(|error| RoutingError::new(error.to_string()))?,
                None => options,
            };
            // `[tls] fragment`: unknown or reversed ranges are a load-time error, because
            // an operator who asked for a shaped handshake must not silently get the default one.
            let fragment = daer_outbound::fragment::Fragment::from_config(&config.tls)
                .map_err(RoutingError::new)?;
            options.with_fragment(fragment)
        };
        let (groups, elections) = build_resources_and_elections(config, &dialer_options)?;
        let node_names: Vec<String> = config
            .node
            .iter()
            .map(|node| Property::from_node(node).name)
            .collect();
        let node_catalog = node_catalog(config, &groups);

        let mut sink = RecordingSink::default();
        let mut fallback = None;
        {
            let mut builder = match &options.rule_providers {
                Some(providers) => RulesBuilder::with_providers(&mut sink, providers),
                None => RulesBuilder::new(&mut sink),
            };
            program.lower(&mut builder, |value| {
                daer_config::validate::check_action_target(config, value, "routing.default")
                    .map_err(|error| RoutingError::new(error.to_string()))?;
                let outbound = Outbound::from_action(value)?;
                fallback = Some(outbound);
                Ok(())
            })?;
        }
        let fallback = fallback.ok_or_else(|| RoutingError::new("no routing fallback"))?;
        for warning in &sink.warnings {
            daer_observe::warn!(daer_observe::EventCode::GenerationRuleWarning,%warning, "routing rule compiled with a warning");
        }

        // Every rule target must resolve too, not just the fallback.
        for rule in &program.rules {
            daer_config::validate::check_action_target(config, &rule.action, "routing.rule.action")
                .map_err(|error| RoutingError::new(error.to_string()))?;
            Outbound::from_action(&rule.action)?;
        }

        let fake_ip = match &options.fake_ip {
            Some(pool) => Some(pool.clone()),
            None => {
                if config.dns.fake_ip.enabled {
                    daer_dns::FakeIpPool::from_config(&config.dns.fake_ip)
                        .ok()
                        .map(Arc::new)
                } else {
                    let _ = config.dns.fake_ip.enabled;
                    let _ = &config.dns.fake_ip.inet;
                    let _ = config.dns.fake_ip.pool_size;
                    let _ = &config.dns.fake_ip.exclude;
                    None
                }
            }
        };
        let dns_snooper = options
            .dns_snooper
            .clone()
            .or_else(|| Some(Arc::new(daer_dns::DnsSnooper::default())));
        let domain_plan = DomainPlan::build(config, &sink.matches)
            .map_err(|error| RoutingError::new(error.to_string()))?;
        let mut warnings = sink.warnings.clone();
        warnings.extend(domain_plan.warnings().iter().cloned());
        let domain = DomainResolver::new(domain_plan, fake_ip, dns_snooper);
        let mut election_names: Vec<&String> = elections.keys().collect();
        election_names.sort();
        for name in election_names {
            if let Some(route) = elections.get(name)
                && route.runtime.is_empty()
            {
                warnings.push(format!(
                    "election {name:?} has no candidates; flows routed to it will fail"
                ));
                daer_observe::warn!(daer_observe::EventCode::GenerationRuleWarning,
                    warning = %format!("election {name:?} has no candidates; flows routed to it will fail"),
                    "routing rule compiled with a warning"
                );
            }
        }

        Ok(Self {
            generation,
            domain,
            program,
            matches: sink.matches,
            fallback,
            direct: DirectDialer::new(so_mark, DEFAULT_DIAL_TIMEOUT),
            datagram_direct: UdpConnector::new()
                .with_socket_config(
                    DialerOptions::new(so_mark, DEFAULT_DIAL_TIMEOUT).socket_config(),
                )
                .with_connect_timeout(Some(DEFAULT_DIAL_TIMEOUT)),
            groups,
            node_names,
            node_catalog,
            elections: std::sync::RwLock::new(elections),
            overrides: Arc::clone(&options.overrides),
            kernel_observer: options.kernel_observer.clone(),
            dial_observer: options.dial_observer.clone(),
            so_mark,
            warnings,
        })
    }

    /// The mark every socket daer creates must carry, including health probes.
    #[must_use]
    pub const fn socket_mark(&self) -> Option<u32> {
        self.so_mark
    }

    /// The generation this router belongs to.
    #[must_use]
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// The normalized routing program this router was built from.
    #[must_use]
    pub const fn program(&self) -> &NormalizedProgram {
        &self.program
    }

    /// Non-fatal compile warnings from this generation.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Compiles this generation's policy into the datapath's table (ADR-0005).
    ///
    /// The result is either a faithful translation or a deferral; it is never an empty table,
    /// and it is never a partial one. The caller publishes it and logs which tier it got.
    #[must_use]
    pub fn kernel_policy(&self) -> daer_routing::Policy {
        // The rule a match-set index came from: the lowering emits one set per predicate
        // operand in rule order, so walking the rules and counting operands recovers it. The
        // count is recomputed here rather than threaded through because the encoder needs it
        // only on the failure path, where an extra walk costs nothing.
        let boundaries = rule_boundaries(&self.program.rules);
        daer_routing::kernel::compile(&self.matches, &self.fallback, move |index| {
            boundaries
                .iter()
                .position(|boundary| index < *boundary)
                .unwrap_or(boundaries.len())
        })
    }

    /// The compiled match sets, for diagnostics and tests.
    #[must_use]
    pub fn matches(&self) -> &[MatchSet] {
        &self.matches
    }

    /// The outbound used when no rule matches.
    #[must_use]
    pub fn fallback(&self) -> &Outbound {
        &self.fallback
    }

    /// The effective domain-acquisition plan.
    #[must_use]
    pub const fn domain_plan(&self) -> &DomainPlan {
        self.domain.plan()
    }

    /// Resolves one flow.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Relay`] when the veredict is `block`, when the group
    /// has no selectable node, or when the dial fails. The flow is closed by the
    /// caller in every one of those cases.
    pub async fn resolve(&self, flow: &Accepted) -> Result<Upstream, RelayError> {
        // The resolver owns the whole policy: Fake-IP, the DNS snooper, and the bounded
        // payload fallback. This path only consumes its answer.
        let outcome = self
            .domain
            .resolve_tcp(&flow.stream, flow.source, flow.destination)
            .await;
        self.log_domain(&flow.flow_id, flow.destination, &outcome);
        let verdict = self.verdict_for_flow(flow.source, flow.destination, outcome.domain());
        self.dial_with_authority(flow, verdict, outcome.domain())
            .await
    }

    fn log_domain(
        &self,
        flow_id: &daer_observe::FlowId,
        destination: SocketAddr,
        outcome: &DomainOutcome,
    ) {
        match outcome {
            DomainOutcome::Named { domain, source, .. } => match source {
                DomainSource::FakeIp | DomainSource::DnsSnooper => {
                    daer_observe::debug!(daer_observe::EventCode::FlowDnsMapping,
                        flow_id = %flow_id,
                        generation = %self.generation,
                        destination = %destination,
                        domain = %domain,
                        "flow resolved via dns mapping"
                    );
                }
                DomainSource::Sniff => {
                    daer_observe::debug!(daer_observe::EventCode::FlowSniffed,
                        flow_id = %flow_id,
                        generation = %self.generation,
                        destination = %destination,
                        sniffed = %outcome.describe(),
                        "flow sniffed"
                    );
                }
            },
            DomainOutcome::Unnamed { .. } => {
                daer_observe::trace!(daer_observe::EventCode::FlowNotSniffed,
                    flow_id = %flow_id,
                    generation = %self.generation,
                    destination = %destination,
                    reason = %outcome.describe(),
                    "flow not sniffed"
                );
            }
        }
    }

    /// Dials the outbound leg for a decided flow.
    pub async fn dial(&self, flow: &Accepted, verdict: Verdict) -> Result<Upstream, RelayError> {
        self.dial_with_authority(flow, verdict, None).await
    }

    /// Dials the outbound leg, overriding authority when unwrapping Fake-IP.
    async fn dial_with_authority(
        &self,
        flow: &Accepted,
        verdict: Verdict,
        domain_override: Option<&str>,
    ) -> Result<Upstream, RelayError> {
        let outbound = &verdict.outbound;
        // One structured event per decision: the first thing anyone needs when
        // asking "why did *this* connection go there?".
        daer_observe::debug!(daer_observe::EventCode::FlowDecided,
            flow_id = %flow.flow_id,
            generation = %self.generation,
            source = %flow.source,
            destination = %flow.destination,
            rule = %verdict.describe(),
            outbound = %outbound.name,
            mark = outbound.mark,
            must = outbound.must,
            "flow decided"
        );

        if outbound.kind == OutboundKind::Block {
            return Err(RelayError::Rejected(daer_relay::Reject::Blocked {
                destination: flow.destination,
            }));
        }

        if outbound.kind == OutboundKind::Direct {
            let direct_authority = flow.destination.to_string();
            let established = self
                .direct
                .connect(&direct_authority)
                .await
                .map_err(|error| {
                    let failure: daer_observe::DialFailure = error.into();
                    daer_observe::warn!(
                        daer_observe::EventCode::FlowDialFailed,
                        flow_id = %flow.flow_id,
                        destination = %flow.destination,
                        election = "direct",
                        stage = %failure.stage,
                        error_code = %failure.code,
                        "flow dial failed"
                    );
                    RelayError::Dial {
                        destination: flow.destination,
                        failure,
                    }
                })?;
            return Ok(established.stream);
        }

        let authority = if let Some(domain) = domain_override {
            format!("{domain}:{}", flow.destination.port())
        } else {
            flow.destination.to_string()
        };

        let established = self
            .connect_through_election(flow.flow_id, flow.destination, &outbound.name, &authority)
            .await?;
        Ok(established.stream)
    }

    /// Opens a TCP leg through `election`, holding the election lock only for the
    /// selection.
    async fn connect_through_election(
        &self,
        flow_id: daer_observe::FlowId,
        destination: SocketAddr,
        election: &str,
        authority: &str,
    ) -> Result<daer_outbound::Established, RelayError> {
        let node = self.select_node(flow_id, destination, election)?;
        let observed = daer_outbound::ObservedDialer::new(
            Arc::clone(&node),
            self.dial_observer.clone(),
            flow_id,
            election,
        );
        observed
            .connect(authority)
            .await
            .map_err(|error| RelayError::Dial {
                destination,
                failure: error.into(),
            })
    }

    /// Selects the node an election would return for `destination`.
    ///
    /// The read lock is taken and released inside this function: selection is a pure
    /// read of measured state, and holding the guard across a dial would make every flow's
    /// future non-`Send`.
    fn select_node(
        &self,
        flow_id: daer_observe::FlowId,
        destination: SocketAddr,
        election: &str,
    ) -> Result<Arc<NodeDialer>, RelayError> {
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        let Some(route) = elections.get(election) else {
            return Err(dial_error(
                flow_id,
                destination,
                election,
                OutboundError::UnknownElection(election.to_owned()),
            ));
        };
        let dialer = route
            .effective(&self.overrides, election)
            .and_then(|id| route.runtime.dialer(id))
            .ok_or_else(|| {
                dial_error(
                    flow_id,
                    destination,
                    election,
                    OutboundError::NoElectableNode(election.to_owned()),
                )
            })?;
        let node = route.node(dialer.id()).map(Arc::clone).ok_or_else(|| {
            dial_error(
                flow_id,
                destination,
                election,
                OutboundError::NoElectableNode(election.to_owned()),
            )
        })?;
        let property = dialer.property();
        daer_observe::trace!(
            daer_observe::EventCode::FlowNodeSelected,
            flow_id = %flow_id,
            election = %election,
            node = %property.name,
            protocol = %property.protocol.as_str(),
            kind = ?route.kind,
            latency_us = ?dialer.last_latency().map(|latency| latency.as_nanos() / 1_000),
            "node selected"
        );
        Ok(node)
    }

    /// The routing verdict for a datagram flow, without dialing.
    ///
    /// Takes [`FlowFacts`] and the optional domain acquired by [`crate::domain`].
    #[must_use]
    pub fn verdict_for_datagram(&self, facts: FlowFacts, domain: Option<&str>) -> Verdict {
        self.verdict_with_kernel(
            facts.source,
            facts.destination,
            domain,
            L4ProtoMask::UDP,
            self.observe(facts.source, facts.destination, IPPROTO_UDP),
        )
    }

    /// The authority a datagram flow should be dialed to.
    ///
    /// # Why the datagram half needs this and TCP could do without it
    ///
    /// TCP's [`Router::resolve`] walks the same sources of a name — Fake-IP, a unique
    /// DNS-snooper candidate, then the explicit `[routing.sniff]` fallback — and passes the
    /// winner to [`Router::dial_with_authority`]. The datagram relay used to skip all of it and dial
    /// `original_destination`, which is correct only when the destination is a real
    /// address. With Fake-IP enabled the destination is a synthetic `198.18.0.0/15`
    /// address, so dialing it sends the flow to a host that does not exist; with DNS
    /// snooping the name is known and dialing the IP silently discards it, which breaks
    /// every `domain(...)` rule for UDP and makes the flow's own SNI/Host irrelevant to
    /// where it goes.
    ///
    /// The `direct` outbound keeps dialing the literal address: a direct flow is a flow
    /// whose destination is authoritative, and turning a known domain into a direct dial
    /// by name would re-resolve through a resolver the user did not ask for.
    #[must_use]
    pub fn dial_target(&self, facts: FlowFacts, domain: Option<&str>) -> String {
        let verdict = self.verdict_for_datagram(facts, domain);
        if verdict.outbound.kind == OutboundKind::Direct {
            return facts.destination.to_string();
        }
        match domain {
            Some(name) => format!("{name}:{}", facts.destination.port()),
            None => facts.destination.to_string(),
        }
    }

    /// Opens a datagram leg from the flow's first payload.
    ///
    /// This is the one entry point the relay calls. Name acquisition, including the
    /// bounded first-datagram parse, happens here rather than in the transport.
    ///
    /// # Errors
    ///
    /// Same as [`Router::open_datagram`].
    pub async fn open_datagram_with_payload(
        &self,
        facts: FlowFacts,
        payload: &[u8],
    ) -> Result<DatagramLeg, RelayError> {
        let outcome = self
            .domain
            .resolve_datagram(facts.source, facts.destination, payload);
        self.log_domain(&facts.flow_id, facts.destination, &outcome);
        let verdict = self.verdict_for_datagram(facts, outcome.domain());
        self.open_datagram(facts, &verdict, outcome.domain()).await
    }

    /// Opens the datagram leg for a decided flow.
    ///
    /// The outbound leg is a [`DatagramConnector`], so this mirrors
    /// [`Router::dial`] one-for-one: the same `block` rejection, the same
    /// `direct` shortcut, the same group selection. The leg is returned as a
    /// trait object because the caller multiplexes several peer sessions over it
    /// and does not care which transport produced each one.
    ///
    /// # Errors
    ///
    /// [`Reject::Blocked`] when a rule matched `block`, and [`RelayError::Dial`]
    /// when the outbound cannot be resolved or the session cannot be opened.
    pub async fn open_datagram(
        &self,
        facts: FlowFacts,
        verdict: &Verdict,
        domain: Option<&str>,
    ) -> Result<DatagramLeg, RelayError> {
        let outbound = &verdict.outbound;
        daer_observe::debug!(daer_observe::EventCode::FlowDatagramDecided,
            flow_id = %facts.flow_id,
            generation = %self.generation,
            source = %facts.source,
            destination = %facts.destination,
            rule = %verdict.describe(),
            outbound = %outbound.name,
            mark = outbound.mark,
            must = outbound.must,
            "datagram flow decided"
        );

        if outbound.kind == OutboundKind::Block {
            return Err(RelayError::Rejected(daer_relay::Reject::Blocked {
                destination: facts.destination,
            }));
        }

        // The target is *this* decision's answer and is returned with the connector. The
        // relay must not ask again: a reload between two calls would let the flow be dialed
        // to a target the rule that opened the leg never chose.
        let target = self.dial_target(facts, domain);

        if outbound.kind == OutboundKind::Direct {
            // The mark is already baked into `datagram_direct` when the generation
            // was built, so a per-flow copy would only add a rebuild.
            return Ok(DatagramLeg {
                target,
                connector: Arc::new(self.datagram_direct.clone()),
            });
        }

        let group_name = outbound.name.clone();
        let node = self.select_node(facts.flow_id, facts.destination, &group_name)?;

        let connector = node.datagram().ok_or_else(|| {
            dial_error(
                facts.flow_id,
                facts.destination,
                &group_name,
                OutboundError::NoDatagramSupport(group_name.to_string()),
            )
        })?;
        Ok(DatagramLeg { target, connector })
    }

    /// What an election would return right now, for diagnostics.
    #[must_use]
    pub fn node_identity(&self, election: &str) -> Option<NodeIdentity> {
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        let route = elections.get(election)?;
        let id = route.effective(&self.overrides, election)?;
        let dialer = route.runtime.dialer(id)?;
        let node = route.node(id)?;
        let property = dialer.property();
        let health = route.runtime.is_alive(id).map(|alive| ElectionHealth {
            alive,
            latency_us: dialer
                .last_latency()
                .and_then(|latency| u64::try_from(latency.as_nanos() / 1_000).ok()),
        });
        Some(NodeIdentity {
            group: route
                .input
                .strip_prefix("group:")
                .unwrap_or_default()
                .to_owned(),
            election: election.to_owned(),
            node: property.name.clone(),
            protocol: property.protocol.clone(),
            security: property.security.clone(),
            udp: property.udp,
            subscription_name: property.subscription_name.clone(),
            detour: node.detour().map(|inner| inner.label().to_owned()),
            elected_by: Some(election.to_owned()),
            health,
        })
    }

    /// Every node resource, grouped by resource pool, for a listing.
    ///
    /// The catalog is built once; this method overlays the current election result so a
    /// `status --nodes` row says which election elects it and how its last probe went.
    #[must_use]
    pub fn nodes(&self) -> Vec<NodeIdentity> {
        let mut rows = self.node_catalog.clone();
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<&String> = elections.keys().collect();
        names.sort();
        for name in names {
            let Some(route) = elections.get(name) else {
                continue;
            };
            let Some(id) = route.effective(&self.overrides, name) else {
                continue;
            };
            let Some(dialer) = route.runtime.dialer(id) else {
                continue;
            };
            let node = &dialer.property().name;
            let health = route.runtime.is_alive(id).map(|alive| ElectionHealth {
                alive,
                latency_us: dialer
                    .last_latency()
                    .and_then(|latency| u64::try_from(latency.as_nanos() / 1_000).ok()),
            });
            for row in &mut rows {
                if &row.node == node && row.elected_by.is_none() {
                    row.elected_by = Some((*name).clone());
                    row.health = health.clone();
                }
            }
        }
        rows
    }

    /// Every resource pool and the elections that consume it.
    #[must_use]
    pub fn groups(&self) -> Vec<GroupIdentity> {
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        let mut names: Vec<&String> = self.groups.keys().collect();
        names.sort();
        for name in names {
            let Some(group) = self.groups.get(name) else {
                continue;
            };
            let candidates = group
                .members
                .iter()
                .filter_map(|(index, _)| self.node_names.get(*index).cloned())
                .collect();
            let mut consumers: Vec<String> = elections
                .iter()
                .filter(|(_, route)| route.input == format!("group:{name}"))
                .map(|(election, _)| election.clone())
                .collect();
            consumers.sort();
            out.push(GroupIdentity {
                name: name.clone(),
                candidates,
                elections: consumers,
            });
        }
        out
    }

    /// Every election, its input and its current result.
    #[must_use]
    pub fn elections(&self) -> Vec<ElectionIdentity> {
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for (name, route) in elections.iter() {
            let pinned = self.overrides.get(name);
            let effective_id = route.effective(&self.overrides, name);
            let dialer = effective_id.and_then(|id| route.runtime.dialer(id));
            let effective = dialer.map(|dialer| dialer.property().name.clone());
            let health = effective_id.and_then(|id| {
                route.runtime.is_alive(id).map(|alive| ElectionHealth {
                    alive,
                    latency_us: route
                        .runtime
                        .dialer(id)
                        .and_then(|dialer| dialer.last_latency())
                        .and_then(|latency| u64::try_from(latency.as_nanos() / 1_000).ok()),
                })
            });
            out.push(ElectionIdentity {
                name: name.clone(),
                input: route.input.clone(),
                kind: route.kind,
                probe: if route.kind == ElectionKind::Manual {
                    None
                } else {
                    Some(route.probe.clone())
                },
                candidates: route.runtime.len(),
                pinned,
                effective,
                health,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Explains the decision for a flow, without dialing.
    ///
    /// Includes the rule as written, because an operator reading
    /// `daer route explain` needs to see the configuration that fired, not an
    /// internal index they then have to look up.
    #[must_use]
    pub fn explain(&self, source: SocketAddr, destination: SocketAddr) -> Explanation {
        self.explain_with_domain(source, destination, None)
    }

    /// Explains the decision for a flow, with an acquired domain.
    ///
    /// # What this cannot see, and why that is correct
    ///
    /// The flow path uses [`Self::verdict_for_flow`], which asks the datapath for the source
    /// MAC, DSCP, and process name it observed. `explain` has no flow and therefore no map key,
    /// so it evaluates with [`KernelFacts::default`]: a `mac(...)`, `dscp(...)`, or `pname(...)`
    /// rule does **not** match here.
    ///
    /// That asymmetry is the honest answer rather than a bug: "what would the rules say about a
    /// hypothetical flow from A to B" and "what did the kernel see for this flow" are different
    /// questions, and inventing a MAC for the first would make the diagnostic claim a fact it
    /// does not have. The rule that a fact nobody observed cannot match is what
    /// `[INV-KERNEL-FACTS-01]` states.
    #[must_use]
    pub fn explain_with_domain(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        domain: Option<&str>,
    ) -> Explanation {
        let verdict = self.verdict_with_domain(source, destination, domain);
        let (rule_name, rule_text) = match verdict.rule {
            Some(index) => self.program.rules.get(index).map_or_else(
                || (None, "<rule index out of range>".to_owned()),
                |rule| (Some(rule.name.clone()), rule.to_string()),
            ),
            None => (None, format!("fallback -> {}", self.fallback)),
        };
        let locked = self.elections.read().unwrap_or_else(|e| e.into_inner());
        let mut elections: Vec<String> = locked.keys().cloned().collect();
        elections.sort();
        let selected = self.node_identity(&verdict.outbound.name);
        Explanation {
            source,
            destination,
            generation: self.generation,
            rule: verdict.rule,
            rule_name,
            rule_text,
            outbound: verdict.outbound,
            elections,
            trace: self.trace_with_domain(source, destination, domain),
            selected,
        }
    }

    /// Why each rule did or did not fire for a flow.
    ///
    /// The same evaluation as [`Router::verdict_for`], replayed with per-predicate
    /// detail. It is a separate call because the hot path must not pay for it.
    ///
    /// The returned [`Trace`] carries the **effective** outbound: when no rule matched,
    /// `outbound` is the configuration's fallback and `decided_by` is `None`. That is
    /// what makes the trace and the verdict two views of one answer instead of two
    /// answers — the invariant `trace.outbound == verdict.outbound` holds always, and is
    /// asserted by tests.
    #[must_use]
    pub fn trace(&self, source: SocketAddr, destination: SocketAddr) -> Trace {
        self.trace_with_domain(source, destination, None)
    }

    /// Why each rule did or did not fire, for a flow with an acquired domain.
    #[must_use]
    pub fn trace_with_domain(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        domain: Option<&str>,
    ) -> Trace {
        let facts = facts_with_kernel(
            source,
            destination,
            domain,
            L4ProtoMask::TCP,
            KernelFacts::default(),
        );
        let mut trace = daer_routing::explain(&self.matches, &facts);
        trace.outbound.get_or_insert_with(|| self.fallback.clone());
        trace
    }

    /// The routing verdict for a pair of addresses.
    ///
    /// Separate from [`Router::verdict`] so the decision can be reasoned about — and
    /// tested — without a socket in hand. This is the function to call from a
    /// diagnostic tool: "what would daer do with this flow?" has an answer.
    #[must_use]
    pub fn verdict_for(&self, source: SocketAddr, destination: SocketAddr) -> Verdict {
        self.verdict_with_domain(source, destination, None)
    }

    /// The routing verdict for a flow, with an acquired domain.
    ///
    /// A domain-sensitive rule (`domain(… )`) only fires through this entry point;
    /// [`Router::verdict_for`] supplies `None` and therefore cannot match one. That is the
    /// same property the data path relies on.
    #[must_use]
    pub fn verdict_with_domain(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        domain: Option<&str>,
    ) -> Verdict {
        self.verdict_with_protocol(source, destination, domain, L4ProtoMask::TCP)
    }

    /// The routing verdict for a TCP flow, asking the datapath what it observed.
    ///
    /// This is the form the flow path uses. [`Self::verdict_with_domain`] stays for the
    /// diagnostic entry points, which have no socket and therefore no map key: a rule needing
    /// a MAC or a process name correctly fails to match there, because `daer route explain`
    /// cannot claim to know what the kernel saw for a flow that does not exist.
    #[must_use]
    pub fn verdict_for_flow(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        domain: Option<&str>,
    ) -> Verdict {
        self.verdict_with_kernel(
            source,
            destination,
            domain,
            L4ProtoMask::TCP,
            self.observe(source, destination, IPPROTO_TCP),
        )
    }

    /// What the datapath observed for a flow, or the honest default.
    fn observe(&self, source: SocketAddr, destination: SocketAddr, l4proto: u8) -> KernelFacts {
        self.kernel_observer
            .as_ref()
            .and_then(|observer| observer.observe(source, destination, l4proto))
            .unwrap_or_default()
    }

    /// The routing verdict for one L4 protocol, with an acquired domain.
    ///
    /// The protocol is a parameter rather than a constant because `l4proto(tcp)` and
    /// `l4proto(udp)` are ordinary rule terms: matching a datagram flow as TCP would
    /// silently send it to the wrong outbound, which is worse than not matching.
    #[must_use]
    pub fn verdict_with_protocol(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        domain: Option<&str>,
        l4proto: L4ProtoMask,
    ) -> Verdict {
        self.verdict_with_kernel(source, destination, domain, l4proto, KernelFacts::default())
    }

    /// The routing verdict, with the facts only the datapath could observe.
    ///
    /// # Why the extra argument exists
    ///
    /// A redirected flow reaches userspace through an accepted socket, which carries the
    /// client address and the original destination and nothing else. The source **MAC**, the
    /// **DSCP**, and the **process name** are gone by then. The kernel writes them into
    /// `routing_handoff_map` before it defers the flow (ADR-0011), so a caller that has the
    /// datapath can pass them here; a caller that does not passes the default and gets
    /// address-and-domain matching, which is what it can prove.
    ///
    /// Leaving them out is not a cosmetic loss: a `mac(...)`, `dscp(...)`, or `pname(...)`
    /// rule compiled into the userspace half matched nothing, so a configuration that read as
    /// "this app goes direct" silently proxied it instead.
    #[must_use]
    pub fn verdict_with_kernel(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        domain: Option<&str>,
        l4proto: L4ProtoMask,
        kernel: KernelFacts,
    ) -> Verdict {
        let facts = facts_with_kernel(source, destination, domain, l4proto, kernel);
        first_hit(&self.matches, &facts).map_or_else(
            || Verdict {
                outbound: self.fallback.clone(),
                rule: None,
            },
            |hit| Verdict {
                outbound: hit.outbound,
                rule: Some(hit.rule),
            },
        )
    }

    /// Every election's candidates, in the shape a health probe needs.
    ///
    /// Returns owned rows rather than borrows: the caller probes across `await`s, and the
    /// election lock must be released before that. A manual election is excluded because it
    /// does not rank candidates; `daer probe` is the on-demand path for a pinned node.
    #[must_use]
    pub fn elections_for_probes(&self) -> Vec<(String, Vec<ProbeRow>)> {
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(elections.len());
        for (name, route) in elections.iter() {
            if route.kind == ElectionKind::Manual {
                continue;
            }
            let mut rows = Vec::new();
            for dialer in route.runtime.dialers() {
                let property = dialer.property();
                let Some(node) = route.node(dialer.id()) else {
                    continue;
                };
                rows.push(ProbeRow {
                    dialer: dialer.id(),
                    name: property.name.clone(),
                    protocol: property.protocol.clone(),
                    address: literal_address(&property.address),
                    udp: property.udp,
                    node: Arc::clone(node),
                    probe: route.probe.clone(),
                });
            }
            out.push((name.clone(), rows));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Whether `election` would return a node right now.
    #[must_use]
    pub fn has_selection(&self, election: &str) -> bool {
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        elections
            .get(election)
            .is_some_and(|route| route.effective(&self.overrides, election).is_some())
    }

    /// Records a probe result for one candidate of one election.
    ///
    /// # Errors
    ///
    /// Returns an error when the election or dialer is unknown to this generation.
    pub fn record(
        &self,
        election: &str,
        dialer: DialerId,
        alive: bool,
        latency: Option<daer_config::TimeSpan>,
    ) -> Result<NotifyOutcome, OutboundError> {
        let mut elections = self.elections.write().unwrap_or_else(|e| e.into_inner());
        let Some(route) = elections.get_mut(election) else {
            return Err(OutboundError::UnknownElection(election.to_owned()));
        };
        route.runtime.record(dialer, alive, latency)
    }

    /// Pins `election` to `node` and persists the override.
    ///
    /// # Errors
    ///
    /// Returns a message when the election is unknown, the node is not one of its
    /// candidates, or the state file cannot be written. The running election is
    /// unchanged on every error.
    pub fn elect(&self, election: &str, node: &str) -> Result<(), String> {
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        let Some(route) = elections.get(election) else {
            return Err(format!("election {election:?} is not declared"));
        };
        if route.runtime.select_named(node).is_none() {
            return Err(format!(
                "node {node:?} is not a candidate of election {election:?}"
            ));
        }
        drop(elections);
        self.overrides.set(election, node)
    }

    /// Clears a runtime override; the election follows its configured rule again.
    pub fn reset_election(&self, election: &str) -> Result<(), String> {
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        if !elections.contains_key(election) {
            return Err(format!("election {election:?} is not declared"));
        }
        drop(elections);
        self.overrides.remove(election)
    }

    /// Drops overrides that this generation cannot honour and persists the result.
    pub fn reconcile_overrides(&self) {
        let elections = self.elections.read().unwrap_or_else(|e| e.into_inner());
        self.overrides.retain_valid(|election, node| {
            elections
                .get(election)
                .is_some_and(|route| route.runtime.select_named(node).is_some())
        });
    }
}

/// A row of the probe table: what a health check needs about one node.
#[derive(Debug, Clone)]
pub struct ProbeRow {
    pub dialer: DialerId,
    pub name: String,
    pub protocol: Protocol,
    pub address: Option<SocketAddr>,
    /// Whether the node can carry datagrams.
    pub udp: bool,
    /// The live dialer, so a detoured probe can open the chain to the node's server.
    pub node: Arc<NodeDialer>,
    /// The election's effective probe settings.
    pub probe: ProbeSettings,
}

/// Parses a node address as a literal `SocketAddr`, or `None` when it is a name.
///
/// A name is not resolved here on purpose: the probe must reach the same address the data
/// path would, and doing the resolution in the scheduler would be a second, silent DNS
/// decision.
fn literal_address(address: &str) -> Option<SocketAddr> {
    address.parse::<SocketAddr>().ok()
}

/// A resource pool: membership only, including pools no election consumes.
#[derive(Debug, Clone)]
struct GroupResource {
    /// Node indices plus the filter annotation's latency offset.
    members: Vec<(usize, daer_config::TimeSpan)>,
}

/// One election and the node dialers its result can name.
#[derive(Debug)]
struct ElectionRoute {
    runtime: ElectionRuntime,
    /// Indexed by [`DialerId`]: the same order as the candidate list.
    nodes: Vec<Arc<NodeDialer>>,
    input: String,
    kind: ElectionKind,
    probe: ProbeSettings,
}

impl ElectionRoute {
    fn node(&self, id: DialerId) -> Option<&Arc<NodeDialer>> {
        self.nodes.get(usize::try_from(id.0).ok()?)
    }

    fn effective(&self, overrides: &ElectionOverrides, election: &str) -> Option<DialerId> {
        if let Some(node) = overrides.get(election)
            && let Some(dialer) = self.runtime.select_named(&node)
        {
            return Some(dialer.id());
        }
        self.runtime.select(None).map(Dialer::id)
    }
}

/// What the datapath observed about a flow and userspace cannot.
///
/// # Why this is a distinct type rather than three more arguments
///
/// The three fields travel together, come from the same map entry, and are absent for the
/// same reason (no datapath, or the kernel decided the flow itself). Bundling them makes
/// "unknown" one value — [`KernelFacts::default`] — instead of three independent zeroes that
/// a caller could set inconsistently.
///
/// The default is the honest answer for a flow whose handoff entry was never written: a rule
/// that needs one of these facts must not match by accident.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelFacts {
    /// The client's source MAC, when the datapath saw the packet.
    pub mac: MacAddr,
    /// The packet's DSCP.
    pub dscp: u8,
    /// The process that opened the flow, when the cgroup hooks are attached.
    pub process_name: ProcessName,
}

impl KernelFacts {
    /// Builds the facts from a `routing_handoff_map` entry.
    ///
    /// A `pid` of `0` means the process was not observed for this flow (for example a
    /// LAN-client connection, which has no local process), and the C leaves `pname` empty
    /// in that case; the process name is then reported as unknown rather than as the empty
    /// string a rule could match.
    #[must_use]
    pub fn from_handoff(result: &daer_ebpf::abi::RoutingResult) -> Self {
        let process_name = if result.pid == 0 {
            ProcessName::from_bytes_truncated(b"")
        } else {
            ProcessName::from_bytes_truncated(&result.pname)
        };
        Self {
            mac: MacAddr(result.mac),
            dscp: result.dscp,
            process_name,
        }
    }
}

/// What a flow's kernel-side facts come from.
///
/// # Why a trait, and why on the router
///
/// `routing_handoff_map` is a BPF map: reading it needs `&mut Ebpf`, which the accept loop
/// cannot hold (it serves many flows concurrently and the map handle is not `Sync`). The
/// datapath handle therefore owns the map and exposes this narrow trait, and the router
/// holds an `Arc<dyn KernelObserver>`. A router built without a datapath — the diagnostics,
/// the tests, `--no-datapath` — has no observer and gets [`KernelFacts::default`], which is
/// exactly the behaviour it had before the map was read at all.
///
/// Implementations must be cheap and non-blocking: this runs once per flow, before the
/// routing decision.
pub trait KernelObserver: Send + Sync + std::fmt::Debug {
    /// The facts the datapath recorded for this flow, or `None` when it recorded none.
    fn observe(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        l4proto: u8,
    ) -> Option<KernelFacts>;
}

/// A [`KernelObserver`] over the datapath's handoff map.
///
/// The map is behind a `Mutex` because `aya`'s map lookup needs `&mut`. The lock is held for
/// one `bpf_map_lookup_elem` and never across an `await`, so a flow pays a uncontended mutex
/// plus one syscall — the same order as the `peek` the sniffer already does.
#[derive(Debug)]
pub struct HandoffObserver {
    ebpf: std::sync::Mutex<Option<aya::Ebpf>>,
}

impl HandoffObserver {
    /// Takes ownership of the loaded object.
    ///
    /// The object is *moved* here rather than borrowed: it is what keeps the programs
    /// attached, so its owner is the datapath handle, and the observer is the one part of
    /// that handle the flow path needs.
    #[must_use]
    pub fn new(ebpf: aya::Ebpf) -> Self {
        Self {
            ebpf: std::sync::Mutex::new(Some(ebpf)),
        }
    }

    /// Runs `f` with the object, for the code that republishes the policy on reload.
    ///
    /// # Errors
    ///
    /// Returns a message when the object has already been taken, which would be a shutdown
    /// race rather than a data-path condition.
    pub fn with_ebpf<T>(&self, f: impl FnOnce(&mut aya::Ebpf) -> T) -> Result<T, String> {
        let mut guard = self.ebpf.lock().unwrap_or_else(|e| e.into_inner());
        let ebpf = guard
            .as_mut()
            .ok_or_else(|| "the datapath object is no longer owned".to_owned())?;
        Ok(f(ebpf))
    }

    /// Detaches the object, returning it to the caller.
    pub fn take(&self) -> Option<aya::Ebpf> {
        self.ebpf.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

impl KernelObserver for HandoffObserver {
    fn observe(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        l4proto: u8,
    ) -> Option<KernelFacts> {
        let mut guard = self.ebpf.lock().unwrap_or_else(|e| e.into_inner());
        let ebpf = guard.as_mut()?;
        let key = daer_ebpf::abi::TuplesKey::of(source, destination, l4proto);
        let entry = daer_ebpf::Handoff::new(ebpf).lookup(key)?;
        Some(KernelFacts::from_handoff(&entry.result))
    }
}

/// Facts for a flow, with whatever the datapath observed.
///
/// The domain is supplied by the acquisition policy — an absent domain is the honest
/// default, because a guessed one would route traffic through the wrong outbound. The
/// kernel-supplied fields come from [`KernelFacts`], which is the default (all unknown) for
/// a flow the kernel never handed off.
///
/// One construction for both callers — the hot path, which may have acquired a name and may have a
/// handoff entry, and the diagnostic entry points, which have neither — so the two cannot
/// drift.
fn facts_with_kernel<'a>(
    source: SocketAddr,
    destination: SocketAddr,
    domain: Option<&'a str>,
    l4proto: L4ProtoMask,
    kernel: KernelFacts,
) -> MatchFacts<'a> {
    MatchFacts {
        source_addr: source.ip(),
        dest_addr: destination.ip(),
        source_port: source.port(),
        dest_port: destination.port(),
        l4proto,
        domain,
        process_name: kernel.process_name,
        dscp: kernel.dscp,
        mac: kernel.mac,
    }
}

/// Dial timeout for the outbound leg.
///
/// Conservative and fixed for now: the per-group `check-interval` governs probes,
/// not dials, and a dial that hangs must not hold an ingress slot forever.
const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// The cumulative match-set count after each rule.
///
/// One set per `(function, parameter key)` group, which is exactly what
/// [`daer_routing::RulesBuilder::apply`] emits: it walks functions, then the parameter groups of
/// each. Recomputing the shape here is what lets a rule index be attributed without the lowering
/// having to carry it — and a divergence would be caught by
/// `crates/daer-routing/tests/kernel_policy.rs`, which builds the same map independently.
fn rule_boundaries(rules: &[daer_config::RoutingRule]) -> Vec<usize> {
    let mut boundaries = Vec::with_capacity(rules.len());
    let mut accumulated = 0usize;
    for rule in rules {
        for function in &rule.match_expr.and_functions {
            let mut keys: Vec<&str> = Vec::new();
            for param in &function.params {
                if !keys.contains(&param.key.as_str()) {
                    keys.push(param.key.as_str());
                }
            }
            accumulated += keys.len().max(1);
        }
        boundaries.push(accumulated);
    }
    boundaries
}

/// Builds a relay dial error and emits the one `warn` event that names its stage and code.
fn dial_error(
    flow_id: daer_observe::FlowId,
    destination: SocketAddr,
    election: &str,
    error: OutboundError,
) -> RelayError {
    let failure: daer_observe::DialFailure = error.into();
    daer_observe::warn!(
        daer_observe::EventCode::FlowDialFailed,
        flow_id = %flow_id,
        destination = %destination,
        election = %election,
        stage = %failure.stage,
        error_code = %failure.code,
        "flow dial failed"
    );
    RelayError::Dial {
        destination,
        failure,
    }
}

/// Builds the diagnostic node catalog: every node, once per resource pool it is in.
///
/// A declared node that no group selects is still a resource and appears with an empty
/// group; otherwise `daer check --nodes` / `daer status --nodes` would hide exactly the
/// node an operator is trying to understand.
fn node_catalog(config: &Config, groups: &HashMap<String, GroupResource>) -> Vec<NodeIdentity> {
    let mut rows = Vec::new();
    let mut grouped = vec![false; config.node.len()];
    let mut names: Vec<&String> = groups.keys().collect();
    names.sort();
    for name in names {
        let Some(group) = groups.get(name) else {
            continue;
        };
        for (index, _) in &group.members {
            let Some(node) = config.node.get(*index) else {
                continue;
            };
            grouped[*index] = true;
            let property = Property::from_node(node);
            rows.push(NodeIdentity {
                group: name.clone(),
                election: String::new(),
                node: property.name,
                protocol: property.protocol,
                security: property.security,
                udp: property.udp,
                subscription_name: property.subscription_name,
                detour: node.detour.clone(),
                elected_by: None,
                health: None,
            });
        }
    }
    for (index, node) in config.node.iter().enumerate() {
        if grouped[index] {
            continue;
        }
        let property = Property::from_node(node);
        rows.push(NodeIdentity {
            group: String::new(),
            election: String::new(),
            node: property.name,
            protocol: property.protocol,
            security: property.security,
            udp: property.udp,
            subscription_name: property.subscription_name,
            detour: node.detour.clone(),
            elected_by: None,
            health: None,
        });
    }
    rows.sort_by(|a, b| (&a.group, &a.node).cmp(&(&b.group, &b.node)));
    rows
}

/// A resource pool keyed by name.
type ResourceMap = HashMap<String, GroupResource>;
/// An election keyed by its routing-target name.
type ElectionMap = HashMap<String, ElectionRoute>;

fn build_resources_and_elections(
    config: &Config,
    dialer_options: &DialerOptions,
) -> Result<(ResourceMap, ElectionMap), RoutingError> {
    let mut graph = NodeGraph::new(&config.node, dialer_options.clone())
        .map_err(|error| RoutingError::new(error.to_string()))?;

    let mut node_by_name = HashMap::new();
    for (index, node) in config.node.iter().enumerate() {
        let property = Property::from_node(node);
        if property.name.trim().is_empty() {
            return Err(RoutingError::new(format!(
                "node at index {index} has no name; an election cannot reference it"
            )));
        }
        if node_by_name.insert(property.name.clone(), index).is_some() {
            return Err(RoutingError::new(format!(
                "duplicate node name {:?}",
                property.name
            )));
        }
    }

    let mut groups = HashMap::new();
    for group in &config.group {
        let filters = FilterSet::compile(
            &group
                .filters
                .iter()
                .map(|filter| filter.functions.clone())
                .collect::<Vec<_>>(),
            &group
                .filters
                .iter()
                .map(|filter| filter.annotate.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(|error| RoutingError::new(format!("group {:?}: {error}", group.name)))?;

        let mut members = Vec::new();
        for (index, node) in config.node.iter().enumerate() {
            let property = Property::from_node(node);
            let Some(annotation) = filters.matches(&property.name, &property.subscription_name)
            else {
                continue;
            };
            members.push((index, annotation.add_latency));
        }
        groups.insert(group.name.clone(), GroupResource { members });
    }

    let mut elections = HashMap::new();
    for election in &config.election {
        let (members, input): (Vec<(usize, daer_config::TimeSpan)>, String) =
            if let Some(group_name) = &election.group {
                let Some(group) = groups.get(group_name) else {
                    return Err(RoutingError::new(format!(
                        "election {:?} names unknown group {group_name:?}",
                        election.name
                    )));
                };
                (group.members.clone(), format!("group:{group_name}"))
            } else if let Some(node_name) = &election.node {
                let Some(index) = node_by_name.get(node_name).copied() else {
                    return Err(RoutingError::new(format!(
                        "election {:?} names unknown node {node_name:?}",
                        election.name
                    )));
                };
                (
                    vec![(index, daer_config::TimeSpan::ZERO)],
                    format!("node:{node_name}"),
                )
            } else {
                return Err(RoutingError::new(format!(
                    "election {:?} has no group or node input",
                    election.name
                )));
            };

        let mut dialers = Vec::new();
        let mut nodes = Vec::new();
        for (index, offset) in members {
            let node = &config.node[index];
            let property = Property::from_node(node);
            let node_dialer = match graph.build(index) {
                Ok(dialer) => dialer,
                Err(OutboundError::UnsupportedLink(message)) if election.group.is_some() => {
                    daer_observe::warn!(daer_observe::EventCode::GenerationNodeUnselectable,
                        node = %property.name,
                        protocol = %property.protocol.as_str(),
                        %message,
                        "node protocol is not implemented by this build; the node is listed \
                         but cannot be selected"
                    );
                    continue;
                }
                Err(error) => {
                    return Err(RoutingError::new(format!(
                        "election {:?}: node {:?}: {error}",
                        election.name, property.name
                    )));
                }
            };
            let id = DialerId(dialers.len() as u64);
            nodes.push(node_dialer);
            dialers.push(Dialer::new(id, property, offset));
        }

        let probe = election.resolved_probe();
        let runtime = ElectionRuntime::new(
            election.name.clone(),
            election.kind.selection_policy(),
            election.effective_tolerance(),
            dialers,
        );
        elections.insert(
            election.name.clone(),
            ElectionRoute {
                runtime,
                nodes,
                input,
                kind: election.kind,
                probe,
            },
        );
    }

    Ok((groups, elections))
}

impl daer_relay::Decide for Router {
    type Upstream = Upstream;
    type Future<'a>
        = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Upstream, RelayError>> + Send + 'a>,
    >
    where
        Self: 'a;

    fn decide<'a>(&'a self, flow: &'a Accepted) -> Self::Future<'a> {
        Box::pin(self.resolve(flow))
    }
}

#[cfg(test)]
mod tests;
