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
//!   group  ──▶ DialerGroup::select ──▶ NodeDialer for the chosen node
//!         │
//!         ▼  Upstream stream, handed back to the relay
//! ```
//!
//! # What a TCP flow knows, and what it does not
//!
//! A redirected TCP flow gives the matcher four things: source address, source
//! port, destination address and destination port, plus `TCP`. Everything else —
//! the sniffed domain, the client's process name, the DSCP field, the source MAC —
//! lives in the kernel's connection state and is not available to the ingress path
//! yet. Those facts are supplied as "unknown" (`None`/zero) rather than guessed, so
//! a rule that depends on them cannot match by accident. Sniffing
//! (`daer-sniff`) and the state map are what will fill them in.
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
use std::sync::Arc;
use std::time::Duration;

use daer_common::net::MacAddr;
use daer_config::{Config, FunctionOrString};
use daer_outbound::{
    DatagramConnector, Dialer, DialerGroup, DialerId, DialerOptions, DirectDialer, FilterSet,
    NodeDialer, NotifyOutcome, OutboundError, Property, Protocol, Security, UdpConnector, Upstream,
    parse_group_policy,
};

use daer_routing::{
    AliasOptimizer, DatReaderOptimizer, DeduplicateParamsOptimizer, MatchFacts, MatchSet,
    MergeAndSortOptimizer, NormalizedProgram, Outbound, RecordingSink, RoutingError, RulesBuilder,
    Trace, first_hit, is_builtin_outbound, parse_outbound,
};
use daer_routing::{L4ProtoMask, ProcessName};

use crate::error::IngressError;
use crate::generation::GenerationId;
use crate::inbound::{Accepted, FlowFacts};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub group: String,
    pub node: String,
    pub protocol: Protocol,
    pub security: Security,
    /// Whether the node is used for UDP as well as TCP.
    pub udp: bool,
    pub subscription_tag: String,
}

impl NodeIdentity {
    /// A one-line description, safe to log: it names the cipher or the TLS name, never a secret.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{}: {} [{} | {}]{}{}",
            self.group,
            self.node,
            self.protocol.as_str(),
            self.security.describe(),
            if self.udp { " udp" } else { "" },
            if self.subscription_tag.is_empty() {
                String::new()
            } else {
                format!(" subtag={}", self.subscription_tag)
            }
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
    /// The rule as the engine evaluated it.
    ///
    /// Normalized, not verbatim: the optimizer rewrites `dport` to `port`, sorts
    /// parameters and merges adjacent rules, so this is the text that actually
    /// fired. Reporting the raw input instead would risk showing a rule the engine
    /// never evaluated.
    pub rule_text: String,
    pub outbound: Outbound,
    /// Outbounds the flow could have gone to, for a rule that did not match.
    pub groups: Vec<String>,
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
        if &*self.outbound.name == "block" {
            return false;
        }
        // `direct` and any built-in outbound are always actionable; only a group has
        // to have a node.
        if daer_routing::is_builtin_outbound(&self.outbound.name) {
            return true;
        }
        // A group the explanation lists but for which no node was selected is
        // empty after filtering (or entirely dead).
        self.selected.is_some()
    }
}

impl fmt::Display for Explanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} → {}  [{}]",
            self.source, self.destination, self.generation
        )?;
        writeln!(f, "  decided by : {}", self.rule_text)?;
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
    /// Where to look for `geoip.dat` / `geosite.dat`.
    ///
    /// The configuration's own directory comes first, because that is where an
    /// operator keeps its assets; the standard system directories are appended by
    /// [`RouterOptions::with_assets_beside`].
    pub geodata_dirs: Vec<std::path::PathBuf>,
    /// The socket mark to put on daer's own outbound sockets, overriding `global.so-mark`.
    ///
    /// # Why an override exists at all
    ///
    /// `SO_MARK` needs `CAP_NET_ADMIN`, so a configuration alone cannot decide it: an
    /// unprivileged run (`--no-datapath`, a container probe, the test suite) must dial without
    /// a mark or every dial fails, and a privileged run **must** dial with one or the proxy
    /// captures its own traffic.
    ///
    /// That is not a hypothetical. With the mark absent, `daer`'s own connection to an origin
    /// matches the same `tproxy` rule as a client's, is redirected back into the listener, and
    /// the result is an unbounded loop: the end-to-end test observed **17,134** accepted flows
    /// for a single client request before this override existed. The process knows which case it
    /// is in (it either attached a datapath or it did not), so it decides once, here, and the
    /// generation carries the answer.
    pub so_mark: Option<Option<u32>>,
}

impl RouterOptions {
    /// Looks for geodata beside `config` first, then in the standard directories.
    #[must_use]
    pub fn with_assets_beside(config: impl AsRef<std::path::Path>) -> Self {
        let mut geodata_dirs = Vec::new();
        if let Some(directory) = config.as_ref().parent() {
            geodata_dirs.push(directory.to_path_buf());
        }
        Self {
            geodata_dirs,
            so_mark: None,
        }
    }

    /// Forces the socket mark daer's own dials carry.
    ///
    /// `Some(None)` disables marking explicitly (an unprivileged run); `Some(Some(mark))` forces
    /// one; `None` leaves it to `global.so-mark`.
    #[must_use]
    pub fn with_socket_mark(mut self, mark: Option<u32>) -> Self {
        self.so_mark = Some(mark);
        self
    }

    /// The mark this generation's dialers apply.
    fn effective_so_mark(&self, config: &Config) -> Option<u32> {
        self.so_mark.unwrap_or(config.global.so_mark)
    }
}

/// The routing program plus every outbound it can name.
#[derive(Debug)]
pub struct Router {
    /// Which generation this router serves. Every flow log carries it, so a log
    /// slice is self-explaining: which configuration made this decision.
    generation: GenerationId,
    /// How long to look for a name before routing by address.
    ///
    /// A zero budget disables sniffing entirely, which is what a configuration with no
    /// domain rules wants: it removes a syscall and a wait from every flow.
    sniffing_timeout: Duration,
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
    /// Groups live behind a lock, and only for one reason: a health check mutates a
    /// node's measured state while flows read it to select. The alternative — an
    /// `Arc<Router>` that can never record — would leave the probe results with nowhere
    /// to land, which is exactly the state this tree was in before the scheduler existed.
    ///
    /// The read path takes a shared lock for the duration of a selection, never across an
    /// await, so a flow still pays no lock on its data path.
    groups: std::sync::RwLock<HashMap<String, GroupRoute>>,
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
        // The dat reader is part of the pipeline, not an extra: `geoip:`/`geosite:`
        // appear in real rules, and omitting it would make those rules fail to
        // compile at run time while `daer config validate` accepted them.
        let dat_reader = DatReaderOptimizer::new(options.geodata_dirs.clone());
        let program = NormalizedProgram::new(
            &config.routing.rules,
            config.routing.fallback.clone(),
            &[
                &AliasOptimizer,
                &dat_reader,
                &MergeAndSortOptimizer,
                &DeduplicateParamsOptimizer,
            ],
        )?;

        // The mark daer's own dials carry. `RouterOptions` overrides the configuration because
        // `SO_MARK` needs `CAP_NET_ADMIN`: an unprivileged run must not mark, and a privileged
        // one must (see `RouterOptions::so_mark` for the loop it prevents).
        let so_mark = options.effective_so_mark(config);
        let dialer_options = {
            let options = DialerOptions::new(so_mark, DEFAULT_DIAL_TIMEOUT);
            // `global.tls.profile`: unknown names are a load-time error. A silently defaulted
            // profile is a ClientHello the operator did not choose, and the handshake that fails
            // because of it reports nothing that points at the profile.
            let options = match &config.global.tls.profile {
                Some(name) => options
                    .with_tls_profile(name)
                    .map_err(|error| RoutingError::new(error.to_string()))?,
                None => options,
            };
            // `[global.tls] fragment`: unknown or reversed ranges are a load-time error, because
            // an operator who asked for a shaped handshake must not silently get the default one.
            let fragment = daer_outbound::fragment::Fragment::from_config(&config.global.tls)
                .map_err(RoutingError::new)?;
            options.with_fragment(fragment)
        };
        // Sniffing is only worth its cost when a rule can use a name. Deciding that here,
        // once per generation, keeps the per-flow path free of the question.
        let needs_domain = program
            .rules
            .iter()
            .any(|rule| rule.and_functions.iter().any(|f| f.name == "domain"));
        // Sniffing is only worth its cost when a rule can use a name. `auto-sniff-punt` = false
        // means the operator wants the name only *after* the flow reaches userspace, never as a
        // reason to hold the flow up, so the budget becomes zero and routing falls back to the
        // address — which is what `global.auto-sniff-punt` documents.
        let sniffing_timeout = if needs_domain && config.global.auto_sniff_punt {
            Duration::from_nanos(
                u64::try_from(config.global.sniffing_timeout.as_nanos()).unwrap_or(0),
            )
        } else {
            Duration::ZERO
        };
        let groups = build_groups(config, &dialer_options)?;
        let known: Vec<String> = groups.keys().cloned().collect();

        let mut sink = RecordingSink::default();
        let mut fallback = None;
        {
            let mut builder = RulesBuilder::new(&mut sink);
            program.lower(&mut builder, |value| {
                let outbound = fallback_outbound(value)?;
                check_target(&outbound.name, &known)?;
                fallback = Some(outbound);
                Ok(())
            })?;
        }
        let fallback = fallback.ok_or_else(|| RoutingError::new("no routing fallback"))?;
        for warning in &sink.warnings {
            tracing::warn!(%warning, "routing rule compiled with a warning");
        }

        // Every rule target must resolve too, not just the fallback.
        for rule in &program.rules {
            let outbound = parse_outbound(&rule.outbound)?;
            check_target(&outbound.name, &known)?;
        }

        Ok(Self {
            generation,
            sniffing_timeout,
            program,
            matches: sink.matches,
            fallback,
            direct: DirectDialer::new(so_mark, DEFAULT_DIAL_TIMEOUT),
            datagram_direct: UdpConnector::new()
                .with_socket_config(
                    DialerOptions::new(so_mark, DEFAULT_DIAL_TIMEOUT).socket_config(),
                )
                .with_connect_timeout(Some(DEFAULT_DIAL_TIMEOUT)),
            groups: std::sync::RwLock::new(groups),
        })
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

    /// Resolves one flow.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError::Relay`] when the veredict is `block`, when the group
    /// has no selectable node, or when the dial fails. The flow is closed by the
    /// caller in every one of those cases.
    pub async fn resolve(&self, flow: &Accepted) -> Result<Upstream, IngressError> {
        // Sniff before deciding: the name is the only way a `domain(...)` rule can fire.
        // The stream is peeked, never consumed, so the origin still receives every byte.
        if !self.sniffing_timeout.is_zero() {
            let outcome = crate::sniff::sniff_stream(&flow.stream, self.sniffing_timeout).await;
            if outcome.is_named() {
                tracing::debug!(
                    generation = %self.generation,
                    destination = %flow.destination,
                    sniffed = %outcome.describe(),
                    "flow sniffed"
                );
            } else {
                tracing::trace!(
                    generation = %self.generation,
                    destination = %flow.destination,
                    reason = %outcome.describe(),
                    "flow not sniffed"
                );
            }
            // The name is borrowed from `outcome`, which lives to the end of this block;
            // the verdict is computed inside it so no borrow outlives the outcome.
            let verdict = self.verdict_with_domain(flow.source, flow.destination, outcome.name());
            return self.dial(flow, verdict).await;
        }

        let verdict = self.verdict(flow);
        self.dial(flow, verdict).await
    }

    /// Dials the outbound leg for a decided flow.
    async fn dial(&self, flow: &Accepted, verdict: Verdict) -> Result<Upstream, IngressError> {
        let outbound = &verdict.outbound;
        // One structured event per decision: the first thing anyone needs when
        // asking "why did *this* connection go there?".
        tracing::debug!(
            generation = %self.generation,
            source = %flow.source,
            destination = %flow.destination,
            rule = %verdict.describe(),
            outbound = %outbound.name,
            mark = outbound.mark,
            must = outbound.must,
            "flow decided"
        );

        if &*outbound.name == "block" {
            return Err(IngressError::Rejected(crate::error::Reject::Blocked {
                destination: flow.destination,
            }));
        }

        let authority = flow.destination.to_string();
        if &*outbound.name == "direct" {
            let established =
                self.direct
                    .connect(&authority)
                    .await
                    .map_err(|error| IngressError::Dial {
                        destination: flow.destination,
                        source: error,
                    })?;
            return Ok(established.stream);
        }

        let established = self
            .connect_through_group(flow.destination, &outbound.name, &authority)
            .await?;
        Ok(established.stream)
    }

    /// Opens a TCP leg through `group`, holding the group lock only for the selection.
    async fn connect_through_group(
        &self,
        destination: SocketAddr,
        group: &str,
        authority: &str,
    ) -> Result<daer_outbound::Established, IngressError> {
        let node = self.select_node(destination, group)?;
        node.connect(authority)
            .await
            .map_err(|error| IngressError::Dial {
                destination,
                source: error,
            })
    }

    /// Selects the node a group would use for `destination`.
    ///
    /// The read lock is taken and released inside this function: selection is a pure
    /// read of measured state, and holding the guard across a dial would make every flow's
    /// future non-`Send` (a `RwLockReadGuard` is not `Send`) — and would serialise every
    /// dial behind the health checker's writes.
    fn select_node(
        &self,
        destination: SocketAddr,
        group: &str,
    ) -> Result<Arc<NodeDialer>, IngressError> {
        let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
        let Some(route) = groups.get(group) else {
            return Err(IngressError::Dial {
                destination,
                source: OutboundError::UnknownGroup(group.to_owned()),
            });
        };
        let dialer = route.group.select(None).ok_or_else(|| IngressError::Dial {
            destination,
            source: OutboundError::NoAliveNode(group.to_owned()),
        })?;
        route
            .node(dialer.id())
            .map(Arc::clone)
            .ok_or_else(|| IngressError::Dial {
                destination,
                source: OutboundError::NoAliveNode(group.to_owned()),
            })
    }

    /// The routing verdict for a datagram flow, without dialing.
    ///
    /// Takes [`FlowFacts`] and an optional sniffed domain name (e.g. from QUIC).
    #[must_use]
    pub fn verdict_for_datagram(&self, facts: FlowFacts, domain: Option<&str>) -> Verdict {
        self.verdict_with_protocol(facts.source, facts.destination, domain, L4ProtoMask::UDP)
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
    /// [`Reject::Blocked`] when a rule matched `block`, and [`IngressError::Dial`]
    /// when the outbound cannot be resolved or the session cannot be opened.
    pub async fn open_datagram(
        &self,
        facts: FlowFacts,
        verdict: &Verdict,
    ) -> Result<Arc<dyn DatagramConnector>, IngressError> {
        let outbound = &verdict.outbound;
        tracing::debug!(
            generation = %self.generation,
            source = %facts.source,
            destination = %facts.destination,
            rule = %verdict.describe(),
            outbound = %outbound.name,
            mark = outbound.mark,
            must = outbound.must,
            "datagram flow decided"
        );

        if &*outbound.name == "block" {
            return Err(IngressError::Rejected(crate::error::Reject::Blocked {
                destination: facts.destination,
            }));
        }

        if &*outbound.name == "direct" {
            // The mark is already baked into `datagram_direct` when the generation
            // was built, so a per-flow copy would only add a rebuild.
            return Ok(Arc::new(self.datagram_direct.clone()));
        }

        let group_name = outbound.name.clone();
        let node = self.select_node(facts.destination, &group_name)?;

        node.datagram().ok_or(IngressError::Dial {
            destination: facts.destination,
            source: OutboundError::NoDatagramSupport(group_name.to_string()),
        })
    }

    /// The routing verdict for a flow, without dialing.
    ///
    /// Falls back to the configuration's fallback outbound when no rule matches.
    #[must_use]
    pub fn verdict(&self, flow: &Accepted) -> Verdict {
        self.verdict_for(flow.source, flow.destination)
    }

    /// What a group would select right now, for diagnostics.
    ///
    /// Reports the node's name, protocol and security identity. It answers "which node, and how
    /// is that session protected" without opening a connection, which is the question a bug
    /// report about a proxy actually asks.
    #[must_use]
    pub fn node_identity(&self, group: &str) -> Option<NodeIdentity> {
        let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
        let route = groups.get(group)?;
        let dialer = route.group.select(None)?;
        Some(NodeIdentity {
            group: group.to_owned(),
            node: dialer.property().name.clone(),
            protocol: dialer.property().protocol.clone(),
            security: dialer.property().security.clone(),
            udp: dialer.property().udp,
            subscription_tag: dialer.property().subscription_tag.clone(),
        })
    }

    /// Every node of every group, sorted, for a listing.
    #[must_use]
    pub fn nodes(&self) -> Vec<NodeIdentity> {
        let mut out = Vec::new();
        let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<&String> = groups.keys().collect();
        names.sort();
        for group in names {
            let Some(route) = groups.get(group) else {
                continue;
            };
            for dialer in route.group.dialers() {
                out.push(NodeIdentity {
                    group: group.clone(),
                    node: dialer.property().name.clone(),
                    protocol: dialer.property().protocol.clone(),
                    security: dialer.property().security.clone(),
                    udp: dialer.property().udp,
                    subscription_tag: dialer.property().subscription_tag.clone(),
                });
            }
        }
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

    /// Explains the decision for a flow, with a sniffed domain.
    #[must_use]
    pub fn explain_with_domain(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        domain: Option<&str>,
    ) -> Explanation {
        let verdict = self.verdict_with_domain(source, destination, domain);
        let rule_text = match verdict.rule {
            Some(index) => self.program.rules.get(index).map_or_else(
                || "<rule index out of range>".to_owned(),
                ToString::to_string,
            ),
            None => format!("fallback -> {}", self.fallback.name),
        };
        let locked = self.groups.read().unwrap_or_else(|e| e.into_inner());
        let mut groups: Vec<String> = locked.keys().cloned().collect();
        groups.sort();
        let selected = self.node_identity(&verdict.outbound.name);
        Explanation {
            source,
            destination,
            generation: self.generation,
            rule: verdict.rule,
            rule_text,
            outbound: verdict.outbound,
            groups,
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

    /// Why each rule did or did not fire, for a flow with a sniffed domain.
    #[must_use]
    pub fn trace_with_domain(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        domain: Option<&str>,
    ) -> Trace {
        let facts = facts_with_domain(source, destination, domain, L4ProtoMask::TCP);
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

    /// The routing verdict for a flow, with a sniffed domain.
    ///
    /// A domain-sensitive rule (`domain(suffix: …)`) only fires through this entry point;
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

    /// The routing verdict for one L4 protocol, with a sniffed domain.
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
        let facts = facts_with_domain(source, destination, domain, l4proto);
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

    /// Every group's nodes, in the shape a health probe needs.
    ///
    /// Returns owned rows rather than borrows: the caller probes across `await`s, and the
    /// group lock must be released before that. A domain-named node reports `None` for its
    /// address, because probing it would need its own resolution and a probe that resolved
    /// differently from the data path would measure the wrong destination.
    #[must_use]
    pub fn groups_for_probes(&self) -> Vec<(String, Vec<ProbeRow>)> {
        let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(groups.len());
        for (name, route) in groups.iter() {
            let mut rows = Vec::new();
            for dialer in route.group.dialers() {
                let property = dialer.property();
                rows.push((
                    dialer.id(),
                    property.name.clone(),
                    property.protocol.clone(),
                    literal_address(&property.address),
                    property.udp,
                ));
            }
            out.push((name.clone(), rows));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Whether `group` would select a node right now.
    ///
    /// The question a health scheduler is judged by: recording a latency must make a node
    /// selectable, and recording a failure must make it not.
    #[must_use]
    pub fn has_selection(&self, group: &str) -> bool {
        let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
        groups
            .get(group)
            .is_some_and(|route| route.group.select(None).is_some())
    }

    /// Records a health-check result for one node of one group.
    ///
    /// # Errors
    ///
    /// Returns an error when the group or dialer is unknown to this generation.
    pub fn record(
        &self,
        group: &str,
        dialer: DialerId,
        alive: bool,
        latency: Option<daer_config::TimeSpan>,
    ) -> Result<NotifyOutcome, OutboundError> {
        let mut groups = self.groups.write().unwrap_or_else(|e| e.into_inner());
        let Some(route) = groups.get_mut(group) else {
            return Err(OutboundError::UnknownGroup(group.to_owned()));
        };
        route.group.record(dialer, alive, latency)
    }
}

/// A row of the probe table: what a health check needs about one node.
pub type ProbeRow = (DialerId, String, Protocol, Option<SocketAddr>, bool);

/// Parses a node address as a literal `SocketAddr`, or `None` when it is a name.
///
/// A name is not resolved here on purpose: the probe must reach the same address the data
/// path would, and doing the resolution in the scheduler would be a second, silent DNS
/// decision.
fn literal_address(address: &str) -> Option<SocketAddr> {
    address.parse::<SocketAddr>().ok()
}

/// One group and the node dialers its selections point at.
#[derive(Debug)]
struct GroupRoute {
    group: DialerGroup,
    /// Indexed by [`DialerId`]: the same order as the filter survivors.
    nodes: Vec<Arc<NodeDialer>>,
}

impl GroupRoute {
    fn node(&self, id: DialerId) -> Option<&Arc<NodeDialer>> {
        self.nodes.get(usize::try_from(id.0).ok()?)
    }
}

/// Facts for a flow.
///
/// Process name, DSCP and source MAC are not known at the ingress: they come from the
/// kernel's connection state and are supplied as unknown, so a rule that needs them cannot
/// match by accident. The domain is supplied when the caller sniffed one — an absent
/// domain is the honest default, because a guessed one would route traffic through the
/// wrong outbound.
///
/// Split from `facts` so the two callers — the hot path, which may have sniffed, and the
/// diagnostic entry points, which have not — share one construction and cannot drift.
fn facts_with_domain<'a>(
    source: SocketAddr,
    destination: SocketAddr,
    domain: Option<&'a str>,
    l4proto: L4ProtoMask,
) -> MatchFacts<'a> {
    MatchFacts {
        source_addr: source.ip(),
        dest_addr: destination.ip(),
        source_port: source.port(),
        dest_port: destination.port(),
        l4proto,
        domain,
        process_name: ProcessName::from_bytes_truncated(b""),
        dscp: 0,
        mac: MacAddr([0; 6]),
    }
}

/// Dial timeout for the outbound leg.
///
/// Conservative and fixed for now: the per-group `check-interval` governs probes,
/// not dials, and a dial that hangs must not hold an ingress slot forever.
const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// The mark `docs/deployment.md` recommends, and what `daer run` applies to `PARAM`.
///
/// Not applied to sockets unless the configuration asks for it: `SO_MARK` needs
/// `CAP_NET_ADMIN`, so a default would break every unprivileged run.
pub const RECOMMENDED_SOCKET_MARK: u32 = 0x0dae;

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
        for function in &rule.and_functions {
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

fn fallback_outbound(fallback: &FunctionOrString) -> Result<Outbound, RoutingError> {
    let function = fallback.as_function().map_err(RoutingError::new)?;
    parse_outbound(&function)
}

fn check_target(name: &str, groups: &[String]) -> Result<(), RoutingError> {
    if is_builtin_outbound(name) || groups.iter().any(|group| group == name) {
        return Ok(());
    }
    Err(RoutingError::new(format!(
        "outbound (group) {name:?} not found; please define it in a [[group]] table"
    )))
}

/// Builds every group from the node pool.
///
/// The pool is `[[node]]` plus every node a `[[subscription]]` resolved to. Both
/// arrive in `config.node`: subscription resolution happens before a generation is
/// built (see [`crate::subscription`]), so this function stays synchronous and a
/// generation stays a pure function of the configuration it was given.
///
/// A node whose protocol this build cannot speak is skipped, never downgraded:
/// treating an unknown scheme as `direct` would leak the flow outside the proxy.
/// That skip is logged at `warn` with the reason, because a group that silently
/// lost half its nodes is a configuration bug an operator must see.
fn build_groups(
    config: &Config,
    dialer_options: &DialerOptions,
) -> Result<HashMap<String, GroupRoute>, RoutingError> {
    let mut groups = HashMap::new();
    for group in &config.group {
        let policy = parse_group_policy(&group.policy).map_err(RoutingError::new)?;
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

        let mut dialers = Vec::new();
        let mut nodes = Vec::new();
        for node in &config.node {
            let property = Property::from_link(
                node.tag.clone().unwrap_or_else(|| node.url.clone()),
                &node.url,
                // The node's provenance, so a `subtag(...)` filter can select it. Passing `""`
                // here meant every subscription node was invisible to every such filter.
                node.subscription_tag(),
            );
            let Some(annotation) = filters.matches(&property.name, &property.subscription_tag)
            else {
                continue;
            };
            // A node whose protocol this build cannot speak is skipped, never
            // downgraded: treating an unknown scheme as `direct` would leak the
            // flow outside the proxy. Any other error is a configuration bug and
            // fails the generation.
            let node_dialer = match NodeDialer::from_link(&node.url, *dialer_options) {
                Ok(dialer) => dialer,
                Err(OutboundError::UnsupportedLink(message)) => {
                    tracing::warn!(
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
                        "node {:?}: {error}",
                        property.name
                    )));
                }
            };
            let id = DialerId(dialers.len() as u64);
            nodes.push(Arc::new(node_dialer));
            dialers.push(Dialer::new(id, property, annotation.add_latency));
        }

        let tolerance = group
            .health_check
            .tolerance
            .unwrap_or(config.global.health_check.tolerance);
        groups.insert(
            group.name.clone(),
            GroupRoute {
                group: DialerGroup::new(group.name.clone(), policy, tolerance, dialers),
                nodes,
            },
        );
    }
    Ok(groups)
}

impl crate::serve::Decide for Router {
    type Upstream = Upstream;
    type Future<'a>
        = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Upstream, IngressError>> + Send + 'a>,
    >
    where
        Self: 'a;

    fn decide<'a>(&'a self, flow: &'a Accepted) -> Self::Future<'a> {
        Box::pin(self.resolve(flow))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_trace_and_the_verdict_never_disagree() {
        // Two ways of asking the same question must not diverge: the trace is what a
        // bug report is diagnosed with, the verdict is what the data path acts on.
        let router = router(TWO_RULES);
        for port in [80u16, 443, 8080] {
            let (source, destination) = flow(port);
            let verdict = router.verdict_for(source, destination);
            let trace = router.trace(source, destination);
            assert_eq!(trace.decided_by, verdict.rule, "port {port}");
            assert_eq!(
                trace.outbound.map(|outbound| outbound.name),
                Some(verdict.outbound.name),
                "the trace must report the effective outbound, fallback included (port {port})"
            );
        }
    }

    #[test]
    fn the_explanation_carries_the_predicate_that_blocked_a_rule() {
        let router = router(TWO_RULES);
        let (source, destination) = flow(80);
        let explanation = router.explain(source, destination);

        let skipped = &explanation.trace.rules[0];
        assert_eq!(skipped.rule, 0);
        let blocking = skipped.blocking().expect("a blocking predicate");
        assert_eq!(blocking.predicate, "port(443)");
    }

    fn router(src: &str) -> Router {
        let config = daer_config::toml_config::load_str(src).expect("config loads");
        Router::new(&config, GenerationId::new(7), &RouterOptions::default())
            .expect("router builds")
    }

    fn flow(destination_port: u16) -> (SocketAddr, SocketAddr) {
        (
            "192.168.1.10:41234".parse().expect("source"),
            SocketAddr::from(([93, 184, 216, 34], destination_port)),
        )
    }

    const TWO_RULES: &str = r#"
[routing]
rules = ["dport(443) -> block", "dport(80) -> direct"]
fallback = "direct"
"#;

    #[test]
    fn a_verdict_names_the_rule_that_decided() {
        let router = router(TWO_RULES);

        let (source, destination) = flow(443);
        let verdict = router.verdict_for(source, destination);
        assert_eq!(verdict.rule, Some(0));
        assert_eq!(&*verdict.outbound.name, "block");
        assert_eq!(verdict.describe(), "rule 0");

        let (source, destination) = flow(80);
        let verdict = router.verdict_for(source, destination);
        assert_eq!(verdict.rule, Some(1));
        assert_eq!(&*verdict.outbound.name, "direct");
        assert_eq!(verdict.describe(), "rule 1");
    }

    #[test]
    fn an_unmatched_flow_is_attributed_to_the_fallback() {
        let router = router(TWO_RULES);
        let (source, destination) = flow(8080);
        let verdict = router.verdict_for(source, destination);
        assert_eq!(verdict.rule, None, "no rule matched");
        assert_eq!(verdict.describe(), "fallback");
        assert_eq!(&*verdict.outbound.name, "direct");
    }

    #[test]
    fn an_explanation_names_the_configured_rule() {
        let router = router(TWO_RULES);
        let (source, destination) = flow(443);
        let explanation = router.explain(source, destination);

        assert_eq!(explanation.rule, Some(0));
        // `dport` was normalized to `port` by the alias optimizer; the explanation
        // reports what the engine evaluated, not the file's spelling.
        assert_eq!(
            explanation.rule_text, "port(443) -> block",
            "the evaluated rule text, not an internal index"
        );
        assert_eq!(&*explanation.outbound.name, "block");

        let rendered = explanation.to_string();
        assert!(rendered.contains("decided by"), "{rendered}");
        assert!(rendered.contains("port(443) -> block"), "{rendered}");
        assert!(rendered.contains("gen7"), "{rendered}");
    }

    #[test]
    fn an_explanation_of_a_fallback_says_so() {
        let router = router(TWO_RULES);
        let (source, destination) = flow(8080);
        let explanation = router.explain(source, destination);
        assert_eq!(explanation.rule, None);
        assert_eq!(explanation.rule_text, "fallback -> direct");
        assert_eq!(&*explanation.outbound.name, "direct");
        // The fallback is a rule like any other; naming it is not a failure.
        assert!(explanation.to_string().contains("fallback -> direct"));
    }

    #[test]
    fn an_explanation_lists_the_groups_that_exist() {
        let router = router(
            r#"
[[node]]
tag = "n1"
url = "socks5://127.0.0.1:1080"

[[group]]
name = "proxy"
policy = "fixed(0)"

[routing]
rules = []
fallback = "proxy"
"#,
        );
        let (source, destination) = flow(80);
        let explanation = router.explain(source, destination);
        assert_eq!(explanation.groups, ["proxy"]);
        assert_eq!(&*explanation.outbound.name, "proxy");
    }

    #[test]
    fn a_domain_rule_only_matches_when_a_domain_is_supplied() {
        // The property the data path depends on: without a sniffed name a `domain(...)`
        // rule cannot fire, so it cannot route by a guess.
        let router = router(
            r#"
[routing]
rules = ["domain(suffix: example.com) -> block"]
fallback = "direct"
"#,
        );
        let (source, destination) = flow(443);

        let without = router.verdict_with_domain(source, destination, None);
        assert_eq!(&*without.outbound.name, "direct", "no domain, no match");
        assert_eq!(without.rule, None);

        let with = router.verdict_with_domain(source, destination, Some("www.example.com"));
        assert_eq!(&*with.outbound.name, "block");
        assert_eq!(with.describe(), "rule 0", "the domain rule fired");

        let other = router.verdict_with_domain(source, destination, Some("example.org"));
        assert_eq!(
            &*other.outbound.name, "direct",
            "a different name does not match"
        );
    }

    #[test]
    fn sniffing_is_enabled_only_when_a_domain_rule_exists() {
        // Deciding this per generation keeps a syscall and a wait off every flow of a
        // configuration that cannot use a name.
        let with_domain =
            router("[routing]\nrules = [\"domain(suffix: a) -> direct\"]\nfallback = \"direct\"\n");
        assert!(!with_domain.sniffing_timeout.is_zero());

        let without_domain = router(TWO_RULES);
        assert!(
            without_domain.sniffing_timeout.is_zero(),
            "no domain rule, no sniffing cost"
        );
    }

    #[test]
    fn an_explanation_can_show_what_a_sniffed_name_changed() {
        let router = router(
            r#"
[routing]
rules = ["domain(suffix: example.com) -> block"]
fallback = "direct"
"#,
        );
        let (source, destination) = flow(443);
        let explanation = router.explain_with_domain(source, destination, Some("api.example.com"));
        assert_eq!(explanation.rule, Some(0));
        assert_eq!(
            explanation.rule_text,
            "domain(suffix: example.com) -> block"
        );
        assert_eq!(&*explanation.outbound.name, "block");
    }

    #[test]
    fn the_router_reports_the_generation_it_serves() {
        let router = router(TWO_RULES);
        assert_eq!(router.generation(), GenerationId::new(7));
        assert_eq!(router.generation().to_string(), "gen7");
    }

    #[test]
    fn facts_carry_the_tuple_and_leave_the_unknowns_unknown() {
        let (source, destination) = flow(443);
        let facts = facts_with_domain(source, destination, None, L4ProtoMask::TCP);
        assert_eq!(facts.source_port, 41_234);
        assert_eq!(facts.dest_port, 443);
        assert_eq!(facts.l4proto, L4ProtoMask::TCP);
        // The ingress cannot know these; a rule that needs them must not match.
        assert!(facts.domain.is_none());
        assert!(facts.process_name.is_unspecified());
        assert_eq!(facts.dscp, 0);
        assert_eq!(facts.mac, MacAddr([0; 6]));
    }
}
