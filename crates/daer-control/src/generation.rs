// SPDX-License-Identifier: AGPL-3.0-only

//! Configuration generations and reload.
//!
//! # Why generations
//!
//! A reload must never be able to break a running proxy. The rule is therefore
//! structural, not procedural: a new generation is **fully built and validated**
//! before anything is published, and publication is a single atomic pointer swap.
//! There is no window in which a flow can observe a half-built configuration, and
//! a configuration that fails to build leaves the previous generation serving —
//! untouched, still answering, with nothing to roll back.
//!
//! ```text
//!   parse + validate ─▶ build Router ─▶ publish (swap) ─▶ report
//!                            │
//!                            └─ error ─▶ previous generation keeps serving
//! ```
//!
//! # Why flows keep their generation
//!
//! A flow resolves its verdict against the generation that was current when it
//! arrived and keeps it for its lifetime (the caller holds an `Arc<Generation>`).
//! A reload therefore cannot change the rules under a connection that is already
//! relaying, which is what makes "reload 1000 times under a long-lived connection"
//! a meaningful acceptance criterion rather than a hope.
//!
//! # Reporting
//!
//! Every reload produces a [`ReloadReport`]: what was built, how long it took, and
//! whether the *routing* actually changed (a semantic hash, not a byte diff). That
//! distinction is the one that matters operationally — an unchanged routing policy
//! means the kernel side has nothing to rewrite, and a changed one is exactly what
//! an operator wants to see in the log when behaviour shifts.
//!
//! The same information is emitted as one structured `tracing` event, so the report
//! is readable in a journal and machine-filterable in a collector.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use daer_config::Config;
use daer_routing::{RoutingError, hash_normalized_program};

use crate::decide::{Router, RouterOptions};

/// Monotonic identifier of a configuration generation.
///
/// Deliberately a plain counter rather than a hash: an operator comparing log lines
/// needs "the one before" and "the one after", not a digest. The semantic content is
/// carried separately by [`Generation::policy_hash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenerationId(u64);

impl GenerationId {
    /// The identifier as it appears in logs and reports.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// An identifier built by the caller.
    ///
    /// [`Generations`] allocates monotonic ids itself; this exists for tooling and
    /// tests that drive a router without a generation history.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for GenerationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gen{}", self.0)
    }
}

/// One immutable configuration generation.
///
/// Nothing in here mutates after construction. `Router` is what a flow consults;
/// the rest is what a human consults when a flow behaved unexpectedly.
#[derive(Debug)]
pub struct Generation {
    id: GenerationId,
    /// The router behind an `Arc` so a health scheduler can hold the *same* router the data
    /// path consults. A copy would let probes record into a router nothing selects from, which
    /// is the exact shape of the bug ADR-0006 records.
    router: Arc<Router>,
    /// Semantic hash of the compiled routing policy.
    ///
    /// Two generations with the same hash route identically, whatever else changed.
    /// The kernel side can skip rewriting its maps when this is stable, and an
    /// operator can tell "the reload changed the config" from "the reload changed
    /// the routing" — a distinction that is otherwise pure guesswork.
    policy_hash: [u8; 32],
    rules: usize,
    groups: usize,
    nodes: usize,
    /// How often to probe nodes, from the configuration this generation was built from.
    ///
    /// Carried on the generation rather than read from the file at scheduling time, so a
    /// generation served with a reloaded interval cannot disagree with the generation that was
    /// built from the same file.
    health_interval: daer_config::HealthCheck,
    build_time: Duration,
    built_at: Instant,
}

impl Generation {
    /// Builds a generation from a validated configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError`] when the rules, groups or outbound names do not
    /// compile. Nothing is published on failure.
    pub fn build(
        id: GenerationId,
        config: &Config,
        options: &RouterOptions,
    ) -> Result<Self, RoutingError> {
        let started = Instant::now();
        let router = Router::new(config, id, options)?;
        let policy_hash = hash_normalized_program(router.program())?;
        Ok(Self {
            id,
            rules: router.matches().len(),
            groups: config.group.len(),
            nodes: config.node.len(),
            router: Arc::new(router),
            policy_hash,
            health_interval: config.global.health_check.clone(),
            build_time: started.elapsed(),
            built_at: Instant::now(),
        })
    }

    /// How often this generation wants its nodes probed.
    #[must_use]
    pub const fn health_interval(&self) -> daer_config::TimeSpan {
        self.health_interval.interval
    }

    /// The health-check table this generation was built from.
    #[must_use]
    pub fn health_check(&self) -> daer_config::HealthCheck {
        self.health_interval.clone()
    }

    /// The generation identifier.
    #[must_use]
    pub const fn id(&self) -> GenerationId {
        self.id
    }

    /// The router flows consult.
    #[must_use]
    pub fn router(&self) -> &Router {
        &self.router
    }

    /// A handle to the same router, for a background task that records into it.
    ///
    /// Sharing rather than cloning is load-bearing: the health scheduler mutates each group's
    /// alive set, and a clone would mutate a set no flow reads.
    #[must_use]
    pub fn router_arc(&self) -> Arc<Router> {
        Arc::clone(&self.router)
    }

    /// Semantic hash of the compiled routing policy.
    #[must_use]
    pub const fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }

    /// Number of compiled match sets.
    #[must_use]
    pub const fn rules(&self) -> usize {
        self.rules
    }

    /// How long building this generation took.
    #[must_use]
    pub const fn build_time(&self) -> Duration {
        self.build_time
    }

    /// How long this generation has been serving.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.built_at.elapsed()
    }

    /// A one-line description for logs.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} rules={} groups={} nodes={} built_in={}ms",
            self.id,
            self.rules,
            self.groups,
            self.nodes,
            self.build_time.as_millis()
        )
    }
}

/// What a reload did, in the form an operator needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadReport {
    /// The generation now serving.
    pub generation: GenerationId,
    /// The generation it replaced.
    pub previous: GenerationId,
    /// Time spent building the new generation (excludes the swap, which is atomic).
    pub build_time: Duration,
    /// Compiled match sets.
    pub rules: usize,
    pub groups: usize,
    pub nodes: usize,
    /// Whether the compiled routing policy is semantically different.
    pub routing_changed: bool,
    /// Warnings surfaced while compiling rules.
    pub warnings: Vec<String>,
}

impl ReloadReport {
    /// A one-line report, suitable for a log or a `systemctl reload` message.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} → {} rules={} groups={} nodes={} routing={} in {}ms",
            self.previous,
            self.generation,
            self.rules,
            self.groups,
            self.nodes,
            if self.routing_changed {
                "changed"
            } else {
                "unchanged"
            },
            self.build_time.as_millis()
        )
    }
}

/// A configuration that could not be published.
///
/// `serving` is `None` only when nothing was ever published — the first load. Saying
/// "gen1 is still serving" in that case would be a lie, and a misleading message
/// costs more than a longer one.
#[derive(Debug)]
pub struct ReloadError {
    /// What went wrong.
    pub source: RoutingError,
    /// The generation that is still serving, untouched.
    pub serving: Option<GenerationId>,
}

impl fmt::Display for ReloadError {
    /// States what happened to the *service*, not what was wrong with the file.
    ///
    /// The rule error is [`ReloadError::source`], so an error chain renders it
    /// exactly once (`anyhow`'s `{:#}` prints `Display: source`). Repeating it here
    /// would double every message an operator reads.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.serving {
            Some(serving) => write!(f, "configuration rejected; {serving} is still serving"),
            None => f.write_str("configuration rejected; nothing is serving"),
        }
    }
}

impl std::error::Error for ReloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// The published generation, swapped atomically.
///
/// Readers never block on a reload: `load` is a pointer read, and the returned
/// `Arc` keeps that generation alive for as long as a flow needs it.
#[derive(Debug)]
pub struct Generations {
    current: ArcSwap<Generation>,
    /// Identifiers count *attempts*, not successes: a rejected reload still burns
    /// one, so a log line `gen4 was rejected` can never be confused with `gen4 is
    /// serving`.
    next_id: AtomicU64,
    /// Generations that actually took over.
    published: AtomicU64,
}

impl Generations {
    /// Publishes the first generation.
    ///
    /// # Errors
    ///
    /// Returns [`ReloadError`] when the configuration does not compile. There is no
    /// previous generation to fall back to, so the caller has nothing serving.
    pub fn new(config: &Config, options: &RouterOptions) -> Result<Self, ReloadError> {
        let first = GenerationId(1);
        let generation = Generation::build(first, config, options).map_err(|source| {
            tracing::error!(
                generation = %first,
                error = %source,
                "configuration rejected; nothing is serving"
            );
            ReloadError {
                source,
                serving: None,
            }
        })?;
        tracing::info!(
            generation = %generation.id(),
            rules = generation.rules(),
            groups = generation.groups,
            nodes = generation.nodes,
            build_ms = generation.build_time().as_millis(),
            "configuration loaded"
        );
        Ok(Self {
            current: ArcSwap::from_pointee(generation),
            next_id: AtomicU64::new(2),
            published: AtomicU64::new(1),
        })
    }

    /// The generation currently serving.
    ///
    /// Hold the returned `Arc` for the lifetime of a flow: that is what pins the
    /// flow to the rules it started under.
    #[must_use]
    pub fn current(&self) -> Arc<Generation> {
        self.current.load_full()
    }

    /// Builds and publishes the next generation.
    ///
    /// The build happens before the swap, so a rejected configuration is a no-op
    /// for every flow in flight.
    ///
    /// # Errors
    ///
    /// Returns [`ReloadError`] when the configuration does not compile; the message
    /// names the generation that is still serving.
    pub fn reload(
        &self,
        config: &Config,
        options: &RouterOptions,
    ) -> Result<ReloadReport, ReloadError> {
        let previous = self.current();
        let id = GenerationId(self.next_id.fetch_add(1, Ordering::Relaxed));

        let generation = Generation::build(id, config, options).map_err(|source| {
            tracing::error!(
                generation = %id,
                serving = %previous.id(),
                error = %source,
                "configuration reload rejected; the running generation is unchanged"
            );
            ReloadError {
                source,
                serving: Some(previous.id()),
            }
        })?;

        let routing_changed = generation.policy_hash() != previous.policy_hash();
        let report = ReloadReport {
            generation: generation.id(),
            previous: previous.id(),
            build_time: generation.build_time(),
            rules: generation.rules(),
            groups: generation.groups,
            nodes: generation.nodes,
            routing_changed,
            warnings: Vec::new(),
        };

        self.current.store(Arc::new(generation));
        self.published.fetch_add(1, Ordering::Relaxed);

        tracing::info!(
            generation = %report.generation,
            previous = %report.previous,
            rules = report.rules,
            groups = report.groups,
            nodes = report.nodes,
            routing_changed = report.routing_changed,
            build_ms = report.build_time.as_millis(),
            "configuration reloaded"
        );

        // The previous generation stays alive until the last flow holding it ends;
        // dropping our handle here is what lets that happen.
        drop(previous);
        Ok(report)
    }

    /// How many generations have taken over, including the first.
    ///
    /// A rejected reload is not counted: it published nothing. The identifiers of
    /// the serving generation may therefore be higher than this number.
    #[must_use]
    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(src: &str) -> Config {
        daer_config::toml_config::load_str(src).expect("config loads")
    }

    fn options() -> RouterOptions {
        RouterOptions::default()
    }

    const DIRECT: &str = "[routing]\nrules = [\"dport(80) -> direct\"]\nfallback = \"direct\"\n";
    const CHANGED: &str = "[routing]\nrules = [\"dport(443) -> direct\"]\nfallback = \"direct\"\n";

    #[test]
    fn the_first_generation_is_published_and_described() {
        let generations = Generations::new(&config(DIRECT), &options()).expect("builds");
        let current = generations.current();
        assert_eq!(current.id(), GenerationId(1));
        assert_eq!(current.rules(), 1);
        assert_eq!(generations.published(), 1);
        assert!(current.describe().contains("gen1"));
    }

    #[test]
    fn a_reload_publishes_a_new_generation_and_reports_the_change() {
        let generations = Generations::new(&config(DIRECT), &options()).expect("builds");
        let report = generations
            .reload(&config(CHANGED), &options())
            .expect("reloads");

        assert_eq!(report.previous, GenerationId(1));
        assert_eq!(report.generation, GenerationId(2));
        assert!(
            report.routing_changed,
            "a different rule is a routing change: {report:?}"
        );
        assert_eq!(generations.published(), 2);
        assert_eq!(generations.current().id(), GenerationId(2));

        let summary = report.summary();
        assert!(summary.contains("gen1 → gen2"), "{summary}");
        assert!(summary.contains("routing=changed"), "{summary}");
    }

    #[test]
    fn an_identical_reload_reports_no_routing_change() {
        // Operationally the interesting case: the config was rewritten but routes
        // the same way, so the kernel side has nothing to rewrite.
        let generations = Generations::new(&config(DIRECT), &options()).expect("builds");
        let report = generations
            .reload(&config(DIRECT), &options())
            .expect("reloads");
        assert!(!report.routing_changed, "{report:?}");
        assert_eq!(generations.current().id(), GenerationId(2));
    }

    #[test]
    fn a_rejected_reload_leaves_the_running_generation_untouched() {
        let generations = Generations::new(&config(DIRECT), &options()).expect("builds");
        let before = generations.current();

        // A fallback that names an outbound nobody declared.
        let broken = config("[routing]\nrules = []\nfallback = \"nope\"\n");
        let error = generations
            .reload(&broken, &options())
            .expect_err("must be rejected");

        assert_eq!(error.serving, Some(GenerationId(1)));
        let rendered = error.to_string();
        assert!(rendered.contains("gen1 is still serving"), "{rendered}");
        // The rule error is the source, not part of the message: an error chain
        // renders it once, and logs get the whole story from `{:#}`.
        assert!(
            error.source.to_string().contains("not found"),
            "{}",
            error.source
        );

        // The published generation is byte-for-byte the same object.
        let after = generations.current();
        assert_eq!(before.id(), after.id());
        assert_eq!(before.policy_hash(), after.policy_hash());
        assert_eq!(
            generations.published(),
            1,
            "a failed reload publishes nothing"
        );
    }

    #[test]
    fn flows_that_hold_a_generation_keep_it_across_a_reload() {
        let generations = Generations::new(&config(DIRECT), &options()).expect("builds");
        let pinned = generations.current();
        generations
            .reload(&config(CHANGED), &options())
            .expect("reloads");

        // The pinned generation is unchanged and still current for its holder: this
        // is what makes "reload under a long-lived connection" safe.
        assert_eq!(pinned.id(), GenerationId(1));
        assert_eq!(generations.current().id(), GenerationId(2));
        assert_ne!(
            pinned.policy_hash(),
            generations.current().policy_hash(),
            "the two generations really do route differently"
        );
    }
}
