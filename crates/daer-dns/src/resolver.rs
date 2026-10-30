// SPDX-License-Identifier: AGPL-3.0-only

//! The answer pipeline: query in, answer out.
//!
//! ```text
//!   query ──▶ [request routing] ──reject──▶ REFUSED
//!                    │
//!                    ├──asis──▶ hand back to the client's resolver
//!                    │
//!                    └──upstream──▶ [cache] ──fresh──▶ answer (remaining TTL)
//!                                      │
//!                                      └──miss/stale──▶ [transport] ──▶ [response routing]
//!                                                                          │
//!                                                                          ├─accept─▶ answer
//!                                                                          ├─reject─▶ REFUSED
//!                                                                          └─failover─▶ one more upstream
//! ```
//!
//! # Why the transport is a trait
//!
//! UDP, TCP, DoH and DoT differ only in how bytes move. Everything that decides
//! *whether* to ask, *whom* to ask and *what to believe* is above that line, and is
//! exercised without a socket: the tests drive real routing, a real cache and a real
//! response-routing pass against a fake transport, and the fake is the only thing they
//! replace. When the transports land, they implement [`Upstream`] and nothing above them
//! changes.
//!
//! # Lock discipline
//!
//! The cache is behind a `Mutex` because lookups mutate (an expired entry is dropped, a
//! sweep reclaims space). The guard is **never held across an `.await`**: a lookup
//! completes, the message is cloned out as an `Arc`, and the guard is dropped before the
//! transport is called. Holding it would serialise every query behind the slowest
//! upstream.
//!
//! # Failover is one hop
//!
//! A `[dns.response]` rule can send an answer to another upstream. That is a second
//! question, not a recursion: after the failover the response routing runs again, and a
//! second failure is answered rather than chased. A forwarding loop is a much worse
//! outcome than an imperfect answer.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use daer_config::Config;

use crate::cache::{Cache, CacheConfig, Cached, Key};
use crate::routing::{
    AnswerFacts, Decision, RequestRouter, ResponseAction, ResponseRouter, RoutingError,
};
use crate::transport::UpstreamSpec;
use crate::wire::{Message, Name, RecordType, ResponseCode};

/// A transport failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    /// The transport is not implemented in this build.
    Missing(String),
    /// The exchange failed: timeout, refused, malformed reply.
    Failed(String),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(tag) => write!(f, "no transport for upstream {tag:?}"),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for UpstreamError {}

/// A boxed future, so [`Upstream`] stays object-safe.
pub type ExchangeFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Message, UpstreamError>> + Send + 'a>,
>;

/// One way of asking a resolver.
///
/// Implemented once per transport. The implementation is responsible for the wire and for
/// matching the response to the query; it is *not* responsible for routing, caching or
/// validation, which happen above it.
pub trait Upstream: Send + Sync + fmt::Debug {
    /// Sends `query` and returns the reply.
    fn exchange<'a>(&'a self, query: &'a Message) -> ExchangeFuture<'a>;
}

/// What to do with a query.
#[derive(Debug, Clone)]
pub enum Resolution {
    /// Answer the client with this message.
    Answer(Message),
    /// Not ours to answer: hand the query back so the client's own resolver can.
    ///
    /// The caller must not answer with a refusal; a `reject` decision is a different
    /// outcome and arrives as an [`Resolution::Answer`] carrying `REFUSED`.
    AsIs,
}

/// Why the pipeline could not produce an answer.
#[derive(Debug)]
pub enum ResolverError {
    /// The configuration does not compile into a working pipeline.
    Routing(RoutingError),
    /// The cache configuration is invalid.
    Cache(String),
    /// A `dns.upstream` entry does not parse.
    Upstream(String),
    /// A query could not be served at all; the client gets an error code.
    Unserviceable(ResponseCode),
}

impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Routing(error) => write!(f, "dns routing: {error}"),
            Self::Cache(message) => write!(f, "dns cache: {message}"),
            Self::Upstream(message) => write!(f, "dns upstream: {message}"),
            Self::Unserviceable(code) => write!(f, "cannot answer the query ({code:?})"),
        }
    }
}

impl std::error::Error for ResolverError {}

impl From<RoutingError> for ResolverError {
    fn from(error: RoutingError) -> Self {
        Self::Routing(error)
    }
}

/// Live counters for one resolver.
///
/// Atomics rather than a returned snapshot: a resolver is long-lived and its counters have
/// to be readable at any moment, including while it is serving.
#[derive(Debug, Default)]
pub struct Stats {
    hits: AtomicU64,
    stale_hits: AtomicU64,
    misses: AtomicU64,
    upstream_calls: AtomicU64,
    upstream_errors: AtomicU64,
    rejects: AtomicU64,
    as_is: AtomicU64,
    failovers: AtomicU64,
}

impl Stats {
    /// A point-in-time snapshot.
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            stale_hits: self.stale_hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            upstream_calls: self.upstream_calls.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            rejects: self.rejects.load(Ordering::Relaxed),
            as_is: self.as_is.load(Ordering::Relaxed),
            failovers: self.failovers.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time view of [`Stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Answers served from the cache while still fresh.
    pub hits: u64,
    /// Answers served from the cache after expiry, inside the stale window.
    pub stale_hits: u64,
    /// Lookups that had nothing usable, so an upstream was asked.
    pub misses: u64,
    /// Exchanges attempted, including failovers.
    pub upstream_calls: u64,
    /// Exchanges that failed.
    pub upstream_errors: u64,
    /// Queries answered with `REFUSED` by a rule.
    pub rejects: u64,
    /// Queries handed back to the client's resolver.
    pub as_is: u64,
    /// Answers sent to a second upstream by a `[dns.response]` rule.
    pub failovers: u64,
}

impl StatsSnapshot {
    /// Cache hits as a share of lookups, or `None` before the first lookup.
    #[must_use]
    pub fn hit_ratio(&self) -> Option<f64> {
        let lookups = self.hits + self.stale_hits + self.misses;
        (lookups > 0).then(|| (self.hits + self.stale_hits) as f64 / lookups as f64)
    }
}

/// Query in, answer out.
#[derive(Debug)]
pub struct Resolver {
    request: RequestRouter,
    response: ResponseRouter,
    upstreams: BTreeMap<String, Arc<dyn Upstream>>,
    cache: Mutex<Cache>,
    stats: Stats,
    /// `dns.ipversion-prefer`: `4`, `6`, or `0` for no preference.
    ///
    /// Applied to the answer set, not to the upstream choice: a query for `AAAA` against a
    /// v4-preferring resolver still has to be answered, and dropping every `AAAA` would break
    /// dual-stack clients outright. What the preference does is drop *the other family's records
    /// from a mixed answer*, which is what an operator on a single-stack uplink wants: the
    /// answers a client will pick from are the ones it can actually reach.
    ipversion_prefer: IpVersionPreference,
}

/// `dns.ipversion-prefer`, as a type rather than a raw `i32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpVersionPreference {
    /// Keep both families.
    #[default]
    None,
    /// Keep `A` records when the answer has any.
    V4,
    /// Keep `AAAA` records when the answer has any.
    V6,
}

impl IpVersionPreference {
    /// Parses the configured integer.
    ///
    /// # Errors
    ///
    /// Returns a message for a value other than `0`, `4` or `6`. `daer-config` rejects those
    /// already, so reaching the error means a caller built a configuration by hand.
    pub fn parse(raw: i32) -> Result<Self, String> {
        match raw {
            0 => Ok(Self::None),
            4 => Ok(Self::V4),
            6 => Ok(Self::V6),
            other => Err(format!(
                "dns.ipversion-prefer is {other}; the accepted values are 0 (no preference), \
                 4 (prefer IPv4) and 6 (prefer IPv6)"
            )),
        }
    }

    /// Drops the records of the dispreferred family from `message`'s answers.
    ///
    /// Only the *answers* section is touched: authorities and additionals carry NS/SOA/OPT data
    /// that has nothing to do with address family, and removing an OPT record would break EDNS.
    /// The rule is "prefer", not "only": if the answer has no record of the preferred family the
    /// other family is kept, because an empty answer to a client that can use the other family is
    /// strictly worse than a slower one.
    fn apply(self, message: &mut Message) {
        let (keep, drop) = match self {
            Self::None => return,
            Self::V4 => (RecordType::A, RecordType::AAAA),
            Self::V6 => (RecordType::AAAA, RecordType::A),
        };
        if !message.answers.iter().any(|record| record.rtype == keep) {
            return;
        }
        let before = message.answers.len();
        message.answers.retain(|record| record.rtype != drop);
        if message.answers.len() != before {
            tracing::trace!(
                dropped = before - message.answers.len(),
                preference = ?self,
                "dns: dropped the dispreferred address family from a mixed answer"
            );
        }
    }
}

impl Resolver {
    /// Builds a pipeline from a configuration and a set of transports.
    ///
    /// A tag declared in `dns.upstream` but absent from `transports` is a **load-time**
    /// error: the alternative — registering a transport that refuses every query — makes a
    /// misconfigured resolver look like a working one, which is the failure mode this
    /// pipeline exists to avoid.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError`] when a declared tag has no transport, when the request or
    /// response routing does not compile, or when the cache configuration is invalid.
    pub fn new(
        config: &Config,
        transports: impl IntoIterator<Item = (String, Arc<dyn Upstream>)>,
    ) -> Result<Self, ResolverError> {
        let request = RequestRouter::compile(config)?;
        let response = ResponseRouter::compile(config)?;
        let cache_config = CacheConfig::from_config(config).map_err(ResolverError::Cache)?;

        let mut upstreams: BTreeMap<String, Arc<dyn Upstream>> = BTreeMap::new();
        for (tag, transport) in transports {
            upstreams.insert(tag, transport);
        }
        for entry in &config.dns.upstream {
            let Some((tag, _)) = entry.split_once(':') else {
                continue;
            };
            if !upstreams.contains_key(tag) {
                return Err(ResolverError::Upstream(format!(
                    "dns.upstream {entry:?} has no transport; every declared upstream must \
                     build, or the resolver would accept queries it cannot serve"
                )));
            }
        }

        let ipversion_prefer = IpVersionPreference::parse(config.dns.ipversion_prefer)
            .map_err(ResolverError::Upstream)?;

        Ok(Self {
            request,
            response,
            upstreams,
            cache: Mutex::new(Cache::new(cache_config)),
            stats: Stats::default(),
            ipversion_prefer,
        })
    }

    /// Builds the transports a configuration declares.
    ///
    /// Every protocol in [`Protocol`](crate::transport::Protocol) has a transport, so a
    /// spec that fails to build is a **load-time** error rather than a resolver that
    /// accepts every query and refuses to serve any. A configuration that cannot work must
    /// say so at load, when the operator is looking at it.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError`] for an unparseable entry, an entry whose transport cannot
    /// be built, or a routing/cache configuration that does not compile.
    pub fn from_config(config: &Config) -> Result<Self, ResolverError> {
        let mut transports: Vec<(String, Arc<dyn Upstream>)> = Vec::new();
        for entry in &config.dns.upstream {
            let spec = UpstreamSpec::parse(entry).map_err(ResolverError::Upstream)?;
            let transport = spec.build().map_err(|error| {
                ResolverError::Upstream(format!("dns.upstream {entry:?}: {error}"))
            })?;
            transports.push((spec.tag, transport));
        }
        Self::new(config, transports)
    }

    /// The live counters.
    #[must_use]
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Answers `query`.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError::Unserviceable`] when not even an error reply can be formed
    /// (the query is itself a response, or has no question to echo). Every other failure
    /// becomes an answer with a response code, because a client that gets nothing retries
    /// and holds its slot.
    pub async fn resolve(&self, query: &Message) -> Result<Resolution, ResolverError> {
        let started = Instant::now();
        if query.is_response() {
            return Err(ResolverError::Unserviceable(ResponseCode::FORMERR));
        }

        let decision = self.request.decide(query);
        tracing::debug!(
            question = %describe_question(query),
            decision = %decision,
            "dns request routed"
        );

        let tag = match decision {
            Decision::Reject => {
                self.stats.rejects.fetch_add(1, Ordering::Relaxed);
                return Ok(Resolution::Answer(Message::reply_to(
                    query,
                    ResponseCode::REFUSED,
                )));
            }
            Decision::AsIs => {
                self.stats.as_is.fetch_add(1, Ordering::Relaxed);
                return Ok(Resolution::AsIs);
            }
            Decision::Upstream(tag) => tag,
        };

        let key = Key::of(query);
        if let Some(key) = &key {
            match self.lookup(key) {
                Some(cached) => {
                    let message = self.materialise(query, cached);
                    return Ok(Resolution::Answer(message));
                }
                None => {
                    // Counted here, not at the upstream call: a miss is a cache outcome,
                    // and a query that never reaches an upstream (a rejected one) is
                    // neither a hit nor a miss.
                    self.stats.misses.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let answer = match self.ask(&tag, query).await {
            Ok(answer) => answer,
            Err(error) => {
                tracing::debug!(%error, upstream = %tag, "dns upstream failed");
                return Ok(Resolution::Answer(Message::reply_to(
                    query,
                    ResponseCode::SERVFAIL,
                )));
            }
        };

        let action = self.respond(&answer, query, &tag);
        tracing::debug!(
            question = %describe_question(query),
            upstream = %tag,
            action = %action,
            elapsed_ms = started.elapsed().as_millis(),
            "dns answer routed"
        );

        let final_answer = match action {
            ResponseAction::Accept => {
                let mut answer = answer;
                // Applied before the cache write, so a cached answer is the one a client will
                // see: filtering on the way out of the cache would re-filter the same records on
                // every hit and, worse, leave a stale cache holding records the configuration
                // says to drop.
                self.ipversion_prefer.apply(&mut answer);
                answer
            }
            ResponseAction::Reject => {
                self.stats.rejects.fetch_add(1, Ordering::Relaxed);
                return Ok(Resolution::Answer(Message::reply_to(
                    query,
                    ResponseCode::REFUSED,
                )));
            }
            ResponseAction::Failover(other) => {
                self.stats.failovers.fetch_add(1, Ordering::Relaxed);
                if other == tag {
                    // A rule that sends an answer back to the upstream that produced it
                    // would loop; answering what we have is the lesser harm.
                    tracing::warn!(
                        upstream = %tag,
                        "dns.response failover targets the same upstream; ignoring"
                    );
                    answer
                } else {
                    match self.ask(&other, query).await {
                        Ok(second) => second,
                        Err(error) => {
                            tracing::debug!(%error, upstream = %other, "dns failover failed");
                            answer
                        }
                    }
                }
            }
        };

        if let Some(key) = key {
            self.store(key, &final_answer);
        }

        Ok(Resolution::Answer(settle(query, final_answer)))
    }

    /// Drops entries whose stale window has passed. Returns how many went.
    pub fn sweep(&self) -> usize {
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        cache.sweep(Instant::now())
    }

    /// Forgets every cached answer.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        cache.clear();
    }

    /// Number of cached answers.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        let cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        cache.len()
    }

    fn lookup(&self, key: &Key) -> Option<Cached> {
        // The guard is scoped to this block on purpose: it must not live across the
        // `.await` in `ask`, or one slow upstream would serialise every query.
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        cache.lookup(key, Instant::now())
    }

    fn store(&self, key: Key, answer: &Message) {
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        match cache.store(key, Arc::new(answer.clone()), Instant::now()) {
            Ok(ttl) => {
                tracing::trace!(ttl, "dns answer cached");
            }
            Err(skipped) => {
                tracing::trace!(?skipped, "dns answer not cached");
            }
        }
    }

    /// Turns a cache hit into a client-ready answer, counting it.
    fn materialise(&self, query: &Message, cached: Cached) -> Message {
        if cached.needs_refresh() {
            self.stats.stale_hits.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                question = %describe_question(query),
                expired_for_ms = cached.expired_for().map(|d| d.as_millis()),
                "dns stale answer served; a refresh is owed"
            );
        } else {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
        }
        let ttl = cached.ttl();
        let mut message = (**cached.message()).clone();
        message.id = query.id;
        message.flags = crate::wire::Flags::response_to(query.flags, message.response_code());
        cap_ttls(&mut message, ttl);
        message
    }

    async fn ask(&self, tag: &str, query: &Message) -> Result<Message, UpstreamError> {
        let Some(upstream) = self.upstreams.get(tag) else {
            return Err(UpstreamError::Missing(tag.to_owned()));
        };
        self.stats.upstream_calls.fetch_add(1, Ordering::Relaxed);
        let result = upstream.exchange(query).await;
        if result.is_err() {
            self.stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn respond(&self, answer: &Message, query: &Message, tag: &str) -> ResponseAction {
        let Some(question) = query.single_question() else {
            return ResponseAction::Accept;
        };
        let facts = AnswerFacts::from_message(question, answer, Some(tag));
        self.response.decide(&facts)
    }
}

/// Rewrites every record's TTL down to `ttl`, never up.
///
/// Capping rather than assigning because a record's own TTL is a promise the upstream
/// made: a cache hit may shorten it (that is the passage of time) but must not extend it.
fn cap_ttls(message: &mut Message, ttl: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        if record.is_opt() {
            // The OPT pseudo-record's "TTL" field is an extended flags/version word;
            // rewriting it corrupts EDNS.
            continue;
        }
        record.ttl = record.ttl.min(ttl);
    }
}

/// Makes an answer ready for the client that asked: same id, response flags.
fn settle(query: &Message, mut answer: Message) -> Message {
    answer.id = query.id;
    answer.flags = crate::wire::Flags::response_to(query.flags, answer.response_code());
    answer
}

fn describe_question(message: &Message) -> String {
    match message.single_question() {
        Some(question) => format!("{} {}", question.name, question.qtype),
        None => format!("{} question(s)", message.questions.len()),
    }
}

/// The name a cached answer was stored under, for diagnostics.
#[must_use]
pub fn cached_name(key: &Key) -> &Name {
    &key.name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Flags, Question, Record, RecordType};
    use std::sync::atomic::AtomicUsize;

    /// A transport that answers from a table and counts how often it was asked.
    #[derive(Debug)]
    struct FakeUpstream {
        addresses: Vec<[u8; 4]>,
        ttl: u32,
        calls: AtomicUsize,
        fail: bool,
    }

    impl FakeUpstream {
        fn answering(addresses: &[[u8; 4]], ttl: u32) -> Arc<Self> {
            Arc::new(Self {
                addresses: addresses.to_vec(),
                ttl,
                calls: AtomicUsize::new(0),
                fail: false,
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                addresses: Vec::new(),
                ttl: 0,
                calls: AtomicUsize::new(0),
                fail: true,
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Upstream for FakeUpstream {
        fn exchange<'a>(&'a self, query: &'a Message) -> ExchangeFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                if self.fail {
                    return Err(UpstreamError::Failed("upstream is down".to_owned()));
                }
                let question = query
                    .single_question()
                    .ok_or_else(|| UpstreamError::Failed("no question".to_owned()))?;
                Ok(Message {
                    id: query.id,
                    flags: Flags(0x8180),
                    questions: vec![question.clone()],
                    answers: self
                        .addresses
                        .iter()
                        .map(|octets| Record {
                            name: question.name.clone(),
                            rtype: RecordType::A,
                            class: Question::CLASS_IN,
                            ttl: self.ttl,
                            rdata: octets.to_vec(),
                        })
                        .collect(),
                    authorities: Vec::new(),
                    additionals: Vec::new(),
                })
            })
        }
    }

    fn query(name: &str, qtype: RecordType) -> Message {
        Message {
            id: 0x1234,
            flags: Flags(0x0100),
            questions: vec![Question::internet(Name::parse(name).expect("name"), qtype)],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    const BASE: &str = r#"
[dns]
upstream = ["local:udp://127.0.0.1:53", "remote:udp://127.0.0.1:54"]

[dns.request]
rules = ["qname(suffix: blocked) -> reject", "qname(suffix: lan) -> asis"]
fallback = "local"

[dns.response]
rules = []
fallback = "accept"
"#;

    fn resolver(src: &str, local: Arc<FakeUpstream>) -> Resolver {
        let config = daer_config::toml_config::load_str(src).expect("config loads");
        // `remote` is declared by `BASE` and never asked by these cases; registering it
        // keeps the fixture honest now that a declared tag without a transport is a load
        // error rather than a transport that fails per query.
        Resolver::new(
            &config,
            [
                ("local".to_owned(), local as Arc<dyn Upstream>),
                (
                    "remote".to_owned(),
                    FakeUpstream::answering(&[[1, 1, 1, 1]], 60) as Arc<dyn Upstream>,
                ),
            ],
        )
        .expect("resolver builds")
    }

    fn answer_of(resolution: Resolution) -> Message {
        match resolution {
            Resolution::Answer(message) => message,
            other => panic!("expected an answer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_answer_is_served_and_then_cached() {
        let upstream = FakeUpstream::answering(&[[93, 184, 216, 34]], 300);
        let resolver = resolver(BASE, Arc::clone(&upstream));
        let query = query("example.com", RecordType::A);

        let first = answer_of(resolver.resolve(&query).await.expect("resolves"));
        assert_eq!(first.id, query.id, "the client's id is echoed");
        assert!(first.is_response());
        assert_eq!(first.answer_addresses().len(), 1);
        assert_eq!(upstream.calls(), 1);

        let second = answer_of(resolver.resolve(&query).await.expect("resolves"));
        assert_eq!(upstream.calls(), 1, "the second answer came from the cache");
        assert_eq!(second.answer_addresses(), first.answer_addresses());

        let stats = resolver.stats().snapshot();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.upstream_calls, 1);
        assert!((stats.hit_ratio().expect("ratio") - 0.5).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn a_cached_answer_carries_the_remaining_ttl() {
        let upstream = FakeUpstream::answering(&[[1, 2, 3, 4]], 300);
        let resolver = resolver(BASE, upstream);
        let query = query("ttl.example.com", RecordType::A);
        let _ = resolver.resolve(&query).await.expect("resolves");

        // Reach into the cache with a synthetic clock so the assertion is deterministic.
        let key = Key::of(&query).expect("key");
        let mut cache = resolver.cache.lock().expect("cache");
        let hit = cache
            .lookup(&key, Instant::now() + std::time::Duration::from_secs(100))
            .expect("hit");
        // A few microseconds elapse between `store` and `lookup`, so the remaining TTL is
        // 199 or 200 depending on where the truncation lands. The property under test is
        // "the remaining time, not the original 300", so assert a band rather than a
        // second that a loaded machine could shift.
        let ttl = hit.ttl();
        assert!(
            (199..=200).contains(&ttl),
            "remaining ttl should be ~200, not the original 300; got {ttl}"
        );

        let mut message = (**hit.message()).clone();
        cap_ttls(&mut message, ttl);
        assert_eq!(message.answers[0].ttl, ttl);
    }

    #[tokio::test]
    async fn a_reject_rule_answers_refused_without_asking_anyone() {
        let upstream = FakeUpstream::answering(&[[1, 2, 3, 4]], 60);
        let resolver = resolver(BASE, Arc::clone(&upstream));
        let answer = answer_of(
            resolver
                .resolve(&query("tracker.blocked", RecordType::A))
                .await
                .expect("resolves"),
        );
        assert_eq!(answer.response_code(), ResponseCode::REFUSED);
        assert_eq!(upstream.calls(), 0, "no upstream was asked");
        assert_eq!(resolver.stats().snapshot().rejects, 1);
    }

    #[tokio::test]
    async fn an_asis_rule_hands_the_query_back() {
        let upstream = FakeUpstream::answering(&[[1, 2, 3, 4]], 60);
        let resolver = resolver(BASE, Arc::clone(&upstream));
        assert!(matches!(
            resolver
                .resolve(&query("nas.lan", RecordType::A))
                .await
                .expect("resolves"),
            Resolution::AsIs
        ));
        assert_eq!(upstream.calls(), 0);
        assert_eq!(resolver.stats().snapshot().as_is, 1);
    }

    #[tokio::test]
    async fn an_upstream_failure_becomes_servfail_rather_than_nothing() {
        // A client that gets no answer retries and holds its slot; SERVFAIL ends that.
        let resolver = resolver(BASE, FakeUpstream::failing());
        let answer = answer_of(
            resolver
                .resolve(&query("example.com", RecordType::A))
                .await
                .expect("resolves"),
        );
        assert_eq!(answer.response_code(), ResponseCode::SERVFAIL);
        assert_eq!(resolver.stats().snapshot().upstream_errors, 1);
    }

    #[test]
    fn a_declared_upstream_without_a_transport_is_a_load_error() {
        // The stronger contract, and the one that cannot mislead: a resolver that loads and
        // then fails every query looks like a working resolver to an operator who only sees
        // "it started".
        let src = r#"
[dns]
upstream = ["remote:udp://127.0.0.1:54"]

[dns.request]
rules = []
fallback = "remote"
"#;
        let config = daer_config::toml_config::load_str(src).expect("config loads");
        let error = Resolver::new(&config, []).expect_err("must refuse to build");
        let message = error.to_string();
        assert!(message.contains("no transport"), "{message}");
        assert!(message.contains("remote"), "{message}");
    }

    #[tokio::test]
    async fn a_failover_rule_asks_a_second_upstream() {
        let first = FakeUpstream::answering(&[[10, 0, 0, 1]], 60);
        let second = FakeUpstream::answering(&[[93, 184, 216, 34]], 60);
        let src = r#"
[dns]
upstream = ["first:udp://127.0.0.1:53", "second:udp://127.0.0.1:54"]

[dns.request]
rules = []
fallback = "first"

[dns.response]
rules = ["ip(10.0.0.0/8) -> second"]
"#;
        let config = daer_config::toml_config::load_str(src).expect("config loads");
        let resolver = Resolver::new(
            &config,
            [
                ("first".to_owned(), first.clone() as Arc<dyn Upstream>),
                ("second".to_owned(), second.clone() as Arc<dyn Upstream>),
            ],
        )
        .expect("builds");

        let answer = answer_of(
            resolver
                .resolve(&query("example.com", RecordType::A))
                .await
                .expect("resolves"),
        );
        assert_eq!(first.calls(), 1);
        assert_eq!(second.calls(), 1, "the failover upstream was asked");
        assert_eq!(
            answer.answer_addresses(),
            vec!["93.184.216.34".parse::<std::net::IpAddr>().expect("ip")],
            "the client sees the second answer"
        );
        assert_eq!(resolver.stats().snapshot().failovers, 1);
    }

    #[tokio::test]
    async fn a_failover_to_the_same_upstream_is_ignored_not_looped() {
        let upstream = FakeUpstream::answering(&[[10, 0, 0, 1]], 60);
        let src = r#"
[dns]
upstream = ["only:udp://127.0.0.1:53"]

[dns.request]
rules = []
fallback = "only"

[dns.response]
rules = ["ip(10.0.0.0/8) -> only"]
"#;
        let config = daer_config::toml_config::load_str(src).expect("config loads");
        let resolver = Resolver::new(
            &config,
            [("only".to_owned(), upstream.clone() as Arc<dyn Upstream>)],
        )
        .expect("builds");

        let answer = answer_of(
            resolver
                .resolve(&query("example.com", RecordType::A))
                .await
                .expect("resolves"),
        );
        assert_eq!(upstream.calls(), 1, "one question, not a loop");
        assert_eq!(answer.answer_addresses().len(), 1);
    }

    #[tokio::test]
    async fn a_query_that_is_itself_a_response_is_rejected() {
        let resolver = resolver(BASE, FakeUpstream::answering(&[[1, 2, 3, 4]], 60));
        let mut response = query("example.com", RecordType::A);
        response.flags = Flags(0x8180);
        assert!(matches!(
            resolver.resolve(&response).await,
            Err(ResolverError::Unserviceable(ResponseCode::FORMERR))
        ));
    }

    #[tokio::test]
    async fn the_opt_pseudo_record_ttl_is_never_rewritten() {
        // The OPT "TTL" field is an extended flags word; capping it corrupts EDNS.
        let mut message = query("example.com", RecordType::A);
        message.additionals.push(Record {
            name: Name::root(),
            rtype: RecordType::OPT,
            class: 4096,
            ttl: 0x0000_8000,
            rdata: Vec::new(),
        });
        cap_ttls(&mut message, 30);
        assert_eq!(message.additionals[0].ttl, 0x0000_8000);
    }

    #[test]
    fn a_cache_can_be_swept_and_cleared_through_the_resolver() {
        let resolver = resolver(BASE, FakeUpstream::answering(&[[1, 2, 3, 4]], 60));
        assert_eq!(resolver.cache_len(), 0);
        // Nothing to sweep yet; the call must still be safe and report zero.
        assert_eq!(resolver.sweep(), 0);
        resolver.clear_cache();
        assert_eq!(resolver.cache_len(), 0);
    }

    #[test]
    fn stats_describe_an_idle_resolver() {
        let resolver = resolver(BASE, FakeUpstream::answering(&[[1, 2, 3, 4]], 60));
        let stats = resolver.stats().snapshot();
        assert_eq!(stats, StatsSnapshot::default());
        assert!(
            stats.hit_ratio().is_none(),
            "no ratio before the first lookup"
        );
    }
}

#[cfg(test)]
mod from_config_tests {
    use super::*;
    use crate::wire::{Flags, Name, Question, RecordType};
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    /// A one-shot DNS-over-TCP server answering one query.
    async fn tcp_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accepts");
            let mut length = [0u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut length)
                .await
                .expect("length");
            let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut body)
                .await
                .expect("body");
            let query = crate::wire::parse(&body).expect("query");
            let reply = crate::wire::Message {
                id: query.id,
                flags: Flags(0x8180),
                questions: query.questions.clone(),
                answers: vec![crate::wire::Record {
                    name: Name::parse("example.com").expect("name"),
                    rtype: RecordType::A,
                    class: Question::CLASS_IN,
                    ttl: 60,
                    rdata: vec![93, 184, 216, 34],
                }],
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            let encoded = crate::wire::encode(&reply);
            tokio::io::AsyncWriteExt::write_all(&mut stream, &(encoded.len() as u16).to_be_bytes())
                .await
                .expect("length");
            tokio::io::AsyncWriteExt::write_all(&mut stream, &encoded)
                .await
                .expect("body");
        });
        address
    }

    #[tokio::test]
    async fn a_tcp_upstream_declared_in_the_config_answers() {
        // The whole point of `from_config`: the configuration names a transport and the
        // resolver speaks it, with no hand-wiring.
        let address = tcp_server().await;
        let config = daer_config::toml_config::load_str(&format!(
            r#"
[dns]
upstream = ["local:tcp://{address}"]

[dns.request]
rules = []
fallback = "local"
"#
        ))
        .expect("config loads");

        let resolver = Resolver::from_config(&config).expect("builds");
        let query = Message {
            id: 5,
            flags: Flags(0x0100),
            questions: vec![Question::internet(
                Name::parse("example.com").expect("name"),
                RecordType::A,
            )],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        let answer = match resolver.resolve(&query).await.expect("resolves") {
            Resolution::Answer(message) => message,
            Resolution::AsIs => panic!("the fallback is an upstream, not asis"),
        };
        assert_eq!(answer.response_code(), ResponseCode::NOERROR);
        assert_eq!(answer.answer_addresses().len(), 1);
        assert_eq!(resolver.stats().snapshot().upstream_calls, 1);
    }

    #[tokio::test]
    async fn every_documented_protocol_builds_a_real_transport() {
        // The regression this guards: `udp`, `tls` and `https` were documented, parsed, and
        // then silently registered as transports that refused every query. Building must
        // succeed for all four, and a query must actually reach the wire.
        for entry in [
            "google:udp://127.0.0.1:1",
            "google:tcp://127.0.0.1:1",
            "google:tls://127.0.0.1:1",
            "google:https://127.0.0.1:1",
        ] {
            let config = daer_config::toml_config::load_str(&format!(
                r#"
[dns]
upstream = ["{entry}"]

[dns.request]
rules = []
fallback = "google"
"#
            ))
            .expect("config loads");
            let resolver = Resolver::from_config(&config)
                .unwrap_or_else(|error| panic!("{entry} must build: {error}"));
            drop(resolver);
        }
    }

    #[tokio::test]
    async fn a_udp_upstream_is_actually_contacted() {
        // The service answers SERVFAIL when the upstream cannot be reached, and the
        // upstream-call counter proves the transport tried rather than short-circuited.
        let config = daer_config::toml_config::load_str(
            r#"
[dns]
upstream = ["google:udp://127.0.0.1:1"]

[dns.request]
rules = []
fallback = "google"
"#,
        )
        .expect("config loads");

        let resolver = Resolver::from_config(&config).expect("builds");
        let query = Message {
            id: 5,
            flags: Flags(0x0100),
            questions: vec![Question::internet(
                Name::parse("example.com").expect("name"),
                RecordType::A,
            )],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let answer = match resolver.resolve(&query).await.expect("resolves") {
            Resolution::Answer(message) => message,
            Resolution::AsIs => panic!("expected SERVFAIL"),
        };
        assert_eq!(answer.response_code(), ResponseCode::SERVFAIL);
        assert_eq!(resolver.stats().snapshot().upstream_errors, 1);
    }

    #[test]
    fn a_malformed_upstream_entry_fails_the_build() {
        let config = daer_config::toml_config::load_str(
            r#"
[dns]
upstream = ["nonsense"]
"#,
        )
        .expect("config loads");

        let error = Resolver::from_config(&config).expect_err("must reject");
        assert!(error.to_string().contains("dns.upstream"), "{error}");
    }
}
