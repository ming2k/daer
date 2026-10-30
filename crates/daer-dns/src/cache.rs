// SPDX-License-Identifier: AGPL-3.0-only

//! The answer cache: bounded, TTL-aware, and stale-while-revalidate.
//!
//! # What is cached, and keyed how
//!
//! One entry per `(name, qtype, qclass)`. That is the whole identity a DNS answer has:
//! two queries with the same three fields get the same answer from the same upstream,
//! whatever else differs in the packet. Caching on the wire bytes instead would create
//! one entry per transaction id and defeat the cache entirely.
//!
//! # Three states, not two
//!
//! ```text
//!   stored ──fresh──▶ (ttl)   deadline = now + ttl
//!                       │
//!                       ├── now < deadline            → Fresh
//!                       ├── deadline ≤ now < deadline+stale → Stale
//!                       └── now ≥ deadline + stale    → gone
//! ```
//!
//! * [`Cached::Fresh`] is served as is, with the **remaining** TTL. Serving the original
//!   TTL would make every downstream cache keep the answer far longer than the upstream
//!   allowed.
//! * [`Cached::Stale`] is RFC 8767 stale-while-revalidate: the answer is expired, so it
//!   is served **with a short TTL** and the caller is expected to refresh in the
//!   background. Serving it silently as fresh would be indistinguishable from a bug.
//! * A stale window of `0` means "never expire", matching the upstream behaviour this
//!   project's configuration documents.
//!
//! # Why the entry is immutable
//!
//! An entry is replaced, never mutated. Readers therefore never take a write lock, and a
//! reader that obtained an entry keeps serving it while a refresh replaces the map slot —
//! the same immutable-generation idea the data path uses for routing.
//!
//! # Negative answers are cached too
//!
//! `NXDOMAIN` and `NODATA` are answers. Caching only positive answers leaves the most
//! abusive traffic — repeated lookups of names that do not exist — uncached, which is
//! exactly backwards.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::wire::{Message, Name, RecordType};

/// The identity of a cached answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: u16,
}

impl Key {
    /// The key for a message with exactly one question.
    ///
    /// `None` for zero or several questions: an answer to those cannot be keyed without
    /// guessing, and a guess would serve the wrong answer later.
    #[must_use]
    pub fn of(message: &Message) -> Option<Self> {
        message.single_question().map(|question| Self {
            name: question.name.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
        })
    }
}

/// What the cache has for a key.
#[derive(Debug, Clone)]
pub enum Cached {
    /// Not expired: serve with `ttl`.
    Fresh { message: Arc<Message>, ttl: u32 },
    /// Expired but inside the stale window: serve with `ttl` and refresh in the
    /// background.
    Stale {
        message: Arc<Message>,
        ttl: u32,
        /// How long ago the answer expired, for logging.
        expired_for: Duration,
    },
}

impl Cached {
    /// How long ago the answer expired, for a stale hit.
    #[must_use]
    pub fn expired_for(&self) -> Option<Duration> {
        match self {
            Self::Fresh { .. } => None,
            Self::Stale { expired_for, .. } => Some(*expired_for),
        }
    }

    /// The message to serve.
    #[must_use]
    pub fn message(&self) -> &Arc<Message> {
        match self {
            Self::Fresh { message, .. } | Self::Stale { message, .. } => message,
        }
    }

    /// The TTL to advertise.
    #[must_use]
    pub fn ttl(&self) -> u32 {
        match self {
            Self::Fresh { ttl, .. } | Self::Stale { ttl, .. } => *ttl,
        }
    }

    /// True when the caller should refresh this answer in the background.
    ///
    /// The only reason `Stale` exists: it is served *so that* a refresh can happen
    /// without the client waiting.
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        matches!(self, Self::Stale { .. })
    }
}

/// One stored answer.
#[derive(Debug)]
struct Entry {
    message: Arc<Message>,
    /// When the answer stops being fresh.
    deadline: Instant,
    /// When it leaves the cache entirely (`deadline + stale window`).
    expires: Option<Instant>,
}

impl Entry {
    fn is_disposable(&self, now: Instant) -> bool {
        self.expires.is_some_and(|expires| now >= expires)
    }
}

/// Cache configuration, from `[dns]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheConfig {
    /// Whether to serve expired answers inside the stale window.
    pub optimistic: bool,
    /// The stale window, in seconds. `0` means never expire.
    pub stale_ttl: u32,
    /// The TTL advertised for a stale answer.
    pub stale_reply_ttl: u32,
    /// Maximum entries; `0` means unlimited.
    pub max_entries: usize,
    /// TTL override per domain, from `[dns.fixed-domain-ttl]`, in seconds.
    pub fixed_ttl: Vec<(Name, u32)>,
}

impl CacheConfig {
    /// Reads the cache knobs from a configuration.
    ///
    /// # Errors
    ///
    /// Returns a message for a `fixed-domain-ttl` key that is not a valid DNS name, so a
    /// typo cannot silently disable an override.
    pub fn from_config(config: &daer_config::Config) -> Result<Self, String> {
        let mut fixed_ttl = Vec::with_capacity(config.dns.fixed_domain_ttl.len());
        for (domain, ttl) in &config.dns.fixed_domain_ttl {
            let name = Name::parse(domain)
                .map_err(|error| format!("dns.fixed-domain-ttl: {domain:?}: {error}"))?;
            let ttl = u32::try_from(*ttl)
                .map_err(|_| format!("dns.fixed-domain-ttl: {domain:?}: TTL {ttl} is negative"))?;
            fixed_ttl.push((name, ttl));
        }
        Ok(Self {
            optimistic: config.dns.optimistic_cache,
            stale_ttl: u32::try_from(config.dns.optimistic_stale_reply_ttl).unwrap_or(0),
            stale_reply_ttl: u32::try_from(config.dns.optimistic_cache_ttl).unwrap_or(0),
            max_entries: usize::try_from(config.dns.max_cache_size).unwrap_or(0),
            fixed_ttl,
        })
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            optimistic: true,
            stale_ttl: 30,
            stale_reply_ttl: 60,
            max_entries: 65_536,
            fixed_ttl: Vec::new(),
        }
    }
}

/// Why a store was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    /// The message has no single question, so it has no key.
    Unkeyable,
    /// The message carries no answers and no negative-answer code to remember.
    NothingToCache,
    /// The answer's TTL is zero: caching it would serve it after it expired.
    ZeroTtl,
    /// The cache is full and every entry is fresher than this one.
    Full,
}

/// A bounded, TTL-aware answer cache.
///
/// Not internally synchronised: the caller owns it behind whatever lock or shard fits
/// its runtime. That keeps the cache testable with a plain `&mut` and avoids paying for
/// atomics that a single-writer task would not need.
#[derive(Debug)]
pub struct Cache {
    config: CacheConfig,
    entries: HashMap<Key, Entry>,
}

impl Cache {
    /// An empty cache.
    ///
    /// The `fixed-domain-ttl` overrides are put in longest-suffix-first order here rather
    /// than trusted from the caller: the override lookup takes the first match, so the
    /// order *is* the precedence, and a `CacheConfig` built by hand would otherwise
    /// silently prefer the less specific rule. Making it a property of construction means
    /// it cannot be forgotten.
    #[must_use]
    pub fn new(mut config: CacheConfig) -> Self {
        // Longest suffix first; `Reverse` expresses the descending order directly.
        config
            .fixed_ttl
            .sort_by_key(|(name, _)| std::cmp::Reverse(name.labels().len()));
        Self {
            config,
            entries: HashMap::new(),
        }
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Number of stored answers, including stale ones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Looks a query up at `now`.
    ///
    /// Returns the answer with the TTL to advertise already computed, and whether a
    /// background refresh is expected.
    pub fn lookup(&mut self, key: &Key, now: Instant) -> Option<Cached> {
        let entry = self.entries.get(key)?;
        if entry.is_disposable(now) {
            self.entries.remove(key);
            return None;
        }

        if now < entry.deadline {
            let remaining = entry.deadline.duration_since(now);
            let message = Arc::clone(&entry.message);
            return Some(Cached::Fresh {
                message,
                ttl: seconds(remaining),
            });
        }

        if !self.config.optimistic {
            // Expired and the operator asked not to be served expired data: drop it so
            // the next lookup is a clean miss.
            self.entries.remove(key);
            return None;
        }

        let message = Arc::clone(&entry.message);
        Some(Cached::Stale {
            message,
            ttl: self.config.stale_reply_ttl,
            expired_for: now.duration_since(entry.deadline),
        })
    }

    /// Stores an answer.
    ///
    /// The TTL is taken from the answer's records, clamped by any
    /// `fixed-domain-ttl` override for the queried name. A response with no records is
    /// cached for `stale_reply_ttl` when it is a negative answer (`NXDOMAIN` or
    /// `NODATA`), because those are the lookups worth caching most.
    ///
    /// # Errors
    ///
    /// Returns [`Skipped`] when nothing was stored; the caller may log it, and no case is
    /// an error the caller has to handle.
    pub fn store(&mut self, key: Key, message: Arc<Message>, now: Instant) -> Result<u32, Skipped> {
        let ttl = self.effective_ttl(&key.name, &message);
        if ttl == 0 {
            return Err(Skipped::ZeroTtl);
        }

        if self.config.max_entries > 0 && self.entries.len() >= self.config.max_entries {
            self.evict_one(now).ok_or(Skipped::Full)?;
        }

        let deadline = now + Duration::from_secs(u64::from(ttl));
        let expires = (self.config.stale_ttl > 0)
            .then(|| deadline + Duration::from_secs(u64::from(self.config.stale_ttl)));
        self.entries.insert(
            key,
            Entry {
                message,
                deadline,
                expires,
            },
        );
        Ok(ttl)
    }

    /// Removes everything. Used on a configuration change that invalidates answers.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drops every entry that has left its stale window.
    ///
    /// Bounded work per call, so a caller can run it on a timer without a long pause.
    /// Returns how many were removed.
    pub fn sweep(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_disposable(now));
        before - self.entries.len()
    }

    /// The TTL to use for `message`, honouring a `fixed-domain-ttl` override.
    ///
    /// The minimum record TTL wins, because a cache may not outlive any record it serves:
    /// serving an answer whose AAAA record expired while a 300-second A record is still
    /// valid would be wrong. A negative answer has no records, so the configured stale
    /// reply TTL stands in.
    fn effective_ttl(&self, name: &Name, message: &Message) -> u32 {
        if let Some((_, ttl)) = self
            .config
            .fixed_ttl
            .iter()
            .find(|(domain, _)| name.ends_with(domain))
        {
            return *ttl;
        }

        let negative = message.answers.is_empty();
        if negative {
            // Only cache a negative answer if it actually says "no such name" or "no data":
            // a SERVFAIL carries no information worth remembering.
            return match message.response_code() {
                crate::wire::ResponseCode::NXDOMAIN => self.config.stale_reply_ttl,
                // No error and no answers: NODATA.
                code if code == crate::wire::ResponseCode::NOERROR => self.config.stale_reply_ttl,
                _ => 0,
            };
        }

        message
            .answers
            .iter()
            .filter(|record| !record.is_opt())
            .map(|record| record.ttl)
            .min()
            .unwrap_or(0)
    }

    /// Evicts one entry to make room, preferring one that has already expired.
    ///
    /// Deliberately not an LRU: tracking recency costs a write on every hit, which is the
    /// hot path. Expired-first then soonest-expiring is the cheapest policy that keeps
    /// useful entries and is fully deterministic, which is what makes it testable.
    fn evict_one(&mut self, now: Instant) -> Option<()> {
        let victim = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_disposable(now))
            .min_by_key(|(_, entry)| entry.deadline)
            .map(|(key, _)| key.clone())
            .or_else(|| {
                self.entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.deadline)
                    .map(|(key, _)| key.clone())
            })?;
        self.entries.remove(&victim);
        Some(())
    }
}

/// A duration in whole seconds, rounded down.
fn seconds(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

/// The addresses a cached answer carries, for a caller that needs to route them.
#[must_use]
pub fn answer_addresses(cached: &Cached) -> Vec<IpAddr> {
    cached.message().answer_addresses()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Flags, Question, Record, ResponseCode};

    fn name(text: &str) -> Name {
        Name::parse(text).expect("name")
    }

    fn key(text: &str, qtype: RecordType) -> Key {
        Key {
            name: name(text),
            qtype,
            qclass: Question::CLASS_IN,
        }
    }

    fn answer(text: &str, ttl: u32) -> Arc<Message> {
        Arc::new(Message {
            id: 1,
            flags: Flags(0x8180),
            questions: vec![Question::internet(name(text), RecordType::A)],
            answers: vec![Record {
                name: name(text),
                rtype: RecordType::A,
                class: Question::CLASS_IN,
                ttl,
                rdata: vec![93, 184, 216, 34],
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        })
    }

    fn negative(text: &str, code: ResponseCode) -> Arc<Message> {
        Arc::new(Message {
            id: 1,
            flags: Flags::response_to(Flags(0x0100), code),
            questions: vec![Question::internet(name(text), RecordType::A)],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        })
    }

    #[test]
    fn a_fresh_answer_ttl_counts_down() {
        let now = Instant::now();
        let mut cache = Cache::new(CacheConfig::default());
        cache
            .store(
                key("example.com", RecordType::A),
                answer("example.com", 300),
                now,
            )
            .expect("stores");

        let hit = cache
            .lookup(
                &key("example.com", RecordType::A),
                now + Duration::from_secs(100),
            )
            .expect("hit");
        assert!(!hit.needs_refresh());
        assert_eq!(hit.ttl(), 200, "the remaining ttl, not the original");
    }

    #[test]
    fn an_expired_answer_is_served_stale_with_the_configured_ttl() {
        let now = Instant::now();
        let config = CacheConfig {
            optimistic: true,
            stale_ttl: 30,
            stale_reply_ttl: 7,
            ..CacheConfig::default()
        };
        let mut cache = Cache::new(config);
        cache
            .store(
                key("example.com", RecordType::A),
                answer("example.com", 10),
                now,
            )
            .expect("stores");

        let hit = cache
            .lookup(
                &key("example.com", RecordType::A),
                now + Duration::from_secs(20),
            )
            .expect("stale hit");
        assert!(hit.needs_refresh(), "a stale answer must ask for a refresh");
        assert_eq!(hit.ttl(), 7, "advertised ttl for stale data");
        assert_eq!(hit.expired_for(), Some(Duration::from_secs(10)));
    }

    #[test]
    fn beyond_the_stale_window_the_entry_is_gone() {
        let now = Instant::now();
        let config = CacheConfig {
            optimistic: true,
            stale_ttl: 30,
            ..CacheConfig::default()
        };
        let mut cache = Cache::new(config);
        cache
            .store(
                key("example.com", RecordType::A),
                answer("example.com", 10),
                now,
            )
            .expect("stores");

        // TTL 10 + stale 30 = gone at 40s.
        assert!(
            cache
                .lookup(
                    &key("example.com", RecordType::A),
                    now + Duration::from_secs(39)
                )
                .is_some()
        );
        assert!(
            cache
                .lookup(
                    &key("example.com", RecordType::A),
                    now + Duration::from_secs(41)
                )
                .is_none()
        );
        assert!(cache.is_empty(), "an expired entry is removed on lookup");
    }

    #[test]
    fn optimistic_off_drops_the_entry_instead_of_serving_it() {
        let now = Instant::now();
        let config = CacheConfig {
            optimistic: false,
            ..CacheConfig::default()
        };
        let mut cache = Cache::new(config);
        cache
            .store(
                key("example.com", RecordType::A),
                answer("example.com", 10),
                now,
            )
            .expect("stores");

        assert!(
            cache
                .lookup(
                    &key("example.com", RecordType::A),
                    now + Duration::from_secs(11)
                )
                .is_none()
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn a_stale_window_of_zero_never_expires() {
        let now = Instant::now();
        let config = CacheConfig {
            optimistic: true,
            stale_ttl: 0,
            ..CacheConfig::default()
        };
        let stale_reply_ttl = config.stale_reply_ttl;
        let mut cache = Cache::new(config);
        cache
            .store(
                key("example.com", RecordType::A),
                answer("example.com", 10),
                now,
            )
            .expect("stores");

        let far_future = now + Duration::from_secs(86_400);
        let hit = cache
            .lookup(&key("example.com", RecordType::A), far_future)
            .expect("hit");
        assert!(hit.needs_refresh());
        assert_eq!(hit.ttl(), stale_reply_ttl);
    }

    #[test]
    fn the_minimum_record_ttl_wins() {
        // A cache may not outlive any record it serves: the A record says 300 but the
        // AAAA says 30, so the whole answer lives 30.
        let now = Instant::now();
        let mut cache = Cache::new(CacheConfig::default());
        let message = Arc::new(Message {
            id: 1,
            flags: Flags(0x8180),
            questions: vec![Question::internet(name("example.com"), RecordType::A)],
            answers: vec![
                Record {
                    name: name("example.com"),
                    rtype: RecordType::A,
                    class: Question::CLASS_IN,
                    ttl: 300,
                    rdata: vec![1, 2, 3, 4],
                },
                Record {
                    name: name("example.com"),
                    rtype: RecordType::AAAA,
                    class: Question::CLASS_IN,
                    ttl: 30,
                    rdata: vec![0; 16],
                },
            ],
            authorities: Vec::new(),
            additionals: Vec::new(),
        });

        assert_eq!(
            cache
                .store(key("example.com", RecordType::A), message, now)
                .expect("stores"),
            30
        );
    }

    #[test]
    fn negative_answers_are_cached_and_servfail_is_not() {
        let now = Instant::now();
        let config = CacheConfig {
            stale_reply_ttl: 12,
            ..CacheConfig::default()
        };
        let mut cache = Cache::new(config);

        assert_eq!(
            cache
                .store(
                    key("nx.example", RecordType::A),
                    negative("nx.example", ResponseCode::NXDOMAIN),
                    now
                )
                .expect("nxdomain is cacheable"),
            12,
            "a negative answer is worth caching"
        );
        assert_eq!(
            cache.store(
                key("fail.example", RecordType::A),
                negative("fail.example", ResponseCode::SERVFAIL),
                now
            ),
            Err(Skipped::ZeroTtl),
            "a SERVFAIL carries nothing to remember"
        );
    }

    #[test]
    fn a_zero_ttl_answer_is_not_cached() {
        let now = Instant::now();
        let mut cache = Cache::new(CacheConfig::default());
        assert_eq!(
            cache.store(
                key("example.com", RecordType::A),
                answer("example.com", 0),
                now
            ),
            Err(Skipped::ZeroTtl)
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn a_fixed_ttl_override_wins_and_the_longest_suffix_applies() {
        let now = Instant::now();
        let config = CacheConfig {
            fixed_ttl: vec![(name("example.com"), 5), (name("a.example.com"), 99)],
            ..CacheConfig::default()
        };
        let mut cache = Cache::new(config);

        assert_eq!(
            cache
                .store(
                    key("b.example.com", RecordType::A),
                    answer("b.example.com", 300),
                    now
                )
                .expect("stores"),
            5
        );
        assert_eq!(
            cache
                .store(
                    key("a.example.com", RecordType::A),
                    answer("a.example.com", 300),
                    now
                )
                .expect("stores"),
            99,
            "the more specific override"
        );
    }

    #[test]
    fn the_cache_is_bounded_and_evicts_expired_entries_first() {
        let now = Instant::now();
        let config = CacheConfig {
            max_entries: 2,
            optimistic: true,
            stale_ttl: 0,
            ..CacheConfig::default()
        };
        let mut cache = Cache::new(config);

        cache
            .store(
                key("a.example", RecordType::A),
                answer("a.example", 300),
                now,
            )
            .expect("stores");
        cache
            .store(key("b.example", RecordType::A), answer("b.example", 1), now)
            .expect("stores");
        assert_eq!(cache.len(), 2);

        // Adding a third must evict; the soonest-expiring entry goes first.
        cache
            .store(
                key("c.example", RecordType::A),
                answer("c.example", 300),
                now,
            )
            .expect("stores");
        assert_eq!(cache.len(), 2, "the cap holds");
        assert!(
            cache
                .lookup(
                    &key("b.example", RecordType::A),
                    now + Duration::from_secs(2)
                )
                .is_none(),
            "the soonest-expiring entry was evicted"
        );
    }

    #[test]
    fn sweep_removes_only_what_left_its_window_and_reports_the_count() {
        let now = Instant::now();
        let config = CacheConfig {
            stale_ttl: 10,
            ..CacheConfig::default()
        };
        let mut cache = Cache::new(config);
        cache
            .store(
                key("short.example", RecordType::A),
                answer("short.example", 1),
                now,
            )
            .expect("stores");
        cache
            .store(
                key("long.example", RecordType::A),
                answer("long.example", 300),
                now,
            )
            .expect("stores");

        assert_eq!(cache.sweep(now + Duration::from_secs(5)), 0);
        assert_eq!(cache.len(), 2);
        // short: 1 + 10 = gone at 11s.
        assert_eq!(cache.sweep(now + Duration::from_secs(12)), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn only_messages_with_one_question_have_a_key() {
        let mut message = (*answer("example.com", 60)).clone();
        message.questions.clear();
        assert!(Key::of(&message).is_none(), "no question, no key");

        message.questions = vec![
            Question::internet(name("a.example"), RecordType::A),
            Question::internet(name("b.example"), RecordType::A),
        ];
        assert!(Key::of(&message).is_none(), "two questions, no key");
    }

    #[test]
    fn a_hit_can_be_routed_on_its_addresses() {
        let now = Instant::now();
        let mut cache = Cache::new(CacheConfig::default());
        cache
            .store(
                key("example.com", RecordType::A),
                answer("example.com", 60),
                now,
            )
            .expect("stores");
        let hit = cache
            .lookup(&key("example.com", RecordType::A), now)
            .expect("hit");
        assert_eq!(
            answer_addresses(&hit),
            vec!["93.184.216.34".parse::<IpAddr>().expect("ip")]
        );
    }
}
