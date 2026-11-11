// SPDX-License-Identifier: AGPL-3.0-only

//! Resolving `[[rule-provider]]` into the routing rule provider pool (ADR-0014).
//!
//! # Why this is a separate step
//!
//! A generation is a **pure function of a configuration**: given the same
//! `Config`, `Router::new` must produce the same router with no network I/O and
//! no clock. Rule providers are resolved before the generation is built.
//!
//! # Failure policy
//!
//! An HTTP provider that cannot be fetched **does not fail the configuration** if a
//! local cache can supply its DRB set: network unavailability must not take a
//! working proxy down at restart. It is reported with a warning.
//!
//! If no cache exists and the provider cannot be fetched or read, it fails
//! validation or load with a clear error.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use daer_config::{Config, ProviderFormat, ProviderType, RuleProvider};
use daer_routing::{DrbSet, RuleProviderPool};

/// How long one rule provider fetch may take.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Environment variable to override the rule cache directory.
pub const RULE_CACHE_ENV: &str = "DAER_RULE_CACHE_DIR";

/// Default directory where HTTP rule provider caches live.
///
/// The supported deployment is system-wide: `/var/cache/daer/rules`. The shipped unit
/// sets this explicitly, and `DAER_RULE_CACHE_DIR` overrides it for non-standard
/// installations. Cache writes are best-effort.
#[must_use]
pub fn cache_directory() -> PathBuf {
    if let Ok(dir) = std::env::var(RULE_CACHE_ENV)
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    PathBuf::from("/var/cache/daer/rules")
}

/// What resolving one `RuleProvider` produced.
#[derive(Debug, Clone)]
pub struct ResolvedRuleProvider {
    pub tag: String,
    pub provider_type: ProviderType,
    pub format: ProviderFormat,
    pub from_cache: bool,
    pub intervals: usize,
    pub domains: usize,
    pub error: Option<String>,
}

impl ResolvedRuleProvider {
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.error.is_none()
    }
}

impl fmt::Display for ResolvedRuleProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.tag)?;
        if let Some(err) = &self.error {
            write!(f, " [failed: {err}]")
        } else {
            write!(
                f,
                " [{} intervals, {} domains{}]",
                self.intervals,
                self.domains,
                if self.from_cache { ", from cache" } else { "" }
            )
        }
    }
}

/// Summary of rule provider resolution across all providers.
#[derive(Debug, Clone, Default)]
pub struct RuleProviderResolution {
    pub providers: Vec<ResolvedRuleProvider>,
    pub pool: Arc<RuleProviderPool>,
}

impl RuleProviderResolution {
    #[must_use]
    pub fn all_usable(&self) -> bool {
        self.providers.iter().all(ResolvedRuleProvider::is_usable)
    }

    #[must_use]
    pub fn failed(&self) -> Vec<&ResolvedRuleProvider> {
        self.providers.iter().filter(|p| !p.is_usable()).collect()
    }

    #[must_use]
    pub fn describe(&self) -> String {
        if self.providers.is_empty() {
            return "no rule providers".to_owned();
        }
        self.providers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// The declared background-refresh cadence of every HTTP provider (ADR-0014, ADR-0037).
///
/// # Why this type exists
///
/// `interval` is a **per-provider** contract: `docs/how-to/rule-providers.md` says a provider
/// that declares an interval is "periodically checked for updates in the background". The
/// reference configuration does declare different values (`24h` next to `168h`), so a single
/// global cadence would fetch the weekly provider seven times more often than asked.
///
/// This type is the only place that reads
/// [`RuleProvider::interval`](daer_config::RuleProvider::interval) for scheduling, which is
/// what keeps the key wired rather than merely parsed (ADR-0006).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderSchedule {
    entries: Vec<ProviderScheduleEntry>,
}

/// One scheduled provider: its tag and how often it may be re-fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderScheduleEntry {
    /// The `tag` that identifies the provider in the pool and in logs.
    pub tag: String,
    /// The declared cadence, always strictly positive.
    pub interval: Duration,
}

impl ProviderSchedule {
    /// Builds the schedule from a configuration, ignoring providers without a usable interval.
    ///
    /// A file provider never appears here: it has no background checks, and
    /// [`validate`](daer_config) rejects an `interval` on it rather than silently ignoring it.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let entries = config
            .rule_provider
            .iter()
            .filter(|provider| provider.provider_type == ProviderType::Http)
            .filter_map(|provider| {
                let interval = provider.interval?.as_std()?;
                (!interval.is_zero()).then(|| ProviderScheduleEntry {
                    tag: provider.tag.clone(),
                    interval,
                })
            })
            .collect();
        Self { entries }
    }

    /// The scheduled providers, in declaration order.
    #[must_use]
    pub fn entries(&self) -> &[ProviderScheduleEntry] {
        &self.entries
    }

    /// Whether any provider asked for background checks at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The shortest cadence, if any provider declared one.
    ///
    /// The supervisor sleeps for this long between wake-ups: waking on the shortest interval is
    /// the only cadence that lets every provider be checked *no later than* it asked for.
    /// [`ProviderSchedule::due`] then decides which providers the wake-up actually serves.
    #[must_use]
    pub fn min_interval(&self) -> Option<Duration> {
        self.entries.iter().map(|entry| entry.interval).min()
    }

    /// The providers that are due at `now`, for a generation that has waited since `last_seen`.
    ///
    /// `last_seen` reports how long ago each tag was last refreshed. A provider is due when
    /// it has never been refreshed, or when it has waited at least its own declared interval.
    /// This is the per-provider rule the single global ticker replaced.
    #[must_use]
    pub fn due(&self, last_seen: impl Fn(&str) -> Option<Duration>) -> Vec<&ProviderScheduleEntry> {
        self.entries
            .iter()
            .filter(|entry| match last_seen(&entry.tag) {
                None => true,
                Some(elapsed) => elapsed >= entry.interval,
            })
            .collect()
    }
}

/// Why one provider was refreshed, so the caller can tell a real change from a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The provider answered with new content; the rule set did change.
    Changed,
    /// The content was byte-for-byte the set already in use.
    Unchanged,
    /// The provider could not be fetched and no cache could stand in for it.
    Failed,
}

/// Resolves all `[[rule-provider]]` declarations in `config`.
pub async fn resolve_rule_providers(
    config: &Config,
    config_directory: &Path,
) -> RuleProviderResolution {
    resolve_rule_providers_with(config, config_directory, DEFAULT_TIMEOUT).await
}

/// Resolves all `[[rule-provider]]` declarations with an explicit timeout.
pub async fn resolve_rule_providers_with(
    config: &Config,
    config_directory: &Path,
    timeout: Duration,
) -> RuleProviderResolution {
    let mut resolution = RuleProviderResolution::default();
    if config.rule_provider.is_empty() {
        return resolution;
    }

    let cache_dir = cache_directory();
    let _ = fs::create_dir_all(&cache_dir);

    let mut pool = RuleProviderPool::new();

    for provider in &config.rule_provider {
        let tag = provider.tag.clone();
        let provider_type = provider.provider_type;
        let format = provider.format;
        // `provider.interval` is intentionally absent here: background refresh cadence is a
        // scheduling concern owned by `ProviderSchedule`, which reads the key for real
        // (ADR-0006, ADR-0037). Naming it here only to satisfy a lint would be the dead
        // binding that made the key look wired while it was not.

        match provider_type {
            ProviderType::File => {
                let Some(path_str) = &provider.path else {
                    resolution.providers.push(ResolvedRuleProvider {
                        tag,
                        provider_type,
                        format,
                        from_cache: false,
                        intervals: 0,
                        domains: 0,
                        error: Some("missing path for file provider".to_owned()),
                    });
                    continue;
                };

                let file_path = if Path::new(path_str).is_absolute() {
                    PathBuf::from(path_str)
                } else {
                    config_directory.join(path_str)
                };

                match load_file_provider(&file_path, &tag, format) {
                    Ok(set) => {
                        let intervals = set.v4_intervals.len() + set.v6_intervals.len();
                        let domains = set.domain_patterns();
                        pool.insert(tag.clone(), set);
                        resolution.providers.push(ResolvedRuleProvider {
                            tag,
                            provider_type,
                            format,
                            from_cache: false,
                            intervals,
                            domains,
                            error: None,
                        });
                    }
                    Err(err) => {
                        resolution.providers.push(ResolvedRuleProvider {
                            tag,
                            provider_type,
                            format,
                            from_cache: false,
                            intervals: 0,
                            domains: 0,
                            error: Some(err),
                        });
                    }
                }
            }
            ProviderType::Http => {
                let Some(url) = &provider.url else {
                    resolution.providers.push(ResolvedRuleProvider {
                        tag,
                        provider_type,
                        format,
                        from_cache: false,
                        intervals: 0,
                        domains: 0,
                        error: Some("missing url for http provider".to_owned()),
                    });
                    continue;
                };

                let cache_file = cache_dir.join(format!("{tag}.drb"));
                match fetch_http_provider(url, &cache_file, &tag, format, timeout).await {
                    Ok((set, from_cache)) => {
                        let intervals = set.v4_intervals.len() + set.v6_intervals.len();
                        let domains = set.domain_patterns();
                        pool.insert(tag.clone(), set);
                        resolution.providers.push(ResolvedRuleProvider {
                            tag,
                            provider_type,
                            format,
                            from_cache,
                            intervals,
                            domains,
                            error: None,
                        });
                    }
                    Err(err) => {
                        resolution.providers.push(ResolvedRuleProvider {
                            tag,
                            provider_type,
                            format,
                            from_cache: false,
                            intervals: 0,
                            domains: 0,
                            error: Some(err),
                        });
                    }
                }
            }
        }
    }

    resolution.pool = Arc::new(pool);
    resolution
}

fn load_file_provider(path: &Path, tag: &str, format: ProviderFormat) -> Result<DrbSet, String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    match format {
        ProviderFormat::Drb => DrbSet::decode(&bytes).map_err(|e| e.to_string()),
        ProviderFormat::Text => {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| format!("{} is not valid UTF-8 text", path.display()))?;
            DrbSet::from_text(tag, text).map_err(|e| e.to_string())
        }
    }
}

async fn fetch_http_provider(
    url: &str,
    cache_file: &Path,
    tag: &str,
    format: ProviderFormat,
    timeout: Duration,
) -> Result<(DrbSet, bool), String> {
    let etag_file = cache_file.with_extension("etag");
    let cached_etag = if cache_file.is_file() {
        fs::read_to_string(&etag_file)
            .ok()
            .map(|s| s.trim().to_owned())
    } else {
        None
    };

    // Attempt conditional network fetch
    match daer_outbound::subscription::fetch_body_conditional(url, cached_etag.as_deref(), timeout)
        .await
    {
        Ok(daer_outbound::subscription::FetchOutcome::NotModified) => {
            if cache_file.is_file()
                && let Ok(cached_bytes) = fs::read(cache_file)
                && let Ok(set) = DrbSet::decode(&cached_bytes)
            {
                daer_observe::debug!(daer_observe::EventCode::ProviderNotModified,
                    provider = %tag,
                    "rule provider not modified (HTTP 304); loaded from cached DRB"
                );
                return Ok((set, true));
            }
            Err(format!(
                "server answered 304 Not Modified but cache {} is missing or invalid",
                cache_file.display()
            ))
        }
        Ok(daer_outbound::subscription::FetchOutcome::Updated { bytes, etag }) => {
            let set = match format {
                ProviderFormat::Drb => DrbSet::decode(&bytes).map_err(|e| e.to_string())?,
                ProviderFormat::Text => {
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|_| "downloaded body is not valid UTF-8 text".to_owned())?;
                    DrbSet::from_text(tag, text).map_err(|e| e.to_string())?
                }
            };
            // Save compiled DRB artifact to disk cache
            let drb_bytes = set.encode();
            let _ = fs::write(cache_file, drb_bytes);
            if let Some(tag_str) = etag {
                let _ = fs::write(&etag_file, tag_str);
            }
            Ok((set, false))
        }
        Err(fetch_err) => {
            // Check if fallback cache exists
            if cache_file.is_file()
                && let Ok(cached_bytes) = fs::read(cache_file)
                && let Ok(set) = DrbSet::decode(&cached_bytes)
            {
                daer_observe::warn!(daer_observe::EventCode::ProviderCacheFallback,
                    %fetch_err,
                    provider = %tag,
                    cache = %cache_file.display(),
                    "rule provider fetch failed; loaded from cached DRB"
                );
                return Ok((set, true));
            }
            Err(format!(
                "fetch failed ({fetch_err}) and no valid cache available at {}",
                cache_file.display()
            ))
        }
    }
}

/// One provider re-fetched outside the load path, with the decision the caller needs.
#[derive(Debug)]
pub struct RefreshedProvider {
    /// The provider's tag, echoed so a caller can report without re-reading the config.
    pub tag: String,
    /// Whether the fetched rule set differs from the one already in use.
    pub outcome: RefreshOutcome,
    /// The freshly fetched set, present whenever the fetch succeeded.
    ///
    /// This is returned even when the content is unchanged so the caller can insert it and
    /// keep the pool's copy authoritative, but it must not trigger a generation swap.
    pub set: Option<DrbSet>,
    /// The fetch error, present only for [`RefreshOutcome::Failed`].
    pub error: Option<String>,
}

impl RefreshedProvider {
    /// Whether this refresh should cause a routing generation swap.
    #[must_use]
    pub fn requires_swap(&self) -> bool {
        self.outcome == RefreshOutcome::Changed
    }
}

/// Re-fetches one provider and compares the result with the set already in use.
///
/// # Why the comparison happens here
///
/// An HTTP provider that answers `304 Not Modified` yields the *same* rule set that is
/// already loaded. Rebuilding the routing generation for it would discard every measured
/// node latency and restart health probes for no reason (ADR-0037), so "did the content
/// change" has to be a first-class answer rather than an assumption.
pub async fn refresh_rule_provider(
    provider: &RuleProvider,
    config_directory: &Path,
    current: Option<&DrbSet>,
    timeout: Duration,
) -> RefreshedProvider {
    let tag = provider.tag.clone();
    let format = provider.format;

    let fetched = match provider.provider_type {
        ProviderType::File => match &provider.path {
            Some(raw) => {
                let path = Path::new(raw);
                let path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    config_directory.join(path)
                };
                load_file_provider(&path, &tag, format)
            }
            None => Err("missing path for file provider".to_owned()),
        },
        ProviderType::Http => match &provider.url {
            Some(url) => {
                let cache_file = cache_directory().join(format!("{tag}.drb"));
                let _ = fs::create_dir_all(cache_directory());
                fetch_http_provider(url, &cache_file, &tag, format, timeout)
                    .await
                    .map(|(set, _from_cache)| set)
            }
            None => Err("missing url for http provider".to_owned()),
        },
    };

    match fetched {
        Ok(set) => {
            let outcome = if current.is_some_and(|known| known == &set) {
                RefreshOutcome::Unchanged
            } else {
                RefreshOutcome::Changed
            };
            RefreshedProvider {
                tag,
                outcome,
                set: Some(set),
                error: None,
            }
        }
        Err(error) => RefreshedProvider {
            tag,
            outcome: RefreshOutcome::Failed,
            set: None,
            error: Some(error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daer_config::{RuleProvider, TimeSpan};

    #[tokio::test]
    async fn resolves_file_provider_text_and_drb() {
        let temp = std::env::temp_dir().join(format!("daer-rule-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&temp);
        let text_path = temp.join("direct.txt");
        fs::write(&text_path, "ip: 10.0.0.0/8\ncorp.lan\n").unwrap();

        let mut config = Config::default();
        config.rule_provider.push(RuleProvider {
            tag: "corp".to_owned(),
            provider_type: ProviderType::File,
            url: None,
            path: Some(text_path.to_str().unwrap().to_owned()),
            format: ProviderFormat::Text,
            interval: Some(TimeSpan::from_secs(3600)),
        });

        let res = resolve_rule_providers_with(&config, &temp, Duration::from_secs(1)).await;
        assert!(res.all_usable(), "resolution: {:?}", res.describe());
        assert_eq!(res.pool.len(), 1);

        let set = res.pool.get("corp").expect("found corp");
        assert_eq!(set.v4_intervals.len(), 1);
        assert_eq!(set.domain_patterns(), 1);

        let _ = fs::remove_dir_all(&temp);
    }

    #[tokio::test]
    async fn a_relative_file_provider_refreshes_from_the_config_directory() {
        let temp = std::env::temp_dir().join(format!("daer-refresh-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&temp);
        fs::write(temp.join("direct.txt"), "ip: 10.0.0.0/8\ncorp.lan\n").unwrap();
        let provider = RuleProvider {
            tag: "corp".to_owned(),
            provider_type: ProviderType::File,
            url: None,
            path: Some("direct.txt".to_owned()),
            format: ProviderFormat::Text,
            interval: None,
        };

        let refreshed = refresh_rule_provider(&provider, &temp, None, Duration::from_secs(1)).await;
        assert_eq!(refreshed.outcome, RefreshOutcome::Changed);
        let set = refreshed.set.expect("the relative path was resolved");
        assert_eq!(set.v4_intervals.len(), 1);
        assert_eq!(set.domain_patterns(), 1);

        let _ = fs::remove_dir_all(&temp);
    }

    /// Falsifier for the global-cadence defect (ADR-0037): with a `1h` and a `7h` provider, a
    /// single global ticker would mark the `7h` provider due after one hour. It must not be due.
    ///
    /// Negative control: the same query at `7h` *must* return it, so a `due` that never fires
    /// cannot pass this test.
    #[test]
    fn schedule_honours_each_provider_interval() {
        let mut config = Config::default();
        for (tag, seconds) in [("fast", 3600), ("slow", 7 * 3600)] {
            config.rule_provider.push(RuleProvider {
                tag: tag.to_owned(),
                provider_type: ProviderType::Http,
                url: Some(format!("https://example.invalid/{tag}.txt")),
                path: None,
                format: ProviderFormat::Text,
                interval: Some(TimeSpan::from_secs(seconds)),
            });
        }

        let schedule = ProviderSchedule::from_config(&config);
        assert_eq!(schedule.entries().len(), 2, "both providers scheduled");
        // Waking on the shortest cadence is what lets each provider be served on time.
        assert_eq!(schedule.min_interval(), Some(Duration::from_secs(3600)));

        // After one hour only the short provider is due.
        let due = schedule.due(|_| Some(Duration::from_secs(3600)));
        let tags: Vec<&str> = due.iter().map(|entry| entry.tag.as_str()).collect();
        assert_eq!(tags, ["fast"], "the 7h provider must not be fetched hourly");

        // Negative control: at seven hours both are due, so the filter is discriminating.
        let due = schedule.due(|_| Some(Duration::from_secs(7 * 3600)));
        assert_eq!(
            due.len(),
            2,
            "a due check that never fires cannot pass the case above"
        );

        // A provider never refreshed is always due, whatever its interval.
        let due = schedule.due(|_| None);
        assert_eq!(due.len(), 2);
    }

    /// A file provider has no background checks. It must not enter the schedule, and the
    /// validation layer rejects an `interval` on it instead of silently ignoring the key.
    #[test]
    fn schedule_ignores_file_providers_and_zero_intervals() {
        let mut config = Config::default();
        config.rule_provider.push(RuleProvider {
            tag: "f".to_owned(),
            provider_type: ProviderType::File,
            url: None,
            path: Some("/tmp/rules.txt".to_owned()),
            format: ProviderFormat::Text,
            interval: Some(TimeSpan::from_secs(60)),
        });
        config.rule_provider.push(RuleProvider {
            tag: "zero".to_owned(),
            provider_type: ProviderType::Http,
            url: Some("https://example.invalid/z.txt".to_owned()),
            path: None,
            format: ProviderFormat::Text,
            interval: Some(TimeSpan::ZERO),
        });
        config.rule_provider.push(RuleProvider {
            tag: "unset".to_owned(),
            provider_type: ProviderType::Http,
            url: Some("https://example.invalid/u.txt".to_owned()),
            path: None,
            format: ProviderFormat::Text,
            interval: None,
        });

        let schedule = ProviderSchedule::from_config(&config);
        assert!(
            schedule.is_empty(),
            "no usable HTTP interval: {:?}",
            schedule
        );
        assert_eq!(schedule.min_interval(), None);
    }

    /// The content gate: an unchanged rule set must not require a generation swap, while a
    /// changed one must. Without the negative control the first half would be vacuous.
    #[test]
    fn unchanged_content_does_not_require_a_swap() {
        let unchanged = RefreshedProvider {
            tag: "p".to_owned(),
            outcome: RefreshOutcome::Unchanged,
            set: Some(DrbSet::default()),
            error: None,
        };
        assert!(
            !unchanged.requires_swap(),
            "a 304 must not restart the world"
        );

        let changed = RefreshedProvider {
            tag: "p".to_owned(),
            outcome: RefreshOutcome::Changed,
            set: Some(DrbSet::default()),
            error: None,
        };
        assert!(
            changed.requires_swap(),
            "real content must reach the data path"
        );

        let failed = RefreshedProvider {
            tag: "p".to_owned(),
            outcome: RefreshOutcome::Failed,
            set: None,
            error: Some("boom".to_owned()),
        };
        assert!(
            !failed.requires_swap(),
            "a failure keeps the running rule set"
        );
    }
}
