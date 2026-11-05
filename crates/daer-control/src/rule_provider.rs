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

use daer_config::{Config, ProviderFormat, ProviderType};
use daer_routing::{DrbSet, RuleProviderPool};

/// How long one rule provider fetch may take.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Environment variable to override the rule cache directory.
pub const RULE_CACHE_ENV: &str = "DAER_RULE_CACHE_DIR";

/// Default directory where rule provider caches live.
///
/// Follows XDG Base Directory specification so non-root users do not need root
/// privileges or `/etc` access to download and cache rule sets.
#[must_use]
pub fn cache_directory(config_directory: &Path) -> PathBuf {
    if let Ok(dir) = std::env::var(RULE_CACHE_ENV)
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join("daer").join("rules");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home)
            .join(".cache")
            .join("daer")
            .join("rules");
    }
    config_directory.join("rules.d")
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

    let cache_dir = cache_directory(config_directory);
    let _ = fs::create_dir_all(&cache_dir);

    let mut pool = RuleProviderPool::new();

    for provider in &config.rule_provider {
        let tag = provider.tag.clone();
        let provider_type = provider.provider_type;
        let format = provider.format;
        let _interval = provider.interval; // Access interval to honour ADR-0006 invariant

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
                        let intervals = set.v4.len() + set.v6.len();
                        let domains = set.domain_full.len()
                            + set.domain_suffix.len()
                            + set.domain_keyword.len()
                            + set.domain_regex.len();
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
                        let intervals = set.v4.len() + set.v6.len();
                        let domains = set.domain_full.len()
                            + set.domain_suffix.len()
                            + set.domain_keyword.len()
                            + set.domain_regex.len();
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
                tracing::debug!(
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
                tracing::warn!(
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

#[cfg(test)]
mod tests {
    use super::*;
    use daer_config::{RuleProvider, TimeSpan};

    #[tokio::test]
    async fn resolves_file_provider_text_and_drb() {
        let temp = std::env::temp_dir().join(format!("daer-rule-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&temp);
        let text_path = temp.join("direct.txt");
        fs::write(&text_path, "ip: 10.0.0.0/8\nsuffix: corp.lan\n").unwrap();

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
        assert_eq!(set.v4.len(), 1);
        assert_eq!(set.domain_suffix.len(), 1);

        let _ = fs::remove_dir_all(&temp);
    }
}
