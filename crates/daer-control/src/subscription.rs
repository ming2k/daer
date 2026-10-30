// SPDX-License-Identifier: AGPL-3.0-only

//! Resolving `[[subscription]]` into the node pool.
//!
//! # Why this is a separate step
//!
//! A generation is a **pure function of a configuration**: given the same
//! `Config`, `Router::new` must produce the same router, with no I/O and no clock.
//! That is what makes a reload atomic and a decision reproducible, and it is the
//! property the handover and explain tests rely on.
//!
//! Fetching is the opposite — network I/O, timeouts, a mutable cache — so it
//! happens *before* a generation is built and its result is folded into
//! `config.node`. By the time `Router::new` runs, a subscription is
//! indistinguishable from an inline `[[node]]`.
//!
//! ```text
//!   Config (with [[subscription]])
//!         │  resolve_subscriptions()   ← the only async, fallible step
//!         ▼
//!   Config (node pool = inline + fetched)
//!         │  Generations::reload()     ← pure, synchronous, testable
//!         ▼
//!   Router
//! ```
//!
//! # Failure policy
//!
//! A subscription that cannot be fetched **does not fail the configuration** if a
//! cache can supply its nodes: a flaky endpoint must not take a working proxy down
//! at restart. It *is* reported, per subscription, with the tag and the reason.
//!
//! If no cache exists and nothing was fetched, that subscription contributed zero
//! nodes. The caller decides whether that is fatal — `daer config validate` treats
//! it as an error, because a validation that passes a configuration with no usable
//! nodes is a validation nobody should trust.

use std::path::PathBuf;
use std::time::Duration;

use daer_config::{Config, Node};
use daer_outbound::subscription::{self, ResolvedSubscription};

/// How long one subscription fetch may take, end to end.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Where persisted subscription caches live.
///
/// Beside the configuration file, not in a system cache directory: the cache is a
/// copy of the operator's node list, and it must move with the configuration it
/// belongs to (a `/etc/daer` tree copied to another host keeps working).
#[must_use]
pub fn cache_directory(config_directory: &std::path::Path) -> PathBuf {
    config_directory.join("persist.d")
}

/// What resolving a configuration's subscriptions did.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    /// One entry per declared subscription, in configuration order.
    pub subscriptions: Vec<ResolvedSubscription>,
    /// Node tags that came from a subscription, so a report can say where a node
    /// came from.
    pub from_subscription: usize,
}

impl Resolution {
    /// True when every declared subscription produced at least one node.
    #[must_use]
    pub fn all_usable(&self) -> bool {
        self.subscriptions.iter().all(|sub| sub.is_usable())
    }

    /// The subscriptions that produced no node.
    #[must_use]
    pub fn failed(&self) -> Vec<&ResolvedSubscription> {
        self.subscriptions
            .iter()
            .filter(|sub| !sub.is_usable())
            .collect()
    }

    /// A one-line summary per subscription, safe to log.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.subscriptions.is_empty() {
            return "no subscriptions".to_owned();
        }
        self.subscriptions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Folds every `[[subscription]]` in `config` into `config.node`.
///
/// Inline nodes keep their position and their tags; fetched nodes follow, tagged
/// with the subscription's tag. Filter groups use `subtag(...)`, so the tag is what
/// makes a fetched node selectable — losing it would silently make every
/// subscription node invisible to every filter.
pub async fn resolve_subscriptions(
    config: &mut Config,
    config_directory: &std::path::Path,
) -> Resolution {
    resolve_subscriptions_with(config, config_directory, DEFAULT_TIMEOUT).await
}

/// [`resolve_subscriptions`] with an explicit timeout, for tests and for a caller
/// that knows its network is slow.
pub async fn resolve_subscriptions_with(
    config: &mut Config,
    config_directory: &std::path::Path,
    timeout: Duration,
) -> Resolution {
    if config.subscription.is_empty() {
        return Resolution::default();
    }

    let cache = cache_directory(config_directory);
    let resolved =
        subscription::resolve(&config.subscription, Some(cache.as_path()), timeout).await;

    // Inline nodes first: an operator's explicit list is the authority, and a
    // subscription that happens to repeat a tag must not shadow it.
    let mut added = 0usize;
    for entry in &resolved {
        for (index, url) in entry.links.iter().enumerate() {
            let tag = if entry.links.len() == 1 {
                entry.tag.clone()
            } else {
                format!("{}/{index}", entry.tag)
            };
            config.node.push(Node {
                tag: Some(tag),
                url: url.clone(),
                // The provenance `subtag(...)` matches on. Filling it here is what makes a
                // subscription node selectable at all.
                subscription: Some(entry.tag.clone()),
            });
            added += 1;
        }
    }

    Resolution {
        subscriptions: resolved,
        from_subscription: added,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(source: &str) -> Config {
        daer_config::toml_config::load_str(source).expect("config")
    }

    #[tokio::test]
    async fn a_configuration_without_subscriptions_is_untouched() {
        let mut config = config_with("schema = 1\n[[node]]\nurl = \"socks5://127.0.0.1:1080\"\n");
        let before = config.node.len();
        let resolution =
            resolve_subscriptions_with(&mut config, std::path::Path::new("."), Duration::ZERO)
                .await;
        assert_eq!(config.node.len(), before);
        assert!(resolution.subscriptions.is_empty());
        assert!(resolution.all_usable(), "vacuously true");
        assert_eq!(resolution.describe(), "no subscriptions");
    }

    #[tokio::test]
    async fn a_failing_subscription_with_no_cache_contributes_nothing_and_says_so() {
        // Port 1 on loopback refuses instantly, so this test needs no network.
        let mut config = config_with(
            "schema = 1\n[[subscription]]\ntag = \"dead\"\nurl = \"http://127.0.0.1:1/sub\"\n",
        );
        let directory =
            std::env::temp_dir().join(format!("daer-sub-resolve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);

        let resolution =
            resolve_subscriptions_with(&mut config, &directory, Duration::from_millis(500)).await;

        assert!(config.node.is_empty(), "nothing was fetched");
        assert_eq!(resolution.subscriptions.len(), 1);
        assert!(!resolution.all_usable());
        assert_eq!(resolution.failed().len(), 1);
        let rendered = resolution.describe();
        assert!(rendered.contains("dead"), "{rendered}");
        assert!(
            rendered.contains("0 node"),
            "the report must state the outcome: {rendered}"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn a_subscription_restores_from_cache_when_the_fetch_fails() {
        // The operational case that matters: the endpoint is down at restart.
        let directory = std::env::temp_dir().join(format!("daer-sub-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let cache = daer_outbound::subscription::Cache::new(cache_directory(&directory), "tag");
        cache
            .write(&["ss://YWVzLTI1Ni1nY206cA@1.2.3.4:8388#cached".to_owned()])
            .expect("writes");

        let mut config = config_with(
            "schema = 1\n[[subscription]]\ntag = \"tag\"\nurl = \"http://127.0.0.1:1/sub\"\npersist = true\n",
        );
        let resolution =
            resolve_subscriptions_with(&mut config, &directory, Duration::from_millis(500)).await;

        assert_eq!(config.node.len(), 1, "the cache supplied the node");
        assert!(resolution.subscriptions[0].from_cache);
        assert!(resolution.all_usable());
        assert!(
            resolution.subscriptions[0].error.is_some(),
            "the fetch failure is still reported"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn fetched_nodes_are_tagged_with_the_subscription() {
        // `subtag(...)` filters are the only way a group selects subscription nodes,
        // so a node without its tag is a node no group can reach.
        let directory = std::env::temp_dir().join(format!("daer-sub-tags-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let cache = daer_outbound::subscription::Cache::new(cache_directory(&directory), "mysub");
        cache
            .write(&[
                "ss://YWVzLTI1Ni1nY206cA@1.2.3.4:8388#a".to_owned(),
                "ss://YWVzLTI1Ni1nY206cA@1.2.3.5:8388#b".to_owned(),
            ])
            .expect("writes");

        let mut config = config_with(
            "schema = 1\n[[subscription]]\ntag = \"mysub\"\nurl = \"http://127.0.0.1:1/sub\"\npersist = true\n",
        );
        let _ =
            resolve_subscriptions_with(&mut config, &directory, Duration::from_millis(500)).await;

        assert_eq!(config.node.len(), 2);
        for node in &config.node {
            let tag = node.tag.as_deref().expect("every fetched node is tagged");
            assert!(tag.starts_with("mysub/"), "{tag}");
        }
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_cache_lives_beside_the_configuration() {
        let directory = cache_directory(std::path::Path::new("/etc/daer"));
        assert_eq!(directory, std::path::Path::new("/etc/daer/persist.d"));
    }
}
