// SPDX-License-Identifier: AGPL-3.0-only

//! The one way to load a configuration for the data path (ADR-0006).
//!
//! # Why this exists as a function rather than as a step in the CLI
//!
//! `daer run` and `daer config validate` must read the **same** configuration. When they did
//! not, the daemon skipped subscription resolution while the diagnostic performed it, so
//! `daer route nodes` listed nodes the daemon had never heard of and `daer route explain`
//! confidently answered about a node pool that did not exist. A diagnostic that disagrees with
//! the thing it diagnoses is worse than no diagnostic.
//!
//! # The one async, fallible step
//!
//! Parsing is synchronous and total; resolving subscriptions is neither. A subscription failure
//! is a *warning* when a cache can supply the nodes and an error only when nothing can, which is
//! the same rule the fetch path uses: a body that cannot be read must never silently become an
//! empty node list, because "no nodes" and "could not read the nodes" lead an operator to
//! opposite conclusions.

use std::path::{Path, PathBuf};

use daer_config::toml_config::{self, Loaded};

use crate::subscription::{Resolution, resolve_subscriptions, resolve_subscriptions_with};

/// A configuration with every subscription resolved, plus what to tell the operator.
#[derive(Debug)]
pub struct Resolved {
    /// The parsed and resolved configuration.
    pub config: daer_config::Config,
    /// Every file that contributed, entry first.
    pub files: Vec<PathBuf>,
    /// Warnings from the loader and from subscription resolution.
    pub warnings: Vec<String>,
    /// What the subscriptions produced, for a caller that wants to report it.
    pub subscriptions: Resolution,
}

impl Resolved {
    /// The directory the configuration lives in, which is where assets and the subscription
    /// cache are looked for.
    #[must_use]
    pub fn directory(&self) -> PathBuf {
        self.files
            .first()
            .and_then(|path| path.parent())
            .filter(|parent| !parent.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }
}

/// Loads `path` and folds every `[[subscription]]` into the node pool.
///
/// # Errors
///
/// Returns a message when the file cannot be read or parsed, and when a subscription produced no
/// nodes *and* no cache could supply them. A subscription that fails while a cache exists is a
/// warning, because the alternative is taking a working proxy down over one unreachable URL.
pub async fn load_resolved(path: &Path) -> anyhow::Result<Resolved> {
    let mut warnings = Vec::new();
    let Loaded {
        files,
        config,
        warnings: loader_warnings,
        ..
    } = toml_config::load(path)
        .map_err(|error| anyhow::anyhow!("failed to load {}: {error}", path.display()))?;
    warnings.extend(loader_warnings);

    let directory = files
        .first()
        .and_then(|path| path.parent())
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let mut config = config;
    let subscriptions = resolve_subscriptions(&mut config, &directory).await;
    if !subscriptions.subscriptions.is_empty() {
        if subscriptions.all_usable() {
            warnings.push(format!(
                "subscriptions: {} ({} node(s) added)",
                subscriptions.describe(),
                subscriptions.from_subscription
            ));
        } else {
            let failed = subscriptions.failed().len();
            let total = subscriptions.subscriptions.len();
            anyhow::bail!(
                "{failed} of {total} subscription(s) produced no node and no cache could supply \
                 one: {}",
                subscriptions.describe()
            );
        }
    }

    warn_about_empty_groups(&config, &mut warnings);
    Ok(Resolved {
        config,
        files,
        warnings,
        subscriptions,
    })
}

/// Warns about groups that select no node.
///
/// # Why this lives in the loader rather than in a CLI subcommand
///
/// The daemon needs it for the same reason `daer config validate` does: a group with no members
/// is a configuration that proxies nothing, and the operator has to learn that at load time from
/// whichever entry point they used. It used to exist only in the validator, so `daer run` started
/// happily on a configuration it could not serve and the only symptom was traffic going nowhere.
///
/// A group selecting nothing is a **warning**, not an error: an operator may be staging a
/// subscription, and refusing to start would be a worse outcome than serving the rules that do
/// work.
pub fn warn_about_empty_groups(config: &daer_config::Config, warnings: &mut Vec<String>) {
    for group in &config.group {
        let matched = config
            .node
            .iter()
            .filter(|node| group_mentions_node(group, node))
            .count();
        if matched == 0 {
            warnings.push(format!(
                "group {:?} selects no node from the {} declared node(s); every flow routed to \
                 it will fail",
                group.name,
                config.node.len()
            ));
        }
    }
}
///
/// # Errors
///
/// Same as [`load_resolved`].
pub async fn load_resolved_with(
    path: &Path,
    timeout: std::time::Duration,
) -> anyhow::Result<Resolved> {
    let mut warnings = Vec::new();
    let Loaded {
        files,
        config,
        warnings: loader_warnings,
        ..
    } = toml_config::load(path)
        .map_err(|error| anyhow::anyhow!("failed to load {}: {error}", path.display()))?;
    warnings.extend(loader_warnings);

    let directory = files
        .first()
        .and_then(|path| path.parent())
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let mut config = config;
    let subscriptions = resolve_subscriptions_with(&mut config, &directory, timeout).await;
    if !subscriptions.subscriptions.is_empty() && !subscriptions.all_usable() {
        let failed = subscriptions.failed().len();
        let total = subscriptions.subscriptions.len();
        anyhow::bail!(
            "{failed} of {total} subscription(s) produced no node and no cache could supply \
             one: {}",
            subscriptions.describe()
        );
    }

    warn_about_empty_groups(&config, &mut warnings);
    Ok(Resolved {
        config,
        files,
        warnings,
        subscriptions,
    })
}

/// Whether `group`'s filters admit `node`.
///
/// Shared by the daemon (which builds the group), `daer config validate` (which warns about an
/// empty group) and `daer route nodes`, so all three agree about the node pool. The subscription
/// provenance is part of the property for exactly that reason: a `subtag(...)` filter that read
/// `""` made the validator and the data path disagree about which nodes a group contains.
pub fn group_mentions_node(group: &daer_config::Group, node: &daer_config::Node) -> bool {
    if group.filters.is_empty() {
        return true;
    }
    let property = daer_outbound::Property::from_node(node);
    let filters: Vec<Vec<daer_config::Function>> = group
        .filters
        .iter()
        .map(|filter| filter.functions.clone())
        .collect();
    let annotations: Vec<Vec<daer_config::Param>> = group
        .filters
        .iter()
        .map(|filter| filter.annotate.clone())
        .collect();
    let Ok(set) = daer_outbound::FilterSet::compile(&filters, &annotations) else {
        // A filter that does not compile is reported by `validate_groups`.
        return true;
    };
    set.matches(&property.name, &property.subscription_tag)
        .is_some()
}
