// SPDX-License-Identifier: AGPL-3.0-only

//! Semantic checks.
//!
//! The TOML loader's job is syntax; this module applies the defaults and rejects
//! values that cannot be honoured. Nothing is repaired silently: a value that has
//! no meaning is an error, because a configuration that says one thing while the
//! daemon does another is worse than a failed start.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use crate::model::{
    Config, ElectionKind, FunctionOrString, ProbeMode, ProviderType, SCHEMA_VERSION,
};

/// A semantic error, attributed to the field that caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub field: &'static str,
    pub message: String,
}

impl ConfigError {
    pub(crate) fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ConfigError {}

/// True for the HTTP methods the probe may use.
#[must_use]
pub fn is_valid_http_method(method: &str) -> bool {
    matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD")
}

/// A conservative probe URL check: `http(s)://host[:port][/path]`.
///
/// `daer-config` cannot depend on `daer-outbound` (which depends on this crate), so
/// the full parser lives where the request is issued. This gate rejects the values
/// that could never be a request before the daemon starts; the scheduler still uses
/// the one authoritative parser.
fn is_valid_probe_url(url: &str) -> bool {
    let url = url.trim();
    if url.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return false;
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, rest)) = bracketed.split_once(']') else {
            return false;
        };
        if host.is_empty() {
            return false;
        }
        return match rest {
            "" => true,
            port => port
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok()),
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
        None => true,
    }
}

/// Applies defaults, then rejects values that cannot be honored.
///
/// # Errors
///
/// Returns the first semantic error found. Checks that only produce warnings
/// (currently just the compatible-mode HTTP method fallback) are returned as
/// strings.
pub fn normalize(config: &mut Config) -> Result<Vec<String>, ConfigError> {
    let warnings = Vec::new();

    if config.schema != SCHEMA_VERSION {
        return Err(ConfigError::new(
            "schema",
            format!(
                "unknown schema version {}; this build understands {SCHEMA_VERSION}",
                config.schema
            ),
        ));
    }

    check_global(config)?;
    check_groups(config)?;
    check_elections(config)?;
    check_dns(config)?;
    check_endpoints(config)?;
    check_nodes(config)?;
    check_rule_providers(config)?;
    Ok(warnings)
}

fn check_global(config: &mut Config) -> Result<(), ConfigError> {
    let probe = &config.global.probe;
    let method = &probe.method;
    if !is_valid_http_method(method) {
        return Err(ConfigError::new(
            "global.probe.method",
            format!("unknown HTTP method {method:?}; this build issues GET or HEAD"),
        ));
    }

    if probe.interval.is_negative() {
        return Err(ConfigError::new(
            "global.probe.interval",
            format!("must not be negative (got \"{}\")", probe.interval),
        ));
    }
    if probe.timeout.as_nanos() <= 0 {
        return Err(ConfigError::new(
            "global.probe.timeout",
            format!("must be a positive duration (got \"{}\")", probe.timeout),
        ));
    }
    if let Some(url) = &probe.url
        && !is_valid_probe_url(url)
    {
        return Err(ConfigError::new(
            "global.probe.url",
            format!("{url:?} is not an http(s) URL"),
        ));
    }
    if probe.mode == ProbeMode::Server && probe.url.is_some() {
        return Err(ConfigError::new(
            "global.probe.url",
            "a server-mode probe does not request a URL; set mode = \"url\" or remove the URL",
        ));
    }
    if probe.mode == ProbeMode::Url && probe.url.is_none() {
        return Err(ConfigError::new(
            "global.probe.url",
            "a url-mode probe requires a URL",
        ));
    }
    // An empty `wan-interface` is unrunnable, and `daer check` has to say so.
    //
    // The daemon's own guard (`run::wait_for_interfaces`) refused it with "daer cannot know which
    // interface carries proxied traffic", so `check` — the command whose entire contract is "will
    // this configuration run" — reported a file as `ok` that `daer run` then exited on. This is
    // the same divergence as a builtin-named group, caught one layer later: validation has to be
    // the place a configuration is judged, or every caller grows its own idea of validity.
    if config.global.wan_interface.is_empty() {
        return Err(ConfigError::new(
            "global.wan-interface",
            "must name at least one interface (use [\"auto\"] to follow the default route)",
        ));
    }
    if let Some(blank) = config
        .global
        .wan_interface
        .iter()
        .find(|entry| entry.trim().is_empty())
    {
        return Err(ConfigError::new(
            "global.wan-interface",
            format!("names an empty interface ({blank:?}); remove it or use \"auto\""),
        ));
    }
    for (name, range) in [
        (
            "global.tls.fragment-length",
            &config.global.tls.fragment_length,
        ),
        (
            "global.tls.fragment-interval",
            &config.global.tls.fragment_interval,
        ),
    ] {
        if config.global.tls.fragment && !is_range_spec(range) {
            return Err(ConfigError::new(
                name,
                format!("{range:?} is not a `low-high` range"),
            ));
        }
    }
    if config.global.log_level.trim().is_empty() {
        return Err(ConfigError::new(
            "global.log-level",
            "must be a tracing filter directive",
        ));
    }
    Ok(())
}

/// `50-100`: two non-negative integers separated by a dash.
fn is_range_spec(spec: &str) -> bool {
    let Some((low, high)) = spec.split_once('-') else {
        return false;
    };
    match (low.trim().parse::<u32>(), high.trim().parse::<u32>()) {
        (Ok(low), Ok(high)) => low <= high,
        _ => false,
    }
}

fn check_groups(config: &Config) -> Result<(), ConfigError> {
    let mut seen = BTreeSet::new();
    for group in &config.group {
        if group.name.trim().is_empty() {
            return Err(ConfigError::new("group.name", "must not be empty"));
        }
        // A group is a resource pool, not a routing target. It still shares the global
        // outbound namespace with elections and builtins, so a name that can never be
        // routed to is a trap; reject it at the same place the user can fix it.
        if daer_common::consts::is_builtin_outbound(&group.name) {
            return Err(ConfigError::new(
                "group.name",
                format!(
                    "{:?} is a built-in outbound name and is reserved; rename the group \
                     (for example \"{}-pool\")",
                    group.name, group.name
                ),
            ));
        }
        if !seen.insert(group.name.as_str()) {
            return Err(ConfigError::new(
                "group.name",
                format!("duplicate group {:?}", group.name),
            ));
        }
    }
    Ok(())
}

fn check_elections(config: &Config) -> Result<(), ConfigError> {
    let groups: BTreeSet<&str> = config
        .group
        .iter()
        .map(|group| group.name.as_str())
        .collect();
    let mut seen = BTreeSet::new();

    for election in &config.election {
        let field = "election.name";
        if election.name.trim().is_empty() {
            return Err(ConfigError::new(field, "must not be empty"));
        }
        if daer_common::consts::is_builtin_outbound(&election.name) {
            return Err(ConfigError::new(
                field,
                format!(
                    "{:?} is a built-in outbound and cannot be redeclared as an election",
                    election.name
                ),
            ));
        }
        if !seen.insert(election.name.as_str()) {
            return Err(ConfigError::new(
                field,
                format!("duplicate election {:?}", election.name),
            ));
        }
        if groups.contains(election.name.as_str()) {
            return Err(ConfigError::new(
                field,
                format!(
                    "election {:?} collides with a group of the same name; groups are resource \
                     pools and elections are routing targets, so keep the names distinct",
                    election.name
                ),
            ));
        }

        match (&election.group, &election.node) {
            (Some(group), None) => {
                if !groups.contains(group.as_str()) {
                    return Err(ConfigError::new(
                        "election.group",
                        format!("election {:?} names unknown group {group:?}", election.name),
                    ));
                }
                if election.kind == ElectionKind::Manual {
                    return Err(ConfigError::new(
                        "election.type",
                        format!(
                            "election {:?} is manual but its input is a group; a manual election \
                             must name a node input, or use `daer elect` for a runtime override",
                            election.name
                        ),
                    ));
                }
            }
            (None, Some(_)) => {}
            (Some(_), Some(_)) => {
                return Err(ConfigError::new(
                    "election.input",
                    format!(
                        "election {:?} sets both `group` and `node`; an election has exactly one \
                         input",
                        election.name
                    ),
                ));
            }
            (None, None) => {
                return Err(ConfigError::new(
                    "election.input",
                    format!(
                        "election {:?} sets neither `group` nor `node`; an election needs one \
                         candidate set",
                        election.name
                    ),
                ));
            }
        }

        let probe = election.resolved_probe(&config.global.probe);
        if !is_valid_http_method(&probe.method) {
            return Err(ConfigError::new(
                "election.method",
                format!(
                    "election {:?}: unknown HTTP method {:?}; this build issues GET or HEAD",
                    election.name, probe.method
                ),
            ));
        }
        if probe.interval.is_negative() {
            return Err(ConfigError::new(
                "election.interval",
                format!(
                    "election {:?}: interval must not be negative (got \"{}\")",
                    election.name, probe.interval
                ),
            ));
        }
        if probe.timeout.as_nanos() <= 0 {
            return Err(ConfigError::new(
                "election.timeout",
                format!(
                    "election {:?}: timeout must be positive (got \"{}\")",
                    election.name, probe.timeout
                ),
            ));
        }
        if probe.mode == ProbeMode::Url && probe.url.is_none() {
            return Err(ConfigError::new(
                "election.url",
                format!(
                    "election {:?} uses mode = \"url\" but has no URL",
                    election.name
                ),
            ));
        }
        if probe.mode == ProbeMode::Url
            && let Some(url) = &probe.url
            && !is_valid_probe_url(url)
        {
            return Err(ConfigError::new(
                "election.url",
                format!(
                    "election {:?}: {url:?} is not an http(s) URL",
                    election.name
                ),
            ));
        }
        if probe.mode == ProbeMode::Server && election.url.is_some() {
            return Err(ConfigError::new(
                "election.url",
                format!(
                    "election {:?} sets a URL but mode is \"server\"; set mode = \"url\" or \
                     remove the URL",
                    election.name
                ),
            ));
        }
        if election.kind.needs_measurement() && probe.interval.as_nanos() == 0 {
            return Err(ConfigError::new(
                "election.interval",
                format!(
                    "election {:?} ranks by latency but probing is disabled (interval = 0s); \
                     enable probing or choose type = \"random\"",
                    election.name
                ),
            ));
        }
    }
    Ok(())
}

fn check_dns(config: &mut Config) -> Result<(), ConfigError> {
    let dns = &mut config.dns;
    if !matches!(dns.ipversion_prefer, 0 | 4 | 6) {
        return Err(ConfigError::new(
            "dns.ipversion-prefer",
            format!("must be 4, 6 or 0 (got {})", dns.ipversion_prefer),
        ));
    }
    if dns.optimistic_cache_ttl < 0 {
        return Err(ConfigError::new(
            "dns.optimistic-cache-ttl",
            "must not be negative",
        ));
    }
    if dns.optimistic_stale_reply_ttl < 0 {
        return Err(ConfigError::new(
            "dns.optimistic-stale-reply-ttl",
            "must not be negative",
        ));
    }
    if dns.max_cache_size < 0 {
        return Err(ConfigError::new(
            "dns.max-cache-size",
            "must not be negative",
        ));
    }
    if let Some((domain, ttl)) = dns.fixed_domain_ttl.iter().find(|(_, ttl)| **ttl < 0) {
        return Err(ConfigError::new(
            "dns.fixed-domain-ttl",
            format!("{domain}: TTL must not be negative (got {ttl})"),
        ));
    }

    if dns.request.fallback.is_none() {
        dns.request.fallback = Some(FunctionOrString::Name("asis".to_owned()));
    }
    if dns.response.fallback.is_none() {
        dns.response.fallback = Some(FunctionOrString::Name("accept".to_owned()));
    }
    Ok(())
}

fn check_endpoints(config: &Config) -> Result<(), ConfigError> {
    for (name, url) in config
        .subscription
        .iter()
        .map(|sub| (sub.name.as_deref(), &sub.url))
    {
        if url.trim().is_empty() {
            return Err(ConfigError::new(
                "subscription.url",
                format!(
                    "empty URL for subscription {:?}",
                    name.unwrap_or("<unnamed>")
                ),
            ));
        }
    }
    for subscription in &config.subscription {
        if let Some(detour) = &subscription.detour
            && detour.trim().is_empty()
        {
            return Err(ConfigError::new(
                "subscription.detour",
                "detour must name a node, not an empty string",
            ));
        }
    }
    for node in &config.node {
        node.endpoint
            .validate()
            .map_err(|e| ConfigError::new("node", e))?;
    }
    Ok(())
}

/// Checks the parts of a detour graph that can be known before subscriptions are resolved.
///
/// A `detour` may name a node that only a subscription will supply, so this pass deliberately
/// stops at "the reference is syntactically usable". [`validate_chain_graph`] is the second,
/// stricter pass, run after the node pool is complete (and again by the router, which is the
/// generation's single source of truth).
fn check_nodes(config: &Config) -> Result<(), ConfigError> {
    let mut names = BTreeSet::new();
    for node in &config.node {
        let name = node
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty());
        if let Some(name) = name
            && !names.insert(name.to_owned())
        {
            return Err(ConfigError::new(
                "node.name",
                format!("duplicate node name {name:?}; a detour must name exactly one node"),
            ));
        }
        if let Some(detour) = &node.detour {
            let detour = detour.trim();
            if detour.is_empty() {
                return Err(ConfigError::new(
                    "node.detour",
                    "detour must name a node name, not an empty string",
                ));
            }
            if Some(detour) == name {
                return Err(ConfigError::new(
                    "node.detour",
                    format!("node {detour:?} cannot detour through itself"),
                ));
            }
            if matches!(node.endpoint, crate::model::NodeEndpoint::Direct(_)) {
                return Err(ConfigError::new(
                    "node.detour",
                    "a direct node has no server leg to replace; remove detour and route to \
                     the inner node's group instead",
                ));
            }
        }
    }
    Ok(())
}

/// Validates the complete node graph after every subscription has been resolved.
///
/// This is the check that makes `detour` a DAG rather than a runtime recursion: every target
/// must exist, names must be unique, and no path may return to a node it already visited. It is
/// called by `daer_control::load_resolved` and by `Router::new`, so the daemon and every
/// diagnostic reach the same verdict (ADR-0006, ADR-0044).
///
/// # Errors
///
/// Returns [`ConfigError`] naming the node whose `detour` is broken and the chain that breaks.
pub fn validate_chain_graph(config: &Config) -> Result<(), ConfigError> {
    let mut names: HashMap<&str, usize> = HashMap::with_capacity(config.node.len());
    for (index, node) in config.node.iter().enumerate() {
        let Some(name) = node
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        if names.insert(name, index).is_some() {
            return Err(ConfigError::new(
                "node.name",
                format!("duplicate node name {name:?}; a detour must name exactly one node"),
            ));
        }
    }

    for node in &config.node {
        let Some(detour) = node.detour.as_deref().map(str::trim) else {
            continue;
        };
        if matches!(node.endpoint, crate::model::NodeEndpoint::Direct(_)) {
            return Err(ConfigError::new(
                "node.detour",
                "a direct node has no server leg to replace; remove detour and route to the \
                 inner node's group instead",
            ));
        }
        if !names.contains_key(detour) {
            return Err(ConfigError::new(
                "node.detour",
                format!(
                    "node {:?} detours through {detour:?}, but no [[node]] declares that name",
                    node.label()
                ),
            ));
        }
    }

    // 0 = unvisited, 1 = on the current path, 2 = proven acyclic.
    let mut state = vec![0u8; config.node.len()];
    let mut path = Vec::new();
    for index in 0..config.node.len() {
        visit(index, config, &names, &mut state, &mut path)?;
    }
    Ok(())
}

fn visit(
    index: usize,
    config: &Config,
    names: &HashMap<&str, usize>,
    state: &mut [u8],
    path: &mut Vec<usize>,
) -> Result<(), ConfigError> {
    match state[index] {
        2 => return Ok(()),
        1 => {
            let start = path
                .iter()
                .position(|visited| *visited == index)
                .unwrap_or(0);
            let mut chain: Vec<String> = path[start..]
                .iter()
                .map(|visited| config.node[*visited].label())
                .collect();
            chain.push(config.node[index].label());
            return Err(ConfigError::new(
                "node.detour",
                format!("detour cycle: {}", chain.join(" -> ")),
            ));
        }
        _ => {}
    }
    state[index] = 1;
    path.push(index);
    if let Some(detour) = config.node[index].detour.as_deref() {
        let target = names.get(detour).copied().ok_or_else(|| {
            ConfigError::new(
                "node.detour",
                format!(
                    "node {:?} detours through {detour:?}, but no [[node]] declares that name",
                    config.node[index].label()
                ),
            )
        })?;
        visit(target, config, names, state, path)?;
    }
    path.pop();
    state[index] = 2;
    Ok(())
}

fn check_rule_providers(config: &Config) -> Result<(), ConfigError> {
    let mut names = BTreeSet::new();
    for provider in &config.rule_provider {
        let name = provider.name.trim();
        if name.is_empty() {
            return Err(ConfigError::new(
                "rule-provider.name",
                "rule provider name must not be empty",
            ));
        }
        if !names.insert(name) {
            return Err(ConfigError::new(
                "rule-provider.name",
                format!("duplicate rule provider name {:?}", provider.name),
            ));
        }
        match provider.provider_type {
            ProviderType::File => {
                let Some(path) = &provider.path else {
                    return Err(ConfigError::new(
                        "rule-provider.path",
                        format!("file provider {:?} must specify 'path'", provider.name),
                    ));
                };
                if path.trim().is_empty() {
                    return Err(ConfigError::new(
                        "rule-provider.path",
                        format!("empty path for file provider {:?}", provider.name),
                    ));
                }
            }
            ProviderType::Http => {
                let Some(url) = &provider.url else {
                    return Err(ConfigError::new(
                        "rule-provider.url",
                        format!("http provider {:?} must specify 'url'", provider.name),
                    ));
                };
                if url.trim().is_empty() {
                    return Err(ConfigError::new(
                        "rule-provider.url",
                        format!("empty URL for http provider {:?}", provider.name),
                    ));
                }
            }
        }
        if let Some(interval) = provider.interval {
            // A file provider has no background checks, so an interval on it would be a key
            // that is accepted and then never acted on. Rejecting it by name is the ADR-0006
            // "removed" branch: the operator learns the truth at validation time, not by
            // watching a daemon that silently ignores the declaration.
            if provider.provider_type == ProviderType::File {
                return Err(ConfigError::new(
                    "rule-provider.interval",
                    format!(
                        "file provider {:?} must not set 'interval': a file has no background \
                         checks, so remove the key or declare an http provider",
                        provider.name
                    ),
                ));
            }
            if interval.as_nanos() <= 0 {
                return Err(ConfigError::new(
                    "rule-provider.interval",
                    format!(
                        "interval must be positive (got \"{}\") for rule provider {:?}",
                        interval, provider.name
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        Config::default()
    }

    #[test]
    fn rejects_an_unknown_schema() {
        let mut config = valid();
        config.schema = 99;
        let error = normalize(&mut config).expect_err("must fail");
        assert_eq!(error.field, "schema");
    }

    #[test]
    fn an_unknown_http_method_is_rejected() {
        let mut config = valid();
        config.global.probe.method = "BREW".to_owned();
        let error = normalize(&mut config).expect_err("must fail");
        assert_eq!(error.field, "global.probe.method");
    }

    #[test]
    fn an_election_url_mode_requires_a_url() {
        let mut config = valid();
        config.election = vec![crate::model::Election {
            name: "proxy".to_owned(),
            group: None,
            node: Some("n".to_owned()),
            kind: crate::model::ElectionKind::Min,
            mode: Some(crate::model::ProbeMode::Url),
            url: None,
            method: None,
            udp_dns: None,
            interval: Some(crate::TimeSpan::from_secs(30)),
            timeout: Some(crate::TimeSpan::from_secs(5)),
            tolerance: None,
        }];
        let error = normalize(&mut config).expect_err("url mode needs a URL");
        assert_eq!(error.field, "election.url");
    }

    #[test]
    fn a_server_mode_election_cannot_carry_a_url() {
        let mut config = valid();
        config.global.probe.url = None;
        config.election = vec![crate::model::Election {
            name: "proxy".to_owned(),
            group: None,
            node: Some("n".to_owned()),
            kind: crate::model::ElectionKind::Min,
            mode: Some(crate::model::ProbeMode::Server),
            url: Some("https://example.com/".to_owned()),
            method: None,
            udp_dns: None,
            interval: Some(crate::TimeSpan::from_secs(30)),
            timeout: Some(crate::TimeSpan::from_secs(5)),
            tolerance: None,
        }];
        let error = normalize(&mut config).expect_err("server mode cannot carry a URL");
        assert_eq!(error.field, "election.url");
    }

    #[test]
    fn a_latency_election_cannot_disable_probing() {
        let mut config = valid();
        config.election = vec![crate::model::Election {
            name: "proxy".to_owned(),
            group: None,
            node: Some("n".to_owned()),
            kind: crate::model::ElectionKind::Min,
            mode: None,
            url: None,
            method: None,
            udp_dns: None,
            interval: Some(crate::TimeSpan::ZERO),
            timeout: None,
            tolerance: None,
        }];
        let error = normalize(&mut config).expect_err("a latency election needs probes");
        assert_eq!(error.field, "election.interval");
    }

    #[test]
    fn dns_fallbacks_are_defaulted() {
        let mut config = valid();
        assert!(config.dns.request.fallback.is_none());
        normalize(&mut config).expect("valid");
        assert_eq!(
            config.dns.request.fallback,
            Some(FunctionOrString::Name("asis".to_owned()))
        );
        assert_eq!(
            config.dns.response.fallback,
            Some(FunctionOrString::Name("accept".to_owned()))
        );
    }

    #[test]
    fn duplicate_and_empty_group_names_are_rejected() {
        let mut config = valid();
        config.group = vec![
            crate::model::Group {
                name: "a".to_owned(),
                filters: Vec::new(),
            },
            crate::model::Group {
                name: "a".to_owned(),
                filters: Vec::new(),
            },
        ];
        assert!(normalize(&mut config).is_err());
    }

    /// A group may not shadow a builtin outbound.
    ///
    /// The falsifier is the observed divergence: `[[group]] name = "direct"` with one node
    /// pointing at a dead SOCKS port loaded fine, `daer route` reported that node as the
    /// selected outbound, and the daemon dialled the flow *directly* and returned the origin's
    /// bytes. Either the name is the builtin everywhere or it is an error everywhere; the
    /// configuration is not allowed to mean two things.
    /// An empty `wan-interface` is rejected here, not only by the daemon.
    ///
    /// The falsifier is one command pair: `printf 'schema = 2\n[global]\nwan-interface = []\n'`
    /// used to be `check` → `ok` and `run` → exit 1, so the gate that promises "will this
    /// configuration run" disagreed with the process that runs it. The default is `["auto"]`,
    /// which is why a plain `schema = 2` file still passes.
    #[test]
    fn an_empty_wan_interface_fails_validation_even_though_the_default_is_not_empty() {
        let mut config = valid();
        config.global.wan_interface = Vec::new();
        let error = normalize(&mut config).expect_err("the daemon cannot honour this");
        assert_eq!(error.field, "global.wan-interface");

        // The control: the defaults pass, so the check is about the empty list and not about
        // `wan-interface` being present at all.
        let mut config = valid();
        normalize(&mut config).expect("the default [\"auto\"] must still validate");

        // And a blank entry, which `run` would otherwise try to resolve as an interface name.
        let mut config = valid();
        config.global.wan_interface = vec!["  ".to_owned()];
        let error = normalize(&mut config).expect_err("a blank interface name is not a name");
        assert_eq!(error.field, "global.wan-interface");
    }

    #[test]
    fn a_group_may_not_shadow_a_builtin_outbound() {
        for name in ["direct", "block", "must_rules", "<OR>", "<AND>"] {
            let mut config = valid();
            config.group = vec![crate::model::Group {
                name: name.to_owned(),
                filters: Vec::new(),
            }];
            let error = normalize(&mut config)
                .expect_err("a group named after a builtin outbound must be rejected");
            assert_eq!(error.field, "group.name", "{name}: {error}");
            assert!(
                error.message.contains("built-in"),
                "{name}: the message must say why: {error}"
            );

            // The control: the same group under a name that is not reserved loads.
            let mut config = valid();
            config.group = vec![crate::model::Group {
                name: format!("proxy-{name}"),
                filters: Vec::new(),
            }];
            normalize(&mut config).expect("a non-reserved name is fine");
        }
    }

    fn node(name: &str, detour: Option<&str>) -> crate::model::Node {
        let mut node = crate::model::Node::from_link(&format!("socks5://127.0.0.1:1080#{name}"))
            .expect("node parses");
        node.detour = detour.map(str::to_owned);
        node
    }

    #[test]
    fn a_detour_chain_is_a_valid_dag() {
        let mut config = valid();
        config.node = vec![node("outer", Some("inner")), node("inner", None)];
        normalize(&mut config).expect("parses");
        validate_chain_graph(&config).expect("a two-node chain is acyclic");
    }

    #[test]
    fn an_unknown_detour_target_is_rejected_after_resolution() {
        let mut config = valid();
        config.node = vec![node("outer", Some("missing"))];
        // The first pass cannot decide existence: a subscription may add the target later.
        normalize(&mut config).expect("syntactically usable");
        let error = validate_chain_graph(&config).expect_err("no such node");
        assert_eq!(error.field, "node.detour");
        assert!(error.message.contains("missing"), "{error}");
    }

    #[test]
    fn a_detour_cycle_is_rejected_with_the_path() {
        let mut config = valid();
        config.node = vec![node("a", Some("b")), node("b", Some("a"))];
        normalize(&mut config).expect("syntactically usable");
        let error = validate_chain_graph(&config).expect_err("cycle");
        assert_eq!(error.field, "node.detour");
        assert!(error.message.contains("cycle"), "{error}");
        assert!(error.message.contains("a"), "{error}");
        assert!(error.message.contains("b"), "{error}");
    }

    #[test]
    fn a_node_cannot_detour_through_itself() {
        let mut config = valid();
        config.node = vec![node("a", Some("a"))];
        let error = normalize(&mut config).expect_err("self detour");
        assert_eq!(error.field, "node.detour");
        assert!(error.message.contains("itself"), "{error}");
    }

    #[test]
    fn duplicate_node_names_are_rejected_because_detour_needs_one_target() {
        let mut config = valid();
        config.node = vec![node("same", None), node("same", None)];
        let error = normalize(&mut config).expect_err("ambiguous target");
        assert_eq!(error.field, "node.name");
        // The control: a chain with distinct names is accepted.
        config.node = vec![node("a", Some("b")), node("b", None)];
        normalize(&mut config).expect("distinct names are fine");
    }
}
