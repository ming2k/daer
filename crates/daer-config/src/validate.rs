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
    Config, ElectionKind, FunctionOrString, ProbeMode, ProviderType, SCHEMA_VERSION, WanInterface,
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

    check_host(config)?;
    check_groups(config)?;
    check_elections(config)?;
    check_routing(config)?;
    check_dns(config)?;
    check_endpoints(config)?;
    check_nodes(config)?;
    check_rule_providers(config)?;
    Ok(warnings)
}

fn check_host(config: &Config) -> Result<(), ConfigError> {
    // An empty `wan-interface` is unrunnable, and `daer check` has to say so.
    //
    // The daemon's own guard (`run::wait_for_interfaces`) refused it with "daer cannot know which
    // interface carries proxied traffic", so `check` — the command whose entire contract is "will
    // this configuration run" — reported a file as `ok` that `daer run` then exited on. This is
    // the same divergence as a builtin-named group, caught one layer later: validation has to be
    // the place a configuration is judged, or every caller grows its own idea of validity.
    match &config.wan_interface {
        WanInterface::Auto => {}
        WanInterface::Named(names) => {
            if names.is_empty() {
                return Err(ConfigError::new(
                    "wan-interface",
                    "must name at least one interface (use \"auto\" to follow the default route)",
                ));
            }
            let mut seen = BTreeSet::new();
            for name in names {
                let trimmed = name.trim();
                if trimmed.is_empty() {
                    return Err(ConfigError::new(
                        "wan-interface",
                        format!("names an empty interface ({name:?}); remove it or use \"auto\""),
                    ));
                }
                if !seen.insert(trimmed) {
                    return Err(ConfigError::new(
                        "wan-interface",
                        format!("names interface {trimmed:?} more than once"),
                    ));
                }
            }
        }
    }

    // One interface cannot be both the client ingress and the egress side: the
    // datapath has one role per hook, and the old combined-role classifiers were
    // removed. An explicit overlap is rejected here; `wan-interface = "auto"` is
    // checked again after the default route is resolved.
    if let WanInterface::Named(wan) = &config.wan_interface
        && let Some(interface) = config.lan_interface.iter().find(|lan| {
            // Loopback is the test/diagnostic interface and has no real
            // LAN/WAN role; the transparent-path fixtures use it for both.
            lan.trim() != "lo" && wan.iter().any(|wan| wan.trim() == lan.trim())
        })
    {
        return Err(ConfigError::new(
            "lan-interface",
            format!(
                "interface {interface:?} is both lan-interface and wan-interface; one interface \
                 cannot carry both roles in this build"
            ),
        ));
    }
    for (name, range) in [
        ("tls.fragment-length", &config.tls.fragment_length),
        ("tls.fragment-interval", &config.tls.fragment_interval),
    ] {
        if config.tls.fragment && !is_range_spec(range) {
            return Err(ConfigError::new(
                name,
                format!("{range:?} is not a `low-high` range"),
            ));
        }
    }
    if config.log_level.trim().is_empty() {
        return Err(ConfigError::new(
            "log-level",
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
        if daer_primitives::consts::is_builtin_outbound(&group.name) {
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
        if daer_primitives::consts::is_builtin_outbound(&election.name) {
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

        // A manual election is never scheduled for probing: the scheduler skips it, and
        // `daer probe node` is the on-demand path for a pinned node. Accepting probe
        // settings here would create keys that cannot take effect (ADR-0006).
        let has_probe_settings = election.mode.is_some()
            || election.url.is_some()
            || election.method.is_some()
            || election.udp_dns.is_some()
            || election.interval.is_some()
            || election.timeout.is_some();
        if election.kind == ElectionKind::Manual && has_probe_settings {
            return Err(ConfigError::new(
                "election.probe",
                format!(
                    "election {:?} is manual and is never probed; remove the probe settings or \
                     use `daer probe node` for on-demand measurement",
                    election.name
                ),
            ));
        }
        if election.tolerance.is_some() && election.kind != ElectionKind::MinMovingAvg {
            return Err(ConfigError::new(
                "election.tolerance",
                format!(
                    "election {:?} sets `tolerance`, which only changes the switch threshold of \
                     type = \"min-moving-avg\"",
                    election.name
                ),
            ));
        }

        let probe = election.resolved_probe();
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

/// Rule identity and action targets.
///
/// A rule's name is what `daer route --why`, logs and tests use; a duplicate is
/// ambiguity. An action is typed, so an election must be declared and a group is
/// never a valid target.
fn check_routing(config: &Config) -> Result<(), ConfigError> {
    let mut names = BTreeSet::new();
    let has_explicit_domain_rule = config.routing.rule.iter().any(|rule| {
        rule.match_expr
            .and_functions
            .iter()
            .any(|function| function.name == "domain")
    });

    check_sniff_shape(config, has_explicit_domain_rule)?;

    for (index, rule) in config.routing.rule.iter().enumerate() {
        let name = rule.name.trim();
        if name.is_empty() {
            return Err(ConfigError::new(
                "routing.rule.name",
                format!("rule {index} has an empty name; every rule needs an identity"),
            ));
        }
        if !names.insert(name) {
            return Err(ConfigError::new(
                "routing.rule.name",
                format!("duplicate routing rule name {name:?}"),
            ));
        }

        if rule.match_expr.and_functions.is_empty() {
            return Err(ConfigError::new(
                "routing.rule.match",
                format!("rule {name:?} has an empty match expression"),
            ));
        }

        check_action_target(config, &rule.action, "routing.rule.action")?;
    }

    check_action_target(config, &config.routing.default, "routing.default")
}

/// Validates the shape of `[routing.sniff]`.
///
/// The rule-dependent half (a domain rule requires an explicit answer) also runs here for
/// explicit `domain(...)` rules, and again in `daer-control::domain::DomainPlan` after rule
/// providers are lowered. The second pass is what catches a domain set contributed by a
/// provider, which the raw configuration cannot see.
fn check_sniff_shape(config: &Config, has_explicit_domain_rule: bool) -> Result<(), ConfigError> {
    let sniff = &config.routing.sniff;

    if has_explicit_domain_rule && sniff.enabled.is_none() {
        return Err(ConfigError::new(
            "routing.sniff.enabled",
            "a domain(...) rule requires an explicit answer: set enabled = true to allow \
             bounded payload inspection, or enabled = false to route by the facts already known",
        ));
    }
    if has_explicit_domain_rule && sniff.enabled == Some(false) && config.dns.bind.is_none() {
        return Err(ConfigError::new(
            "routing.sniff.enabled",
            "domain(...) rules have no name source: set enabled = true or configure [dns].bind",
        ));
    }

    match (sniff.enabled, sniff.timeout) {
        (Some(true), None) => Err(ConfigError::new(
            "routing.sniff.timeout",
            "enabled = true requires a positive timeout (for example \"30ms\")",
        )),
        (Some(true), Some(timeout)) if timeout.as_nanos() <= 0 => Err(ConfigError::new(
            "routing.sniff.timeout",
            format!("must be a positive duration (got \"{timeout}\")"),
        )),
        (Some(false), Some(_)) => Err(ConfigError::new(
            "routing.sniff.timeout",
            "enabled = false does not inspect payload; remove timeout",
        )),
        (None, Some(_)) => Err(ConfigError::new(
            "routing.sniff.timeout",
            "timeout has no effect without enabled = true",
        )),
        _ => Ok(()),
    }
}

/// Checks that an action is a built-in or a declared election.
///
/// This is the one target check shared by configuration validation, generation
/// construction, and `daer check`/`daer route`. A group is a candidate pool, never
/// a routing target.
pub fn check_action_target(
    config: &Config,
    action: &crate::model::OutboundAction,
    field: &'static str,
) -> Result<(), ConfigError> {
    let Some(election) = action.election_name() else {
        return Ok(());
    };
    if config
        .election
        .iter()
        .any(|declared| declared.name == election)
    {
        return Ok(());
    }
    if config.group.iter().any(|group| group.name == election) {
        return Err(ConfigError::new(
            field,
            format!(
                "{election:?} is a group (a candidate pool), not a routing action; add \
                 [[election]] name = \"{election}\" group = \"{election}\""
            ),
        ));
    }
    Err(ConfigError::new(
        field,
        format!("election {election:?} is not declared; add [[election]] name = \"{election}\""),
    ))
}

fn check_dns(config: &mut Config) -> Result<(), ConfigError> {
    let dns = &mut config.dns;

    // Fake-IP is an answer mode of the DNS server, not a routing mode. Without a listener
    // there is no channel to hand a synthetic address to a client and no reverse mapping to
    // read later, so enabling it alone used to start an implicit `0.0.0.0:53` listener.
    // That side effect is gone: the listener is the operator's explicit decision.
    if dns.fake_ip.enabled && dns.bind.is_none() {
        return Err(ConfigError::new(
            "dns.fake-ip.enabled",
            "Fake-IP requires an explicit [dns].bind; a synthetic address is only useful when \
             daer answers the client's queries",
        ));
    }
    if dns.bind.is_some() && dns.upstream.is_empty() {
        return Err(ConfigError::new(
            "dns.upstream",
            "[dns].bind starts the resolver but no upstream is declared; add at least one \
             upstream or remove bind",
        ));
    }

    if dns.optimistic_cache_ttl.is_negative() {
        return Err(ConfigError::new(
            "dns.optimistic-cache-ttl",
            "must not be negative",
        ));
    }
    if dns.optimistic_stale_reply_ttl.is_negative() {
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
    if let Some((domain, ttl)) = dns
        .fixed_domain_ttl
        .iter()
        .find(|(_, ttl)| ttl.is_negative())
    {
        return Err(ConfigError::new(
            "dns.fixed-domain-ttl",
            format!("{domain}: TTL must not be negative (got {ttl})"),
        ));
    }

    if dns.request.default.is_none() {
        dns.request.default = Some(FunctionOrString::Name("asis".to_owned()));
    }
    if dns.response.default.is_none() {
        dns.response.default = Some(FunctionOrString::Name("accept".to_owned()));
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
/// Built-in policy names are routing verdicts, not node labels.
///
/// A node named `direct` or `block` would make `daer probe node direct`, `daer elect`, and the
/// rule compiler disagree about what the name means. The datapath already reserves the ids, so
/// the configuration must not create a second owner.
fn check_reserved_node_name(name: &str) -> Result<(), ConfigError> {
    if daer_primitives::consts::is_builtin_outbound(name) {
        return Err(ConfigError::new(
            "node.name",
            format!("{name:?} is a built-in routing policy, not a node name; choose another name"),
        ));
    }
    Ok(())
}

fn check_nodes(config: &Config) -> Result<(), ConfigError> {
    let mut names = BTreeSet::new();
    for node in &config.node {
        let name = node
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty());
        if let Some(name) = name {
            check_reserved_node_name(name)?;
            if !names.insert(name.to_owned()) {
                return Err(ConfigError::new(
                    "node.name",
                    format!("duplicate node name {name:?}; a detour must name exactly one node"),
                ));
            }
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
        check_reserved_node_name(name)?;
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
                "rule-set.name",
                "rule set name must not be empty",
            ));
        }
        if !names.insert(name) {
            return Err(ConfigError::new(
                "rule-set.name",
                format!("duplicate rule set name {:?}", provider.name),
            ));
        }
        match provider.provider_type {
            ProviderType::File => {
                let Some(path) = &provider.path else {
                    return Err(ConfigError::new(
                        "rule-set.path",
                        format!("file provider {:?} must specify 'path'", provider.name),
                    ));
                };
                if path.trim().is_empty() {
                    return Err(ConfigError::new(
                        "rule-set.path",
                        format!("empty path for file provider {:?}", provider.name),
                    ));
                }
            }
            ProviderType::Http => {
                let Some(url) = &provider.url else {
                    return Err(ConfigError::new(
                        "rule-set.url",
                        format!("http provider {:?} must specify 'url'", provider.name),
                    ));
                };
                if url.trim().is_empty() {
                    return Err(ConfigError::new(
                        "rule-set.url",
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
                    "rule-set.interval",
                    format!(
                        "file provider {:?} must not set 'interval': a file has no background \
                         checks, so remove the key or declare an http provider",
                        provider.name
                    ),
                ));
            }
            if interval.as_nanos() <= 0 {
                return Err(ConfigError::new(
                    "rule-set.interval",
                    format!(
                        "interval must be positive (got \"{}\") for rule set {:?}",
                        interval, provider.name
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
