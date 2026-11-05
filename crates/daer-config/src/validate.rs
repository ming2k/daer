// SPDX-License-Identifier: AGPL-3.0-only

//! Semantic checks.
//!
//! The TOML loader's job is syntax; this module applies the defaults and rejects
//! values that cannot be honoured. Nothing is repaired silently: a value that has
//! no meaning is an error, because a configuration that says one thing while the
//! daemon does another is worse than a failed start.

use std::collections::BTreeSet;
use std::fmt;

use crate::model::{Config, FunctionOrString, ProviderType, SCHEMA_VERSION};

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

/// True for the HTTP methods the health-check probe may use.
#[must_use]
pub fn is_valid_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET"
            | "POST"
            | "PUT"
            | "PATCH"
            | "DELETE"
            | "COPY"
            | "HEAD"
            | "OPTIONS"
            | "LINK"
            | "UNLINK"
            | "PURGE"
            | "LOCK"
            | "UNLOCK"
            | "PROPFIND"
            | "CONNECT"
            | "TRACE"
    )
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
    check_dns(config)?;
    check_endpoints(config)?;
    check_rule_providers(config)?;
    Ok(warnings)
}

fn check_global(config: &mut Config) -> Result<(), ConfigError> {
    let method = &config.global.health_check.tcp_method;
    if !is_valid_http_method(method) {
        return Err(ConfigError::new(
            "global.health-check.tcp-method",
            format!("unknown HTTP method {method:?}"),
        ));
    }

    if config.global.health_check.interval.as_nanos() <= 0 {
        return Err(ConfigError::new(
            "global.health-check.interval",
            format!(
                "must be a positive duration (got \"{}\")",
                config.global.health_check.interval
            ),
        ));
    }
    if config.global.health_check.tcp_url.is_empty() {
        return Err(ConfigError::new(
            "global.health-check.tcp-url",
            "must list at least one URL",
        ));
    }
    if config.global.tproxy_port == 0 {
        return Err(ConfigError::new(
            "global.tproxy-port",
            "must not be 0: the eBPF program redirects to this port",
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
        // A group that shadows a builtin outbound is not an override: the compiled program
        // resolves the name to the builtin, so the group's nodes are unreachable while
        // `daer route`/`daer check --nodes` report them as selected. Rejecting it at load time
        // is the only outcome that keeps the configuration and the daemon saying the same thing.
        if daer_common::consts::is_builtin_outbound(&group.name) {
            return Err(ConfigError::new(
                "group.name",
                format!(
                    "{:?} is a built-in outbound and cannot be redeclared as a group; rename it \
                     (for example \"proxy-{}\") and route to that name instead",
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
        group
            .policy
            .as_function()
            .map_err(|message| ConfigError::new("group.policy", message))?;
        if let Some(interval) = group.health_check.interval
            && interval.is_negative()
        {
            return Err(ConfigError::new(
                "group.health-check.interval",
                format!(
                    "must not be negative (got \"{interval}\") for group {:?}",
                    group.name
                ),
            ));
        }
        if let Some(method) = &group.health_check.tcp_method
            && !is_valid_http_method(method)
        {
            return Err(ConfigError::new(
                "group.health-check.tcp-method",
                format!("unknown HTTP method {method:?} for group {:?}", group.name),
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
    for (tag, url) in config
        .subscription
        .iter()
        .map(|sub| (sub.tag.as_deref(), &sub.url))
    {
        if url.trim().is_empty() {
            return Err(ConfigError::new(
                "subscription.url",
                format!(
                    "empty URL for subscription {:?}",
                    tag.unwrap_or("<untagged>")
                ),
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

fn check_rule_providers(config: &Config) -> Result<(), ConfigError> {
    let mut tags = BTreeSet::new();
    for provider in &config.rule_provider {
        let tag = provider.tag.trim();
        if tag.is_empty() {
            return Err(ConfigError::new(
                "rule-provider.tag",
                "rule provider tag must not be empty",
            ));
        }
        if !tags.insert(tag) {
            return Err(ConfigError::new(
                "rule-provider.tag",
                format!("duplicate rule provider tag {:?}", provider.tag),
            ));
        }
        match provider.provider_type {
            ProviderType::File => {
                let Some(path) = &provider.path else {
                    return Err(ConfigError::new(
                        "rule-provider.path",
                        format!("file provider {:?} must specify 'path'", provider.tag),
                    ));
                };
                if path.trim().is_empty() {
                    return Err(ConfigError::new(
                        "rule-provider.path",
                        format!("empty path for file provider {:?}", provider.tag),
                    ));
                }
            }
            ProviderType::Http => {
                let Some(url) = &provider.url else {
                    return Err(ConfigError::new(
                        "rule-provider.url",
                        format!("http provider {:?} must specify 'url'", provider.tag),
                    ));
                };
                if url.trim().is_empty() {
                    return Err(ConfigError::new(
                        "rule-provider.url",
                        format!("empty URL for http provider {:?}", provider.tag),
                    ));
                }
            }
        }
        if let Some(interval) = provider.interval
            && interval.as_nanos() <= 0
        {
            return Err(ConfigError::new(
                "rule-provider.interval",
                format!(
                    "interval must be positive (got \"{}\") for rule provider {:?}",
                    interval, provider.tag
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        let mut config = Config::default();
        config.global.tproxy_port = 12_345;
        config
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
        config.global.health_check.tcp_method = "BREW".to_owned();
        let error = normalize(&mut config).expect_err("must fail");
        assert_eq!(error.field, "global.health-check.tcp-method");
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
                policy: FunctionOrString::Name("min_moving_avg".to_owned()),
                health_check: crate::model::HealthCheckOverride::default(),
            },
            crate::model::Group {
                name: "a".to_owned(),
                filters: Vec::new(),
                policy: FunctionOrString::Name("min_moving_avg".to_owned()),
                health_check: crate::model::HealthCheckOverride::default(),
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
    /// The falsifier is one command pair: `printf 'schema = 1\n[global]\nwan-interface = []\n'`
    /// used to be `check` → `ok` and `run` → exit 1, so the gate that promises "will this
    /// configuration run" disagreed with the process that runs it. The default is `["auto"]`,
    /// which is why a plain `schema = 1` file still passes.
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
                policy: FunctionOrString::Name("min_moving_avg".to_owned()),
                health_check: crate::model::HealthCheckOverride::default(),
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
                policy: FunctionOrString::Name("min_moving_avg".to_owned()),
                health_check: crate::model::HealthCheckOverride::default(),
            }];
            normalize(&mut config).expect("a non-reserved name is fine");
        }
    }
}
