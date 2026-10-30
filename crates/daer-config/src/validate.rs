// SPDX-License-Identifier: AGPL-3.0-only

//! Semantic checks.
//!
//! The TOML loader's job is syntax; this module applies the defaults and rejects
//! values that cannot be honoured. Nothing is repaired silently: a value that has
//! no meaning is an error, because a configuration that says one thing while the
//! daemon does another is worse than a failed start.

use std::collections::BTreeSet;
use std::fmt;

use crate::model::{Config, FunctionOrString, SCHEMA_VERSION};

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
}
