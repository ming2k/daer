// SPDX-License-Identifier: AGPL-3.0-only

//! The daer configuration model.
//!
//! This is the single source of truth for configuration. Field names are
//! kebab-case in TOML, values are typed (`Option` instead of sentinel strings,
//! [`Bandwidth`] instead of a free-form string, [`TimeSpan`] instead of
//! nanoseconds), and knobs that were declared twice are one struct: the
//! health-check group is shared by `[global]` and every `[[group]]`.
//!
//! # Defaults
//!
//! Every table applies [`Default`] for absent keys, so a minimal configuration
//! is legitimate. Unknown keys are rejected: a typo must fail loudly rather
//! than silently keep a default.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserializer;
use serde::de::Error as _;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::error::ParseError;
use crate::expr::{Function, Param, ParamValue, RoutingRule};
use crate::scalar::{Bandwidth, TimeSpan, parse_bandwidth, parse_duration};

/// The configuration schema version written as `schema = 1`.
pub const SCHEMA_VERSION: u32 = 1;

pub const DEFAULT_TCP_CHECK_URL: &str = "http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111";
pub const DEFAULT_UDP_CHECK_DNS: &str = "dns.google:53,8.8.8.8,2001:4860:4860::8888";

/// A configuration value that may be written either as a bare name or as a
/// function expression (`policy: min_moving_avg` vs `policy: fixed(0)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionOrString {
    Name(String),
    Functions(Vec<Function>),
}

impl FunctionOrString {
    /// Mirrors `config.ParseFunctionOrString`: a function list must contain
    /// exactly one function.
    pub fn as_function(&self) -> Result<Function, String> {
        match self {
            Self::Name(name) => Ok(Function::new(name.clone())),
            Self::Functions(functions) if functions.len() == 1 => Ok(functions[0].clone()),
            Self::Functions(functions) => Err(format!(
                "expected exactly 1 function, got {}",
                functions.len()
            )),
        }
    }
}

impl From<ParamValue> for FunctionOrString {
    fn from(value: ParamValue) -> Self {
        match value {
            ParamValue::Literal(name) => Self::Name(name),
            ParamValue::Functions(functions) => Self::Functions(functions),
        }
    }
}

impl fmt::Display for FunctionOrString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name),
            Self::Functions(functions) => {
                for (index, function) in functions.iter().enumerate() {
                    if index != 0 {
                        f.write_str(" && ")?;
                    }
                    write!(f, "{function}")?;
                }
                Ok(())
            }
        }
    }
}

/// Parses a standalone routing rule expression.
///
/// # Errors
///
/// Returns a positioned [`ParseError`] when the expression is not a rule.
pub fn parse_rule_expr(src: &str) -> Result<RoutingRule, ParseError> {
    crate::expr::parse_rule(src)
}

/// Parses a standalone value expression (`min`, `fixed(0)`, `min(10%)`).
///
/// # Errors
///
/// Returns a positioned [`ParseError`] when the expression is not a value.
pub fn parse_value_expr(src: &str) -> Result<FunctionOrString, ParseError> {
    Ok(crate::expr::parse_value(src)?.into())
}

/// `routing.rules` / `dns.request.rules` style lists: an array of expressions.
mod rule_list {
    use serde::de::Error as _;
    use serde::ser::SerializeSeq as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::RoutingRule;
    use super::parse_rule_expr;

    pub fn serialize<S: Serializer>(
        rules: &[RoutingRule],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(rules.len()))?;
        for rule in rules {
            seq.serialize_element(&rule.to_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<RoutingRule>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|text| {
                parse_rule_expr(text)
                    .map_err(|error| D::Error::custom(super::fragment_error(text, &error)))
            })
            .collect()
    }
}

/// Parses a filter expression (`subtag(a) && !name(keyword: 'x')`).
///
/// # Errors
///
/// Returns a rendered expression error, or a message when the text is a bare
/// name instead of a predicate.
pub fn parse_filter_expr(text: &str) -> Result<Vec<Function>, String> {
    crate::expr::parse_filter(text)
}

pub use crate::expr::{render_fragment_error as fragment_error, render_functions};

/// A single expression that is either a bare name or a function call.
mod function_value {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{FunctionOrString, parse_value_expr};

    pub fn serialize<S: Serializer>(
        value: &FunctionOrString,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<FunctionOrString, D::Error> {
        let text = String::deserialize(d)?;
        parse_value_expr(&text)
            .map_err(|error| D::Error::custom(super::fragment_error(&text, &error)))
    }
}

/// `Option<FunctionOrString>`, as used by the DNS routings.
mod function_option {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{FunctionOrString, parse_value_expr};

    pub fn serialize<S: Serializer>(
        value: &Option<FunctionOrString>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<FunctionOrString>, D::Error> {
        let Some(text) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        parse_value_expr(&text)
            .map(Some)
            .map_err(|error| D::Error::custom(super::fragment_error(&text, &error)))
    }
}

impl Serialize for TimeSpan {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl Serialize for Bandwidth {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Bandwidth {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        parse_bandwidth(&text).ok_or_else(|| {
            D::Error::custom(format!(
                "invalid bandwidth {text:?} (expected e.g. \"0\", \"1048576\", \"200 mbps\", \"1.5Gbps\")"
            ))
        })
    }
}

impl<'de> Deserialize<'de> for TimeSpan {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        parse_duration(&text).ok_or_else(|| {
            D::Error::custom(format!(
                "invalid duration {text:?} (expected e.g. \"30s\", \"250ms\", \"-1m\")"
            ))
        })
    }
}

// The JSON Schema is derived from the same attributes serde uses, so the published
// schema cannot describe a field the loader would reject. The `schemars(with = …)`
// overrides name the schema-only mirrors in `crate::schema::mirror` for the shapes
// the loader accepts but derives by hand.
#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// The health-check knobs, shared by `[global.health-check]` (the defaults) and
/// every `[[group.health-check]]` (the overrides).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct HealthCheck {
    /// `tcp-check-url`: URL first, then optional direct IP addresses.
    pub tcp_url: Vec<String>,
    /// `tcp-check-http-method`.
    #[cfg_attr(
        feature = "schema",
        schemars(with = "crate::schema::mirror::HttpMethod")
    )]
    pub tcp_method: String,
    /// `udp-check-dns`: DNS endpoints used for the UDP probe.
    pub udp_dns: Vec<String>,
    /// `check-interval`.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub interval: TimeSpan,
    /// `check-tolerance`: shifts the switch threshold of moving averages.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub tolerance: TimeSpan,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            tcp_url: DEFAULT_TCP_CHECK_URL
                .split(',')
                .map(str::to_owned)
                .collect(),
            tcp_method: "HEAD".to_owned(),
            udp_dns: DEFAULT_UDP_CHECK_DNS
                .split(',')
                .map(str::to_owned)
                .collect(),
            interval: TimeSpan::from_secs(30),
            tolerance: TimeSpan::ZERO,
        }
    }
}

/// A group's partial override of [`HealthCheck`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct HealthCheckOverride {
    pub tcp_url: Option<Vec<String>>,
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<crate::schema::mirror::HttpMethod>")
    )]
    pub tcp_method: Option<String>,
    pub udp_dns: Option<Vec<String>>,
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub interval: Option<TimeSpan>,
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub tolerance: Option<TimeSpan>,
}

/// TLS identity and fragmentation.
///
/// `profile` names a TLS fingerprint preset owned by netune; an unknown name
/// fails at load time rather than silently falling back to the default identity,
/// because a silently different ClientHello defeats the point of the option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct Tls {
    /// TLS fingerprint preset name, e.g. `chrome`. `None` uses netune's default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Split the ClientHello across TCP segments.
    pub fragment: bool,
    /// Byte range for `fragment`, e.g. `50-100`.
    pub fragment_length: String,
    /// Millisecond range for the delay between fragments, e.g. `10-20`.
    pub fragment_interval: String,
}

impl Default for Tls {
    fn default() -> Self {
        Self {
            profile: None,
            fragment: false,
            fragment_length: "50-100".to_owned(),
            fragment_interval: "10-20".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct Global {
    /// Transparent-proxy port. Not an HTTP/SOCKS port: the eBPF program
    /// redirects here.
    pub tproxy_port: u16,
    /// Reject traffic that did not go through the eBPF program.
    ///
    /// Enforced by [`crate::validate`] against the listener's shape: with this on, a flow whose
    /// original destination *is* the transparent port is refused, because such a flow was not
    /// redirected. `false` weakens that to what the socket can observe, and exists only for a
    /// debugging session on a box nobody else can reach.
    pub tproxy_port_protect: bool,
    /// Socket mark for daer-originated traffic.
    ///
    /// Omitted, a privileged run picks [`crate::DEFAULT_SOCKET_MARK`] and an unprivileged one
    /// marks nothing; the datapath and the redirect rule have to agree with whichever it is, so
    /// the daemon decides once and reports the value it used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub so_mark: Option<u32>,
    /// `tracing` filter directive, e.g. `info`, `debug`, or `daer=debug,netune=trace`.
    pub log_level: String,
    pub lan_interface: Vec<String>,
    pub wan_interface: Vec<String>,
    pub allow_insecure: bool,
    pub disable_waiting_network: bool,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub sniffing_timeout: TimeSpan,
    pub auto_sniff_punt: bool,
    pub tls: Tls,
    pub health_check: HealthCheck,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            tproxy_port: 12_345,
            tproxy_port_protect: true,
            so_mark: None,
            log_level: "info".to_owned(),
            lan_interface: Vec::new(),
            wan_interface: Vec::new(),
            allow_insecure: false,
            disable_waiting_network: false,
            sniffing_timeout: TimeSpan::from_millis(30),
            auto_sniff_punt: true,
            tls: Tls::default(),
            health_check: HealthCheck::default(),
        }
    }
}

/// One `[[subscription]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Subscription {
    /// Tag used by `subtag()` filters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    pub url: String,
    /// Cache the last successful fetch next to the configuration.
    pub persist: bool,
}

impl<'de> Deserialize<'de> for Subscription {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Url(String),
            Table(Table),
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "kebab-case")]
        struct Table {
            tag: Option<String>,
            url: String,
            #[serde(default)]
            persist: bool,
        }

        Ok(match Repr::deserialize(d)? {
            Repr::Url(url) => Self {
                tag: None,
                url,
                persist: false,
            },
            Repr::Table(table) => Self {
                tag: table.tag,
                url: table.url,
                persist: table.persist,
            },
        })
    }
}

/// One `[[node]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Node {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    pub url: String,
    /// The subscription this node came from, filled in by the resolver.
    ///
    /// Deliberately **not** deserialized: it is not part of the file format, it is derived from
    /// which `[[subscription]]` produced the link. `subtag(...)` filters read it, and leaving it
    /// empty (as the daemon did) made every subscription node unselectable while `daer route
    /// nodes` still listed it — the two diagnostics disagreed and the group silently had no
    /// members.
    #[serde(skip)]
    pub subscription: Option<String>,
}

impl Node {
    /// The tag `subtag(...)` matches against, or `""` for an inline node.
    #[must_use]
    pub fn subscription_tag(&self) -> &str {
        self.subscription.as_deref().unwrap_or("")
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Url(String),
            Table(Table),
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "kebab-case")]
        struct Table {
            tag: Option<String>,
            url: String,
        }

        Ok(match Repr::deserialize(d)? {
            Repr::Url(url) => Self {
                tag: None,
                url,
                subscription: None,
            },
            Repr::Table(table) => Self {
                tag: table.tag,
                url: table.url,
                subscription: None,
            },
        })
    }
}

/// A `group.filter` entry: a predicate conjunction plus the values the selected
/// node inherits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub functions: Vec<Function>,
    pub annotate: Vec<Param>,
}

impl Filter {
    pub fn from_functions(functions: Vec<Function>) -> Self {
        Self {
            functions,
            annotate: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for Filter {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Expr(String),
            Table(Table),
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "kebab-case")]
        struct Table {
            #[serde(rename = "match")]
            expr: String,
            #[serde(default)]
            annotate: BTreeMap<String, String>,
        }

        Ok(match Repr::deserialize(d)? {
            Repr::Expr(text) => Self {
                functions: parse_filter_expr(&text).map_err(D::Error::custom)?,
                annotate: Vec::new(),
            },
            Repr::Table(table) => Self {
                functions: parse_filter_expr(&table.expr).map_err(D::Error::custom)?,
                annotate: table
                    .annotate
                    .into_iter()
                    .map(|(key, value)| Param::literal(key, value))
                    .collect(),
            },
        })
    }
}

impl Serialize for Filter {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;

        if self.annotate.is_empty() {
            return serializer.serialize_str(&render_functions(&self.functions));
        }
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("match", &render_functions(&self.functions))?;
        let annotate: BTreeMap<&str, String> = self
            .annotate
            .iter()
            .map(|param| (param.key.as_str(), param.compact_value()))
            .collect();
        map.serialize_entry("annotate", &annotate)?;
        map.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Group {
    pub name: String,
    /// Multiple filters are OR-ed; each filter is a conjunction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Vec<crate::schema::mirror::Filter>")
    )]
    pub filters: Vec<Filter>,
    /// `min_moving_avg`, `fixed(0)`, … `None` means
    /// [`daer_common::SelectionPolicy`]'s default.
    #[serde(with = "function_value")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub policy: FunctionOrString,
    #[serde(default, skip_serializing_if = "HealthCheckOverride::is_empty")]
    pub health_check: HealthCheckOverride,
}

impl HealthCheckOverride {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// `[dns.request]` / `[dns.response]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct DnsRouting {
    #[serde(with = "rule_list")]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub rules: Vec<RoutingRule>,
    #[serde(
        with = "function_option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub fallback: Option<FunctionOrString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct Dns {
    /// `4`, `6`, or `0` for no preference.
    pub ipversion_prefer: i32,
    /// `[dns.fixed-domain-ttl]` — domain to TTL in seconds.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fixed_domain_ttl: BTreeMap<String, i64>,
    pub upstream: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    pub optimistic_cache: bool,
    pub optimistic_cache_ttl: i32,
    pub optimistic_stale_reply_ttl: i32,
    pub max_cache_size: i32,
    pub request: DnsRouting,
    pub response: DnsRouting,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            ipversion_prefer: 0,
            fixed_domain_ttl: BTreeMap::new(),
            upstream: Vec::new(),
            bind: None,
            optimistic_cache: true,
            optimistic_cache_ttl: 60,
            optimistic_stale_reply_ttl: 30,
            max_cache_size: 65_536,
            request: DnsRouting::default(),
            response: DnsRouting::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct Routing {
    #[serde(with = "rule_list")]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub rules: Vec<RoutingRule>,
    #[serde(with = "function_value")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub fallback: FunctionOrString,
}

impl Default for Routing {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            fallback: FunctionOrString::Name("direct".to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct Config {
    /// Schema version. Bumped when a change cannot be expressed as a default.
    pub schema: u32,
    /// Globs, relative to the directory of the file that names them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    pub global: Global,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Vec<crate::schema::mirror::Subscription>")
    )]
    pub subscription: Vec<Subscription>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Vec<crate::schema::mirror::Node>")
    )]
    pub node: Vec<Node>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group: Vec<Group>,
    pub routing: Routing,
    pub dns: Dns,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            include: Vec::new(),
            global: Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: Routing::default(),
            dns: Dns::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> Config {
        toml::from_str(toml).expect("parses")
    }

    #[test]
    fn defaults_apply_and_unknown_keys_are_rejected() {
        let parsed = config("");
        assert_eq!(parsed.schema, SCHEMA_VERSION);
        assert_eq!(parsed.global.tproxy_port, 12_345);
        assert_eq!(
            parsed.routing.fallback,
            FunctionOrString::Name("direct".into())
        );

        let error = toml::from_str::<Config>("[global]\ntproxy-port = 1\ntproxy-prt = 2\n")
            .expect_err("unknown key must fail");
        assert!(
            error.to_string().contains("tproxy-prt"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rules_are_parsed_from_expressions() {
        let parsed = config(
            "[routing]\nrules = [\"domain(suffix: a.com) && port(443) -> proxy\"]\nfallback = \"direct\"\n",
        );
        let rule = &parsed.routing.rules[0];
        assert_eq!(rule.and_functions.len(), 2);
        assert_eq!(rule.outbound.name, "proxy");

        let error = toml::from_str::<Config>("[routing]\nrules = [\"domain(a) direct\"]\n")
            .expect_err("missing arrow must fail");
        assert!(error.to_string().contains("invalid expression"), "{error}");
    }

    #[test]
    fn durations_require_units() {
        let parsed = config("[global.health-check]\ninterval = \"45s\"\ntolerance = \"-1s\"\n");
        assert_eq!(parsed.global.health_check.interval, TimeSpan::from_secs(45));
        assert!(parsed.global.health_check.tolerance.is_negative());

        let error = toml::from_str::<Config>("[global.health-check]\ninterval = \"45\"\n")
            .expect_err("a unitless duration must fail");
        assert!(error.to_string().contains("invalid duration"), "{error}");
    }

    #[test]
    fn subscriptions_and_nodes_accept_both_shapes() {
        // An array of strings and an array of tables cannot coexist in one TOML
        // document, so a file picks one shape.
        let plain = config("subscription = [\"https://a/sub\"]\nnode = [\"ss://x\"]\n");
        assert_eq!(plain.subscription[0].tag, None);
        assert!(!plain.subscription[0].persist);
        assert_eq!(plain.node[0].url, "ss://x");

        let tables = config(
            "[[subscription]]\ntag = \"b\"\nurl = \"https://b/sub\"\npersist = true\n\
             [[node]]\ntag = \"n1\"\nurl = \"ss://...\"\n",
        );
        assert_eq!(tables.subscription[0].tag.as_deref(), Some("b"));
        assert!(tables.subscription[0].persist);
        assert_eq!(tables.node[0].tag.as_deref(), Some("n1"));
    }

    #[test]
    fn filters_accept_a_string_or_a_table() {
        let parsed = config(
            "[[group]]\nname = \"g\"\npolicy = \"min-moving-avg\"\n\
             filters = [\"subtag(a) && !name(keyword: 'x')\", { match = \"name(n1)\", annotate = { mark = \"1\" } }]\n",
        );
        assert_eq!(parsed.group[0].filters.len(), 2);
        assert_eq!(parsed.group[0].filters[0].functions.len(), 2);
        assert_eq!(parsed.group[0].filters[1].annotate[0].key, "mark");
    }

    #[test]
    fn every_field_round_trips_through_the_serializer() {
        let original = config(
            "schema = 1\n[global]\ntproxy-port = 1234\nso-mark = 7\n\
             [global.tls]\nprofile = \"chrome\"\n[global.health-check]\ninterval = \"10s\"\n\
             [[subscription]]\ntag = \"s\"\nurl = \"https://s\"\n\
             [[group]]\nname = \"g\"\npolicy = \"fixed(0)\"\n\
             [routing]\nrules = [\"pname(NetworkManager) -> direct\"]\nfallback = \"g\"\n\
             [dns]\nupstream = [\"udp://1.1.1.1:53\"]\n[dns.fixed-domain-ttl]\n\"example.com\" = 60\n",
        );
        let rendered = toml::to_string(&original).expect("serializes");
        let reparsed = config(&rendered);
        assert_eq!(original, reparsed, "rendered:\n{rendered}");
    }
}
