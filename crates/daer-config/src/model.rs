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
use serde::de::{DeserializeOwned, Error as _};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::error::ParseError;
use crate::expr::{Function, Param, ParamValue, RoutingRule};
use crate::scalar::{Bandwidth, TimeSpan, parse_bandwidth, parse_duration};

/// The configuration schema version written as `schema = 2`.
///
/// Version 2 is the clean break that separates resources (`node`/`group`) from
/// elections: a group is a candidate set, an election is the routing target that
/// selects one node from it, and the old `group.policy`/`group.health-check`
/// surface no longer exists.
pub const SCHEMA_VERSION: u32 = 2;

/// Default UDP endpoints for the server-liveness probe.
pub const DEFAULT_UDP_CHECK_DNS: &str = "1.1.1.1:53,8.8.8.8:53,2001:4860:4860::8888:53";

/// A configuration value that may be written either as a bare name or as a
/// function expression (`fallback: direct` vs `provider: name(...)`).
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

/// What a probe measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ProbeMode {
    /// A cheap liveness probe against the node's own server address. It proves the
    /// server is reachable, not that the node can carry a request to the internet.
    #[default]
    Server,
    /// A request through the node to `url`. This is the Clash `url-test` shape: it
    /// proves the proxy session authenticated and the node can reach the target.
    Url,
}

/// Probe defaults, shared by `[global.probe]` and every election that overrides them.
///
/// Measurement is not a property of a group: a group is only a candidate set. An
/// election owns the probe it needs; the global table supplies defaults so a file
/// does not repeat the same URL for every election.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct ProbeSettings {
    pub mode: ProbeMode,
    /// The URL requested when `mode = "url"`.
    pub url: Option<String>,
    #[cfg_attr(
        feature = "schema",
        schemars(with = "crate::schema::mirror::HttpMethod")
    )]
    pub method: String,
    /// DNS endpoints used by the server-liveness probe for datagram-carrying nodes.
    pub udp_dns: Vec<String>,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub interval: TimeSpan,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub timeout: TimeSpan,
    /// Shifts the switch threshold of moving averages.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub tolerance: TimeSpan,
}

impl Default for ProbeSettings {
    fn default() -> Self {
        Self {
            mode: ProbeMode::Server,
            url: None,
            method: "HEAD".to_owned(),
            udp_dns: DEFAULT_UDP_CHECK_DNS
                .split(',')
                .map(str::to_owned)
                .collect(),
            interval: TimeSpan::from_secs(30),
            timeout: TimeSpan::from_secs(5),
            tolerance: TimeSpan::ZERO,
        }
    }
}

/// How an election selects one node from its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ElectionKind {
    /// The input must be a node; the election returns that node or fails when it is
    /// not usable.
    Manual,
    /// Pick a random alive node.
    #[default]
    Random,
    /// Pick the node with the lowest last measured latency.
    Min,
    /// Pick the node with the lowest average of its last 10 latencies.
    MinAvg10,
    /// Pick the node with the lowest exponentially weighted moving average.
    MinMovingAvg,
}

impl ElectionKind {
    /// The runtime selection policy this election uses.
    #[must_use]
    pub const fn selection_policy(self) -> daer_common::SelectionPolicy {
        match self {
            Self::Manual => daer_common::SelectionPolicy::Manual,
            Self::Random => daer_common::SelectionPolicy::Random,
            Self::Min => daer_common::SelectionPolicy::MinLastLatency,
            Self::MinAvg10 => daer_common::SelectionPolicy::MinAverage10,
            Self::MinMovingAvg => daer_common::SelectionPolicy::MinMovingAverage,
        }
    }

    /// Whether the election ranks candidates by measured latency.
    #[must_use]
    pub const fn needs_measurement(self) -> bool {
        matches!(self, Self::Min | Self::MinAvg10 | Self::MinMovingAvg)
    }
}

/// One `[[election]]` entry: the routing target and the rule that elects one node.
///
/// The input is exactly one of `group` or `node`. A group is a set of candidates; a
/// node is a singleton candidate set. The output is always one node (or no node when
/// the input has no usable candidate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Election {
    pub name: String,
    /// The candidate set. Mutually exclusive with `node`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// A singleton candidate set. Mutually exclusive with `group`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The selection rule.
    #[serde(rename = "type")]
    pub kind: ElectionKind,
    /// Probe overrides. `None` inherits `[global.probe]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ProbeMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<crate::schema::mirror::HttpMethod>")
    )]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_dns: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub interval: Option<TimeSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub timeout: Option<TimeSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub tolerance: Option<TimeSpan>,
}

impl Election {
    /// Resolves this election's effective probe settings.
    #[must_use]
    pub fn resolved_probe(&self, defaults: &ProbeSettings) -> ProbeSettings {
        let mode = self.mode.unwrap_or(defaults.mode);
        ProbeSettings {
            mode,
            // A server probe never requests a URL. The mode is the authority; a URL
            // inherited from the global defaults must not silently make it a URL probe.
            url: if mode == ProbeMode::Url {
                self.url.clone().or_else(|| defaults.url.clone())
            } else {
                None
            },
            method: self
                .method
                .clone()
                .unwrap_or_else(|| defaults.method.clone()),
            udp_dns: self
                .udp_dns
                .clone()
                .unwrap_or_else(|| defaults.udp_dns.clone()),
            interval: self.interval.unwrap_or(defaults.interval),
            timeout: self.timeout.unwrap_or(defaults.timeout),
            tolerance: self.tolerance.unwrap_or(defaults.tolerance),
        }
    }

    /// The input kind, as a diagnostic string.
    #[must_use]
    pub fn input(&self) -> &'static str {
        if self.group.is_some() {
            "group"
        } else {
            "node"
        }
    }
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
    /// Socket mark for daer-originated traffic.
    ///
    /// Omitted, a privileged run picks [`daer_common::consts::DEFAULT_SOCKET_MARK`] and an
    /// unprivileged one marks nothing; the datapath and the redirect rule have to agree with
    /// whichever it is, so the daemon decides once and reports the value it used.
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
    pub probe: ProbeSettings,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            so_mark: None,
            log_level: "info".to_owned(),
            lan_interface: Vec::new(),
            // `["auto"]`, not `[]`. The daemon refuses an empty list ("daer cannot know which
            // interface carries proxied traffic"), so an empty default made the *defaults* —
            // and therefore an otherwise empty configuration file — unrunnable, while the
            // reference documentation and `daer.example.toml` both promised `["auto"]`.
            // A default that `run` rejects is a trap; the honest default is the one the
            // example and the docs already named.
            wan_interface: vec!["auto".to_owned()],
            allow_insecure: false,
            disable_waiting_network: false,
            sniffing_timeout: TimeSpan::from_millis(30),
            auto_sniff_punt: true,
            tls: Tls::default(),
            probe: ProbeSettings::default(),
        }
    }
}

/// One `[[subscription]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Subscription {
    /// Name used by `sub(...)` / `subtag()` filters.
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    pub url: String,
    /// Cache the last successful fetch next to the configuration.
    pub persist: bool,
    /// Apply this detour to every node the subscription contributes (ADR-0044).
    ///
    /// A subscription link cannot carry a detour (it is another panel's wire format), so the
    /// operator declares the chain once, next to the subscription. The target may be an inline
    /// node or another subscription node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
}

impl Subscription {
    /// Compatibility accessor for the subscription name.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.name.as_deref()
    }
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
            #[serde(alias = "tag")]
            name: Option<String>,
            url: String,
            #[serde(default)]
            persist: bool,
            #[serde(default)]
            detour: Option<String>,
        }

        Ok(match Repr::deserialize(d)? {
            Repr::Url(url) => Self {
                name: None,
                url,
                persist: false,
                detour: None,
            },
            Repr::Table(table) => Self {
                name: table.name,
                url: table.url,
                persist: table.persist,
                detour: table.detour,
            },
        })
    }
}

/// One `[[rule-provider]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuleProvider {
    #[serde(alias = "tag")]
    pub name: String,
    #[serde(rename = "type", default)]
    pub provider_type: ProviderType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub format: ProviderFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub interval: Option<TimeSpan>,
}

impl RuleProvider {
    /// Compatibility accessor for the rule provider name.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ProviderType {
    #[default]
    File,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ProviderFormat {
    #[default]
    Drb,
    Text,
}

/// One `[[node]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Node {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub endpoint: NodeEndpoint,
    /// The node whose outbound carries this node's connection to its own server.
    ///
    /// This is the detour seam (ADR-0044): the outer node's proxy protocol still names the
    /// *final* target, while the byte stream to its server is opened by another node. A chain
    /// is therefore `outer(detour=inner)`, not a new protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    /// The subscription this node came from, filled in by the resolver.
    #[serde(skip)]
    pub subscription: Option<String>,
}

impl Node {
    /// The optional name of this node.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Compatibility accessor for the node name.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.name()
    }

    /// Creates a node with an optional name and an endpoint.
    pub fn new(name: Option<String>, endpoint: NodeEndpoint) -> Self {
        Self {
            name,
            endpoint,
            detour: None,
            subscription: None,
        }
    }

    /// Creates a node with a subscription name provenance.
    pub fn with_subscription(
        name: Option<String>,
        endpoint: NodeEndpoint,
        subscription: Option<String>,
    ) -> Self {
        Self {
            name,
            endpoint,
            detour: None,
            subscription,
        }
    }

    /// Creates a node from an endpoint, extracting any name declared on it.
    pub fn from_endpoint(endpoint: NodeEndpoint) -> Self {
        let name = endpoint.name().map(str::to_owned);
        Self::new(name, endpoint)
    }

    /// Alias for `from_endpoint`.
    pub fn from_structured(structured: NodeEndpoint) -> Self {
        Self::from_endpoint(structured)
    }

    /// The subscription name `sub(...)` / `subtag(...)` matches against, or `""` for an inline node.
    #[must_use]
    pub fn subscription_name(&self) -> &str {
        self.subscription.as_deref().unwrap_or("")
    }

    /// Compatibility alias for `subscription_name`.
    #[must_use]
    pub fn subscription_tag(&self) -> &str {
        self.subscription_name()
    }

    /// Default name for this node when name is omitted.
    #[must_use]
    pub fn default_name(&self) -> String {
        self.endpoint.default_name()
    }

    /// Display label for this node.
    #[must_use]
    pub fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.default_name())
    }

    /// Formats this node as a URI link.
    #[must_use]
    pub fn to_link(&self) -> String {
        self.endpoint.to_link()
    }

    /// Parses an outbound URI link (vless://, ss://, trojan://, socks5://, http://, direct://)
    /// into a typed `Node`.
    pub fn from_link(link: &str) -> Result<Self, String> {
        let endpoint = NodeEndpoint::from_link(link)?;
        let name = endpoint.name().map(str::to_owned);
        Ok(Self {
            name,
            endpoint,
            detour: None,
            subscription: None,
        })
    }

    /// Renders this node as a formatted `[[node]]` TOML block.
    pub fn to_toml_node(&self) -> Result<String, String> {
        self.endpoint.to_toml_node()
    }
}

/// A structured outbound node definition with dedicated fields per protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum NodeEndpoint {
    Direct(DirectNode),
    #[serde(alias = "socks")]
    Socks5(Socks5Node),
    Http(HttpNode),
    #[serde(alias = "ss")]
    Shadowsocks(ShadowsocksNode),
    Trojan(TrojanNode),
    AnyTls(AnyTlsNode),
    Hysteria2(Hysteria2Node),
    Vless(VlessNode),
    Vmess(VmessNode),
    #[serde(skip_deserializing)]
    Unsupported {
        scheme: String,
        link: String,
    },
}

pub type StructuredNode = NodeEndpoint;
pub type DirectEndpoint = DirectNode;
pub type Socks5Endpoint = Socks5Node;
pub type HttpEndpoint = HttpNode;
pub type ShadowsocksEndpoint = ShadowsocksNode;
pub type TrojanEndpoint = TrojanNode;
pub type AnyTlsEndpoint = AnyTlsNode;
pub type Hysteria2Endpoint = Hysteria2Node;
pub type VlessEndpoint = VlessNode;
pub type VmessEndpoint = VmessNode;

impl NodeEndpoint {
    /// Validates the semantic constraints of the structured node.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Direct(_) => Ok(()),
            Self::Socks5(node) => {
                if node.server.trim().is_empty() {
                    return Err("socks5: 'server' must not be empty".to_owned());
                }
                if node.port == 0 {
                    return Err("socks5: 'port' must not be 0".to_owned());
                }
                Ok(())
            }
            Self::Http(node) => {
                if node.server.trim().is_empty() {
                    return Err("http: 'server' must not be empty".to_owned());
                }
                if node.port == 0 {
                    return Err("http: 'port' must not be 0".to_owned());
                }
                Ok(())
            }
            Self::Shadowsocks(node) => {
                if node.server.trim().is_empty() {
                    return Err("shadowsocks: 'server' must not be empty".to_owned());
                }
                if node.port == 0 {
                    return Err("shadowsocks: 'port' must not be 0".to_owned());
                }
                if node.password.is_empty() {
                    return Err("shadowsocks: 'password' must not be empty".to_owned());
                }
                validate_ss_method(&node.method)?;
                if let Some(expected) = ss_2022_key_len(&node.method) {
                    let decoded_len = validate_base64_len(&node.password).map_err(|e| {
                        format!(
                            "shadowsocks 2022: method '{}' password must be valid base64: {e}",
                            node.method
                        )
                    })?;
                    if decoded_len != expected {
                        return Err(format!(
                            "shadowsocks 2022: method '{}' requires a {expected}-byte base64-encoded key, but decoded length is {decoded_len}",
                            node.method
                        ));
                    }
                }
                Ok(())
            }
            Self::Trojan(node) => {
                if node.server.trim().is_empty() {
                    return Err("trojan: 'server' must not be empty".to_owned());
                }
                if node.port == 0 {
                    return Err("trojan: 'port' must not be 0".to_owned());
                }
                if node.password.is_empty() {
                    return Err("trojan: 'password' must not be empty".to_owned());
                }
                // A certificate cannot be verified against an address: the TLS client would
                // present the IP as SNI, and no CA signs an IP for a proxy node.
                if node.sni.is_none() && node.server.parse::<std::net::IpAddr>().is_ok() {
                    return Err(format!(
                        "trojan: the server {:?} is an address, so an explicit `sni` is \
                         required (write `sni = \"hostname\"` or `?sni=…` in a link); a \
                         certificate cannot be verified against an address",
                        node.server
                    ));
                }
                Ok(())
            }
            Self::AnyTls(node) => {
                if node.server.trim().is_empty() {
                    return Err("anytls: 'server' must not be empty".to_owned());
                }
                if node.port == 0 {
                    return Err("anytls: 'port' must not be 0".to_owned());
                }
                if node.password.is_empty() {
                    return Err("anytls: 'password' must not be empty".to_owned());
                }
                Ok(())
            }
            Self::Hysteria2(node) => {
                if node.server.trim().is_empty() {
                    return Err("hysteria2: 'server' must not be empty".to_owned());
                }
                if node.ports.ranges.is_empty() {
                    return Err("hysteria2: 'ports' must name at least one port".to_owned());
                }
                if node
                    .ports
                    .ranges
                    .iter()
                    .any(|(low, high)| *low == 0 && *high == 0)
                {
                    return Err("hysteria2: port 0 is not a dialable port".to_owned());
                }
                if node.password.is_empty() {
                    return Err("hysteria2: 'password' must not be empty".to_owned());
                }
                if node.ports.hops() {
                    // The reference's floor: a hop schedule shorter than 5 s would
                    // exhaust the server's port table faster than it can release it.
                    let low = if node.ports.hop_min_ms > 0 {
                        node.ports.hop_min_ms
                    } else {
                        node.ports.hop_ms
                    };
                    let high = if node.ports.hop_max_ms > 0 {
                        node.ports.hop_max_ms
                    } else {
                        node.ports.hop_ms
                    };
                    if low != 0 && high != 0 && low > high {
                        return Err(format!(
                            "hysteria2: hop-min-interval ({low}ms) must not exceed \
                             hop-max-interval ({high}ms)"
                        ));
                    }
                    if low < 5_000 {
                        return Err(format!(
                            "hysteria2: the hop interval must be at least 5s, got {low}ms"
                        ));
                    }
                }
                if let Some(obfs) = &node.obfs {
                    if obfs.password().len() < 4 {
                        return Err(format!(
                            "hysteria2.obfs.{}: the password must be at least 4 bytes; the \
                             reference refuses a shorter pre-shared key",
                            obfs.kind()
                        ));
                    }
                    if let Hysteria2Obfs::Gecko {
                        min_packet_size,
                        max_packet_size,
                        ..
                    } = obfs
                    {
                        let low = if *min_packet_size == 0 {
                            512
                        } else {
                            *min_packet_size
                        };
                        let high = if *max_packet_size == 0 {
                            1200
                        } else {
                            *max_packet_size
                        };
                        if low > high || high > 2048 {
                            return Err(format!(
                                "hysteria2.obfs.gecko: min/max packet size {low}/{high} is not a \
                                 usable range (min <= max <= 2048)"
                            ));
                        }
                    }
                }
                if matches!(node.congestion, Hysteria2Congestion::Brutal)
                    && node.up_mbps == 0
                    && node.down_mbps == 0
                {
                    return Err(
                        "hysteria2: congestion = \"brutal\" pins the window to a configured \
                         rate, so at least one of up-mbps/down-mbps must be set"
                            .to_owned(),
                    );
                }
                if let Some(pin) = &node.pin_sha256 {
                    let digits: String = pin
                        .chars()
                        .filter(|c| *c != ':' && *c != ' ' && *c != '-')
                        .collect();
                    if digits.len() != 64 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err(format!(
                            "hysteria2.pin-sha256 = {pin:?} is not a SHA-256 digest; write the \
                             64 hex digits of the certificate's fingerprint"
                        ));
                    }
                }
                Ok(())
            }
            Self::Vless(node) => {
                if node.server.trim().is_empty() {
                    return Err("vless: 'server' must not be empty".to_owned());
                }
                if node.port == 0 {
                    return Err("vless: 'port' must not be 0".to_owned());
                }
                if node.uuid.trim().is_empty() {
                    return Err("vless: 'uuid' must not be empty".to_owned());
                }
                if let Err(reason) = parse_node_uuid(&node.uuid) {
                    return Err(format!("vless: {reason}"));
                }
                validate_security(&node.security, "vless", &node.server)?;
                validate_transport(&node.transport, "vless")?;
                // The reference rejects this combination on both ends: `VisionWriter` needs
                // a record layer to splice, and Xray's inbound refuses a plaintext outer
                // stream outright ("XTLS only supports TLS and REALITY directly for now").
                // Accepting it would produce a session that authenticates and then
                // deadlocks, so it is refused by name.
                if node.flow.is_vision() && node.security.is_none() {
                    return Err(format!(
                        "vless: flow = {:?} needs a security layer that can be spliced; add \
                         security = \"tls\" or security = \"reality\"",
                        node.flow.as_str()
                    ));
                }
                // Vision splices the *record layer*, so it needs TLS or REALITY to be the thing
                // directly under the protocol. The reference says so on both ends — a
                // `ws`-wrapped connection is neither `*tls.Conn` nor `*reality.UConn`, so
                // `inbound.go` answers "XTLS only supports TLS and REALITY directly for now" and
                // the outbound refuses to build the flow at all. Accepting this combination would
                // produce a node that authenticates and then never carries a byte.
                if node.flow.is_vision() && !matches!(node.transport, TransportConfig::Tcp) {
                    return Err(format!(
                        "vless: flow = {:?} needs TLS or REALITY directly under the protocol, but \
                         transport.type = \"{}\" wraps the record layer. The reference refuses \
                         this on both ends (\"XTLS only supports TLS and REALITY directly for \
                         now\"); either drop the flow or use transport.type = \"tcp\"",
                        node.flow.as_str(),
                        node.transport.kind()
                    ));
                }
                Ok(())
            }
            Self::Vmess(node) => {
                if node.server.trim().is_empty() {
                    return Err("vmess: 'server' must not be empty".to_owned());
                }
                if node.port == 0 {
                    return Err("vmess: 'port' must not be 0".to_owned());
                }
                if let Err(reason) = parse_node_uuid(&node.uuid) {
                    return Err(format!("vmess: {reason}"));
                }
                validate_security(&node.security, "vmess", &node.server)?;
                validate_transport(&node.transport, "vmess")?;
                Ok(())
            }
            Self::Unsupported { scheme, .. } => {
                Err(format!("unsupported node protocol {scheme:?}"))
            }
        }
    }

    /// The optional name of this node.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Direct(n) => n.name.as_deref(),
            Self::Socks5(n) => n.name.as_deref(),
            Self::Http(n) => n.name.as_deref(),
            Self::Shadowsocks(n) => n.name.as_deref(),
            Self::Trojan(n) => n.name.as_deref(),
            Self::AnyTls(n) => n.name.as_deref(),
            Self::Hysteria2(n) => n.name.as_deref(),
            Self::Vless(n) => n.name.as_deref(),
            Self::Vmess(n) => n.name.as_deref(),
            Self::Unsupported { .. } => None,
        }
    }

    /// Compatibility accessor for the node name.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.name()
    }

    /// Default name for this node when tag is omitted.
    #[must_use]
    pub fn default_name(&self) -> String {
        match self {
            Self::Direct(_) => "direct".to_owned(),
            Self::Socks5(n) => format!("{}:{}", n.server, n.port),
            Self::Http(n) => format!("{}:{}", n.server, n.port),
            Self::Shadowsocks(n) => format!("{}:{}", n.server, n.port),
            Self::Trojan(n) => format!("{}:{}", n.server, n.port),
            Self::AnyTls(n) => format!("{}:{}", n.server, n.port),
            Self::Hysteria2(n) => format!("{}:{}", n.server, n.ports.to_link_port()),
            Self::Vless(n) => format!("{}:{}", n.server, n.port),
            Self::Vmess(n) => format!("{}:{}", n.server, n.port),
            // A name is printed, logged and shown in `daer probe`; the link is not. For a
            // protocol this build cannot speak the link *is* all we have, so it is redacted
            // rather than shown: `tuic://pw@host:443` carries a credential in its userinfo,
            // and a diagnostic that echoes it writes a secret to stdout and to any log that
            // captured it. The scheme is the part an operator needs.
            Self::Unsupported { scheme, link } => redact_link(scheme, link),
        }
    }

    /// Converts the structured node into its canonical URI link.
    #[must_use]
    pub fn to_link(&self) -> String {
        match self {
            Self::Direct(n) => n.to_link(),
            Self::Socks5(n) => n.to_link(),
            Self::Http(n) => n.to_link(),
            Self::Shadowsocks(n) => n.to_link(),
            Self::Trojan(n) => n.to_link(),
            Self::AnyTls(n) => n.to_link(),
            Self::Hysteria2(n) => n.to_link(),
            Self::Vless(n) => n.to_link(),
            Self::Vmess(n) => n.to_link(),
            Self::Unsupported { link, .. } => link.clone(),
        }
    }

    /// Renders this structured node as a formatted `[[node]]` TOML block.
    ///
    /// # Why this serializes a wrapper rather than the node itself
    ///
    /// A node is an *element* of the `node` array of tables, so the TOML it belongs in is
    /// `[[node]]` plus `[node.reality]` for a nested table. Serializing the node on its own
    /// and prepending `[[node]]` by hand gets both of those wrong, and each failure is
    /// silent in the output and loud only when the text is pasted back:
    ///
    /// * a nested table renders as `[reality]`, a top-level table the schema does not have;
    /// * `Node` carries `tag` **and** its flattened endpoint carries `tag`, so the block
    ///   contains `tag` twice and TOML rejects it as a duplicate key.
    ///
    /// Both made `daer node convert` unusable for its one documented purpose — the output
    /// could not be loaded by `daer config validate`. Serializing the *document* lets
    /// `toml` decide the table headers, and taking the endpoint (not the `Node` wrapper)
    /// keeps `tag` single.
    ///
    /// # Why this validates
    ///
    /// This is the conversion path, so an unusable node is a defect rather than something to
    /// carry along: rendering `ss://…` with a mistyped cipher as `method = "aes-128-grm"`
    /// produces a block that `daer config validate` then rejects, i.e. the tool hands back a
    /// broken file and says nothing. [`from_link`](Self::from_link) stays parse-only for the
    /// subscription case, where "well formed and unsupported" must survive to be reported.
    pub fn to_toml_node(&self) -> Result<String, String> {
        self.validate()?;

        #[derive(serde::Serialize)]
        struct Document<'a> {
            node: [&'a NodeEndpoint; 1],
        }
        toml::to_string_pretty(&Document { node: [self] }).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DirectNode {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
}

impl DirectNode {
    #[must_use]
    pub fn to_link(&self) -> String {
        "direct://".to_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Socks5Node {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    pub server: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl Socks5Node {
    #[must_use]
    pub fn to_link(&self) -> String {
        let server = format_host(&self.server);
        let auth = match (&self.username, &self.password) {
            (Some(user), Some(pass)) => {
                format!("{}:{}@", percent_encode(user), percent_encode(pass))
            }
            (Some(user), None) => format!("{}@", percent_encode(user)),
            (None, Some(pass)) => format!(":{}@", percent_encode(pass)),
            (None, None) => String::new(),
        };
        format!("socks5://{auth}{server}:{}", self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct HttpNode {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    pub server: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl HttpNode {
    #[must_use]
    pub fn to_link(&self) -> String {
        let server = format_host(&self.server);
        let auth = match (&self.username, &self.password) {
            (Some(user), Some(pass)) => {
                format!("{}:{}@", percent_encode(user), percent_encode(pass))
            }
            (Some(user), None) => format!("{}@", percent_encode(user)),
            (None, Some(pass)) => format!(":{}@", percent_encode(pass)),
            (None, None) => String::new(),
        };
        format!("http://{auth}{server}:{}", self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ShadowsocksNode {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    pub server: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

impl ShadowsocksNode {
    #[must_use]
    pub fn to_link(&self) -> String {
        let server = format_host(&self.server);
        let creds = format!("{}:{}", self.method, self.password);
        let userinfo = encode_base64(creds.as_bytes());
        format!("ss://{userinfo}@{server}:{}", self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TrojanNode {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_insecure: bool,
}

impl TrojanNode {
    #[must_use]
    pub fn to_link(&self) -> String {
        let server = format_host(&self.server);
        let mut query = Vec::new();
        if let Some(sni) = &self.sni
            && !sni.is_empty()
        {
            query.push(format!("sni={}", percent_encode(sni)));
        }
        if self.allow_insecure {
            query.push("allowInsecure=1".to_owned());
        }
        let query_str = if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query.join("&"))
        };
        format!(
            "trojan://{}@{server}:{}{query_str}",
            self.password, self.port
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AnyTlsNode {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_insecure: bool,
    #[serde(
        default = "default_idle_sessions",
        skip_serializing_if = "is_default_idle_sessions"
    )]
    pub idle_sessions: usize,
}

fn default_idle_sessions() -> usize {
    1
}

fn is_default_idle_sessions(v: &usize) -> bool {
    *v == 1
}

impl AnyTlsNode {
    #[must_use]
    pub fn to_link(&self) -> String {
        let server = format_host(&self.server);
        let mut query = Vec::new();
        if let Some(sni) = &self.sni
            && !sni.is_empty()
        {
            query.push(format!("sni={}", percent_encode(sni)));
        }
        if self.allow_insecure {
            query.push("allowInsecure=1".to_owned());
        }
        if self.idle_sessions > 1 {
            query.push(format!("idle_sessions={}", self.idle_sessions));
        }
        let query_str = if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query.join("&"))
        };
        format!(
            "anytls://{}@{server}:{}{query_str}",
            percent_encode(&self.password),
            self.port
        )
    }
}

/// Ports a Hysteria 2 node may be reached on, and the hop schedule (ADR-0029).
///
/// A reference `hysteria2://` link names either one port or a set
/// (`443`, `443,8443`, `20000-30000`, `all`). The set is kept normalised — sorted,
/// merged, no overlaps — because the hop layer samples uniformly from it and a
/// duplicated range would bias the rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PortSet {
    /// `low-high` ranges, inclusive, sorted and non-overlapping.
    pub ranges: Vec<(u16, u16)>,
    /// Rotate the source port on this interval. `0` disables hopping.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub hop_ms: u64,
    /// Lower bound of the randomised interval, when it differs from `hop_ms`.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub hop_min_ms: u64,
    /// Upper bound of the randomised interval.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub hop_max_ms: u64,
}

impl PortSet {
    /// A single port and no hopping.
    #[must_use]
    pub fn single(port: u16) -> Self {
        Self {
            ranges: vec![(port, port)],
            hop_ms: 0,
            hop_min_ms: 0,
            hop_max_ms: 0,
        }
    }

    /// Parses the reference's port-union syntax: `443`, `443,8443`, `1000-2000,443`,
    /// `all`.
    ///
    /// Ranges are swapped when written backwards (`8443-443`) exactly as
    /// `portunion.go` does, and `all` is `0-65535`. The result is normalised so two
    /// spellings of the same set compare equal.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending component, because a typo in a port
    /// list is otherwise a node that dials nothing.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("port list is empty".to_owned());
        }
        if text == "all" || text == "*" {
            return Ok(Self {
                ranges: vec![(0, 65535)],
                hop_ms: 0,
                hop_min_ms: 0,
                hop_max_ms: 0,
            });
        }
        let mut ranges = Vec::new();
        for part in text.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(format!("port list {text:?} has an empty component"));
            }
            let range = match part.split_once('-') {
                Some((low, high)) => {
                    let low: u16 = low
                        .trim()
                        .parse()
                        .map_err(|_| format!("{part:?} is not a port range"))?;
                    let high: u16 = high
                        .trim()
                        .parse()
                        .map_err(|_| format!("{part:?} is not a port range"))?;
                    if low <= high {
                        (low, high)
                    } else {
                        (high, low)
                    }
                }
                None => {
                    let port: u16 = part
                        .parse()
                        .map_err(|_| format!("{part:?} is not a port number"))?;
                    (port, port)
                }
            };
            ranges.push(range);
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::with_capacity(ranges.len());
        for (low, high) in ranges {
            match merged.last_mut() {
                Some(last) if u32::from(low) <= u32::from(last.1) + 1 => {
                    if high > last.1 {
                        last.1 = high;
                    }
                }
                _ => merged.push((low, high)),
            }
        }
        Ok(Self {
            ranges: merged,
            hop_ms: 0,
            hop_min_ms: 0,
            hop_max_ms: 0,
        })
    }

    /// Every port in the set, for the hop layer.
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        for (low, high) in &self.ranges {
            for port in *low..=*high {
                ports.push(port);
            }
        }
        ports
    }

    /// Whether hopping is configured.
    #[must_use]
    pub const fn hops(&self) -> bool {
        self.hop_ms > 0 || self.hop_min_ms > 0 || self.hop_max_ms > 0
    }

    /// The port written as a reference link does.
    #[must_use]
    pub fn to_link_port(&self) -> String {
        self.ranges
            .iter()
            .map(|(low, high)| {
                if low == high {
                    low.to_string()
                } else {
                    format!("{low}-{high}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Hysteria 2's QUIC tuning (ADR-0029).
///
/// Every field maps onto a `netune_quic::QuicProfile`/`QuicTransportParameters` knob, so a
/// value here either changes the connection or is not in the model. The defaults are netune's
/// (30 s idle timeout, 10 MB connection window); they are daer's own, not the reference's,
/// because a daer deployment shares one daemon across many nodes and a buffer sized for one
/// node's 500 Mbit link would be wrong everywhere else.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct Hysteria2Quic {
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub init_stream_receive_window: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub max_stream_receive_window: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub init_conn_receive_window: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub max_conn_receive_window: u64,
    /// Connection idle timeout in milliseconds. `0` keeps netune's default.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub max_idle_timeout_ms: u64,
    /// Keep-alive period in milliseconds. `0` keeps daer's 10 s default.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub keep_alive_period_ms: u64,
    /// Disable netune's DPLPMTUD probing and keep datagrams at the QUIC
    /// 1200-byte floor, matching the reference's `disablePathMTUDiscovery`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_path_mtu_discovery: bool,
    /// Skip GSO. The owned QUIC engine performs no segmentation offload, so
    /// this key is already satisfied; it is accepted for reference
    /// compatibility and read by the connector rather than silently dropped.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_segmentation_offload: bool,
}

/// Hysteria 2's congestion controller (ADR-0029).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Hysteria2Congestion {
    /// netune's BBR model window.
    #[default]
    Bbr,
    Cubic,
    NewReno,
    /// The reference's throughput-pinning controller; needs `up-mbps`/`down-mbps`.
    Brutal,
}

/// Hysteria 2's obfuscation layer (ADR-0029).
///
/// Tagged by `type` so a password is required by construction: `type = "salamander"`
/// without a `password` does not deserialize, rather than connecting in the clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum Hysteria2Obfs {
    /// `[salt 8][payload]`, XORed with `BLAKE2b-256(psk ‖ salt)`.
    Salamander { password: String },
    /// Salamander plus fragmentation of QUIC long-header packets.
    Gecko {
        password: String,
        #[serde(default, skip_serializing_if = "is_zero_u16")]
        min_packet_size: u16,
        #[serde(default, skip_serializing_if = "is_zero_u16")]
        max_packet_size: u16,
    },
}

impl Hysteria2Obfs {
    /// The pre-shared key.
    #[must_use]
    pub fn password(&self) -> &str {
        match self {
            Self::Salamander { password } | Self::Gecko { password, .. } => password,
        }
    }

    /// The name a link and a log use.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Salamander { .. } => "salamander",
            Self::Gecko { .. } => "gecko",
        }
    }
}

impl<'de> Deserialize<'de> for Hysteria2Obfs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut table = toml::Table::deserialize(d)?;
        let kind = take_tag(&mut table, "node.obfs", &["salamander", "gecko"])
            .map_err(D::Error::custom)?;
        let obfs = match kind.as_str() {
            "salamander" => {
                let salamander: ObfsSalamander =
                    variant(table, "node.obfs").map_err(D::Error::custom)?;
                Self::Salamander {
                    password: salamander.password,
                }
            }
            _ => {
                let gecko: ObfsGecko = variant(table, "node.obfs").map_err(D::Error::custom)?;
                Self::Gecko {
                    password: gecko.password,
                    min_packet_size: gecko.min_packet_size,
                    max_packet_size: gecko.max_packet_size,
                }
            }
        };
        Ok(obfs)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ObfsSalamander {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ObfsGecko {
    password: String,
    #[serde(default)]
    min_packet_size: u16,
    #[serde(default)]
    max_packet_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Hysteria2Node {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    pub server: String,
    /// One port, a list, or a range (ADR-0029).
    pub ports: PortSet,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_insecure: bool,
    /// Certificate digest pin: the SHA-256 of the server's leaf certificate, hex.
    /// Compared after the handshake, so it is a second factor rather than a
    /// replacement for the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub up_mbps: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub down_mbps: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Hysteria2Obfs>,
    #[serde(default, skip_serializing_if = "is_default_congestion")]
    pub congestion: Hysteria2Congestion,
    #[serde(default, skip_serializing_if = "Hysteria2Quic::is_default")]
    pub quic: Hysteria2Quic,
}

impl Hysteria2Quic {
    /// Whether this is the default tuning, so the table is omitted on output.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

const fn is_default_congestion(congestion: &Hysteria2Congestion) -> bool {
    matches!(congestion, Hysteria2Congestion::Bbr)
}

const fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

const fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

// ── The layers every Xray-family node composes (ADR-0028) ────────────────────

/// How a node's byte stream is made opaque.
///
/// This is the *security* layer: it owns a handshake, a certificate policy and an
/// ALPN offer, and it knows nothing about the protocol above it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SecurityConfig {
    /// The protocol speaks over the transport directly.
    None {},
    /// Ordinary TLS to the node, verified against the platform trust store.
    Tls(TlsSecurity),
    /// REALITY: a tag in `legacy_session_id` authenticates the flow, and the
    /// presented certificate belongs to an impersonated site rather than to the node.
    Reality(RealitySecurity),
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self::None {}
    }
}

impl SecurityConfig {
    /// The `type` this layer is spelled as in TOML and in a link.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::None {} => "none",
            Self::Tls(_) => "tls",
            Self::Reality(_) => "reality",
        }
    }
}

impl<'de> Deserialize<'de> for SecurityConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut table = toml::Table::deserialize(d)?;
        // Absent is `none`: a `vless://` link with no `security=` is a plaintext node,
        // and a table that says nothing must mean the same thing.
        if !table.contains_key("type") {
            return Ok(Self::None {});
        }
        let kind = take_tag(&mut table, "node.security", &["none", "tls", "reality"])
            .map_err(D::Error::custom)?;
        match kind.as_str() {
            "none" => reject_extra(table, "node.security", "none")
                .map(|()| Self::None {})
                .map_err(D::Error::custom),
            "tls" => variant(table, "node.security")
                .map(Self::Tls)
                .map_err(D::Error::custom),
            _ => variant(table, "node.security")
                .map(Self::Reality)
                .map_err(D::Error::custom),
        }
    }
}

/// Ordinary TLS to the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TlsSecurity {
    /// SNI to present. Absent means the node's own hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Accept any certificate. A node that needs this is a node whose chain cannot
    /// be verified, which is a fact the operator should be asserting deliberately.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_insecure: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// netune TLS preset name for this node's ClientHello. Absent uses
    /// `global.tls.profile`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// REALITY (ADR-0010).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RealitySecurity {
    /// The impersonated site. Required, and never an address: SNI names a host.
    pub sni: String,
    /// The node's X25519 public key, base64url.
    pub public_key: String,
    /// Short id, up to 8 bytes, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
}

/// What wraps the stream below the protocol (ADR-0028).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum TransportConfig {
    /// A raw TCP session.
    #[default]
    Tcp,
    /// RFC 6455 over TCP, with the reference's `path`/`Host` framing.
    Ws(WsTransport),
}

impl TransportConfig {
    /// The `type` this layer is spelled as.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws(_) => "ws",
        }
    }
}

impl<'de> Deserialize<'de> for TransportConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut table = toml::Table::deserialize(d)?;
        if !table.contains_key("type") {
            return reject_extra(table, "node.transport", "tcp")
                .map(|()| Self::Tcp)
                .map_err(D::Error::custom);
        }
        let kind =
            take_tag(&mut table, "node.transport", &["tcp", "ws"]).map_err(D::Error::custom)?;
        match kind.as_str() {
            "tcp" => reject_extra(table, "node.transport", "tcp")
                .map(|()| Self::Tcp)
                .map_err(D::Error::custom),
            _ => variant(table, "node.transport")
                .map(Self::Ws)
                .map_err(D::Error::custom),
        }
    }
}

/// WebSocket framing below the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct WsTransport {
    /// Request path, e.g. `/ray`.
    pub path: String,
    /// `Host` header. Absent uses the node's SNI, then its hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Extra request headers, sent verbatim.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

/// How a protocol's payload is framed (ADR-0028).
///
/// Vision is a VLESS flow, not a REALITY feature: the reference applies it from
/// `flow`, and a node whose user is configured for it **rejects** a client that omits
/// it, so this is not a tuning knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum Flow {
    #[default]
    #[serde(rename = "none", alias = "", alias = "xtls-rprx-direct")]
    None,
    #[serde(rename = "xtls-rprx-vision", alias = "vision")]
    Vision,
    /// Vision with UDP/443 allowed through the tunnel. The reference refuses UDP/443
    /// under plain Vision because a QUIC flow inside XTLS double-encrypts; this is the
    /// opt-out.
    #[serde(rename = "xtls-rprx-vision-udp443", alias = "vision-udp443")]
    VisionUdp443,
}

impl Flow {
    /// Whether the flow frames the payload at all.
    #[must_use]
    pub const fn is_vision(self) -> bool {
        matches!(self, Self::Vision | Self::VisionUdp443)
    }

    /// Whether UDP/443 may use the flow.
    #[must_use]
    pub const fn allows_udp443(self) -> bool {
        matches!(self, Self::VisionUdp443)
    }

    /// The reference's spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Vision => "xtls-rprx-vision",
            Self::VisionUdp443 => "xtls-rprx-vision-udp443",
        }
    }
}

/// VLESS: a UUID-authenticated session with an optional Vision flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct VlessNode {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Flow::is_none")]
    pub flow: Flow,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_none")]
    pub security: SecurityConfig,
    #[serde(default, skip_serializing_if = "TransportConfig::is_tcp")]
    pub transport: TransportConfig,
}

impl SecurityConfig {
    /// Whether this is the absent layer, so it is omitted on output.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None {})
    }
}

impl TransportConfig {
    /// Whether this is a raw TCP session, so it is omitted on output.
    #[must_use]
    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp)
    }
}

impl Flow {
    /// Whether the flow is absent, so it is omitted on output.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// VMess's body cipher (ADR-0030).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum VmessCipher {
    /// AES-GCM when the CPU has AES-NI, ChaCha20-Poly1305 otherwise — the
    /// reference's `SecurityType_AUTO`.
    #[default]
    Auto,
    #[serde(rename = "aes-128-gcm", alias = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
}

/// VMess AEAD (ADR-0030). The legacy handshake is not expressible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct VmessNode {
    #[serde(skip_serializing_if = "Option::is_none", alias = "tag")]
    pub name: Option<String>,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "is_default_cipher")]
    pub cipher: VmessCipher,
    /// Authenticate each chunk's length, not only its body. A wire change the server
    /// must also have enabled, so it is explicit rather than defaulted (ADR-0030).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub authenticated_length: bool,
    /// Omit the terminating signal on shutdown.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_termination_signal: bool,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_none")]
    pub security: SecurityConfig,
    #[serde(default, skip_serializing_if = "TransportConfig::is_tcp")]
    pub transport: TransportConfig,
}

const fn is_default_cipher(cipher: &VmessCipher) -> bool {
    matches!(cipher, VmessCipher::Auto)
}

/// Reads and removes the `type` discriminant of a layer table.
///
/// `serde` does not support `deny_unknown_fields` on an internally tagged enum, and a
/// typo inside `[node.security]` would silently keep a default — the failure
/// [ADR-0006](../../../docs/adr/0006-wiring-ownership.md) forbids. Reading the table by
/// hand lets the *variant* own `deny_unknown_fields`, so the check survives.
fn take_tag(table: &mut toml::Table, what: &str, expected: &[&str]) -> Result<String, String> {
    let value = table.remove("type").ok_or_else(|| {
        format!("{what} must declare `type`; the implemented layers are {expected:?}")
    })?;
    let kind = value
        .as_str()
        .ok_or_else(|| format!("{what}.type must be one of {expected:?}, got {value:?}"))?
        .to_owned();
    if !expected.contains(&kind.as_str()) {
        return Err(format!(
            "{what}.type = {kind:?} is not implemented; the implemented layers are {expected:?}"
        ));
    }
    Ok(kind)
}

/// Rejects any key left in an unparameterised layer table.
fn reject_extra(table: toml::Table, what: &str, kind: &str) -> Result<(), String> {
    if let Some(key) = table.keys().next() {
        return Err(format!(
            "{what}.{key} is not a key of the `{kind}` layer; it takes no parameters"
        ));
    }
    Ok(())
}

/// Deserializes a layer's own keys into its variant struct.
fn variant<T: DeserializeOwned>(table: toml::Table, what: &str) -> Result<T, String> {
    T::deserialize(toml::Value::Table(table)).map_err(|error| format!("{what}: {error}"))
}

impl Hysteria2Node {
    /// The first port, for a diagnostic that names one address.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.ports.ranges.first().map(|(low, _)| *low).unwrap_or(0)
    }

    #[must_use]
    pub fn to_link(&self) -> String {
        let server = format_host(&self.server);
        let mut query = Vec::new();
        if let Some(sni) = &self.sni
            && !sni.is_empty()
        {
            query.push(format!("sni={}", percent_encode(sni)));
        }
        if self.allow_insecure {
            query.push("insecure=1".to_owned());
        }
        if let Some(pin) = &self.pin_sha256
            && !pin.is_empty()
        {
            query.push(format!("pinSHA256={}", percent_encode(pin)));
        }
        if self.up_mbps > 0 {
            query.push(format!("upmbps={}", self.up_mbps));
        }
        if self.down_mbps > 0 {
            query.push(format!("downmbps={}", self.down_mbps));
        }
        if let Some(obfs) = &self.obfs {
            query.push(format!("obfs={}", percent_encode(obfs.kind())));
            query.push(format!("obfs-password={}", percent_encode(obfs.password())));
        }
        if self.ports.hop_ms > 0 {
            query.push(format!("hop-interval={}", self.ports.hop_ms));
        }
        if self.ports.hop_min_ms > 0 {
            query.push(format!("hop-min-interval={}", self.ports.hop_min_ms));
        }
        if self.ports.hop_max_ms > 0 {
            query.push(format!("hop-max-interval={}", self.ports.hop_max_ms));
        }
        let query_str = if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query.join("&"))
        };
        format!(
            "hysteria2://{}@{server}:{}{query_str}",
            percent_encode(&self.password),
            self.ports.to_link_port()
        )
    }
}

impl VlessNode {
    /// The layers this node composes, as `(security, transport, flow)` names.
    #[must_use]
    pub fn layers(&self) -> (&'static str, &'static str, &'static str) {
        (
            self.security.kind(),
            self.transport.kind(),
            self.flow.as_str(),
        )
    }

    #[must_use]
    pub fn to_link(&self) -> String {
        let server = format_host(&self.server);
        let mut query = vec!["encryption=none".to_owned()];
        query.push(format!("security={}", self.security.kind()));
        match &self.security {
            SecurityConfig::None {} => {}
            SecurityConfig::Tls(tls) => {
                if let Some(sni) = &tls.sni
                    && !sni.is_empty()
                {
                    query.push(format!("sni={}", percent_encode(sni)));
                }
                if tls.allow_insecure {
                    query.push("allowInsecure=1".to_owned());
                }
                if let Some(fp) = &tls.fingerprint
                    && !fp.is_empty()
                {
                    query.push(format!("fp={}", percent_encode(fp)));
                }
                if !tls.alpn.is_empty() {
                    query.push(format!("alpn={}", tls.alpn.join(",")));
                }
            }
            SecurityConfig::Reality(reality) => {
                query.push(format!("sni={}", percent_encode(&reality.sni)));
                query.push(format!("pbk={}", percent_encode(&reality.public_key)));
                if let Some(sid) = &reality.short_id
                    && !sid.is_empty()
                {
                    query.push(format!("sid={}", percent_encode(sid)));
                }
                if !reality.alpn.is_empty() {
                    query.push(format!("alpn={}", reality.alpn.join(",")));
                }
            }
        }
        query.push(format!("type={}", self.transport.kind()));
        if let TransportConfig::Ws(ws) = &self.transport {
            if !ws.path.is_empty() {
                query.push(format!("path={}", percent_encode(&ws.path)));
            }
            if let Some(host) = &ws.host
                && !host.is_empty()
            {
                query.push(format!("host={}", percent_encode(host)));
            }
        }
        if !self.flow.is_none() {
            query.push(format!("flow={}", percent_encode(self.flow.as_str())));
        }
        format!(
            "vless://{}@{server}:{}?{}",
            self.uuid,
            self.port,
            query.join("&")
        )
    }
}

impl VmessNode {
    #[must_use]
    pub fn to_link(&self) -> String {
        // The reference's own share format: base64url of a JSON object, not a query
        // string. `ps` is the tag, and `scy` is the cipher — both are read back by
        // `from_link`, so the two directions stay inverse.
        let mut fields: Vec<String> = vec![
            "\"v\":\"2\"".to_owned(),
            format!("\"add\":\"{}\"", json_escape(&self.server)),
            format!("\"port\":\"{}\"", self.port),
            format!("\"id\":\"{}\"", json_escape(&self.uuid)),
            "\"aid\":\"0\"".to_owned(),
            format!("\"scy\":\"{}\"", vmess_cipher_name(self.cipher)),
            format!("\"net\":\"{}\"", self.transport.kind()),
            format!(
                "\"tls\":\"{}\"",
                if self.security.is_none() { "" } else { "tls" }
            ),
            // `type` is the header-obfuscation type, which is independent of the
            // transport: this model carries none, so it is always "none". The previous
            // form branched on `is_tcp()` and returned "none" either way.
            "\"type\":\"none\"".to_owned(),
        ];
        if let Some(name) = &self.name {
            fields.push(format!("\"ps\":\"{}\"", json_escape(name)));
        }
        match &self.security {
            SecurityConfig::Tls(tls) => {
                if let Some(sni) = &tls.sni {
                    fields.push(format!("\"sni\":\"{}\"", json_escape(sni)));
                }
                if let Some(fp) = &tls.fingerprint {
                    fields.push(format!("\"fp\":\"{}\"", json_escape(fp)));
                }
                if !tls.alpn.is_empty() {
                    fields.push(format!("\"alpn\":\"{}\"", json_escape(&tls.alpn.join(","))));
                }
            }
            SecurityConfig::Reality(_) => {
                // VMess has no REALITY client in the reference either: REALITY
                // authenticates a VLESS flow. Validation refuses this combination;
                // the arm exists so the match is exhaustive.
            }
            SecurityConfig::None {} => {}
        }
        if let TransportConfig::Ws(ws) = &self.transport {
            fields.push(format!("\"path\":\"{}\"", json_escape(&ws.path)));
            if let Some(host) = &ws.host {
                fields.push(format!("\"host\":\"{}\"", json_escape(host)));
            }
        }
        format!(
            "vmess://{}",
            encode_base64(format!("{{{}}}", fields.join(",")).as_bytes())
        )
    }
}

fn format_host(server: &str) -> String {
    let server = server.trim();
    if server.contains(':') && !server.starts_with('[') && !server.ends_with(']') {
        format!("[{server}]")
    } else {
        server.to_owned()
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

fn validate_ss_method(method: &str) -> Result<(), String> {
    match method.trim().to_ascii_lowercase().as_str() {
        "aes-128-gcm"
        | "aes-256-gcm"
        | "chacha20-ietf-poly1305"
        | "xchacha20-ietf-poly1305"
        | "2022-blake3-aes-128-gcm"
        | "2022-blake3-aes-256-gcm"
        | "2022-blake3-chacha20-poly1305" => Ok(()),
        legacy @ ("aes-128-cfb" | "aes-192-cfb" | "aes-256-cfb" | "aes-128-ctr" | "aes-192-ctr"
        | "aes-256-ctr" | "rc4-md5" | "chacha20" | "chacha20-ietf" | "salsa20"
        | "bf-cfb" | "camellia-128-cfb" | "camellia-192-cfb" | "camellia-256-cfb"
        | "des-cfb" | "table") => Err(format!(
            "shadowsocks: method '{legacy}' is an insecure legacy cipher and is not supported (use an AEAD cipher like chacha20-ietf-poly1305 or aes-256-gcm)"
        )),
        other => Err(format!(
            "shadowsocks: unknown method '{other}'; supported ciphers are chacha20-ietf-poly1305, aes-128-gcm, aes-256-gcm, xchacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305"
        )),
    }
}

fn ss_2022_key_len(method: &str) -> Option<usize> {
    match method.trim().to_ascii_lowercase().as_str() {
        "2022-blake3-aes-128-gcm" => Some(16),
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => Some(32),
        _ => None,
    }
}

fn validate_base64_len(text: &str) -> Result<usize, String> {
    fn value(byte: u8) -> Option<u8> {
        Some(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    }

    let text: Vec<u8> = text.trim().bytes().filter(|byte| *byte != b'=').collect();
    if text.is_empty() {
        return Ok(0);
    }
    let mut out_len = 0;
    for chunk in text.chunks(4) {
        if chunk.len() == 1 {
            return Err("a single trailing character is not a valid group".to_owned());
        }
        for byte in chunk {
            if value(*byte).is_none() {
                return Err(format!("{:?} is not in the base64 alphabet", *byte as char));
            }
        }
        out_len += match chunk.len() {
            2 => 1,
            3 => 2,
            4 => 3,
            _ => unreachable!(),
        };
    }
    Ok(out_len)
}

/// Parses a UUID the way both VLESS and VMess need it: 32 hex digits in the canonical
/// 8-4-4-4-12 layout.
///
/// Validated at load rather than at connect because a malformed id produces a session
/// that authenticates to nobody and fails with the node's generic rejection — the one
/// error an operator cannot attribute.
fn parse_node_uuid(text: &str) -> Result<[u8; 16], String> {
    let mut digits = [0u8; 32];
    let mut count = 0;
    for byte in text.trim().bytes() {
        if byte == b'-' {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return Err(format!(
                "'{text}' is not a UUID: {:?} is not a hex digit",
                byte as char
            ));
        }
        if count == 32 {
            return Err(format!("'{text}' is not a UUID: more than 32 hex digits"));
        }
        digits[count] = byte;
        count += 1;
    }
    if count != 32 {
        return Err(format!(
            "'{text}' is not a UUID: expected 32 hex digits, got {count}"
        ));
    }
    let mut uuid = [0u8; 16];
    for (index, pair) in digits.chunks(2).enumerate() {
        let hex = std::str::from_utf8(pair).map_err(|_| "uuid is not UTF-8".to_owned())?;
        uuid[index] = u8::from_str_radix(hex, 16).map_err(|_| format!("'{text}' is not a UUID"))?;
    }
    Ok(uuid)
}

/// Checks the security layer's own invariants.
fn validate_security(
    security: &SecurityConfig,
    protocol: &str,
    server: &str,
) -> Result<(), String> {
    match security {
        SecurityConfig::None {} => Ok(()),
        SecurityConfig::Tls(tls) => {
            // A certificate cannot be verified against an address: the TLS client would present
            // the IP as SNI, and no CA signs an IP for a proxy node. Failing here gives the
            // operator a message instead of an opaque handshake error.
            if tls.sni.is_none() && server.parse::<std::net::IpAddr>().is_ok() {
                return Err(format!(
                    "{protocol}: a TLS node whose server is an address needs an explicit SNI; \
                     write `[node.security] sni = \"…\"` (or `?sni=…` in a link), because a \
                     certificate cannot be verified against an address"
                ));
            }
            if let Some(sni) = &tls.sni {
                if sni.trim().is_empty() {
                    return Err(format!("{protocol}.security.sni must not be empty"));
                }
                if sni.parse::<std::net::IpAddr>().is_ok() {
                    return Err(format!(
                        "{protocol}.security.sni = {sni:?} is an address; SNI names the host \
                         whose certificate the node presents"
                    ));
                }
            }
            if let Some(fingerprint) = &tls.fingerprint
                && fingerprint.trim().is_empty()
            {
                return Err(format!("{protocol}.security.fingerprint must not be empty"));
            }
            for protocol_name in &tls.alpn {
                if protocol_name.is_empty() || protocol_name.len() > 255 {
                    return Err(format!(
                        "{protocol}.security.alpn entry {protocol_name:?} is not a protocol name"
                    ));
                }
            }
            Ok(())
        }
        SecurityConfig::Reality(reality) => {
            if reality.sni.trim().is_empty() {
                return Err(format!("{protocol}.security.sni must not be empty"));
            }
            if reality.sni.parse::<std::net::IpAddr>().is_ok() {
                return Err(format!(
                    "{protocol}.security.sni = {:?} is an address; REALITY impersonates a site, \
                     and a site is named, not addressed",
                    reality.sni
                ));
            }
            if reality.public_key.trim().is_empty() {
                return Err(format!("{protocol}.security.public-key must not be empty"));
            }
            if let Some(short_id) = &reality.short_id {
                let digits = short_id.trim();
                if digits.len() > 16 || (digits.len() % 2 != 0) {
                    return Err(format!(
                        "{protocol}.security.short-id = {short_id:?} must be an even number of \
                         hex digits (at most 16, i.e. 8 bytes)"
                    ));
                }
                if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!(
                        "{protocol}.security.short-id = {short_id:?} is not hex"
                    ));
                }
            }
            // VMess has no REALITY client: REALITY authenticates a VLESS flow, and the
            // reference's VMess outbound has no branch for it at all.
            if protocol == "vmess" {
                return Err(
                    "vmess.security.type = \"reality\" is not a combination the reference \
                     implements; REALITY authenticates a vless flow"
                        .to_owned(),
                );
            }
            Ok(())
        }
    }
}

/// Checks the transport layer's own invariants.
fn validate_transport(transport: &TransportConfig, protocol: &str) -> Result<(), String> {
    match transport {
        TransportConfig::Tcp => Ok(()),
        TransportConfig::Ws(ws) => {
            if !ws.path.starts_with('/') {
                return Err(format!(
                    "{protocol}.transport.path = {:?} must start with '/', because a WebSocket \
                     upgrade targets a path",
                    ws.path
                ));
            }
            if let Some(host) = &ws.host
                && host.trim().is_empty()
            {
                return Err(format!("{protocol}.transport.host must not be empty"));
            }
            for (name, value) in &ws.headers {
                if name.is_empty() || name.chars().any(|c| c.is_ascii_control() || c == ':') {
                    return Err(format!(
                        "{protocol}.transport.headers: {name:?} is not a header name"
                    ));
                }
                if value.chars().any(|c| c.is_ascii_control()) {
                    return Err(format!(
                        "{protocol}.transport.headers.{name} contains a control character"
                    ));
                }
            }
            Ok(())
        }
    }
}

/// The `scy` spelling a VMess link uses.
const fn vmess_cipher_name(cipher: VmessCipher) -> &'static str {
    match cipher {
        VmessCipher::Auto => "auto",
        VmessCipher::Aes128Gcm => "aes-128-gcm",
        VmessCipher::Chacha20Poly1305 => "chacha20-poly1305",
    }
}

/// Escapes the characters a JSON string literal cannot carry bare.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A display-only name for a link this build cannot parse.
///
/// `scheme://user:secret@host:443#name` is a link, and the part before `@` is a credential.
/// A node's `default_name` is printed by `daer probe`, `daer check --nodes` and the daemon's
/// own logs, so returning the raw link writes a secret wherever a node name goes. Only the
/// scheme is kept: it is what tells an operator *why* the node was skipped, and it is the
/// one part of the link that cannot be a credential.
fn redact_link(scheme: &str, _link: &str) -> String {
    format!("{scheme}://<redacted>")
}

fn percent_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next().unwrap_or(b'0');
            let h2 = chars.next().unwrap_or(b'0');
            let hex_str = [h1, h2];
            if let Ok(hex_ascii) = std::str::from_utf8(&hex_str)
                && let Ok(val) = u8::from_str_radix(hex_ascii, 16)
            {
                bytes.push(val);
                continue;
            }
            bytes.push(b'%');
            bytes.push(h1);
            bytes.push(h2);
            continue;
        }
        bytes.push(b);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn decode_base64(text: &str) -> Result<String, String> {
    fn value(byte: u8) -> Option<u8> {
        Some(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    }

    let text: Vec<u8> = text
        .bytes()
        .filter(|byte| *byte != b'=' && !byte.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.chunks(4) {
        if chunk.len() == 1 {
            return Err("base64: invalid trailing byte".to_owned());
        }
        let mut accumulator = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            let value = value(*byte).ok_or_else(|| {
                format!("base64: byte {:?} is not in the alphabet", *byte as char)
            })?;
            accumulator |= u32::from(value) << (18 - 6 * index);
        }
        let bytes = accumulator.to_be_bytes();
        out.push(bytes[1]);
        if chunk.len() > 2 {
            out.push(bytes[2]);
        }
        if chunk.len() > 3 {
            out.push(bytes[3]);
        }
    }
    String::from_utf8(out).map_err(|_| "base64 payload is not UTF-8".to_owned())
}

fn parse_host_port(authority: &str) -> Result<(String, u16), String> {
    let authority = authority.trim();
    let authority = match authority.split_once('?') {
        Some((auth, _query)) => auth,
        None => authority,
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("{authority:?} has an unclosed '['"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("{authority:?} has no port"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| format!("{authority:?} has an invalid port"))?;
        return Ok((host.to_owned(), port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("{authority:?} has no port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("{authority:?} has an invalid port"))?;
    Ok((host.to_owned(), port))
}

/// Splits `host:ports` where `ports` may be a set (`443,8443`, `1-100`, `all`).
///
/// Distinct from [`parse_host_port`] because the port field is the only one that can
/// carry a list, and a list is what port hopping needs (ADR-0029). The split is on the
/// last colon so an IPv6 literal survives, and bracketed literals are handled first.
fn split_host_ports(authority: &str) -> Result<(String, String), String> {
    let authority = authority.trim();
    let authority = match authority.split_once('?') {
        Some((auth, _query)) => auth,
        None => authority,
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("{authority:?} has an unclosed '['"))?;
        let ports = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("{authority:?} has no port"))?;
        return Ok((host.to_owned(), ports.to_owned()));
    }
    let (host, ports) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("{authority:?} has no port"))?;
    Ok((host.to_owned(), ports.to_owned()))
}

/// Whether a query value means "on": `1`, `true`, `yes`.
fn truthy(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
}

/// A hop interval: bare milliseconds, or a Go duration (`30s`, `1m`).
fn parse_interval_ms(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(millis) = value.parse::<u64>() {
        return Some(millis);
    }
    parse_duration(value).and_then(|span| u64::try_from(span.as_nanos() / 1_000_000).ok())
}

/// Builds a VLESS node from a link's query, splitting the security and transport layers
/// out of the flat parameter list the link format uses (ADR-0028).
fn parse_vless_layers(
    name: Option<String>,
    user_part: &str,
    server: String,
    port: u16,
    query: &str,
) -> Result<VlessNode, String> {
    let mut security_kind = None;
    let mut public_key = None;
    let mut short_id = None;
    let mut fingerprint = None;
    let mut flow_text = None;
    let mut kind = None;
    let mut sni = None;
    let mut alpn: Vec<String> = Vec::new();
    let mut allow_insecure = false;
    let mut path = None;
    let mut host = None;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        // Xray's own spelling for "no encryption" is mandatory in a link and carries no
        // information daer does not already know; anything else is a real request.
        if key == "encryption" && !value.eq_ignore_ascii_case("none") {
            return Err(format!(
                "vless link asks for encryption={value}; VLESS carries no inner encryption, and \
                 only `none` is a valid value"
            ));
        }
        let decoded = percent_decode(value);
        match key {
            "security" => security_kind = Some(decoded),
            "pbk" if !decoded.is_empty() => public_key = Some(decoded),
            "sid" if !decoded.is_empty() => short_id = Some(decoded),
            "fp" if !decoded.is_empty() => fingerprint = Some(decoded),
            "flow" if !decoded.is_empty() => flow_text = Some(decoded),
            "type" if !decoded.is_empty() => kind = Some(decoded),
            "sni" | "peer" if !decoded.is_empty() => sni = Some(decoded),
            "alpn" if !decoded.is_empty() => {
                alpn = decoded.split(',').map(str::to_owned).collect();
            }
            "allowInsecure" | "allow_insecure" | "insecure" => allow_insecure = truthy(value),
            "path" if !decoded.is_empty() => path = Some(decoded),
            "host" if !decoded.is_empty() => host = Some(decoded),
            "headerType" | "serviceName" | "mode" | "extra" => {}
            // Unknown parameters are not an error: panels add them freely and a strict
            // parser would lock an operator out of their own subscription.
            _ => {}
        }
    }

    let flow = match flow_text.as_deref() {
        None | Some("") | Some("none") => Flow::None,
        Some("xtls-rprx-vision") | Some("vision") => Flow::Vision,
        Some("xtls-rprx-vision-udp443") | Some("vision-udp443") => Flow::VisionUdp443,
        Some(other) => {
            return Err(format!(
                "vless link asks for flow={other}; the implemented flows are none, \
                 xtls-rprx-vision and xtls-rprx-vision-udp443"
            ));
        }
    };

    let transport = match kind.as_deref() {
        None | Some("") | Some("tcp") | Some("raw") | Some("none") => TransportConfig::Tcp,
        Some("ws") | Some("websocket") => TransportConfig::Ws(WsTransport {
            path: path.unwrap_or_else(|| "/".to_owned()),
            host,
            headers: BTreeMap::new(),
        }),
        Some(other) => {
            return Err(format!(
                "vless link asks for type={other}; the implemented transports are tcp and ws. \
                 A {other} session is a framing layer daer does not have, so it is refused \
                 rather than silently downgraded to tcp"
            ));
        }
    };

    let security = match security_kind.as_deref() {
        None | Some("") | Some("none") => SecurityConfig::None {},
        Some("tls") => SecurityConfig::Tls(TlsSecurity {
            sni,
            allow_insecure,
            alpn,
            fingerprint,
        }),
        Some("reality") => SecurityConfig::Reality(RealitySecurity {
            sni: sni.ok_or_else(|| {
                "vless:// REALITY link has no `sni`; REALITY impersonates a named site, and the \
                 node's address cannot be one"
                    .to_owned()
            })?,
            public_key: public_key.ok_or_else(|| {
                "vless:// REALITY link has no `pbk`; the server's public key is what the tag is \
                 derived from, and without it no handshake can be attempted"
                    .to_owned()
            })?,
            short_id,
            alpn,
        }),
        Some("xtls") => {
            return Err(
                "vless link asks for security=xtls; that is the retired pre-Vision XTLS, which \
                 the reference removed. Use security=reality with flow=xtls-rprx-vision"
                    .to_owned(),
            );
        }
        Some(other) => {
            return Err(format!(
                "vless link asks for security={other}; the implemented security layers are none, \
                 tls and reality"
            ));
        }
    };

    let vless = VlessNode {
        name,
        server,
        port,
        uuid: user_part.to_owned(),
        flow,
        security,
        transport,
    };
    vless
        .validate_self()
        .map_err(|reason| format!("vless link is not usable: {reason}"))?;
    Ok(vless)
}

impl VlessNode {
    /// Validates this node, for the link path where the caller wants a usable node.
    fn validate_self(&self) -> Result<(), String> {
        NodeEndpoint::Vless(self.clone()).validate()
    }
}

impl VmessNode {
    /// Validates this node, for the link path where the caller wants a usable node.
    fn validate_self(&self) -> Result<(), String> {
        NodeEndpoint::Vmess(self.clone()).validate()
    }
}

/// Parses `vmess://<base64(json)>` (ADR-0030).
///
/// The reference's share format is a base64url JSON object rather than a query string, so
/// there is no shared query parser to reuse. Unknown fields are ignored — panels add
/// them — but a field naming a layer daer does not implement is refused, because silently
/// dialling `net = "kcp"` as TCP produces a session that never authenticates.
fn parse_vmess_link(
    name: Option<String>,
    body: &str,
    whole_link: &str,
) -> Result<VmessNode, String> {
    let json = decode_base64(body.trim())
        .map_err(|reason| format!("vmess link payload is not base64 JSON: {reason}"))?;
    let fields = parse_json_object(&json)?;

    let get = |key: &str| fields.get(key).map(String::as_str).unwrap_or("");
    let server = get("add");
    if server.is_empty() {
        return Err("vmess link has no `add` (server)".to_owned());
    }
    let port: u16 = get("port")
        .parse()
        .map_err(|_| format!("vmess link port {:?} is not a number", get("port")))?;
    let uuid = get("id");
    if uuid.is_empty() {
        return Err("vmess link has no `id` (uuid)".to_owned());
    }
    // `aid` is the legacy handshake's parameter. Accepting a non-zero value while
    // speaking AEAD would be a lie about which handshake is on the wire.
    match get("aid") {
        "" | "0" => {}
        other => {
            return Err(format!(
                "vmess link has aid={other}; a non-zero alterId selects the legacy handshake, \
                 which daer does not implement (ADR-0030). Only VMess AEAD is spoken"
            ));
        }
    }

    let cipher = match get("scy").to_ascii_lowercase().as_str() {
        "" | "auto" => VmessCipher::Auto,
        "aes-128-gcm" => VmessCipher::Aes128Gcm,
        "chacha20-poly1305" => VmessCipher::Chacha20Poly1305,
        other => {
            return Err(format!(
                "vmess link asks for scy={other}; the implemented ciphers are auto, \
                 aes-128-gcm and chacha20-poly1305"
            ));
        }
    };

    let tls_field = get("tls").to_ascii_lowercase();
    let alpn: Vec<String> = if get("alpn").is_empty() {
        Vec::new()
    } else {
        get("alpn").split(',').map(str::to_owned).collect()
    };
    let security = match tls_field.as_str() {
        "" | "none" => SecurityConfig::None {},
        "tls" => SecurityConfig::Tls(TlsSecurity {
            sni: (!get("sni").is_empty()).then(|| get("sni").to_owned()),
            allow_insecure: truthy(get("allowinsecure")) || truthy(get("allow_insecure")),
            alpn,
            fingerprint: (!get("fp").is_empty()).then(|| get("fp").to_owned()),
        }),
        "reality" => {
            return Err(
                "vmess link asks for tls=reality; REALITY authenticates a vless flow, and the \
                 reference implements no VMess REALITY client"
                    .to_owned(),
            );
        }
        other => {
            return Err(format!(
                "vmess link asks for tls={other}; the implemented security layers are none and \
                 tls"
            ));
        }
    };

    let transport = match get("net").to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => TransportConfig::Tcp,
        "ws" | "websocket" => {
            let path = get("path");
            TransportConfig::Ws(WsTransport {
                path: if path.is_empty() {
                    "/".to_owned()
                } else {
                    path.to_owned()
                },
                host: (!get("host").is_empty()).then(|| get("host").to_owned()),
                headers: BTreeMap::new(),
            })
        }
        other => {
            return Err(format!(
                "vmess link asks for net={other}; the implemented transports are tcp and ws \
                 (in {whole_link:?})"
            ));
        }
    };

    let name = name.or_else(|| (!get("ps").is_empty()).then(|| get("ps").to_owned()));
    let vmess = VmessNode {
        name,
        server: server.to_owned(),
        port,
        uuid: uuid.to_owned(),
        cipher,
        authenticated_length: get("authenticatedLength").eq_ignore_ascii_case("true"),
        no_termination_signal: get("noTerminationSignal").eq_ignore_ascii_case("true"),
        security,
        transport,
    };
    vmess
        .validate_self()
        .map_err(|reason| format!("vmess link is not usable: {reason}"))?;
    Ok(vmess)
}

/// A flat JSON object of string values, which is all a `vmess://` payload is.
///
/// Hand-rolled rather than a `serde_json` dependency in `daer-config`: the payload is a
/// dozen string fields, `serde_json` is already a workspace dependency but pulling a JSON
/// parser into the configuration crate for one link format would put a second
/// deserializer on the load path. Escapes are decoded; nested values are refused because
/// a `vmess://` payload has none and accepting one would silently drop it.
fn parse_json_object(json: &str) -> Result<BTreeMap<String, String>, String> {
    let bytes: Vec<char> = json.trim().chars().collect();
    let mut index = 0;
    let mut fields = BTreeMap::new();

    let skip_ws = |index: &mut usize| {
        while *index < bytes.len() && bytes[*index].is_whitespace() {
            *index += 1;
        }
    };
    let parse_string = |index: &mut usize| -> Result<String, String> {
        skip_ws(index);
        if bytes.get(*index) != Some(&'"') {
            return Err(format!("expected a string at offset {index}"));
        }
        *index += 1;
        let mut out = String::new();
        loop {
            let c = *bytes.get(*index).ok_or("unterminated string")?;
            *index += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let escape = *bytes.get(*index).ok_or("unterminated escape")?;
                    *index += 1;
                    match escape {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let hex: String = bytes
                                .get(*index..*index + 4)
                                .ok_or("truncated \\u escape")?
                                .iter()
                                .collect();
                            *index += 4;
                            let code = u32::from_str_radix(&hex, 16)
                                .map_err(|_| format!("{hex:?} is not a code point"))?;
                            out.push(char::from_u32(code).ok_or("invalid code point")?);
                        }
                        other => return Err(format!("unknown escape \\{other}")),
                    }
                }
                c => out.push(c),
            }
        }
    };

    skip_ws(&mut index);
    if bytes.get(index) != Some(&'{') {
        return Err("payload is not a JSON object".to_owned());
    }
    index += 1;
    loop {
        skip_ws(&mut index);
        match bytes.get(index) {
            Some('}') => break,
            Some('"') => {}
            Some(other) => return Err(format!("expected a key or '}}', got {other:?}")),
            None => return Err("unterminated object".to_owned()),
        }
        let key = parse_string(&mut index)?;
        skip_ws(&mut index);
        if bytes.get(index) != Some(&':') {
            return Err(format!("expected ':' after key {key:?}"));
        }
        index += 1;
        skip_ws(&mut index);
        match bytes.get(index) {
            Some('"') => {
                let value = parse_string(&mut index)?;
                fields.insert(key, value);
            }
            Some('{') | Some('[') => {
                return Err(format!(
                    "vmess link field {key:?} holds a nested value; a `vmess://` payload is a \
                     flat object of strings"
                ));
            }
            Some(_) => {
                // Numbers and booleans are written bare by some panels. Reading the token
                // as text is what the reference does, and it keeps `"port": 443` working.
                let start = index;
                while index < bytes.len() && !matches!(bytes[index], ',' | '}') {
                    index += 1;
                }
                let token: String = bytes[start..index].iter().collect();
                fields.insert(key, token.trim().to_owned());
            }
            None => return Err("unterminated object".to_owned()),
        }
        skip_ws(&mut index);
        match bytes.get(index) {
            Some(',') => index += 1,
            Some('}') => {}
            Some(other) => return Err(format!("expected ',' or '}}', got {other:?}")),
            None => return Err("unterminated object".to_owned()),
        }
    }
    Ok(fields)
}

impl StructuredNode {
    /// Parses an outbound URI link (`vless://`, `ss://`, `trojan://`, `socks5://`, `http://`,
    /// `direct://`) into a structured node representation.
    pub fn from_link(link: &str) -> Result<Self, String> {
        let endpoint = Self::from_link_unchecked(link)?;
        // Deliberately **not** validated here.
        //
        // Parsing a link and supporting it are different questions, and subscription
        // handling depends on the difference: an airport's `vless://…?security=tls` or
        // `tuic://` link is well formed and unsupported, and it has to enter the pool so the
        // generation builder can report it by name. Validating here made such a link vanish
        // during resolution instead — a pool that looks populated while a node was silently
        // dropped, which is the failure mode
        // `a_subscription_with_no_usable_node_is_not_a_silent_empty_group` exists to prevent.
        //
        // The conversion path, where emitting an unusable node *is* a defect, validates in
        // [`to_toml_node`](Self::to_toml_node).
        Ok(endpoint)
    }

    /// Splits a link into a node **without** checking that the result is usable.
    ///
    /// Only [`from_link`](Self::from_link) should call this: an unchecked node may declare a
    /// cipher that is not implemented, an empty server, or a `vless` node with no REALITY.
    fn from_link_unchecked(link: &str) -> Result<Self, String> {
        let link = link.trim();
        if link.is_empty() || link == "direct" || link == "direct://" {
            return Ok(Self::Direct(DirectNode { name: None }));
        }

        if link.contains("->") {
            return Err("chained links ('a -> b') are not implemented".to_owned());
        }

        let Some((scheme, rest)) = link.split_once("://") else {
            return Err(format!("{link:?} has no '://' scheme separator"));
        };

        // Split off #fragment as name
        let (before_fragment, name) = match rest.split_once('#') {
            Some((before, fragment)) => {
                let name = percent_decode(fragment);
                let name = if name.is_empty() { None } else { Some(name) };
                (before, name)
            }
            None => (rest, None),
        };

        match scheme.to_ascii_lowercase().as_str() {
            "direct" => Ok(Self::Direct(DirectNode { name })),
            "socks" | "socks5" | "socks5h" => {
                let (auth, authority) = match before_fragment.rsplit_once('@') {
                    Some((auth, hostport)) => (Some(auth), hostport),
                    None => (None, before_fragment),
                };
                let (username, password) = match auth {
                    Some(auth) => match auth.split_once(':') {
                        Some((u, p)) => (Some(percent_decode(u)), Some(percent_decode(p))),
                        None => (Some(percent_decode(auth)), None),
                    },
                    None => (None, None),
                };
                let (server, port) = parse_host_port(authority)?;
                Ok(Self::Socks5(Socks5Node {
                    name,
                    server,
                    port,
                    username,
                    password,
                }))
            }
            "http" => {
                let (auth, authority) = match before_fragment.rsplit_once('@') {
                    Some((auth, hostport)) => (Some(auth), hostport),
                    None => (None, before_fragment),
                };
                let (username, password) = match auth {
                    Some(auth) => match auth.split_once(':') {
                        Some((u, p)) => (Some(percent_decode(u)), Some(percent_decode(p))),
                        None => (Some(percent_decode(auth)), None),
                    },
                    None => (None, None),
                };
                let (server, port) = parse_host_port(authority)?;
                Ok(Self::Http(HttpNode {
                    name,
                    server,
                    port,
                    username,
                    password,
                }))
            }
            "ss" | "shadowsocks" => {
                let (creds, authority) = match before_fragment.rsplit_once('@') {
                    Some((userinfo, hostport)) => {
                        if userinfo.contains(':')
                            && validate_ss_method(userinfo.split_once(':').unwrap().0).is_ok()
                        {
                            (userinfo.to_owned(), hostport.to_owned())
                        } else {
                            match decode_base64(userinfo) {
                                Ok(decoded) => (decoded, hostport.to_owned()),
                                Err(_) if userinfo.contains(':') => {
                                    (userinfo.to_owned(), hostport.to_owned())
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    None => {
                        let decoded = decode_base64(before_fragment)?;
                        let (creds, hostport) = decoded.rsplit_once('@').ok_or_else(|| {
                            "ss link has no '@' separating credentials from server".to_owned()
                        })?;
                        (creds.to_owned(), hostport.to_owned())
                    }
                };
                let (method, password) = creds.split_once(':').ok_or_else(|| {
                    "ss credentials are not in 'method:password' format".to_owned()
                })?;
                let (server, port) = parse_host_port(&authority)?;
                Ok(Self::Shadowsocks(ShadowsocksNode {
                    name,
                    server,
                    port,
                    method: method.to_owned(),
                    password: password.to_owned(),
                }))
            }
            "trojan" | "trojan-go" => {
                let (authority, query) = match before_fragment.split_once('?') {
                    Some((auth, q)) => (auth, q),
                    None => (before_fragment, ""),
                };
                let (password, hostport) = authority
                    .rsplit_once('@')
                    .ok_or_else(|| "trojan link has no 'password@server:port'".to_owned())?;
                let (server, port) = parse_host_port(hostport)?;

                let mut sni = None;
                let mut allow_insecure = false;
                for pair in query.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = match pair.split_once('=') {
                        Some((k, v)) => (k, v),
                        None => (pair, ""),
                    };
                    match k {
                        "sni" | "peer" if !v.is_empty() => {
                            sni = Some(percent_decode(v));
                        }
                        "allowInsecure" | "allow_insecure" => {
                            allow_insecure = v == "1" || v.eq_ignore_ascii_case("true");
                        }
                        _ => {}
                    }
                }
                Ok(Self::Trojan(TrojanNode {
                    name,
                    server,
                    port,
                    password: password.to_owned(),
                    sni,
                    allow_insecure,
                }))
            }
            "anytls" => {
                let (authority, query) = match before_fragment.split_once('?') {
                    Some((auth, q)) => (auth, q),
                    None => (before_fragment, ""),
                };
                let (password, hostport) = authority
                    .rsplit_once('@')
                    .ok_or_else(|| "anytls link has no 'password@server:port'".to_owned())?;
                let (server, port) = parse_host_port(hostport)?;

                let mut sni = None;
                let mut allow_insecure = false;
                let mut idle_sessions = 1;
                for pair in query.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = match pair.split_once('=') {
                        Some((k, v)) => (k, v),
                        None => (pair, ""),
                    };
                    match k {
                        "sni" | "peer" if !v.is_empty() => {
                            sni = Some(percent_decode(v));
                        }
                        "allowInsecure" | "allow_insecure" | "insecure" => {
                            allow_insecure = v == "1" || v.eq_ignore_ascii_case("true");
                        }
                        "idle_sessions" | "min_idle_sessions" => {
                            if let Ok(n) = v.parse::<usize>() {
                                idle_sessions = n.max(1);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Self::AnyTls(AnyTlsNode {
                    name,
                    server,
                    port,
                    password: percent_decode(password),
                    sni,
                    allow_insecure,
                    idle_sessions,
                }))
            }
            "hysteria2" | "hy2" => {
                let (authority, query) = match before_fragment.split_once('?') {
                    Some((auth, q)) => (auth, q),
                    None => (before_fragment, ""),
                };
                let (password, hostport) = authority
                    .rsplit_once('@')
                    .ok_or_else(|| "hysteria2 link has no 'password@server:port'".to_owned())?;
                // The port field may be a set (`443,8443`, `20000-30000`, `all`), which is
                // what the reference's port hopping needs. Splitting on the *last* colon
                // keeps an IPv6 literal intact.
                let (server, port_text) = split_host_ports(hostport)?;
                let mut ports = PortSet::parse(&port_text)?;

                let mut sni = None;
                let mut allow_insecure = false;
                let mut pin_sha256 = None;
                let mut up_mbps = 0;
                let mut down_mbps = 0;
                let mut obfs_kind = None;
                let mut obfs_password = None;
                let mut congestion = Hysteria2Congestion::Bbr;
                let mut gecko_min = 0u16;
                let mut gecko_max = 0u16;

                for pair in query.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = match pair.split_once('=') {
                        Some((k, v)) => (k, v),
                        None => (pair, ""),
                    };
                    match k {
                        "sni" | "peer" if !v.is_empty() => sni = Some(percent_decode(v)),
                        "insecure" | "allowInsecure" | "allow_insecure" => {
                            allow_insecure = truthy(v);
                        }
                        "pinSHA256" | "pin-sha256" if !v.is_empty() => {
                            pin_sha256 = Some(percent_decode(v));
                        }
                        "upmbps" | "up_mbps" => up_mbps = v.parse().unwrap_or(0),
                        "downmbps" | "down_mbps" => down_mbps = v.parse().unwrap_or(0),
                        "obfs" if !v.is_empty() => obfs_kind = Some(percent_decode(v)),
                        "obfs-password" if !v.is_empty() => {
                            obfs_password = Some(percent_decode(v));
                        }
                        "hop-interval" | "hop_interval" => {
                            ports.hop_ms = parse_interval_ms(v).unwrap_or(0);
                        }
                        "hop-min-interval" | "hop_min_interval" => {
                            ports.hop_min_ms = parse_interval_ms(v).unwrap_or(0);
                        }
                        "hop-max-interval" | "hop_max_interval" => {
                            ports.hop_max_ms = parse_interval_ms(v).unwrap_or(0);
                        }
                        "congestion" if !v.is_empty() => {
                            congestion = match percent_decode(v).to_ascii_lowercase().as_str() {
                                "bbr" => Hysteria2Congestion::Bbr,
                                "cubic" => Hysteria2Congestion::Cubic,
                                "new_reno" | "newreno" | "reno" => Hysteria2Congestion::NewReno,
                                "brutal" => Hysteria2Congestion::Brutal,
                                other => {
                                    return Err(format!(
                                        "hysteria2 link asks for congestion={other}; the \
                                         implemented controllers are bbr, cubic, new-reno and \
                                         brutal"
                                    ));
                                }
                            };
                        }
                        "gecko-min-packet-size" => gecko_min = v.parse().unwrap_or(0),
                        "gecko-max-packet-size" => gecko_max = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }

                let obfs = match (obfs_kind.as_deref(), obfs_password) {
                    (None, None) | (Some(""), None) => None,
                    (Some(kind), Some(password)) => match kind.to_ascii_lowercase().as_str() {
                        "salamander" => Some(Hysteria2Obfs::Salamander { password }),
                        "gecko" => Some(Hysteria2Obfs::Gecko {
                            password,
                            min_packet_size: gecko_min,
                            max_packet_size: gecko_max,
                        }),
                        other => {
                            return Err(format!(
                                "hysteria2 link asks for obfs={other}; the implemented \
                                 obfuscations are salamander and gecko (and omitting obfs)"
                            ));
                        }
                    },
                    (Some(kind), None) => {
                        return Err(format!(
                            "hysteria2 link names obfs={kind} without obfs-password; the \
                             obfuscation is a pre-shared key"
                        ));
                    }
                    (None, Some(_)) => {
                        return Err(
                            "hysteria2 link names obfs-password without obfs; the password has \
                             no meaning on its own"
                                .to_owned(),
                        );
                    }
                };

                Ok(Self::Hysteria2(Hysteria2Node {
                    name,
                    server,
                    ports,
                    password: percent_decode(password),
                    sni,
                    allow_insecure,
                    pin_sha256,
                    up_mbps,
                    down_mbps,
                    obfs,
                    congestion,
                    quic: Hysteria2Quic::default(),
                }))
            }
            "vless" => {
                let (user_part, rest) = before_fragment
                    .split_once('@')
                    .ok_or_else(|| "vless link has no 'uuid@server:port'".to_owned())?;
                let (authority, query) = match rest.split_once('?') {
                    Some((auth, q)) => (auth, q),
                    None => (rest, ""),
                };
                let (server, port) = parse_host_port(authority)?;
                parse_vless_layers(name, user_part, server, port, query).map(Self::Vless)
            }
            "vmess" => parse_vmess_link(name, before_fragment, link).map(Self::Vmess),
            other => Ok(Self::Unsupported {
                scheme: other.to_owned(),
                link: link.to_owned(),
            }),
        }
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = toml::Value::deserialize(d)?;
        match value {
            toml::Value::String(_) => Err(D::Error::custom(
                "bare URL strings in 'node' have been retired; configure nodes as [[node]] structured tables, or use [[subscription]] to fetch URL lists",
            )),
            toml::Value::Table(table) => {
                if table.contains_key("url") {
                    return Err(D::Error::custom(
                        "the 'url' field in [[node]] has been retired in favor of structured configuration tables; \
                         declare node fields directly (e.g. type = \"vless\", server = ..., port = ...) or run 'daer node convert <url>' to convert your link",
                    ));
                }
                if !table.contains_key("type") {
                    return Err(D::Error::custom(
                        "missing 'type' in [[node]] table (expected e.g. type = \"vless\", \"anytls\", \"shadowsocks\", \"trojan\", \"socks5\", \"http\", \"direct\")",
                    ));
                }

                #[derive(Deserialize)]
                #[serde(rename_all = "kebab-case")]
                struct NodeHelper {
                    #[serde(alias = "tag")]
                    name: Option<String>,
                    detour: Option<String>,
                    #[serde(flatten)]
                    endpoint: NodeEndpoint,
                }

                let helper =
                    NodeHelper::deserialize(toml::Value::Table(table)).map_err(D::Error::custom)?;
                helper.endpoint.validate().map_err(D::Error::custom)?;
                Ok(Self {
                    name: helper.name,
                    endpoint: helper.endpoint,
                    detour: helper.detour,
                    subscription: None,
                })
            }
            other => Err(D::Error::custom(format!(
                "expected [[node]] to be a structured table, got {}",
                other.type_str()
            ))),
        }
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
    /// The candidate set: multiple filters are OR-ed; each filter is a conjunction.
    ///
    /// A group carries no selection rule and no probe. It is a resource pool; an
    /// `[[election]]` names it as input and owns the rule that picks one member.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Vec<crate::schema::mirror::Filter>")
    )]
    pub filters: Vec<Filter>,
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

/// `[dns.fake-ip]` — synthetic IP pool configuration (ADR-0012).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct FakeIpConfig {
    pub enabled: bool,
    pub inet: String,
    /// The optional IPv6 pool.
    ///
    /// `None` keeps the historic IPv4-only Fake-IP behaviour: `A` is synthesised and `AAAA`
    /// is answered with an empty NOERROR so a dual-stack client falls back to the synthetic
    /// address. Setting a prefix enables IPv6 synthesis as well. The key is explicit rather
    /// than a second meaning for `inet`, because one prefix cannot describe both families.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inet6: Option<String>,
    pub pool_size: usize,
    pub exclude: Vec<String>,
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            inet: "198.18.0.0/15".to_owned(),
            inet6: None,
            pool_size: 65535,
            exclude: Vec::new(),
        }
    }
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
    pub fake_ip: FakeIpConfig,
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
            fake_ip: FakeIpConfig::default(),
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub election: Vec<Election>,
    #[serde(
        default,
        rename = "rule-provider",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub rule_provider: Vec<RuleProvider>,
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
            election: Vec::new(),
            rule_provider: Vec::new(),
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
        assert_eq!(
            parsed.routing.fallback,
            FunctionOrString::Name("direct".into())
        );

        let error = toml::from_str::<Config>("[global]\ntproxy-port = 1\n")
            .expect_err("unknown key must fail");
        assert!(
            error.to_string().contains("tproxy-port"),
            "unexpected error: {error}"
        );
    }

    /// The defaults must be a configuration `daer run` accepts.
    ///
    /// `daer run` refuses an empty `wan-interface` ("daer cannot know which interface carries
    /// proxied traffic"), so while the default was `[]` the documented smallest valid file —
    /// and the reference documentation's own default column, and `daer.example.toml`, which
    /// both said `["auto"]` — produced a daemon that exited immediately. The falsifier is one
    /// command: `printf 'schema = 2\n' > c.toml && daer run -c c.toml --no-datapath` used to
    /// fail with that message; the default is now the value the documentation promised.
    #[test]
    fn the_defaults_are_a_configuration_the_daemon_can_run() {
        let parsed = config("");
        assert_eq!(
            parsed.global.wan_interface,
            vec!["auto".to_owned()],
            "an empty configuration must name a WAN interface the daemon can resolve"
        );
        // And the default survives semantic validation, which is what `run` performs first.
        let mut validated = parsed;
        crate::validate::normalize(&mut validated).expect("the defaults must validate");
        assert_eq!(validated.global.wan_interface, vec!["auto".to_owned()]);
    }

    #[test]
    fn rules_are_parsed_from_expressions() {
        let parsed = config(
            "[routing]\nrules = [\"domain(a.com) && port(443) -> proxy\"]\nfallback = \"direct\"\n",
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
        let parsed = config("[global.probe]\ninterval = \"45s\"\ntolerance = \"-1s\"\n");
        assert_eq!(parsed.global.probe.interval, TimeSpan::from_secs(45));
        assert!(parsed.global.probe.tolerance.is_negative());

        let error = toml::from_str::<Config>("[global.probe]\ninterval = \"45\"\n")
            .expect_err("a unitless duration must fail");
        assert!(error.to_string().contains("invalid duration"), "{error}");
    }

    #[test]
    fn subscriptions_accept_both_shapes_and_nodes_require_structured_tables() {
        let plain = config("subscription = [\"https://a/sub\"]\n");
        assert_eq!(plain.subscription[0].name, None);
        assert!(!plain.subscription[0].persist);

        let tables = config(
            "[[subscription]]\nname = \"b\"\nurl = \"https://b/sub\"\npersist = true\n\
             [[node]]\nname = \"n1\"\ntype = \"direct\"\n",
        );
        assert_eq!(tables.subscription[0].name.as_deref(), Some("b"));
        assert!(tables.subscription[0].persist);
        assert_eq!(tables.node[0].name.as_deref(), Some("n1"));

        // Backwards compatibility alias for `tag`
        let legacy = config(
            "[[subscription]]\ntag = \"b_leg\"\nurl = \"https://b/sub\"\n\
             [[node]]\ntag = \"n_leg\"\ntype = \"direct\"\n",
        );
        assert_eq!(legacy.subscription[0].name.as_deref(), Some("b_leg"));
        assert_eq!(legacy.node[0].name.as_deref(), Some("n_leg"));

        // Legacy bare URL strings in node are rejected with clear explanation
        let err = toml::from_str::<Config>("node = [\"ss://x\"]\n")
            .expect_err("bare url array must fail");
        assert!(
            err.to_string()
                .contains("bare URL strings in 'node' have been retired"),
            "{err}"
        );

        // Legacy `url = "..."` in [[node]] is rejected with clear explanation
        let err = toml::from_str::<Config>("[[node]]\ntag = \"n1\"\nurl = \"ss://x\"\n")
            .expect_err("url in node must fail");
        assert!(
            err.to_string()
                .contains("the 'url' field in [[node]] has been retired"),
            "{err}"
        );
    }

    #[test]
    fn structured_node_from_link_converts_real_world_links() {
        // Real-world VLESS REALITY link from user's subscription (note: omits fp=, should default to chrome).
        let vless_link = "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkus1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=portal.citygrainla.com&pbk=9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E&sid=672f&type=tcp&udp=1&tfo=1#US%20VIP%2001";
        let structured = StructuredNode::from_link(vless_link).expect("converts vless link");
        match structured {
            StructuredNode::Vless(vless) => {
                assert_eq!(vless.name.as_deref(), Some("US VIP 01"));
                assert_eq!(vless.server, "fkus1keria.itknowledgeblog.com");
                assert_eq!(vless.port, 443);
                assert_eq!(vless.uuid, "df4af3d0-030e-4062-baa6-eb9dd45298ef");
                assert_eq!(vless.flow, Flow::Vision);
                let SecurityConfig::Reality(reality) = &vless.security else {
                    panic!(
                        "expected a REALITY security layer, got {:?}",
                        vless.security
                    );
                };
                assert_eq!(reality.sni, "portal.citygrainla.com");
                assert_eq!(
                    reality.public_key,
                    "9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E"
                );
                assert_eq!(reality.short_id.as_deref(), Some("672f"));
                // The transport layer is its own axis now (ADR-0028): `type=tcp` in the
                // link is `TransportConfig::Tcp`, not a field on the REALITY layer.
                assert_eq!(vless.transport, TransportConfig::Tcp);
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        // Real-world Shadowsocks link with base64 userinfo
        let ss_link =
            "ss://YWVzLTEyOC1nY206bm9uZQ==@127.0.0.1:1080?udp=0#Website%3A%20user.totorofree.com";
        let structured = StructuredNode::from_link(ss_link).expect("converts ss link");
        match structured {
            StructuredNode::Shadowsocks(ss) => {
                assert_eq!(ss.name.as_deref(), Some("Website: user.totorofree.com"));
                assert_eq!(ss.server, "127.0.0.1");
                assert_eq!(ss.port, 1080);
                // The fixture spelled the cipher `aes-128-grm` — a typo the test asserted
                // as if correct. `from_link` now validates, so it has to be a real cipher;
                // the assertion follows the link's base64 rather than the old typo.
                assert_eq!(ss.method, "aes-128-gcm");
                assert_eq!(ss.password, "none");
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        // SOCKS5 and Trojan
        let socks_link = "socks5://user:pass@127.0.0.1:1080#my-socks";
        let structured = StructuredNode::from_link(socks_link).expect("converts socks link");
        assert_eq!(structured.name(), Some("my-socks"));

        let trojan_link = "trojan://password@node.example.com:443?sni=sni.example.com#my-trojan";
        let structured = StructuredNode::from_link(trojan_link).expect("converts trojan link");
        assert_eq!(structured.name(), Some("my-trojan"));

        let anytls_link = "anytls://secret-pass@anytls.example.com:443?sni=sni.example.com&allowInsecure=1&idle_sessions=3#my-anytls";
        let structured = StructuredNode::from_link(anytls_link).expect("converts anytls link");
        match structured {
            StructuredNode::AnyTls(anytls) => {
                assert_eq!(anytls.name.as_deref(), Some("my-anytls"));
                assert_eq!(anytls.server, "anytls.example.com");
                assert_eq!(anytls.port, 443);
                assert_eq!(anytls.password, "secret-pass");
                assert_eq!(anytls.sni.as_deref(), Some("sni.example.com"));
                assert!(anytls.allow_insecure);
                assert_eq!(anytls.idle_sessions, 3);
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        let hy2_link = "hysteria2://secret-hy2@hy2.example.com:443?sni=sni.example.com&insecure=1&upmbps=50&downmbps=100&obfs=salamander&obfs-password=cry_me_a_r1ver#my-hy2";
        let structured = StructuredNode::from_link(hy2_link).expect("converts hysteria2 link");
        match structured {
            StructuredNode::Hysteria2(hy2) => {
                assert_eq!(hy2.name.as_deref(), Some("my-hy2"));
                assert_eq!(hy2.server, "hy2.example.com");
                assert_eq!(hy2.ports.ranges, vec![(443, 443)]);
                assert_eq!(hy2.password, "secret-hy2");
                assert_eq!(hy2.sni.as_deref(), Some("sni.example.com"));
                assert!(hy2.allow_insecure);
                assert_eq!(hy2.up_mbps, 50);
                assert_eq!(hy2.down_mbps, 100);
                // `obfs=salamander` with no password is refused at link-parse time, so the
                // fixture carries one and the layer survives with its key.
                assert_eq!(
                    hy2.obfs,
                    Some(Hysteria2Obfs::Salamander {
                        password: "cry_me_a_r1ver".to_owned()
                    })
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn filters_accept_a_string_or_a_table() {
        let parsed = config(
            "[[group]]\nname = \"g\"\n\
             filters = [\"subtag(a) && !name(keyword: 'x')\", { match = \"name(n1)\", annotate = { mark = \"1\" } }]\n",
        );
        assert_eq!(parsed.group[0].filters.len(), 2);
        assert_eq!(parsed.group[0].filters[0].functions.len(), 2);
        assert_eq!(parsed.group[0].filters[1].annotate[0].key, "mark");
    }

    #[test]
    fn structured_nodes_parse_validate_and_generate_canonical_links() {
        let toml_str = r#"
[[node]]
tag = "hk-vless"
type = "vless"
server = "198.51.100.1"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"
[node.security]
type = "reality"
sni = "example.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
short-id = "ab01cd02"

[[node]]
tag = "us-ss"
type = "shadowsocks"
server = "198.51.100.2"
port = 8388
method = "chacha20-ietf-poly1305"
password = "secret-password"

[[node]]
tag = "jp-trojan"
type = "trojan"
server = "198.51.100.3"
port = 443
password = "my-password"
sni = "trojan.example.com"
allow-insecure = true

[[node]]
tag = "local-socks5"
type = "socks5"
server = "127.0.0.1"
port = 1080
username = "admin"
password = "123"

[[node]]
tag = "local-http"
type = "http"
server = "127.0.0.1"
port = 8080

[[node]]
tag = "direct-node"
type = "direct"
"#;
        let parsed = config(toml_str);
        assert_eq!(parsed.node.len(), 6);

        // hk-vless
        let n0 = &parsed.node[0];
        assert_eq!(n0.name.as_deref(), Some("hk-vless"));
        assert!(matches!(n0.endpoint, NodeEndpoint::Vless(_)));
        let link0 = n0.to_link();
        assert!(
            link0.starts_with("vless://b831381d-6324-4d53-ad4f-8cda48b30811@198.51.100.1:443?"),
            "link: {}",
            link0
        );
        assert!(link0.contains("security=reality"));
        assert!(link0.contains("sni=example.com"));
        assert!(link0.contains("pbk=f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"));
        assert!(link0.contains("sid=ab01cd02"));
        assert!(link0.contains("flow=xtls-rprx-vision"));

        // us-ss
        let n1 = &parsed.node[1];
        assert_eq!(n1.name.as_deref(), Some("us-ss"));
        assert!(matches!(n1.endpoint, NodeEndpoint::Shadowsocks(_)));
        let link1 = n1.to_link();
        assert!(link1.starts_with("ss://"));
        assert!(link1.contains("@198.51.100.2:8388"));

        // jp-trojan
        let n2 = &parsed.node[2];
        assert_eq!(n2.name.as_deref(), Some("jp-trojan"));
        assert!(matches!(n2.endpoint, NodeEndpoint::Trojan(_)));
        assert_eq!(
            n2.to_link(),
            "trojan://my-password@198.51.100.3:443?sni=trojan.example.com&allowInsecure=1"
        );

        // local-socks5
        let n3 = &parsed.node[3];
        assert_eq!(n3.name.as_deref(), Some("local-socks5"));
        assert!(matches!(n3.endpoint, NodeEndpoint::Socks5(_)));
        assert_eq!(n3.to_link(), "socks5://admin:123@127.0.0.1:1080");

        // local-http
        let n4 = &parsed.node[4];
        assert_eq!(n4.name.as_deref(), Some("local-http"));
        assert!(matches!(n4.endpoint, NodeEndpoint::Http(_)));
        assert_eq!(n4.to_link(), "http://127.0.0.1:8080");

        // direct-node
        let n5 = &parsed.node[5];
        assert_eq!(n5.name.as_deref(), Some("direct-node"));
        assert!(matches!(n5.endpoint, NodeEndpoint::Direct(_)));
        assert_eq!(n5.to_link(), "direct://");

        // Serialization roundtrip preserves structured representation
        let rendered = toml::to_string(&parsed).expect("serializes");
        let reparsed = config(&rendered);
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn a_converted_node_reloads_as_the_configuration_it_came_from() {
        // The falsifier for `daer node convert`: its output is only useful if pasting it
        // into a configuration *loads*. Two defects made that impossible, and neither was
        // visible in the printed text — both surfaced as a TOML error from a file the tool
        // had just written:
        //
        // 1. a nested table was rendered as `[reality]` instead of `[node.reality]`;
        // 2. `Node` carries `tag` and so does its flattened endpoint, so the block held
        //    `tag` twice and TOML rejected it as a duplicate key.
        //
        // The test asserts the round trip through the *real* loader, not through
        // `toml::from_str`: the loader is what `config validate` and `daer run` use.
        let links = [
            "vless://3141d7ca-f74d-46ad-bda6-a5b32a9ae991@212.50.249.175:443?security=reality&encryption=none&pbk=Ka8Bf3HpMgsAeQVmlFAIXrzlEpBsXck-QQn4RA6z_EE&headerType=none&fp=chrome&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=cdn.softbank.jp&sid=8e3af867d5ffc09f#bwg-jp",
            "ss://YWVzLTEyOC1nY206bm9uZQ==@127.0.0.1:1080#Website",
            "trojan://my-password@198.51.100.3:443?sni=trojan.example.com#tj",
            "socks5://admin:123@127.0.0.1:1080#local",
            "http://127.0.0.1:8080#local-http",
            "direct://#direct-node",
            "anytls://secret@anytls.example.com:443?sni=sni.example.com#anytls-node",
            "hysteria2://secret-hy2@hy2.example.com:443?sni=sni.example.com#my-hy2",
        ];
        for link in links {
            let endpoint = NodeEndpoint::from_link(link).expect("link converts");
            let rendered = endpoint.to_toml_node().expect("renders");
            // A nested table is legal TOML *and* wrong here: the node's sub-table is
            // `[node.reality]`, and a bare `[reality]` is a key the schema does not have.
            assert!(
                !rendered.lines().any(|line| line.starts_with("[reality]")),
                "the sub-table must be scoped to the node:\n{rendered}"
            );
            let document = format!("schema = 2\n\n{rendered}");
            let parsed: Config = toml::from_str(&document)
                .unwrap_or_else(|error| panic!("{link}\n{rendered}\n{error}"));
            assert_eq!(
                parsed.node.len(),
                1,
                "one block must be one node:\n{rendered}"
            );
            // The loader keeps the tag on the `Node`, not on the endpoint, so the
            // comparison is on the two things the block carries: the tag and the protocol
            // fields. Comparing endpoints directly would fail on `tag: Some/None` while
            // every other field matched, which is a difference in where the loader stores
            // the value, not in what was written.
            assert_eq!(
                parsed.node[0].name.as_deref(),
                endpoint.name(),
                "\n{rendered}"
            );
            let mut expected = endpoint.clone();
            match &mut expected {
                NodeEndpoint::Direct(n) => n.name = None,
                NodeEndpoint::Socks5(n) => n.name = None,
                NodeEndpoint::Http(n) => n.name = None,
                NodeEndpoint::Shadowsocks(n) => n.name = None,
                NodeEndpoint::Trojan(n) => n.name = None,
                NodeEndpoint::AnyTls(n) => n.name = None,
                NodeEndpoint::Hysteria2(n) => n.name = None,
                NodeEndpoint::Vless(n) => n.name = None,
                NodeEndpoint::Vmess(n) => n.name = None,
                NodeEndpoint::Unsupported { .. } => {}
            }
            assert_eq!(parsed.node[0].endpoint, expected, "\n{rendered}");
        }
    }

    #[test]
    fn structured_node_negative_controls() {
        // A chain is not "a link with an arrow": it is a routing topology this build does not
        // implement, and truncating it to the first hop would silently proxy somewhere the
        // operator did not write.
        let err = StructuredNode::from_link("socks5://127.0.0.1:1080 -> socks5://127.0.0.1:1081")
            .expect_err("chained link must fail");
        assert!(err.contains("chained links"), "{err}");

        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"socks5\"\nserver = \"1.1.1.1\"\nport = 1080\nunknown_field = 1\n",
        )
        .expect_err("unknown field must fail");
        assert!(err.to_string().contains("unknown_field"), "{err}");

        // Unknown field inside a layer table fails. `deny_unknown_fields` on an internally
        // tagged enum is not something serde provides, so `SecurityConfig::deserialize`
        // reads the table itself; this is the test that keeps that hand-written check
        // honest.
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"b831381d-6324-4d53-ad4f-8cda48b30811\"\n[node.security]\ntype = \"reality\"\nsni = \"s\"\npublic-key = \"k\"\nextra = \"bad\"\n",
        )
        .expect_err("unknown field in the security layer must fail");
        assert!(err.to_string().contains("extra"), "{err}");

        // The retired `[node.reality]` table is gone (ADR-0028 moved it under
        // `[node.security]`), and the error is a plain unknown-field error naming the key.
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"b831381d-6324-4d53-ad4f-8cda48b30811\"\n[node.reality]\nsni = \"s\"\npublic-key = \"k\"\n",
        )
        .expect_err("the retired [node.reality] table must fail");
        assert!(err.to_string().contains("reality"), "{err}");

        // Having 'url' fails with retirement explanation
        let err = toml::from_str::<Config>("[[node]]\nurl = \"socks5://1.1.1.1:1080\"\n")
            .expect_err("url field must fail");
        assert!(
            err.to_string()
                .contains("the 'url' field in [[node]] has been retired"),
            "{err}"
        );

        // Missing type fails
        let err = toml::from_str::<Config>("[[node]]\ntag = \"lonely\"\n")
            .expect_err("missing type must fail");
        assert!(
            err.to_string().contains("missing 'type' in [[node]] table"),
            "{err}"
        );

        // Port 0 fails
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"socks5\"\nserver = \"1.1.1.1\"\nport = 0\n",
        )
        .expect_err("port 0 must fail");
        assert!(err.to_string().contains("port"), "{err}");

        // Empty server fails
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"socks5\"\nserver = \"   \"\nport = 1080\n",
        )
        .expect_err("empty server must fail");
        assert!(err.to_string().contains("server"), "{err}");

        // A VLESS node needs no security layer at all now (ADR-0028), but it does need a
        // UUID: the id is what authenticates the session, and a malformed one produces a
        // generic node rejection with nothing to attribute it to.
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"u\"\n",
        )
        .expect_err("a malformed vless uuid must fail");
        assert!(err.to_string().contains("UUID"), "{err}");

        // A malformed REALITY public key is refused only at dial time today, but the
        // missing `sni` is a load-time error because REALITY impersonates a named site.
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"b831381d-6324-4d53-ad4f-8cda48b30811\"\n[node.security]\ntype = \"reality\"\npublic-key = \"k\"\n",
        )
        .expect_err("reality without sni must fail");
        assert!(err.to_string().contains("sni"), "{err}");

        // Vision needs a record layer it can splice. The reference rejects this on both
        // ends; accepting it would produce a session that authenticates and deadlocks.
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"b831381d-6324-4d53-ad4f-8cda48b30811\"\nflow = \"xtls-rprx-vision\"\n",
        )
        .expect_err("vision without a security layer must fail");
        assert!(err.to_string().contains("security layer"), "{err}");

        // Shadowsocks with legacy cipher fails with clear explanation
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"shadowsocks\"\nserver = \"1.1.1.1\"\nport = 8388\nmethod = \"aes-128-cfb\"\npassword = \"p\"\n",
        )
        .expect_err("legacy cipher must fail");
        assert!(err.to_string().contains("insecure legacy cipher"), "{err}");

        // Shadowsocks 2022 with valid 16-byte base64 key succeeds
        let valid_2022 = toml::from_str::<Config>(
            "[[node]]\ntag = \"ss22\"\ntype = \"shadowsocks\"\nserver = \"1.1.1.1\"\nport = 8388\nmethod = \"2022-blake3-aes-128-gcm\"\npassword = \"3L69X4PF2eSL/JSLkoWnXg==\"\n",
        );
        assert!(valid_2022.is_ok(), "{valid_2022:?}");

        // Shadowsocks 2022 with wrong key length fails
        let err = toml::from_str::<Config>(
            "[[node]]\ntag = \"ss22\"\ntype = \"shadowsocks\"\nserver = \"1.1.1.1\"\nport = 8388\nmethod = \"2022-blake3-aes-128-gcm\"\npassword = \"bm90MTZieXRlcw==\"\n",
        )
        .expect_err("wrong key length must fail");
        assert!(err.to_string().contains("requires a 16-byte"), "{err}");

        // Shadowsocks 2022 with invalid base64 fails
        let err = toml::from_str::<Config>(
            "[[node]]\ntag = \"ss22\"\ntype = \"shadowsocks\"\nserver = \"1.1.1.1\"\nport = 8388\nmethod = \"2022-blake3-aes-128-gcm\"\npassword = \"not-valid-base64!\"\n",
        )
        .expect_err("invalid base64 must fail");
        assert!(err.to_string().contains("valid base64"), "{err}");
    }

    #[test]
    fn every_field_round_trips_through_the_serializer() {
        let original = config(
            "schema = 2\n[global]\nso-mark = 7\n\
             [global.tls]\nprofile = \"chrome\"\n[global.probe]\ninterval = \"10s\"\n\
             [[subscription]]\nname = \"s\"\nurl = \"https://s\"\n\
             [[node]]\nname = \"n\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\
             [[group]]\nname = \"g\"\n\
             [[election]]\nname = \"e\"\ngroup = \"g\"\ntype = \"random\"\n\
             [routing]\nrules = [\"pname(NetworkManager) -> direct\"]\nfallback = \"e\"\n\
             [dns]\nupstream = [\"udp://1.1.1.1:53\"]\n[dns.fixed-domain-ttl]\n\"example.com\" = 60\n",
        );
        let rendered = toml::to_string(&original).expect("serializes");
        let reparsed = config(&rendered);
        assert_eq!(original, reparsed, "rendered:\n{rendered}");
    }
}
