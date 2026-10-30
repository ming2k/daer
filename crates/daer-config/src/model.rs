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
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Node {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(flatten)]
    pub endpoint: NodeEndpoint,
    /// The subscription this node came from, filled in by the resolver.
    #[serde(skip)]
    pub subscription: Option<String>,
}

impl Node {
    /// Creates a node with an optional tag and an endpoint.
    pub fn new(tag: Option<String>, endpoint: NodeEndpoint) -> Self {
        Self {
            tag,
            endpoint,
            subscription: None,
        }
    }

    /// Creates a node with a subscription tag provenance.
    pub fn with_subscription(
        tag: Option<String>,
        endpoint: NodeEndpoint,
        subscription: Option<String>,
    ) -> Self {
        Self {
            tag,
            endpoint,
            subscription,
        }
    }

    /// Creates a node from an endpoint, extracting any tag declared on it.
    pub fn from_endpoint(endpoint: NodeEndpoint) -> Self {
        let tag = endpoint.tag().map(str::to_owned);
        Self::new(tag, endpoint)
    }

    /// Alias for `from_endpoint`.
    pub fn from_structured(structured: NodeEndpoint) -> Self {
        Self::from_endpoint(structured)
    }

    /// The tag `subtag(...)` matches against, or `""` for an inline node.
    #[must_use]
    pub fn subscription_tag(&self) -> &str {
        self.subscription.as_deref().unwrap_or("")
    }

    /// Default name for this node when tag is omitted.
    #[must_use]
    pub fn default_name(&self) -> String {
        self.endpoint.default_name()
    }

    /// Display label for this node.
    #[must_use]
    pub fn label(&self) -> String {
        self.tag.clone().unwrap_or_else(|| self.default_name())
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
        let tag = endpoint.tag().map(str::to_owned);
        Ok(Self {
            tag,
            endpoint,
            subscription: None,
        })
    }

    /// Renders this node as a formatted `[[node]]` TOML block.
    pub fn to_toml_node(&self) -> Result<String, String> {
        let body = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        Ok(format!("[[node]]\n{body}"))
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
    Vless(VlessNode),
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
pub type VlessEndpoint = VlessNode;

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
                let Some(reality) = &node.reality else {
                    return Err(
                        "vless: missing [node.reality] configuration; daer only supports VLESS with REALITY"
                            .to_owned(),
                    );
                };
                if reality.sni.trim().is_empty() {
                    return Err("vless.reality: 'sni' must not be empty".to_owned());
                }
                if reality.public_key.trim().is_empty() {
                    return Err("vless.reality: 'public-key' must not be empty".to_owned());
                }
                if reality
                    .fingerprint
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(
                        "vless.reality: 'fingerprint' is required (e.g. fingerprint = \"chrome\")"
                            .to_owned(),
                    );
                }
                Ok(())
            }
            Self::Unsupported { scheme, .. } => {
                Err(format!("unsupported node protocol {scheme:?}"))
            }
        }
    }

    /// The optional tag of this node.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        match self {
            Self::Direct(n) => n.tag.as_deref(),
            Self::Socks5(n) => n.tag.as_deref(),
            Self::Http(n) => n.tag.as_deref(),
            Self::Shadowsocks(n) => n.tag.as_deref(),
            Self::Trojan(n) => n.tag.as_deref(),
            Self::Vless(n) => n.tag.as_deref(),
            Self::Unsupported { .. } => None,
        }
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
            Self::Vless(n) => format!("{}:{}", n.server, n.port),
            Self::Unsupported { link, .. } => link.clone(),
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
            Self::Vless(n) => n.to_link(),
            Self::Unsupported { link, .. } => link.clone(),
        }
    }

    /// Renders this structured node as a formatted `[[node]]` TOML block.
    pub fn to_toml_node(&self) -> Result<String, String> {
        let node = Node::from_structured(self.clone());
        let body = toml::to_string_pretty(&node).map_err(|e| e.to_string())?;
        Ok(format!("[[node]]\n{body}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DirectNode {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
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
pub struct VlessNode {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RealityConfig {
    pub sni: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
}

impl VlessNode {
    #[must_use]
    pub fn to_link(&self) -> String {
        let server = format_host(&self.server);
        let mut query = vec!["encryption=none".to_owned(), "security=reality".to_owned()];
        if let Some(reality) = &self.reality {
            query.push(format!("sni={}", percent_encode(&reality.sni)));
            query.push(format!("pbk={}", percent_encode(&reality.public_key)));
            if let Some(sid) = &reality.short_id
                && !sid.is_empty()
            {
                query.push(format!("sid={}", percent_encode(sid)));
            }
            if let Some(fp) = &reality.fingerprint
                && !fp.is_empty()
            {
                query.push(format!("fp={}", percent_encode(fp)));
            }
            if !reality.alpn.is_empty() {
                query.push(format!("alpn={}", reality.alpn.join(",")));
            }
        }
        if let Some(flow) = &self.flow
            && !flow.is_empty()
        {
            query.push(format!("flow={}", percent_encode(flow)));
        }
        format!(
            "vless://{}@{server}:{}?{}",
            self.uuid,
            self.port,
            query.join("&")
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
        "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305" | "xchacha20-ietf-poly1305" => {
            Ok(())
        }
        legacy @ ("aes-128-cfb" | "aes-192-cfb" | "aes-256-cfb" | "aes-128-ctr" | "aes-192-ctr"
        | "aes-256-ctr" | "rc4-md5" | "chacha20" | "chacha20-ietf" | "salsa20"
        | "bf-cfb" | "camellia-128-cfb" | "camellia-192-cfb" | "camellia-256-cfb"
        | "des-cfb" | "table") => Err(format!(
            "shadowsocks: method '{legacy}' is an insecure legacy cipher and is not supported (use an AEAD cipher like chacha20-ietf-poly1305 or aes-256-gcm)"
        )),
        other => Err(format!(
            "shadowsocks: unknown method '{other}'; supported AEAD ciphers are chacha20-ietf-poly1305, aes-128-gcm, aes-256-gcm, xchacha20-ietf-poly1305"
        )),
    }
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

impl StructuredNode {
    /// Parses an outbound URI link (`vless://`, `ss://`, `trojan://`, `socks5://`, `http://`,
    /// `direct://`) into a structured node representation.
    pub fn from_link(link: &str) -> Result<Self, String> {
        let link = link.trim();
        if link.is_empty() || link == "direct" || link == "direct://" {
            return Ok(Self::Direct(DirectNode { tag: None }));
        }

        if link.contains("->") {
            return Err("chained links ('a -> b') are not implemented".to_owned());
        }

        let Some((scheme, rest)) = link.split_once("://") else {
            return Err(format!("{link:?} has no '://' scheme separator"));
        };

        // Split off #fragment as tag
        let (before_fragment, tag) = match rest.split_once('#') {
            Some((before, fragment)) => {
                let tag = percent_decode(fragment);
                let tag = if tag.is_empty() { None } else { Some(tag) };
                (before, tag)
            }
            None => (rest, None),
        };

        match scheme.to_ascii_lowercase().as_str() {
            "direct" => Ok(Self::Direct(DirectNode { tag })),
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
                    tag,
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
                    tag,
                    server,
                    port,
                    username,
                    password,
                }))
            }
            "ss" | "shadowsocks" => {
                let (creds, authority) = match before_fragment.rsplit_once('@') {
                    Some((userinfo, hostport)) => (decode_base64(userinfo)?, hostport.to_owned()),
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
                    tag,
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
                    tag,
                    server,
                    port,
                    password: password.to_owned(),
                    sni,
                    allow_insecure,
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

                let mut sni = None;
                let mut public_key = None;
                let mut short_id = None;
                let mut fingerprint = None;
                let mut flow = None;
                let mut alpn = Vec::new();

                for pair in query.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = match pair.split_once('=') {
                        Some((k, v)) => (k, v),
                        None => (pair, ""),
                    };
                    let decoded_v = percent_decode(v);
                    match k {
                        "sni" | "peer" if !decoded_v.is_empty() => sni = Some(decoded_v),
                        "pbk" if !decoded_v.is_empty() => public_key = Some(decoded_v),
                        "sid" if !decoded_v.is_empty() => short_id = Some(decoded_v),
                        "fp" if !decoded_v.is_empty() => fingerprint = Some(decoded_v),
                        "flow" if !decoded_v.is_empty() => flow = Some(decoded_v),
                        "alpn" if !decoded_v.is_empty() => {
                            alpn = decoded_v.split(',').map(str::to_owned).collect();
                        }
                        _ => {}
                    }
                }

                let reality = match (sni, public_key) {
                    (Some(sni), Some(public_key)) => Some(RealityConfig {
                        sni,
                        public_key,
                        short_id,
                        fingerprint: Some(fingerprint.unwrap_or_else(|| "chrome".to_owned())),
                        alpn,
                    }),
                    _ => None,
                };

                Ok(Self::Vless(VlessNode {
                    tag,
                    server,
                    port,
                    uuid: user_part.to_owned(),
                    flow,
                    reality,
                }))
            }
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
                        "missing 'type' in [[node]] table (expected e.g. type = \"vless\", \"shadowsocks\", \"trojan\", \"socks5\", \"http\", \"direct\")",
                    ));
                }

                #[derive(Deserialize)]
                #[serde(rename_all = "kebab-case")]
                struct NodeHelper {
                    tag: Option<String>,
                    #[serde(flatten)]
                    endpoint: NodeEndpoint,
                }

                let helper =
                    NodeHelper::deserialize(toml::Value::Table(table)).map_err(D::Error::custom)?;
                helper.endpoint.validate().map_err(D::Error::custom)?;
                Ok(Self {
                    tag: helper.tag,
                    endpoint: helper.endpoint,
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

/// `[dns.fake-ip]` — synthetic IP pool configuration (ADR-0012).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct FakeIpConfig {
    pub enabled: bool,
    pub inet: String,
    pub pool_size: usize,
    pub exclude: Vec<String>,
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            inet: "198.18.0.0/15".to_owned(),
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
    fn subscriptions_accept_both_shapes_and_nodes_require_structured_tables() {
        let plain = config("subscription = [\"https://a/sub\"]\n");
        assert_eq!(plain.subscription[0].tag, None);
        assert!(!plain.subscription[0].persist);

        let tables = config(
            "[[subscription]]\ntag = \"b\"\nurl = \"https://b/sub\"\npersist = true\n\
             [[node]]\ntag = \"n1\"\ntype = \"direct\"\n",
        );
        assert_eq!(tables.subscription[0].tag.as_deref(), Some("b"));
        assert!(tables.subscription[0].persist);
        assert_eq!(tables.node[0].tag.as_deref(), Some("n1"));

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
        // Real-world VLESS REALITY link from user's subscription (note: omits fp=, should default to chrome)
        let vless_link = "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkus1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=portal.citygrainla.com&pbk=9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E&sid=672f&type=tcp&udp=1&tfo=1#US%20VIP%2001";
        let structured = StructuredNode::from_link(vless_link).expect("converts vless link");
        match structured {
            StructuredNode::Vless(vless) => {
                assert_eq!(vless.tag.as_deref(), Some("US VIP 01"));
                assert_eq!(vless.server, "fkus1keria.itknowledgeblog.com");
                assert_eq!(vless.port, 443);
                assert_eq!(vless.uuid, "df4af3d0-030e-4062-baa6-eb9dd45298ef");
                assert_eq!(vless.flow.as_deref(), Some("xtls-rprx-vision"));
                let reality = vless.reality.expect("reality config");
                assert_eq!(reality.sni, "portal.citygrainla.com");
                assert_eq!(
                    reality.public_key,
                    "9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E"
                );
                assert_eq!(reality.short_id.as_deref(), Some("672f"));
                assert_eq!(reality.fingerprint.as_deref(), Some("chrome"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        // Real-world Shadowsocks link with base64 userinfo
        let ss_link =
            "ss://YWVzLTEyOC1ncm06bm9uZQ==@127.0.0.1:1080?udp=0#Website%3A%20user.totorofree.com";
        let structured = StructuredNode::from_link(ss_link).expect("converts ss link");
        match structured {
            StructuredNode::Shadowsocks(ss) => {
                assert_eq!(ss.tag.as_deref(), Some("Website: user.totorofree.com"));
                assert_eq!(ss.server, "127.0.0.1");
                assert_eq!(ss.port, 1080);
                assert_eq!(ss.method, "aes-128-grm");
                assert_eq!(ss.password, "none");
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        // SOCKS5 and Trojan
        let socks_link = "socks5://user:pass@127.0.0.1:1080#my-socks";
        let structured = StructuredNode::from_link(socks_link).expect("converts socks link");
        assert_eq!(structured.tag(), Some("my-socks"));

        let trojan_link = "trojan://password@node.example.com:443?sni=sni.example.com#my-trojan";
        let structured = StructuredNode::from_link(trojan_link).expect("converts trojan link");
        assert_eq!(structured.tag(), Some("my-trojan"));
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
    fn structured_nodes_parse_validate_and_generate_canonical_links() {
        let toml_str = r#"
[[node]]
tag = "hk-vless"
type = "vless"
server = "198.51.100.1"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"
[node.reality]
sni = "example.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
short-id = "ab01cd02"
fingerprint = "chrome"

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
        assert_eq!(n0.tag.as_deref(), Some("hk-vless"));
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
        assert!(link0.contains("fp=chrome"));
        assert!(link0.contains("flow=xtls-rprx-vision"));

        // us-ss
        let n1 = &parsed.node[1];
        assert_eq!(n1.tag.as_deref(), Some("us-ss"));
        assert!(matches!(n1.endpoint, NodeEndpoint::Shadowsocks(_)));
        let link1 = n1.to_link();
        assert!(link1.starts_with("ss://"));
        assert!(link1.contains("@198.51.100.2:8388"));

        // jp-trojan
        let n2 = &parsed.node[2];
        assert_eq!(n2.tag.as_deref(), Some("jp-trojan"));
        assert!(matches!(n2.endpoint, NodeEndpoint::Trojan(_)));
        assert_eq!(
            n2.to_link(),
            "trojan://my-password@198.51.100.3:443?sni=trojan.example.com&allowInsecure=1"
        );

        // local-socks5
        let n3 = &parsed.node[3];
        assert_eq!(n3.tag.as_deref(), Some("local-socks5"));
        assert!(matches!(n3.endpoint, NodeEndpoint::Socks5(_)));
        assert_eq!(n3.to_link(), "socks5://admin:123@127.0.0.1:1080");

        // local-http
        let n4 = &parsed.node[4];
        assert_eq!(n4.tag.as_deref(), Some("local-http"));
        assert!(matches!(n4.endpoint, NodeEndpoint::Http(_)));
        assert_eq!(n4.to_link(), "http://127.0.0.1:8080");

        // direct-node
        let n5 = &parsed.node[5];
        assert_eq!(n5.tag.as_deref(), Some("direct-node"));
        assert!(matches!(n5.endpoint, NodeEndpoint::Direct(_)));
        assert_eq!(n5.to_link(), "direct://");

        // Serialization roundtrip preserves structured representation
        let rendered = toml::to_string(&parsed).expect("serializes");
        let reparsed = config(&rendered);
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn structured_node_negative_controls() {
        // Unknown field on node table fails
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"socks5\"\nserver = \"1.1.1.1\"\nport = 1080\nunknown_field = 1\n",
        )
        .expect_err("unknown field must fail");
        assert!(err.to_string().contains("unknown_field"), "{err}");

        // Unknown field inside [node.reality] fails
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"u\"\n[node.reality]\nsni = \"s\"\npublic-key = \"k\"\nextra = \"bad\"\n",
        )
        .expect_err("unknown field in reality must fail");
        assert!(err.to_string().contains("extra"), "{err}");

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

        // Vless without reality fails
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"u\"\n",
        )
        .expect_err("vless without reality must fail");
        assert!(err.to_string().contains("reality"), "{err}");

        // Shadowsocks with legacy cipher fails with clear explanation
        let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"shadowsocks\"\nserver = \"1.1.1.1\"\nport = 8388\nmethod = \"aes-128-cfb\"\npassword = \"p\"\n",
        )
        .expect_err("legacy cipher must fail");
        assert!(err.to_string().contains("insecure legacy cipher"), "{err}");
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
