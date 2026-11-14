// SPDX-License-Identifier: AGPL-3.0-only

//! Configuration for daer.
//!
//! The format is **TOML**, and only TOML. [`toml_config::load`] reads a file
//! (or a tree of files, via `include`), [`toml_config::load_str`] reads text,
//! [`toml_config::to_string`] renders the canonical form, and [`validate::normalize`]
//! applies the defaults and rejects values that cannot be honoured.
//!
//! A few things in the schema are *expressions* rather than data — a routing
//! rule's `match`, group filters, DNS rules and policy names — and they are
//! parsed by [`expr`], because a boolean combination over arbitrary predicates
//! has no faithful tabular encoding, and because the parsed tree is exactly what
//! the routing engine consumes. Everything else is data.

mod error;
pub mod expr;
mod model;
mod scalar;
#[cfg(feature = "schema")]
pub mod schema;
pub mod toml_config;
pub mod validate;

pub use error::ParseError;
pub use expr::{DnsRule, Function, MatchExpr, Param, ParamValue, parse_dns_rule_expr};
pub use model::{
    AnyTlsEndpoint, AnyTlsNode, BuiltinOutbound, Config, Dns, DnsRouting, Election, ElectionKind,
    FakeIpConfig, Filter, Flow, FunctionOrString, Group, HttpEndpoint, HttpNode,
    Hysteria2Bandwidth, Hysteria2Congestion, Hysteria2Endpoint, Hysteria2Node, Hysteria2Obfs,
    Hysteria2Quic, Hysteria2Tls, IpVersionPrefer, Node, NodeEndpoint, NodeTls, OutboundAction,
    OutboundKind, PortHopping, PortSet, ProbeMode, ProbeSettings, ProviderFormat, ProviderType,
    RealitySecurity, Routing, RoutingRule, RuleProvider, SCHEMA_VERSION, SecurityConfig,
    ShadowsocksEndpoint, ShadowsocksNode, SniffConfig, Socks5Endpoint, Socks5Node, StructuredNode,
    Subscription, Tls, TlsSecurity, TransportConfig, TrojanEndpoint, TrojanNode, VlessEndpoint,
    VlessNode, VmessCipher, VmessEndpoint, VmessNode, WanInterface, WsTransport, parse_filter_expr,
    parse_match_expr, parse_value_expr, render_functions,
};
pub use scalar::{Bandwidth, TimeSpan, parse_bandwidth, parse_duration, parse_integer};
pub use toml_config::{Loaded, load, load_str};
pub use validate::{ConfigError, normalize};

/// Default configuration directory.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/daer";

/// File names tried, in order, when the CLI is not given `--config`.
pub const DEFAULT_CONFIG_NAMES: [&str; 1] = ["config.toml"];
