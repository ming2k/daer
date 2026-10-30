// SPDX-License-Identifier: AGPL-3.0-only

//! Configuration for daer.
//!
//! The format is **TOML**, and only TOML. [`toml_config::load`] reads a file
//! (or a tree of files, via `include`), [`toml_config::load_str`] reads text,
//! [`toml_config::to_string`] renders the canonical form, and [`validate::normalize`]
//! applies the defaults and rejects values that cannot be honoured.
//!
//! Three things in the schema are *expressions* rather than data — routing rules,
//! group filters and policy names — and they are parsed by [`expr`], because a
//! boolean combination over arbitrary predicates has no faithful tabular
//! encoding, and because the parsed tree is exactly what the routing engine
//! consumes. Everything else is data.

mod error;
pub mod expr;
mod model;
mod scalar;
#[cfg(feature = "schema")]
pub mod schema;
pub mod toml_config;
pub mod validate;

pub use error::ParseError;
pub use expr::{Function, Param, ParamValue, RoutingRule};
pub use model::{
    Config, DirectEndpoint, DirectNode, Dns, DnsRouting, FakeIpConfig, Filter, FunctionOrString,
    Global, Group, HealthCheck, HealthCheckOverride, HttpEndpoint, HttpNode, Node, NodeEndpoint,
    RealityConfig, Routing, SCHEMA_VERSION, ShadowsocksEndpoint, ShadowsocksNode, Socks5Endpoint,
    Socks5Node, StructuredNode, Subscription, Tls, TrojanEndpoint, TrojanNode, VlessEndpoint,
    VlessNode, parse_filter_expr, parse_rule_expr, parse_value_expr, render_functions,
};
pub use scalar::{Bandwidth, TimeSpan, parse_bandwidth, parse_duration, parse_integer};
pub use toml_config::Loaded;
pub use validate::{ConfigError, normalize};

/// Default configuration directory.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/daer";

/// File names tried, in order, when the CLI is not given `--config`.
pub const DEFAULT_CONFIG_NAMES: [&str; 1] = ["config.toml"];
