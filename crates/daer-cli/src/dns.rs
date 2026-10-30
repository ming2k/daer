// SPDX-License-Identifier: AGPL-3.0-only

//! The `dns` subcommand: run the resolver, or inspect what it would do.
//!
//! # Why `serve` lives here and not behind the data path
//!
//! The resolver is a complete subsystem — sockets, routing, cache, upstreams — and it is
//! useful on its own: a box can be a DNS server before it is a transparent proxy. Exposing
//! it as its own subcommand means the DNS layer can be exercised end to end while the
//! kernel side is still being written, and it gives the eventual combined daemon one code
//! path instead of two.
//!
//! # Shutdown
//!
//! `SIGINT`/`SIGTERM` stop accepting and let `serve` return; in-flight queries finish or hit
//! their own timeout. Nothing is killed mid-exchange, because a truncated DNS reply is
//! indistinguishable from a wrong one at the client.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::Subcommand;
use daer_config::Config;
use daer_dns::transport::UpstreamSpec;
use daer_dns::{Resolver, Upstream, UpstreamError};

/// A single DNS query endpoint.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the DNS server.
    Serve {
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Address to listen on. Overrides `dns.bind`.
        #[arg(long, value_name = "IP:PORT")]
        listen: Option<SocketAddr>,
        /// Serve UDP only.
        #[arg(long, conflicts_with = "tcp_only")]
        udp_only: bool,
        /// Serve TCP only.
        #[arg(long, conflicts_with = "udp_only")]
        tcp_only: bool,
    },
    /// Report which upstreams this build can actually use.
    Check {
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
}

/// What to bind, and on which transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub address: SocketAddr,
    pub udp: bool,
    pub tcp: bool,
}

impl Plan {
    /// Resolves the plan from a configuration and the command-line overrides.
    ///
    /// `dns.bind` is a bare IP (`0.0.0.0`, `[::]`), not an address: the port is always 53,
    /// which is the only port a client will ask without being told. A bare port in `--listen`
    /// is therefore an error rather than a guess about which address was meant.
    ///
    /// # Errors
    ///
    /// Returns a message when `dns.bind` is not an IP, or when both `--udp-only` and
    /// `--tcp-only` are given (clap catches the second; this keeps the invariant local).
    pub fn resolve(
        config: &Config,
        listen: Option<SocketAddr>,
        udp_only: bool,
        tcp_only: bool,
    ) -> Result<Self, String> {
        let address = match listen {
            Some(address) => address,
            None => {
                let ip = match &config.dns.bind {
                    Some(bind) => bind
                        .parse::<IpAddr>()
                        .map_err(|_| format!("dns.bind: {bind:?} is not an IP address"))?,
                    None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                };
                SocketAddr::new(ip, 53)
            }
        };
        Ok(Self {
            address,
            udp: !tcp_only,
            tcp: !udp_only,
        })
    }

    /// A one-line description, for the startup log.
    #[must_use]
    pub fn describe(&self) -> String {
        let transports = match (self.udp, self.tcp) {
            (true, true) => "udp+tcp",
            (true, false) => "udp",
            (false, true) => "tcp",
            (false, false) => "none",
        };
        format!("{} on {transports}", self.address)
    }
}

/// The availability of one upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamReport {
    pub tag: String,
    pub protocols: String,
    /// `None` when the upstream is usable.
    pub unavailable: Option<String>,
}

impl UpstreamReport {
    /// A one-line report.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.unavailable {
            None => format!("{} [{}] ok", self.tag, self.protocols),
            Some(reason) => format!("{} [{}] unusable: {reason}", self.tag, self.protocols),
        }
    }
}

/// Checks every declared upstream against what this build implements.
///
/// # Errors
///
/// Returns a message for a malformed `dns.upstream` entry — the same parse the resolver
/// performs, so the two can never disagree about whether a configuration is valid.
pub fn check_upstreams(config: &Config) -> Result<Vec<UpstreamReport>, String> {
    let mut reports = Vec::with_capacity(config.dns.upstream.len());
    for entry in &config.dns.upstream {
        let spec = UpstreamSpec::parse(entry)?;
        let protocols = spec
            .protocols
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("+");
        // One predicate, two callers: a spec `serve` cannot build is a spec `check` reports.
        // Both go through `UpstreamSpec::build`, so they cannot disagree.
        let unavailable = transport_for(&spec).err().map(|error| error.to_string());
        reports.push(UpstreamReport {
            tag: spec.tag,
            protocols,
            unavailable,
        });
    }
    Ok(reports)
}

/// Builds the resolver a server uses.
///
/// # Errors
///
/// Returns the resolver's own error, which names the part that failed.
pub fn build_resolver(config: &Config) -> anyhow::Result<Arc<Resolver>> {
    let resolver = Resolver::from_config(config).context("cannot build the dns resolver")?;
    Ok(Arc::new(resolver))
}

/// Builds the transport a spec names.
///
/// `check` calls this, so a spec that reports usable is one that builds. Kept as a function
/// rather than duplicated so the two can never disagree.
///
/// # Errors
///
/// Returns the build error, which names the protocol that could not be built.
pub fn transport_for(spec: &UpstreamSpec) -> Result<Arc<dyn Upstream>, UpstreamError> {
    spec.build()
}

/// Reads a configuration, mapping the error for a daemon that must not start on a bad file.
///
/// # Errors
///
/// Returns the loader error with the path attached.
pub fn load(path: &Path) -> anyhow::Result<Config> {
    let loaded = daer_config::toml_config::load(path)
        .with_context(|| format!("failed to load {}", path.display()))?;
    for warning in &loaded.warnings {
        tracing::warn!(%warning, "configuration warning");
    }
    Ok(loaded.config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(src: &str) -> Config {
        daer_config::toml_config::load_str(src).expect("config loads")
    }

    #[test]
    fn the_default_plan_is_port_53_on_both_transports() {
        let plan = Plan::resolve(&config(""), None, false, false).expect("resolves");
        assert_eq!(plan.address.port(), 53);
        assert!(plan.address.ip().is_unspecified());
        assert!(plan.udp && plan.tcp);
        assert_eq!(plan.describe(), "0.0.0.0:53 on udp+tcp");
    }

    #[test]
    fn dns_bind_sets_the_address_and_the_port_stays_53() {
        let plan = Plan::resolve(&config("[dns]\nbind = \"127.0.0.1\"\n"), None, false, false)
            .expect("resolves");
        assert_eq!(plan.address.to_string(), "127.0.0.1:53");
    }

    #[test]
    fn an_explicit_listen_overrides_everything() {
        let plan = Plan::resolve(
            &config("[dns]\nbind = \"127.0.0.1\"\n"),
            Some("10.0.0.1:5353".parse().expect("addr")),
            false,
            false,
        )
        .expect("resolves");
        assert_eq!(plan.address.to_string(), "10.0.0.1:5353");
    }

    #[test]
    fn the_transport_flags_are_exclusive() {
        let udp = Plan::resolve(&config(""), None, true, false).expect("resolves");
        assert!(udp.udp && !udp.tcp);
        let tcp = Plan::resolve(&config(""), None, false, true).expect("resolves");
        assert!(tcp.tcp && !tcp.udp);
    }

    #[test]
    fn a_bind_that_is_not_an_ip_is_rejected_with_the_field_name() {
        let error = Plan::resolve(&config("[dns]\nbind = \"not-an-ip\"\n"), None, false, false)
            .expect_err("must reject");
        assert!(error.contains("dns.bind"), "{error}");
        assert!(error.contains("not an IP"), "{error}");
    }

    #[test]
    fn a_port_in_dns_bind_is_rejected_not_guessed() {
        // `dns.bind` is an address, not a socket address: accepting `127.0.0.1:5353` would
        // silently ignore the port or bind something unexpected.
        let error = Plan::resolve(
            &config("[dns]\nbind = \"127.0.0.1:5353\"\n"),
            None,
            false,
            false,
        )
        .expect_err("must reject");
        assert!(error.contains("dns.bind"), "{error}");
    }

    #[test]
    fn upstreams_are_reported_as_usable_or_not() {
        let config = config(
            r#"
[dns]
upstream = [
    "plain:tcp://127.0.0.1:5300",
    "remote:udp://8.8.8.8:53",
    "chained:tcp+udp://1.1.1.1:53",
]
"#,
        );
        let reports = check_upstreams(&config).expect("checks");
        assert_eq!(reports.len(), 3);
        // Every protocol is implemented, so every entry is usable. An `unusable` here would
        // mean a protocol the documentation promises and the build lacks.
        for report in &reports {
            assert_eq!(
                report.unavailable,
                None,
                "{} must be usable: {}",
                report.tag,
                report.line()
            );
            assert!(report.line().contains("ok"), "{}", report.line());
        }
        assert_eq!(reports[2].protocols, "tcp+udp");
    }

    #[test]
    fn a_malformed_upstream_fails_the_check_with_the_same_error_the_resolver_gives() {
        let config = config("[dns]\nupstream = [\"nonsense\"]\n");
        let error = check_upstreams(&config).expect_err("must reject");
        assert!(error.contains("dns.upstream"), "{error}");
        // The resolver must agree: one parse, two callers.
        assert!(Resolver::from_config(&config).is_err());
    }

    #[test]
    fn every_protocol_is_reported_usable_and_builds() {
        // The property that replaced "which protocols exist": all four are implemented, so
        // `check` must report every one usable and the build must agree. A protocol that
        // reports usable but cannot build would be the old lie in a new place.
        for entry in [
            "a:udp://127.0.0.1:1",
            "b:tcp://127.0.0.1:1",
            "c:tls://127.0.0.1:1",
            "d:https://127.0.0.1:1",
        ] {
            let spec = UpstreamSpec::parse(entry).expect("parses");
            let report = &check_upstreams(&config(&format!("[dns]\nupstream = [\"{entry}\"]\n")))
                .expect("checks")[0];
            assert!(
                report.unavailable.is_none(),
                "{entry} must be usable, got {:?}",
                report.unavailable
            );
            assert!(transport_for(&spec).is_ok(), "{entry} must build");
        }
    }

    #[test]
    fn an_upstream_report_renders_both_states() {
        let usable = UpstreamReport {
            tag: "a".to_owned(),
            protocols: "tcp".to_owned(),
            unavailable: None,
        };
        assert_eq!(usable.line(), "a [tcp] ok");
        let unusable = UpstreamReport {
            tag: "b".to_owned(),
            protocols: "udp".to_owned(),
            unavailable: Some("no transport".to_owned()),
        };
        assert_eq!(unusable.line(), "b [udp] unusable: no transport");
    }
}
