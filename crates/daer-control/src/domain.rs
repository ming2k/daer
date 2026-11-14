// SPDX-License-Identifier: AGPL-3.0-only

//! Domain acquisition: how routing obtains the `domain` fact.
//!
//! DNS is the primary source. Fake-IP gives an exact mapping before the first byte;
//! the DNS snooper gives one or more candidates for a real address. Payload sniffing
//! is a bounded fallback that is used **only** when `[routing.sniff] enabled = true`
//! and DNS/Fake-IP did not produce a unique name.
//!
//! The fixed order is deliberate and not configurable:
//!
//! ```text
//! Fake-IP
//!   > DNS snooper (unique candidate)
//!   > sniff (only when enabled)
//!   > address
//! ```
//!
//! # Why the policy is a value
//!
//! `DomainPlan` is built once from the generation's configuration and lowered match
//! sets. Every caller — the TCP path, the datagram path, `daer check` and the reload
//! report — reads the same plan. A configuration with a domain rule and no explicit
//! answer for `routing.sniff.enabled` is rejected here, not discovered per flow.
//!
//! # Why the outcome is not `Option<String>`
//!
//! "No name" has several meanings: DNS missed, DNS was ambiguous, sniffing was
//! disabled, sniffing timed out. Collapsing them into `None` makes the flow log
//! useless and makes "sniff failed" indistinguishable from "sniff was not allowed".
//! [`DomainOutcome`] carries the source on success and the reason on failure.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use daer_config::Config;
use daer_dns::{DnsSnooper, FakeIpPool, SnoopLookup};
use daer_routing::{MatchSet, MatchValue};
use daer_sniff::Protocol;
use tokio::net::TcpStream;

use crate::sniff::{self, Outcome as SniffOutcome, Unnamed as SniffUnnamed};

/// A name that was actually recovered and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSource {
    /// A synthetic address was reverse-mapped to its exact domain.
    FakeIp,
    /// The DNS snooper observed exactly one domain for this client and address.
    DnsSnooper,
    /// The first bytes of the flow carried a TLS SNI, HTTP Host or QUIC Initial SNI.
    Sniff,
}

impl DomainSource {
    /// Stable spelling for events and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FakeIp => "fake-ip",
            Self::DnsSnooper => "dns-snooper",
            Self::Sniff => "sniff",
        }
    }
}

impl fmt::Display for DomainSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Extra detail for a successful lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedDetail {
    /// A synthetic address mapped to exactly one domain.
    Exact,
    /// The DNS snooper had exactly one live candidate.
    UniqueCandidate,
    /// Payload sniffing recovered the name.
    Sniffed { protocol: Protocol, bytes: usize },
}

/// Why no domain was available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnnamedReason {
    /// DNS/Fake-IP missed and `[routing.sniff] enabled = false`.
    NoDnsMapping,
    /// DNS/Fake-IP had more than one candidate and sniffing was not allowed.
    AmbiguousDnsMapping { candidates: usize },
    /// The bytes are not a protocol whose name can be recovered.
    NotSniffable,
    /// A length field contradicted itself.
    Malformed,
    /// The TCP sniff budget expired.
    TimedOut,
    /// The peer closed before a name arrived.
    Closed,
    /// `peek` failed.
    Io,
    /// The name needed more than the sniff byte budget.
    TooLarge,
    /// A datagram carried no payload to inspect.
    EmptyDatagram,
    /// A datagram's first payload was a prefix that declared more bytes.
    Truncated,
}

impl UnnamedReason {
    /// Stable spelling for events and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoDnsMapping => "dns miss",
            Self::AmbiguousDnsMapping { .. } => "dns mapping ambiguous",
            Self::NotSniffable => "not a sniffable protocol",
            Self::Malformed => "malformed prefix",
            Self::TimedOut => "sniff timeout",
            Self::Closed => "peer closed during sniff",
            Self::Io => "peek failed",
            Self::TooLarge => "name exceeded the sniff budget",
            Self::EmptyDatagram => "empty datagram",
            Self::Truncated => "datagram prefix was truncated",
        }
    }
}

impl fmt::Display for UnnamedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousDnsMapping { candidates } => {
                write!(f, "{} ({candidates} candidates)", self.as_str())
            }
            _ => f.write_str(self.as_str()),
        }
    }
}

/// What domain acquisition produced for one flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainOutcome {
    /// A name is available; routing may evaluate `domain(...)` rules.
    Named {
        domain: String,
        source: DomainSource,
        detail: NamedDetail,
    },
    /// No name is available; routing proceeds with the remaining facts.
    Unnamed { reason: UnnamedReason },
}

impl DomainOutcome {
    /// The name, when one was recovered.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::Named { domain, .. } => Some(domain),
            Self::Unnamed { .. } => None,
        }
    }

    /// The source, when a name was recovered.
    #[must_use]
    pub const fn source(&self) -> Option<DomainSource> {
        match self {
            Self::Named { source, .. } => Some(*source),
            Self::Unnamed { .. } => None,
        }
    }

    /// A one-line description for the flow log.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Named {
                domain,
                source,
                detail,
            } => match detail {
                NamedDetail::Exact => format!("source={source} domain={domain}"),
                NamedDetail::UniqueCandidate => format!("source={source} domain={domain}"),
                NamedDetail::Sniffed { protocol, bytes } => {
                    format!("source={source} protocol={protocol} domain={domain} after={bytes}B")
                }
            },
            Self::Unnamed { reason } => format!("source=none reason={reason}"),
        }
    }
}

/// The effective domain-acquisition policy for one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainPlan {
    /// `None` means payload inspection is disabled.
    sniff_timeout: Option<Duration>,
    dns_service: bool,
    fake_ip: bool,
    domain_rules: bool,
    warnings: Vec<String>,
}

impl DomainPlan {
    /// Builds the plan from the configuration and the generation's lowered match sets.
    ///
    /// # Errors
    ///
    /// Returns a message when the configuration cannot answer the name-acquisition
    /// question consistently. The checks here include rule-provider-derived domain
    /// sets, which the raw configuration cannot see.
    pub fn build(config: &Config, matches: &[MatchSet]) -> Result<Self, DomainPlanError> {
        let domain_rules = matches
            .iter()
            .any(|set| matches!(set.value, MatchValue::Domain(_)));
        let sniff = &config.routing.sniff;

        let enabled = match sniff.enabled {
            Some(enabled) => enabled,
            None if domain_rules => {
                return Err(DomainPlanError::new(
                    "routing.sniff.enabled: a domain rule requires an explicit answer; set \
                     enabled = true to allow bounded payload inspection, or enabled = false to \
                     route by the facts already known",
                ));
            }
            None => false,
        };

        let sniff_timeout = match (enabled, sniff.timeout) {
            (false, Some(_)) => {
                return Err(DomainPlanError::new(
                    "routing.sniff.timeout: enabled = false does not inspect payload; remove \
                     timeout",
                ));
            }
            (false, None) => None,
            (true, None) => {
                return Err(DomainPlanError::new(
                    "routing.sniff.timeout: enabled = true requires a positive timeout",
                ));
            }
            (true, Some(timeout)) => {
                let Some(duration) = timeout.as_std() else {
                    return Err(DomainPlanError::new(format!(
                        "routing.sniff.timeout: must be a positive duration (got \"{timeout}\")"
                    )));
                };
                if duration.is_zero() {
                    return Err(DomainPlanError::new(
                        "routing.sniff.timeout: must be greater than 0; use enabled = false to \
                         route by address",
                    ));
                }
                Some(duration)
            }
        };

        let dns_service = config.dns.bind.is_some();
        let fake_ip = config.dns.fake_ip.enabled;
        if fake_ip && !dns_service {
            return Err(DomainPlanError::new(
                "dns.fake-ip.enabled: Fake-IP requires an explicit [dns].bind",
            ));
        }
        if domain_rules && !enabled && !dns_service {
            return Err(DomainPlanError::new(
                "routing.sniff.enabled: domain(...) rules have no name source; set enabled = \
                 true or configure [dns].bind",
            ));
        }

        let mut warnings = Vec::new();
        if !domain_rules && (sniff.enabled.is_some() || sniff.timeout.is_some()) {
            warnings.push(
                "routing.sniff is unused: the configuration has no domain(...) rule".to_owned(),
            );
        }
        if enabled && !dns_service {
            warnings.push(
                "routing.sniff is the only domain source: ECH, raw TCP and server-first \
                 protocols cannot be named"
                    .to_owned(),
            );
        }
        if !enabled && dns_service && !fake_ip && domain_rules {
            warnings.push(
                "routing.sniff is disabled and Fake-IP is off: a shared real IP can map to \
                 more than one domain, and routing will not disambiguate it"
                    .to_owned(),
            );
        }

        Ok(Self {
            sniff_timeout,
            dns_service,
            fake_ip,
            domain_rules,
            warnings,
        })
    }

    /// Whether payload inspection is allowed.
    #[must_use]
    pub const fn sniff_enabled(&self) -> bool {
        self.sniff_timeout.is_some()
    }

    /// The TCP sniff budget, when enabled.
    #[must_use]
    pub const fn sniff_timeout(&self) -> Option<Duration> {
        self.sniff_timeout
    }

    /// Whether the built-in DNS server listens.
    #[must_use]
    pub const fn dns_service(&self) -> bool {
        self.dns_service
    }

    /// Whether Fake-IP is enabled.
    #[must_use]
    pub const fn fake_ip(&self) -> bool {
        self.fake_ip
    }

    /// Whether the generation contains a domain predicate.
    #[must_use]
    pub const fn has_domain_rules(&self) -> bool {
        self.domain_rules
    }

    /// Non-fatal warnings produced while building the plan.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// A compact description for `daer check` and the startup log.
    #[must_use]
    pub fn describe(&self) -> String {
        let sniff = self.sniff_timeout.map_or_else(
            || "off".to_owned(),
            |timeout| format!("tcp {timeout:?}, udp first datagram"),
        );
        format!(
            "dns={}, fake-ip={}, domain-rules={}, sniff={sniff}",
            if self.dns_service { "on" } else { "off" },
            if self.fake_ip { "on" } else { "off" },
            if self.domain_rules { "yes" } else { "no" },
        )
    }
}

/// A plan construction error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainPlanError {
    message: String,
}

impl DomainPlanError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DomainPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DomainPlanError {}

/// The DNS half of name acquisition, before any payload inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainLookup {
    /// Fake-IP or a unique DNS-snooper candidate named the flow.
    Found {
        domain: String,
        source: DomainSource,
        detail: NamedDetail,
    },
    /// The DNS snooper saw more than one live candidate.
    Ambiguous { candidates: usize },
    /// Neither Fake-IP nor the DNS snooper knows the destination.
    Missing,
}

/// Resolves domains for both transports.
///
/// The resolver owns no socket and no timer of its own; it borrows the stream for one
/// TCP attempt and the first datagram payload for one UDP parse. The plan decides
/// whether either attempt is allowed.
#[derive(Debug, Clone)]
pub struct DomainResolver {
    plan: DomainPlan,
    fake_ip: Option<Arc<FakeIpPool>>,
    snooper: Option<Arc<DnsSnooper>>,
}

impl DomainResolver {
    /// Builds a resolver from a validated plan and the process-level DNS state.
    #[must_use]
    pub fn new(
        plan: DomainPlan,
        fake_ip: Option<Arc<FakeIpPool>>,
        snooper: Option<Arc<DnsSnooper>>,
    ) -> Self {
        Self {
            plan,
            fake_ip,
            snooper,
        }
    }

    /// The effective plan.
    #[must_use]
    pub const fn plan(&self) -> &DomainPlan {
        &self.plan
    }

    /// The DNS-only lookup, used by diagnostics and by both transport paths.
    #[must_use]
    pub fn lookup(&self, source: SocketAddr, destination: SocketAddr) -> DomainLookup {
        if self.plan.fake_ip
            && let Some(domain) = self
                .fake_ip
                .as_ref()
                .and_then(|pool| pool.reverse_lookup_ip(destination.ip()))
        {
            return DomainLookup::Found {
                domain: domain.to_string(),
                source: DomainSource::FakeIp,
                detail: NamedDetail::Exact,
            };
        }

        let Some(snooper) = self.snooper.as_ref() else {
            return DomainLookup::Missing;
        };
        match snooper.lookup(source.ip(), destination.ip()) {
            SnoopLookup::Unique(domain) => DomainLookup::Found {
                domain: domain.to_string(),
                source: DomainSource::DnsSnooper,
                detail: NamedDetail::UniqueCandidate,
            },
            SnoopLookup::Ambiguous { candidates } => DomainLookup::Ambiguous { candidates },
            SnoopLookup::None => DomainLookup::Missing,
        }
    }

    /// Resolves a TCP flow, peeking only when the plan allows it.
    pub async fn resolve_tcp(
        &self,
        stream: &TcpStream,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> DomainOutcome {
        match self.lookup(source, destination) {
            DomainLookup::Found {
                domain,
                source,
                detail,
            } => DomainOutcome::Named {
                domain,
                source,
                detail,
            },
            DomainLookup::Ambiguous { candidates } => {
                let Some(timeout) = self.plan.sniff_timeout else {
                    return DomainOutcome::Unnamed {
                        reason: UnnamedReason::AmbiguousDnsMapping { candidates },
                    };
                };
                self.sniff_tcp(stream, timeout).await
            }
            DomainLookup::Missing => {
                let Some(timeout) = self.plan.sniff_timeout else {
                    return DomainOutcome::Unnamed {
                        reason: UnnamedReason::NoDnsMapping,
                    };
                };
                self.sniff_tcp(stream, timeout).await
            }
        }
    }

    /// Resolves a datagram flow from its first payload. No timer is involved: a UDP
    /// datagram has already arrived, so inspecting it cannot delay the flow.
    #[must_use]
    pub fn resolve_datagram(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> DomainOutcome {
        match self.lookup(source, destination) {
            DomainLookup::Found {
                domain,
                source,
                detail,
            } => DomainOutcome::Named {
                domain,
                source,
                detail,
            },
            DomainLookup::Ambiguous { candidates } => {
                if self.plan.sniff_timeout.is_none() {
                    return DomainOutcome::Unnamed {
                        reason: UnnamedReason::AmbiguousDnsMapping { candidates },
                    };
                }
                self.sniff_datagram(payload)
            }
            DomainLookup::Missing => {
                if self.plan.sniff_timeout.is_none() {
                    return DomainOutcome::Unnamed {
                        reason: UnnamedReason::NoDnsMapping,
                    };
                }
                self.sniff_datagram(payload)
            }
        }
    }

    async fn sniff_tcp(&self, stream: &TcpStream, timeout: Duration) -> DomainOutcome {
        match sniff::sniff_stream(stream, timeout).await {
            SniffOutcome::Named {
                name,
                protocol,
                bytes,
            } => DomainOutcome::Named {
                domain: name,
                source: DomainSource::Sniff,
                detail: NamedDetail::Sniffed { protocol, bytes },
            },
            SniffOutcome::Unnamed(reason) => DomainOutcome::Unnamed {
                reason: match reason {
                    SniffUnnamed::NotSniffable => UnnamedReason::NotSniffable,
                    SniffUnnamed::Malformed => UnnamedReason::Malformed,
                    SniffUnnamed::TimedOut => UnnamedReason::TimedOut,
                    SniffUnnamed::Closed => UnnamedReason::Closed,
                    SniffUnnamed::Io => UnnamedReason::Io,
                    SniffUnnamed::TooLarge => UnnamedReason::TooLarge,
                },
            },
        }
    }

    fn sniff_datagram(&self, payload: &[u8]) -> DomainOutcome {
        if payload.is_empty() {
            return DomainOutcome::Unnamed {
                reason: UnnamedReason::EmptyDatagram,
            };
        }
        match daer_sniff::sniff(payload) {
            daer_sniff::Sniffed::Domain { name, protocol } => DomainOutcome::Named {
                domain: name,
                source: DomainSource::Sniff,
                detail: NamedDetail::Sniffed {
                    protocol,
                    bytes: payload.len(),
                },
            },
            daer_sniff::Sniffed::None => DomainOutcome::Unnamed {
                reason: UnnamedReason::NotSniffable,
            },
            daer_sniff::Sniffed::Malformed(_) => DomainOutcome::Unnamed {
                reason: UnnamedReason::Malformed,
            },
            daer_sniff::Sniffed::NeedMore { .. } => DomainOutcome::Unnamed {
                reason: UnnamedReason::Truncated,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use daer_config::toml_config::load_str;
    use daer_dns::{DnsSnooper, FakeIpPool};
    use daer_routing::{MatchSet, MatchTarget, MatchValue};

    fn config(source: &str) -> Config {
        load_str(source).expect("config loads")
    }

    fn domain_set() -> MatchSet {
        MatchSet {
            value: MatchValue::Domain(daer_routing::DomainTable::default()),
            target: MatchTarget::Outbound(daer_routing::Outbound::direct()),
            negated: false,
        }
    }

    fn plan(config: &Config, domain_rules: bool) -> Result<DomainPlan, DomainPlanError> {
        let matches = if domain_rules {
            vec![domain_set()]
        } else {
            Vec::new()
        };
        DomainPlan::build(config, &matches)
    }

    #[test]
    fn a_domain_rule_requires_an_explicit_answer() {
        let config = Config::default();
        let error = plan(&config, true).expect_err("must fail");
        assert!(error.to_string().contains("routing.sniff.enabled"));
    }

    #[test]
    fn sniffing_without_a_timeout_is_rejected() {
        let mut config = Config::default();
        config.routing.sniff.enabled = Some(true);
        let error = plan(&config, true).expect_err("must fail");
        assert!(error.to_string().contains("routing.sniff.timeout"));
    }

    #[test]
    fn address_mode_rejects_an_unused_timeout() {
        let mut config = Config::default();
        config.routing.sniff.enabled = Some(false);
        config.routing.sniff.timeout = Some(daer_config::TimeSpan::from_millis(30));
        let error = plan(&config, false).expect_err("must fail");
        assert!(error.to_string().contains("routing.sniff.timeout"));
    }

    #[test]
    fn no_dns_and_no_sniff_is_no_name_source() {
        let mut config = Config::default();
        config.routing.sniff.enabled = Some(false);
        let error = plan(&config, true).expect_err("must fail");
        assert!(error.to_string().contains("no name source"));
    }

    #[test]
    fn no_domain_rules_make_an_explicit_policy_unused() {
        let config = config("[routing.sniff]\nenabled = false\n[routing]\ndefault = \"direct\"\n");
        let plan = plan(&config, false).expect("valid");
        assert!(!plan.sniff_enabled());
        assert!(
            plan.warnings()
                .iter()
                .any(|warning| warning.contains("unused")),
            "{:?}",
            plan.warnings()
        );
    }

    #[test]
    fn dns_only_is_valid_and_never_sniffs() {
        let config = config(
            "[dns]\nbind = \"127.0.0.1\"\nupstream = [\"udp://1.1.1.1:53\"]\n\
             [routing.sniff]\nenabled = false\n",
        );
        let plan = plan(&config, true).expect("valid");
        assert!(!plan.sniff_enabled());
        assert!(plan.dns_service());
        assert!(plan.has_domain_rules());
        assert!(
            plan.warnings()
                .iter()
                .any(|warning| warning.contains("shared real IP")),
            "{:?}",
            plan.warnings()
        );
    }

    #[test]
    fn fake_ip_wins_and_never_sniffs() {
        let config = config(
            "[dns]\nbind = \"127.0.0.1\"\nupstream = [\"udp://1.1.1.1:53\"]\n\
             [dns.fake-ip]\nenabled = true\n\
             [routing.sniff]\nenabled = true\ntimeout = \"30ms\"\n",
        );
        let plan = plan(&config, true).expect("valid");
        let pool = Arc::new(FakeIpPool::from_config(&config.dns.fake_ip).expect("pool"));
        let domain = pool.allocate("example.com");
        let destination = SocketAddr::from((domain, 443));
        let resolver = DomainResolver::new(
            plan,
            Some(Arc::clone(&pool)),
            Some(Arc::new(DnsSnooper::default())),
        );
        let source = SocketAddr::from(([192, 168, 1, 1], 12345));
        let lookup = resolver.lookup(source, destination);
        match lookup {
            DomainLookup::Found { domain, source, .. } => {
                assert_eq!(domain, "example.com");
                assert_eq!(source, DomainSource::FakeIp);
            }
            other => panic!("expected a fake-ip mapping, got {other:?}"),
        }
    }

    #[test]
    fn a_unique_dns_candidate_skips_sniff() {
        let config = config(
            "[dns]\nbind = \"127.0.0.1\"\nupstream = [\"udp://1.1.1.1:53\"]\n\
             [routing.sniff]\nenabled = true\ntimeout = \"30ms\"\n",
        );
        let plan = plan(&config, true).expect("valid");
        let snooper = Arc::new(DnsSnooper::default());
        let source = SocketAddr::from(([192, 168, 1, 1], 12345));
        let destination = SocketAddr::from(([93, 184, 216, 34], 443));
        snooper.record(source.ip(), destination.ip(), "example.com", 60);
        let resolver = DomainResolver::new(plan, None, Some(snooper));
        let lookup = resolver.lookup(source, destination);
        match lookup {
            DomainLookup::Found { domain, source, .. } => {
                assert_eq!(domain, "example.com");
                assert_eq!(source, DomainSource::DnsSnooper);
            }
            other => panic!("expected a dns-snooper mapping, got {other:?}"),
        }
    }

    #[test]
    fn an_ambiguous_mapping_is_reported_without_a_guess() {
        let config = config(
            "[dns]\nbind = \"127.0.0.1\"\nupstream = [\"udp://1.1.1.1:53\"]\n\
             [routing.sniff]\nenabled = false\n",
        );
        let plan = plan(&config, true).expect("valid");
        let snooper = Arc::new(DnsSnooper::default());
        let source = SocketAddr::from(([192, 168, 1, 1], 12345));
        let destination = SocketAddr::from(([93, 184, 216, 34], 443));
        snooper.record(source.ip(), destination.ip(), "a.example", 60);
        snooper.record(source.ip(), destination.ip(), "b.example", 60);
        let resolver = DomainResolver::new(plan, None, Some(snooper));
        assert_eq!(
            resolver.lookup(source, destination),
            DomainLookup::Ambiguous { candidates: 2 }
        );
    }

    #[test]
    fn a_datagram_is_inspected_only_when_sniffing_is_enabled() {
        let enabled = config("[routing.sniff]\nenabled = true\ntimeout = \"30ms\"\n");
        let enabled_plan = plan(&enabled, true).expect("valid");
        let resolver = DomainResolver::new(enabled_plan, None, None);
        let source = SocketAddr::from(([192, 168, 1, 1], 12345));
        let destination = SocketAddr::from(([1, 1, 1, 1], 443));
        let out = resolver.resolve_datagram(
            source,
            destination,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        assert_eq!(out.domain(), Some("example.com"));
        assert_eq!(out.source(), Some(DomainSource::Sniff));

        let disabled = config("[routing.sniff]\nenabled = false\n");
        let disabled_plan = plan(&disabled, false).expect("valid");
        let resolver = DomainResolver::new(disabled_plan, None, None);
        let out = resolver.resolve_datagram(
            source,
            destination,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        assert_eq!(
            out,
            DomainOutcome::Unnamed {
                reason: UnnamedReason::NoDnsMapping
            }
        );
    }

    #[test]
    fn the_snooper_is_keyed_by_client_and_address() {
        let snooper = DnsSnooper::default();
        let destination = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let client_a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let client_b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        snooper.record(client_a, destination, "a.example", 60);
        snooper.record(client_b, destination, "b.example", 60);
        assert_eq!(
            snooper.lookup(client_a, destination),
            SnoopLookup::Unique(Arc::from("a.example"))
        );
        assert_eq!(
            snooper.lookup(client_b, destination),
            SnoopLookup::Unique(Arc::from("b.example"))
        );
    }
}
