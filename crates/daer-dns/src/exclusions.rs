// SPDX-License-Identifier: AGPL-3.0-only

//! The `dns.fake-ip.exclude` pattern language.
//!
//! # Why this is not `daer_routing::DomainTable`
//!
//! Routing and Fake-IP ask the same *kind* of question but accept different answers:
//!
//! | | routing | fake-ip exclusion |
//! | --- | --- | --- |
//! | source | a published corpus of thousands of entries | a handful of hand-written lines |
//! | frequency | per connection, on the matching path | once per DNS query |
//! | artifact size matters | yes — every client downloads it | no |
//! | needs `keyword:`/`regex:` | no (measured: zero across every published set) | yes — "never synthesise anything under `.internal`" |
//!
//! Sharing one structure forced the routing path to carry an Aho-Corasick automaton and a regex
//! set for syntax nobody wrote. So the two are separate.
//!
//! # What is *not* separate
//!
//! `keyword:` and `regex:` are parsed by [`crate::routing::NameMatch`], the same type the DNS
//! router uses. That is the point of ADR-0023 in type form: two subsystems needing the same
//! *meaning* share one definition; they split only where their requirements actually differ.

use std::net::IpAddr;

use crate::routing::NameMatch;

/// A compiled set of Fake-IP exclusion rules.
#[derive(Debug, Default)]
pub struct Exclusions {
    matchers: Vec<NameMatch>,
}

impl Exclusions {
    /// Compiles the configured patterns.
    ///
    /// Accepted spellings: `full:`, `suffix:`, `keyword:`, `regex:`, and a bare name read as a
    /// suffix — the same vocabulary `[routing]` uses, so an operator learns it once.
    ///
    /// # Errors
    ///
    /// Returns a message naming the entry that could not be understood. A silently ignored
    /// exclusion would hand out a synthetic address for exactly the domain the operator excluded,
    /// so every failure here is fatal.
    pub fn compile(patterns: &[String]) -> Result<Self, String> {
        let mut matchers = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (kind, value) = match trimmed.split_once(':') {
                Some((kind, value)) => (kind.trim(), value.trim()),
                // A bare name is a suffix, matching `[routing]`'s default.
                None => ("suffix", trimmed),
            };
            if matches!(kind, "geosite" | "geoip" | "ext") {
                return Err(format!(
                    "dns.fake-ip.exclude: {trimmed:?} names a Protobuf .dat category, which this \
                     build no longer reads (ADR-0031); write the domains as patterns \
                     (suffix:/full:/keyword:/regex:) instead"
                ));
            }
            let matcher = NameMatch::parse_kind(kind, value).map_err(|err| {
                format!(
                    "dns.fake-ip.exclude: {trimmed:?} is not a domain matcher \
                     (expected full, suffix, keyword, or regex): {err}"
                )
            })?;
            matchers.push(matcher);
        }
        Ok(Self { matchers })
    }

    /// Whether `domain` is excluded from synthesis.
    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        let trimmed = domain.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return false;
        }
        self.matchers
            .iter()
            .any(|matcher| matcher.matches_text(trimmed))
    }

    /// True when no pattern was configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }
}

/// Whether `addr` is inside `net`. Used by the pool's address-exclusion path.
#[must_use]
pub fn ip_in_net(addr: IpAddr, net: &ipnet::Ipv4Net) -> bool {
    match addr {
        IpAddr::V4(v4) => net.contains(&v4),
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(patterns: &[&str]) -> Exclusions {
        Exclusions::compile(&patterns.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
            .expect("compiles")
    }

    #[test]
    fn a_bare_name_excludes_the_name_and_its_subdomains() {
        let e = compile(&["corp.internal"]);
        assert!(e.matches("corp.internal"));
        assert!(e.matches("a.corp.internal"));
        assert!(
            !e.matches("notcorp.internal"),
            "a label boundary is required, or `notcorp.internal` would be excluded by `corp.internal`"
        );
    }

    #[test]
    fn keyword_matches_a_substring() {
        let e = compile(&["keyword: telemetry"]);
        assert!(e.matches("host.telemetry.example"));
        assert!(!e.matches("example.com"));
    }

    #[test]
    fn regex_matches() {
        let e = compile(&[r"regex: ^srv\d+\.corp\.local$"]);
        assert!(e.matches("srv12.corp.local"));
        assert!(!e.matches("srv12.corp.local.example"));
    }

    #[test]
    fn a_dat_category_is_refused_by_name() {
        let err = Exclusions::compile(&["geosite:cn".to_owned()]).expect_err("must refuse");
        assert!(err.contains("no longer reads"), "{err}");
    }

    #[test]
    fn a_broken_regex_is_refused() {
        let err = Exclusions::compile(&["regex: (unclosed".to_owned()]).expect_err("must refuse");
        assert!(err.contains("not a domain matcher"), "{err}");
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let err = Exclusions::compile(&["nonsense: x".to_owned()]).expect_err("must refuse");
        assert!(err.contains("not a domain matcher"), "{err}");
    }
}
