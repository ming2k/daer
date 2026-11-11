// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical Rule Source (CRS v2) intermediate representation and AST (ADR-0031, ADR-0036).
//!
//! Under ADR-0031, ADR-0033, and ADR-0036, `RuleSet` is the single source of truth for routing rules:
//! * **IP**: Normalized as mathematical disjoint closed intervals (`v4_intervals`, `v6_intervals`).
//! * **Domain**: Normalized as hierarchical patterns (`Suffix` and `Full`, rendered as `=domain`, `.domain`, `domain`).
//! * **Attributes**: Preserved for pipeline filtering (`--without ads`), omitted from binary.

mod error;
mod pattern;

pub use error::AstError;
pub use pattern::{DomainPattern, SuffixScope, is_valid_domain_char};

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// One domain rule, optionally annotated with provenance attributes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainRule {
    pub pattern: DomainPattern,
    pub attributes: Vec<String>,
}

impl DomainRule {
    #[must_use]
    pub fn new(pattern: DomainPattern) -> Self {
        Self {
            pattern,
            attributes: Vec::new(),
        }
    }

    #[must_use]
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.iter().any(|a| a.eq_ignore_ascii_case(name))
    }

    pub fn canonical(self) -> Result<Self, AstError> {
        let mut attributes = self.attributes;
        for a in &mut attributes {
            *a = a.trim().to_ascii_lowercase();
            if a.is_empty() {
                return Err(AstError::new("an attribute name is empty"));
            }
        }
        attributes.sort_unstable();
        attributes.dedup();
        Ok(Self {
            pattern: self.pattern.canonical()?,
            attributes,
        })
    }
}

/// A normalized rule set in Canonical Rule Source (CRS v1) format.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleSet {
    name: String,
    v4_intervals: Vec<(u32, u32)>,
    v6_intervals: Vec<(u128, u128)>,
    domains: Vec<DomainRule>,
}

impl RuleSet {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            v4_intervals: Vec::new(),
            v6_intervals: Vec::new(),
            domains: Vec::new(),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    #[must_use]
    pub fn v4_intervals(&self) -> &[(u32, u32)] {
        &self.v4_intervals
    }

    #[must_use]
    pub fn v6_intervals(&self) -> &[(u128, u128)] {
        &self.v6_intervals
    }

    #[must_use]
    pub fn domains(&self) -> &[DomainRule] {
        &self.domains
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4_intervals.is_empty() && self.v6_intervals.is_empty() && self.domains.is_empty()
    }

    pub fn push_v4_range(&mut self, start: u32, end: u32) {
        if start <= end {
            self.v4_intervals.push((start, end));
        }
    }

    pub fn push_v6_range(&mut self, start: u128, end: u128) {
        if start <= end {
            self.v6_intervals.push((start, end));
        }
    }

    pub fn push_domain(&mut self, rule: DomainRule) {
        self.domains.push(rule);
    }

    /// Drops any domain rule carrying `attribute`.
    pub fn drop_attribute(&mut self, attribute: &str) -> usize {
        let before = self.domains.len();
        self.domains.retain(|r| !r.has_attribute(attribute));
        before - self.domains.len()
    }

    /// Strips attributes while retaining domain rules.
    pub fn strip_attributes(&mut self) -> usize {
        let mut count = 0;
        for r in &mut self.domains {
            if !r.attributes.is_empty() {
                count += 1;
                r.attributes.clear();
            }
        }
        count
    }

    /// Normalizes, merges IP intervals, and sorts/prunes domain patterns.
    pub fn canonical(mut self) -> Result<Self, AstError> {
        self.v4_intervals = merge_u32_ranges(std::mem::take(&mut self.v4_intervals));
        self.v6_intervals = merge_u128_ranges(std::mem::take(&mut self.v6_intervals));

        let mut canonical_domains = Vec::with_capacity(self.domains.len());
        for rule in std::mem::take(&mut self.domains) {
            canonical_domains.push(rule.canonical()?);
        }

        // Sort by pattern value
        canonical_domains.sort_by(|a, b| a.pattern.cmp(&b.pattern));

        // Deduplicate and merge attributes
        let mut merged: Vec<DomainRule> = Vec::with_capacity(canonical_domains.len());
        for rule in canonical_domains {
            match merged.last_mut() {
                Some(last) if last.pattern == rule.pattern => {
                    last.attributes.extend(rule.attributes);
                    last.attributes.sort_unstable();
                    last.attributes.dedup();
                }
                _ => merged.push(rule),
            }
        }

        self.domains = merged;
        Ok(self)
    }

    /// Parses text in CRS v1 format.
    pub fn parse(text: &str) -> Result<Self, AstError> {
        let mut set = Self::new("");
        for (idx, raw_line) in text.lines().enumerate() {
            let line_num = idx + 1;
            let line = strip_comment(raw_line);
            if line.is_empty() {
                continue;
            }
            set.push_line(line).map_err(|err| match err.line() {
                Some(_) => err,
                None => AstError::at_line(line_num, err.to_string()),
            })?;
        }
        set.canonical()
    }

    fn push_line(&mut self, line: &str) -> Result<(), AstError> {
        if let Some(rest) = line.strip_prefix("name:") {
            self.name = rest.trim().to_owned();
            return Ok(());
        }
        if let Some(rest) = line.strip_prefix("ip:") {
            return self.push_ip_directive(rest.trim());
        }
        if let Some(rest) = line.strip_prefix('=') {
            let (val_clean, attrs) = split_attributes(rest);
            let pattern = DomainPattern::from_kind("=", val_clean)?;
            self.domains.push(DomainRule {
                pattern,
                attributes: attrs,
            });
            return Ok(());
        }
        if let Some((kind, _val)) = line.split_once(':') {
            let k = kind.trim();
            if k == "full" {
                return Err(AstError::new(
                    "'full:' is retired (ADR-0036); write '=domain' for exact full match",
                ));
            }
            if k == "suffix" || k == "domain" {
                return Err(AstError::new(format!(
                    "'{k}:' is retired (ADR-0036); write bare 'domain' or '.domain' for suffix match"
                )));
            }
            if k == "keyword" || k == "regex" {
                return Err(AstError::new(format!(
                    "'{k}:' directives are removed (ADR-0031, ADR-0033); write explicit '=domain' or suffix patterns, or expand them before compiling."
                )));
            }
        }

        // Fallbacks
        if let Ok(()) = self.push_ip_directive(line) {
            return Ok(());
        }
        let (val_clean, attrs) = split_attributes(line);
        let pattern = if let Some(rest) = val_clean.strip_prefix('=') {
            DomainPattern::from_kind("=", rest)?
        } else {
            DomainPattern::from_kind("suffix", val_clean)?
        };
        self.domains.push(DomainRule {
            pattern,
            attributes: attrs,
        });
        Ok(())
    }

    fn push_ip_directive(&mut self, val: &str) -> Result<(), AstError> {
        // Range: start - end
        if let Some((start_s, end_s)) = val.split_once('-') {
            let start_s = start_s.trim();
            let end_s = end_s.trim();
            let start_ip: IpAddr = start_s
                .parse()
                .map_err(|_| AstError::new(format!("invalid IP start address: {start_s:?}")))?;
            let end_ip: IpAddr = end_s
                .parse()
                .map_err(|_| AstError::new(format!("invalid IP end address: {end_s:?}")))?;

            match (start_ip, end_ip) {
                (IpAddr::V4(s), IpAddr::V4(e)) => {
                    let s_num = u32::from(s);
                    let e_num = u32::from(e);
                    if s_num > e_num {
                        return Err(AstError::new(format!(
                            "IPv4 interval start ({s}) > end ({e})"
                        )));
                    }
                    self.push_v4_range(s_num, e_num);
                    return Ok(());
                }
                (IpAddr::V6(s), IpAddr::V6(e)) => {
                    let s_num = u128::from(s);
                    let e_num = u128::from(e);
                    if s_num > e_num {
                        return Err(AstError::new(format!(
                            "IPv6 interval start ({s}) > end ({e})"
                        )));
                    }
                    self.push_v6_range(s_num, e_num);
                    return Ok(());
                }
                _ => {
                    return Err(AstError::new(
                        "IP interval start and end must belong to the same address family",
                    ));
                }
            }
        }

        // CIDR
        if let Ok(net) = val.parse::<IpNet>() {
            match net {
                IpNet::V4(net) => {
                    let host_bits = 32 - net.prefix_len();
                    let base = u32::from(net.addr()) & (!0u32 << host_bits);
                    let end = base | ((1u32 << host_bits).wrapping_sub(1));
                    self.push_v4_range(base, end);
                }
                IpNet::V6(net) => {
                    let host_bits = 128 - net.prefix_len();
                    let base = u128::from(net.addr()) & (!0u128 << host_bits);
                    let end = base | ((1u128 << host_bits).wrapping_sub(1));
                    self.push_v6_range(base, end);
                }
            }
            return Ok(());
        }

        // Single IP
        if let Ok(ip) = val.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(ip) => {
                    let n = u32::from(ip);
                    self.push_v4_range(n, n);
                }
                IpAddr::V6(ip) => {
                    let n = u128::from(ip);
                    self.push_v6_range(n, n);
                }
            }
            return Ok(());
        }

        Err(AstError::new(format!(
            "{val:?} is not a valid IP address, CIDR, or range"
        )))
    }

    /// Renders the canonical text representation of this rule set.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        if !self.name.is_empty() {
            let _ = writeln!(out, "name: {}", self.name);
        }

        for &(start, end) in &self.v4_intervals {
            for cidr in decompose_v4_interval(start, end) {
                let _ = writeln!(out, "ip: {cidr}");
            }
        }

        for &(start, end) in &self.v6_intervals {
            for cidr in decompose_v6_interval(start, end) {
                let _ = writeln!(out, "ip: {cidr}");
            }
        }

        for rule in &self.domains {
            let rendered = rule.pattern.to_string();
            if rule.attributes.is_empty() {
                let _ = writeln!(out, "{rendered}");
            } else {
                let attrs: Vec<String> = rule.attributes.iter().map(|a| format!("@{a}")).collect();
                let _ = writeln!(out, "{rendered} {}", attrs.join(" "));
            }
        }

        out
    }
}

impl FromStr for RuleSet {
    type Err = AstError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

fn strip_comment(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return "";
    }
    let cut = trimmed.find('#').unwrap_or(trimmed.len());
    trimmed[..cut].trim()
}

fn split_attributes(value: &str) -> (&str, Vec<String>) {
    let mut attributes = Vec::new();
    let mut rest = value.trim_end();
    while let Some(head) = rest.rsplit_once(char::is_whitespace) {
        let candidate = head.1;
        let Some(name) = candidate.strip_prefix('@') else {
            break;
        };
        if name.is_empty() || name.contains('@') {
            break;
        }
        attributes.push(name.to_owned());
        rest = head.0.trim_end();
    }
    attributes.reverse();
    (rest, attributes)
}

fn merge_u32_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if ranges.len() < 2 {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged = Vec::with_capacity(ranges.len());
    let mut cur = ranges[0];
    for (start, end) in ranges.into_iter().skip(1) {
        if start <= cur.1 || cur.1.checked_add(1).is_some_and(|next| start <= next) {
            cur.1 = cur.1.max(end);
        } else {
            merged.push(cur);
            cur = (start, end);
        }
    }
    merged.push(cur);
    merged
}

fn merge_u128_ranges(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    if ranges.len() < 2 {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged = Vec::with_capacity(ranges.len());
    let mut cur = ranges[0];
    for (start, end) in ranges.into_iter().skip(1) {
        if start <= cur.1 || cur.1.checked_add(1).is_some_and(|next| start <= next) {
            cur.1 = cur.1.max(end);
        } else {
            merged.push(cur);
            cur = (start, end);
        }
    }
    merged.push(cur);
    merged
}

/// Decomposes an arbitrary [start, end] IPv4 interval into minimal standard CIDRs.
pub fn decompose_v4_interval(mut start: u32, end: u32) -> Vec<Ipv4Net> {
    let mut cidrs = Vec::new();
    while start <= end {
        // Max power of 2 aligned with start
        let max_size_bits = if start == 0 {
            32
        } else {
            start.trailing_zeros().min(32)
        };
        // Max size that fits inside [start, end]
        let diff = (end - start).saturating_add(1);
        let max_fit_bits = 31 - diff.leading_zeros();
        let bits = max_size_bits.min(max_fit_bits);
        let prefix_len = (32 - bits) as u8;

        cidrs.push(Ipv4Net::new(Ipv4Addr::from(start), prefix_len).expect("valid cidr"));
        let step = 1u64 << bits;
        if (start as u64) + step > (end as u64) {
            break;
        }
        start += step as u32;
    }
    cidrs
}

/// Decomposes an arbitrary [start, end] IPv6 interval into minimal standard CIDRs.
pub fn decompose_v6_interval(mut start: u128, end: u128) -> Vec<Ipv6Net> {
    let mut cidrs = Vec::new();
    while start <= end {
        let max_size_bits = if start == 0 {
            128
        } else {
            start.trailing_zeros().min(128)
        };
        let diff = (end - start).saturating_add(1);
        let max_fit_bits = 127 - diff.leading_zeros();
        let bits = max_size_bits.min(max_fit_bits);
        let prefix_len = (128 - bits) as u8;

        cidrs.push(Ipv6Net::new(Ipv6Addr::from(start), prefix_len).expect("valid cidr"));
        let step = 1u128 << bits;
        if start.checked_add(step).is_none_or(|next| next > end + 1) {
            break;
        }
        start += step;
    }
    cidrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_merges_ip_intervals() {
        let text =
            "name: test\nip: 192.168.1.0/24\nip: 192.168.2.0/24\nip: 192.168.3.1 - 192.168.3.254\n";
        let set = RuleSet::parse(text).unwrap();
        // 192.168.1.0/24 + 192.168.2.0/24 are adjacent! Merges into [192.168.1.0, 192.168.2.255]
        assert_eq!(set.v4_intervals().len(), 2);
    }

    #[test]
    fn decompose_round_trips_arbitrary_ranges() {
        let start = 0x0a000105; // 10.0.1.5
        let end = 0x0a000320; // 10.0.3.32
        let cidrs = decompose_v4_interval(start, end);
        assert!(!cidrs.is_empty());
        // Verify coverage
        let mut reconstructed_start = u32::from(cidrs[0].network());
        assert_eq!(reconstructed_start, start);
        for cidr in &cidrs {
            let base = u32::from(cidr.network());
            let size = 1u32 << (32 - cidr.prefix_len());
            assert_eq!(base, reconstructed_start);
            reconstructed_start = base + size;
        }
        assert_eq!(reconstructed_start - 1, end);
    }

    #[test]
    fn parses_domains_and_rejects_regex_and_retired_prefixes() {
        let text = "example.com\n=api.example.com\n.corp.local\n";
        let set = RuleSet::parse(text).unwrap();
        assert_eq!(set.domains().len(), 3);
        let rendered = set.render();
        assert!(rendered.contains("=api.example.com"));
        assert!(rendered.contains(".corp.local"));
        assert!(rendered.contains("example.com"));

        let err_regex = RuleSet::parse("regex: ^.*$").unwrap_err();
        assert!(err_regex.to_string().contains("removed"), "{err_regex}");

        let err_full = RuleSet::parse("full: api.example.com").unwrap_err();
        assert!(err_full.to_string().contains("retired"), "{err_full}");

        let err_suffix = RuleSet::parse("suffix: example.com").unwrap_err();
        assert!(err_suffix.to_string().contains("retired"), "{err_suffix}");
    }
}
