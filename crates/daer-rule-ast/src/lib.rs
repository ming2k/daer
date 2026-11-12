// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical Rule Source (CRS v3) intermediate representation and AST (ADR-0031, ADR-0036, ADR-0045).
//!
//! Under ADR-0031, ADR-0033, ADR-0036, and ADR-0045, `RuleSet` is the single source of truth for routing rules:
//! * **IP**: Normalized as mathematical disjoint closed intervals (`v4_intervals`, `v6_intervals`), parsed from bare IPs, CIDRs, and `..` ranges.
//! * **Domain**: Normalized as hierarchical patterns (`Suffix` and `Full`, rendered as `=domain`, `.domain`, `domain`).
//! * **Metadata**: Frontmatter header `--- \n name: <set-name> \n ---` decoupled from rule lines.

mod error;
mod pattern;

pub use error::AstError;
pub use pattern::{DomainPattern, SuffixScope, is_valid_domain_char};

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// One domain rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainRule {
    pub pattern: DomainPattern,
}

impl DomainRule {
    #[must_use]
    pub fn new(pattern: DomainPattern) -> Self {
        Self { pattern }
    }

    pub fn canonical(self) -> Result<Self, AstError> {
        Ok(Self {
            pattern: self.pattern.canonical()?,
        })
    }
}

/// A normalized rule set in Canonical Rule Source (CRS v3) format.
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

    /// Normalizes, merges IP intervals, and sorts/prunes domain patterns.
    pub fn canonical(mut self) -> Result<Self, AstError> {
        self.v4_intervals = merge_u32_ranges(std::mem::take(&mut self.v4_intervals));
        self.v6_intervals = merge_u128_ranges(std::mem::take(&mut self.v6_intervals));

        let mut canonical_domains = Vec::with_capacity(self.domains.len());
        for rule in std::mem::take(&mut self.domains) {
            canonical_domains.push(rule.canonical()?);
        }

        // Sort by pattern value and remove duplicate patterns.
        canonical_domains.sort_by(|a, b| a.pattern.cmp(&b.pattern));
        canonical_domains.dedup_by(|a, b| a.pattern == b.pattern);

        self.domains = canonical_domains;
        Ok(self)
    }

    /// Parses text in CRS v3 format (ADR-0045).
    pub fn parse(text: &str) -> Result<Self, AstError> {
        let mut set = Self::new("");
        let mut lines = text.lines().enumerate().peekable();

        // 1. Check for optional Frontmatter
        let mut in_frontmatter = false;
        let mut frontmatter_closed = false;

        while let Some(&(_idx, raw_line)) = lines.peek() {
            let line = strip_comment(raw_line);
            if line.is_empty() {
                lines.next();
                continue;
            }
            if line == "---" {
                lines.next();
                in_frontmatter = true;
                break;
            }
            break;
        }

        if in_frontmatter {
            for (idx, raw_line) in lines.by_ref() {
                let line_num = idx + 1;
                let line = strip_comment(raw_line);
                if line.is_empty() {
                    continue;
                }
                if line == "---" {
                    frontmatter_closed = true;
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    let key = k.trim();
                    let val = v.trim();
                    if key == "name" {
                        if !set.name.is_empty() {
                            return Err(AstError::at_line(
                                line_num,
                                "duplicate frontmatter key 'name'",
                            ));
                        }
                        if val.is_empty() {
                            return Err(AstError::at_line(
                                line_num,
                                "frontmatter key 'name' cannot be empty",
                            ));
                        }
                        set.name = val.to_owned();
                    } else {
                        return Err(AstError::at_line(
                            line_num,
                            format!("unknown frontmatter key {key:?}; only 'name' is supported"),
                        ));
                    }
                } else {
                    return Err(AstError::at_line(
                        line_num,
                        format!("invalid frontmatter line {line:?}; expected 'key: value'"),
                    ));
                }
            }

            if !frontmatter_closed {
                return Err(AstError::new(
                    "unclosed frontmatter (missing closing '---')",
                ));
            }
        }

        // 2. Parse rule entries
        for (idx, raw_line) in lines {
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
        if line == "---" {
            return Err(AstError::new("unexpected '---' outside frontmatter"));
        }
        if line.starts_with("name:") {
            return Err(AstError::new(
                "'name:' must be declared in frontmatter '--- ... ---' at top of file (ADR-0045)",
            ));
        }
        if line.starts_with("ip:") {
            return Err(AstError::new(
                "'ip:' is retired (ADR-0045); write bare CIDR, host IP, or 'start..end' range",
            ));
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
                    "'{k}:' directives are removed (ADR-0031, ADR-0033); write explicit '=domain' or suffix patterns."
                )));
            }
        }

        // 1. Range: `start..end`
        if let Some((start_s, end_s)) = line.split_once("..") {
            if end_s.contains("..") {
                return Err(AstError::new(format!(
                    "invalid IP range syntax {line:?}; expected 'start..end'"
                )));
            }
            let s_trimmed = start_s.trim();
            let e_trimmed = end_s.trim();
            if s_trimmed.is_empty() || e_trimmed.is_empty() {
                return Err(AstError::new(format!(
                    "invalid IP range {line:?}: both start and end must be specified"
                )));
            }
            let start_ip: IpAddr = s_trimmed
                .parse()
                .map_err(|_| AstError::new(format!("invalid IP start address: {s_trimmed:?}")))?;
            let end_ip: IpAddr = e_trimmed
                .parse()
                .map_err(|_| AstError::new(format!("invalid IP end address: {e_trimmed:?}")))?;

            return match (start_ip, end_ip) {
                (IpAddr::V4(s), IpAddr::V4(e)) => {
                    let s_num = u32::from(s);
                    let e_num = u32::from(e);
                    if s_num > e_num {
                        return Err(AstError::new(format!(
                            "IPv4 interval start ({s}) > end ({e})"
                        )));
                    }
                    self.push_v4_range(s_num, e_num);
                    Ok(())
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
                    Ok(())
                }
                _ => Err(AstError::new(
                    "IP interval start and end must belong to the same address family",
                )),
            };
        }

        // Catch retired hyphen range `start - end`
        if let Some((start_s, end_s)) = line.split_once('-')
            && start_s.trim().parse::<IpAddr>().is_ok()
            && end_s.trim().parse::<IpAddr>().is_ok()
        {
            return Err(AstError::new(
                "'-' range syntax is retired (ADR-0045); write 'start..end'",
            ));
        }

        // 2. CIDR: contains `/`
        if line.contains('/') {
            let net: IpNet = line
                .parse()
                .map_err(|e| AstError::new(format!("invalid CIDR {line:?}: {e}")))?;
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

        // 3. IPv6 single address: contains `:`
        if line.contains(':') {
            let ip: Ipv6Addr = line
                .parse()
                .map_err(|e| AstError::new(format!("invalid IPv6 address {line:?}: {e}")))?;
            let n = u128::from(ip);
            self.push_v6_range(n, n);
            return Ok(());
        }

        // 4. IPv4 single address: 4 numeric octets separated by dots
        if is_ipv4_shape(line) {
            let ip: Ipv4Addr = line
                .parse()
                .map_err(|e| AstError::new(format!("invalid IPv4 address {line:?}: {e}")))?;
            let n = u32::from(ip);
            self.push_v4_range(n, n);
            return Ok(());
        }

        // 5. Exact Domain: starts with '='
        if let Some(rest) = line.strip_prefix('=') {
            let pattern = DomainPattern::from_kind("=", rest)?;
            self.domains.push(DomainRule::new(pattern));
            return Ok(());
        }

        // 6. Subdomain-only Domain: starts with '.'
        if let Some(rest) = line.strip_prefix('.') {
            if rest.is_empty() {
                return Err(AstError::new("empty subdomain pattern '.'"));
            }
            let pattern = DomainPattern::from_kind("suffix", line)?;
            self.domains.push(DomainRule::new(pattern));
            return Ok(());
        }

        // 7. Domain Suffix: bare domain
        let pattern = DomainPattern::from_kind("suffix", line)?;
        self.domains.push(DomainRule::new(pattern));
        Ok(())
    }

    /// Renders the canonical text representation of this rule set.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        if !self.name.is_empty() {
            let _ = writeln!(out, "---");
            let _ = writeln!(out, "name: {}", self.name);
            let _ = writeln!(out, "---");
            let _ = writeln!(out);
        }

        for &(start, end) in &self.v4_intervals {
            for cidr in decompose_v4_interval(start, end) {
                if cidr.prefix_len() == 32 {
                    let _ = writeln!(out, "{}", cidr.addr());
                } else {
                    let _ = writeln!(out, "{cidr}");
                }
            }
        }

        for &(start, end) in &self.v6_intervals {
            for cidr in decompose_v6_interval(start, end) {
                if cidr.prefix_len() == 128 {
                    let _ = writeln!(out, "{}", cidr.addr());
                } else {
                    let _ = writeln!(out, "{cidr}");
                }
            }
        }

        for rule in &self.domains {
            let _ = writeln!(out, "{}", rule.pattern);
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

fn is_ipv4_shape(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn strip_comment(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return "";
    }
    let cut = trimmed.find('#').unwrap_or(trimmed.len());
    trimmed[..cut].trim()
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
        let text = "---\nname: test\n---\n192.168.1.0/24\n192.168.2.0/24\n192.168.3.1..192.168.3.254\n10.0.0.1\n2001:db8::1\n";
        let set = RuleSet::parse(text).unwrap();
        assert_eq!(set.name(), "test");
        // 192.168.1.0/24 + 192.168.2.0/24 are adjacent! Merges into [192.168.1.0, 192.168.2.255]
        assert_eq!(set.v4_intervals().len(), 3); // (192.168.1..2), (192.168.3), (10.0.0.1)
        assert_eq!(set.v6_intervals().len(), 1); // 2001:db8::1
    }

    #[test]
    fn rejects_retired_prefixes_and_syntax() {
        let err_ip = RuleSet::parse("ip: 1.1.1.1").unwrap_err();
        assert!(
            err_ip.to_string().contains("'ip:' is retired (ADR-0045)"),
            "{err_ip}"
        );

        let err_name = RuleSet::parse("name: orphan").unwrap_err();
        assert!(
            err_name
                .to_string()
                .contains("'name:' must be declared in frontmatter"),
            "{err_name}"
        );

        let err_range = RuleSet::parse("10.0.0.1 - 10.0.0.50").unwrap_err();
        assert!(
            err_range
                .to_string()
                .contains("'-' range syntax is retired (ADR-0045)"),
            "{err_range}"
        );

        let err_v4 = RuleSet::parse("192.168.1.256").unwrap_err();
        assert!(
            err_v4.to_string().contains("invalid IPv4 address"),
            "{err_v4}"
        );

        let err_tld = RuleSet::parse("foo.123").unwrap_err();
        assert!(err_tld.to_string().contains("all-numeric TLD"), "{err_tld}");
    }

    #[test]
    fn round_trip_render_and_parse() {
        let text = "---\nname: my-set\n---\n192.168.1.0/24\n10.0.0.1\n2001:db8::1\nexample.com\n.sub.corp\n=exact.corp\n";
        let set = RuleSet::parse(text).unwrap();
        let rendered = set.render();
        assert!(rendered.starts_with("---\nname: my-set\n---"));
        assert!(rendered.contains("192.168.1.0/24"));
        assert!(rendered.contains("10.0.0.1"));
        assert!(rendered.contains("2001:db8::1"));
        assert!(rendered.contains("example.com"));
        assert!(rendered.contains(".sub.corp"));
        assert!(rendered.contains("=exact.corp"));

        let reparsed = RuleSet::parse(&rendered).unwrap();
        assert_eq!(set, reparsed);
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

    #[test]
    fn attribute_suffixes_are_not_valid_syntax() {
        // No special-case parser code: the ordinary domain/IP validation rejects `@`.
        assert!(RuleSet::parse("example.com @ads").is_err());
        assert!(RuleSet::parse("ip: 1.2.3.4 @ads").is_err());
    }

    #[test]
    fn frontmatter_validations() {
        let err_dup = RuleSet::parse("---\nname: a\nname: b\n---\n1.1.1.1\n").unwrap_err();
        assert!(
            err_dup
                .to_string()
                .contains("duplicate frontmatter key 'name'"),
            "{err_dup}"
        );

        let err_empty = RuleSet::parse("---\nname:\n---\n1.1.1.1\n").unwrap_err();
        assert!(
            err_empty.to_string().contains("cannot be empty"),
            "{err_empty}"
        );

        let err_unclosed = RuleSet::parse("---\nname: a\n").unwrap_err();
        assert!(
            err_unclosed.to_string().contains("unclosed frontmatter"),
            "{err_unclosed}"
        );

        let err_caret = RuleSet::parse("test^domain.com").unwrap_err();
        assert!(
            err_caret.to_string().contains("illegal character '^'"),
            "{err_caret}"
        );
    }
}
