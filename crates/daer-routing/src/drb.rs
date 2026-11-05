// SPDX-License-Identifier: AGPL-3.0-only

//! daer Rule Binary (DRB) specification and engine (ADR-0014).
//!
//! A `.drb` artifact is a pre-compiled, binary rule set that encodes:
//!
//! * IPv4 and IPv6 address intervals, already sorted and merged for binary search;
//! * IP prefixes, preserved for kernel LPM trie lowering;
//! * Domain patterns (exact/full, suffix with scope, keyword, regex).
//!
//! # Invariants
//!
//! * `[INV-DRB-01]`: Loading a DRB requires zero interval merging and zero pattern
//!   normalization. Bit flips and truncated downloads are caught by header magic,
//!   version bounds, and cryptographic SHA-256 verification.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use sha2::{Digest, Sha256};

use crate::domain::{DomainIndex, SuffixScope};
use crate::error::RoutingError;
use crate::ipset::IpIndex;
use crate::matcher::{MatchSet, MatchValue};
use crate::outbound::MatchTarget;

/// Fixed 8-byte magic for DRB artifacts.
pub const DRB_MAGIC: &[u8; 8] = b"DAER_DRB";

/// DRB format version implemented by this build.
pub const DRB_VERSION: u32 = 1;

/// Fixed header size: magic(8) + version(4) + section_count(4) + timestamp(8) + checksum(32) = 56 bytes.
pub const DRB_HEADER_SIZE: usize = 56;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrbError {
    Truncated {
        field: &'static str,
        needed: usize,
        available: usize,
    },
    InvalidMagic,
    UnsupportedVersion(u32),
    ChecksumMismatch {
        expected: String,
        actual: String,
    },
    InvalidUtf8(&'static str),
    InvalidInterval(&'static str),
    InvalidPrefix(&'static str),
    ParseError(String),
}

impl fmt::Display for DrbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                field,
                needed,
                available,
            } => write!(
                f,
                "truncated DRB payload at {field}: need {needed} bytes, only {available} available"
            ),
            Self::InvalidMagic => write!(f, "invalid DRB magic header"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported DRB version {v} (this build supports {DRB_VERSION})"
            ),
            Self::ChecksumMismatch { expected, actual } => write!(
                f,
                "DRB checksum mismatch: expected {expected}, computed {actual}"
            ),
            Self::InvalidUtf8(field) => write!(f, "invalid UTF-8 string in DRB {field}"),
            Self::InvalidInterval(reason) => write!(f, "invalid interval in DRB: {reason}"),
            Self::InvalidPrefix(reason) => write!(f, "invalid IP prefix in DRB: {reason}"),
            Self::ParseError(msg) => write!(f, "failed to parse rule text: {msg}"),
        }
    }
}

impl std::error::Error for DrbError {}

impl From<DrbError> for RoutingError {
    fn from(err: DrbError) -> Self {
        Self::new(err.to_string())
    }
}

/// A pre-compiled rule set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DrbSet {
    pub name: String,
    pub v4: Vec<(u32, u32)>,
    pub v6: Vec<(u128, u128)>,
    pub prefixes: Vec<IpNet>,
    pub domain_full: Vec<String>,
    pub domain_suffix: Vec<(String, SuffixScope)>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
}

/// Metadata summary of a DRB file, for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrbSummary {
    pub name: String,
    pub version: u32,
    pub created_at: u64,
    pub checksum: String,
    pub v4_intervals: usize,
    pub v6_intervals: usize,
    pub prefixes: usize,
    pub domain_full: usize,
    pub domain_suffix: usize,
    pub domain_keyword: usize,
    pub domain_regex: usize,
    pub total_domains: usize,
    pub file_size: usize,
}

impl DrbSet {
    /// Creates a new empty rule set with `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// True when the rule set holds neither IPs nor domain patterns.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty()
            && self.v6.is_empty()
            && self.prefixes.is_empty()
            && self.domain_full.is_empty()
            && self.domain_suffix.is_empty()
            && self.domain_keyword.is_empty()
            && self.domain_regex.is_empty()
    }

    /// Compiles a `DrbSet` directly from human-readable text rules.
    pub fn from_text(name: &str, source: &str) -> Result<Self, DrbError> {
        let mut set = Self::new(name);
        let mut raw_prefixes = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }
            // Strip trailing inline comments if present
            let content = if let Some(idx) = trimmed.find('#') {
                trimmed[..idx].trim()
            } else {
                trimmed
            };
            if content.is_empty() {
                continue;
            }

            if let Some(rest) = content.strip_prefix("name:") {
                set.name = rest.trim().to_owned();
                continue;
            }

            // 1. IP rule prefixes
            if let Some(val) = content
                .strip_prefix("ip:")
                .or_else(|| content.strip_prefix("dip:"))
                .or_else(|| content.strip_prefix("sip:"))
            {
                let prefix = parse_prefix(val.trim()).map_err(|e| {
                    DrbError::ParseError(format!("line {line_num}: invalid IP/CIDR '{val}': {e}"))
                })?;
                raw_prefixes.push(prefix);
                continue;
            }

            // 2. Domain patterns
            if let Some(val) = content
                .strip_prefix("domain:full:")
                .or_else(|| content.strip_prefix("full:"))
            {
                set.domain_full.push(val.trim().to_ascii_lowercase());
                continue;
            }
            if let Some(val) = content
                .strip_prefix("domain:keyword:")
                .or_else(|| content.strip_prefix("keyword:"))
            {
                set.domain_keyword.push(val.trim().to_ascii_lowercase());
                continue;
            }
            if let Some(val) = content
                .strip_prefix("domain:regex:")
                .or_else(|| content.strip_prefix("regex:"))
            {
                set.domain_regex.push(val.trim().to_owned());
                continue;
            }
            if let Some(val) = content
                .strip_prefix("domain:suffix:")
                .or_else(|| content.strip_prefix("suffix:"))
                .or_else(|| content.strip_prefix("domain:"))
            {
                let (bare, scope) = parse_suffix(val.trim());
                set.domain_suffix.push((bare, scope));
                continue;
            }

            // 3. Fallbacks: bare CIDR / IP address or bare domain
            if let Ok(prefix) = parse_prefix(content) {
                raw_prefixes.push(prefix);
            } else {
                // Treat as bare domain (suffix by default)
                let (bare, scope) = parse_suffix(content);
                set.domain_suffix.push((bare, scope));
            }
        }

        // Compile and merge intervals
        let (v4, v6) = compile_intervals(&raw_prefixes);
        set.v4 = v4;
        set.v6 = v6;
        set.prefixes = raw_prefixes;

        // Deduplicate domain patterns
        set.domain_full.sort_unstable();
        set.domain_full.dedup();
        set.domain_suffix.sort_unstable();
        set.domain_suffix.dedup();
        set.domain_keyword.sort_unstable();
        set.domain_keyword.dedup();
        set.domain_regex.sort_unstable();
        set.domain_regex.dedup();

        Ok(set)
    }

    /// Compiles a `DrbSet` from IP prefixes, merging intervals as a bake step.
    ///
    /// This is the constructor a producer uses ([`geodrb`] maps `.dat` entries onto it). It
    /// deliberately knows nothing about geodata types: `daer-routing` must not depend on the
    /// Protobuf reader that ADR-0014 retires (ADR-0015).
    ///
    /// [`geodrb`]: https://github.com/daeuniverse/geodrb
    #[must_use]
    pub fn from_prefixes(name: &str, prefixes: &[IpNet]) -> Self {
        let (v4, v6) = compile_intervals(prefixes);
        Self {
            name: name.to_owned(),
            v4,
            v6,
            prefixes: prefixes.to_vec(),
            domain_full: Vec::new(),
            domain_suffix: Vec::new(),
            domain_keyword: Vec::new(),
            domain_regex: Vec::new(),
        }
    }

    /// Compiles a `DrbSet` from domain patterns that a producer has already classified.
    ///
    /// `suffix` carries the scope, because `.example.com` and `example.com` are different
    /// predicates and collapsing them would widen a rule the operator narrowed on purpose.
    #[must_use]
    pub fn from_patterns(
        name: &str,
        full: Vec<String>,
        suffix: Vec<(String, SuffixScope)>,
        keyword: Vec<String>,
        regex: Vec<String>,
    ) -> Self {
        let mut set = Self::new(name);
        set.domain_full = normalize(full, |s: &String| s.to_ascii_lowercase());
        set.domain_suffix = normalize(suffix, |(pattern, _)| pattern.to_ascii_lowercase());
        set.domain_keyword = normalize(keyword, |s: &String| s.to_ascii_lowercase());
        // A regex keeps its case: lowercasing a character class changes what it matches.
        set.domain_regex = normalize(regex, String::clone);
        set
    }

    /// Serializes this rule set into DRB binary bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // 1. Name
        let name_bytes = self.name.as_bytes();
        payload.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        payload.extend_from_slice(name_bytes);

        // 2. IPv4 intervals
        payload.extend_from_slice(&(self.v4.len() as u32).to_le_bytes());
        for &(start, end) in &self.v4 {
            payload.extend_from_slice(&start.to_le_bytes());
            payload.extend_from_slice(&end.to_le_bytes());
        }

        // 3. IPv6 intervals
        payload.extend_from_slice(&(self.v6.len() as u32).to_le_bytes());
        for &(start, end) in &self.v6 {
            payload.extend_from_slice(&start.to_le_bytes());
            payload.extend_from_slice(&end.to_le_bytes());
        }

        // 4. Prefixes
        payload.extend_from_slice(&(self.prefixes.len() as u32).to_le_bytes());
        for prefix in &self.prefixes {
            match prefix {
                IpNet::V4(net) => {
                    payload.push(4);
                    payload.push(net.prefix_len());
                    payload.extend_from_slice(&net.addr().octets());
                }
                IpNet::V6(net) => {
                    payload.push(6);
                    payload.push(net.prefix_len());
                    payload.extend_from_slice(&net.addr().octets());
                }
            }
        }

        // 5. Domain Full
        payload.extend_from_slice(&(self.domain_full.len() as u32).to_le_bytes());
        for item in &self.domain_full {
            let b = item.as_bytes();
            payload.extend_from_slice(&(b.len() as u16).to_le_bytes());
            payload.extend_from_slice(b);
        }

        // 6. Domain Suffix
        payload.extend_from_slice(&(self.domain_suffix.len() as u32).to_le_bytes());
        for (item, scope) in &self.domain_suffix {
            let scope_byte = match scope {
                SuffixScope::SelfAndSubdomains => 0u8,
                SuffixScope::SubdomainsOnly => 1u8,
            };
            payload.push(scope_byte);
            let b = item.as_bytes();
            payload.extend_from_slice(&(b.len() as u16).to_le_bytes());
            payload.extend_from_slice(b);
        }

        // 7. Domain Keyword
        payload.extend_from_slice(&(self.domain_keyword.len() as u32).to_le_bytes());
        for item in &self.domain_keyword {
            let b = item.as_bytes();
            payload.extend_from_slice(&(b.len() as u16).to_le_bytes());
            payload.extend_from_slice(b);
        }

        // 8. Domain Regex
        payload.extend_from_slice(&(self.domain_regex.len() as u32).to_le_bytes());
        for item in &self.domain_regex {
            let b = item.as_bytes();
            payload.extend_from_slice(&(b.len() as u16).to_le_bytes());
            payload.extend_from_slice(b);
        }

        // Compute SHA-256 over payload
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let checksum: [u8; 32] = hasher.finalize().into();

        // Assemble Header
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut out = Vec::with_capacity(DRB_HEADER_SIZE + payload.len());
        out.extend_from_slice(DRB_MAGIC);
        out.extend_from_slice(&DRB_VERSION.to_le_bytes());
        out.extend_from_slice(&7u32.to_le_bytes()); // section count
        out.extend_from_slice(&now.to_le_bytes());
        out.extend_from_slice(&checksum);
        out.extend_from_slice(&payload);
        out
    }

    /// Deserializes and validates a DRB artifact from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DrbError> {
        if bytes.len() < DRB_HEADER_SIZE {
            return Err(DrbError::Truncated {
                field: "header",
                needed: DRB_HEADER_SIZE,
                available: bytes.len(),
            });
        }

        // 1. Magic
        if &bytes[0..8] != DRB_MAGIC {
            return Err(DrbError::InvalidMagic);
        }

        // 2. Version
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != DRB_VERSION {
            return Err(DrbError::UnsupportedVersion(version));
        }

        // 3. Section count (bytes 12..16) and timestamp (bytes 16..24)
        let _sections = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let _timestamp = u64::from_le_bytes(bytes[16..24].try_into().unwrap());

        // 4. Checksum verification
        let expected_checksum: [u8; 32] = bytes[24..56].try_into().unwrap();
        let payload = &bytes[DRB_HEADER_SIZE..];

        let mut hasher = Sha256::new();
        hasher.update(payload);
        let actual_checksum: [u8; 32] = hasher.finalize().into();

        if expected_checksum != actual_checksum {
            return Err(DrbError::ChecksumMismatch {
                expected: hex::encode(expected_checksum),
                actual: hex::encode(actual_checksum),
            });
        }

        // 5. Decode payload
        let mut cur = payload;

        // Name
        let name_len = read_u16(&mut cur, "name_len")? as usize;
        let name_bytes = read_slice(&mut cur, name_len, "name")?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| DrbError::InvalidUtf8("name"))?
            .to_owned();

        // IPv4 intervals
        let v4_count = read_u32(&mut cur, "v4_count")? as usize;
        let mut v4 = Vec::with_capacity(v4_count);
        for _ in 0..v4_count {
            let start = read_u32(&mut cur, "v4_interval.start")?;
            let end = read_u32(&mut cur, "v4_interval.end")?;
            if start > end {
                return Err(DrbError::InvalidInterval("IPv4 start > end"));
            }
            v4.push((start, end));
        }

        // IPv6 intervals
        let v6_count = read_u32(&mut cur, "v6_count")? as usize;
        let mut v6 = Vec::with_capacity(v6_count);
        for _ in 0..v6_count {
            let start = read_u128(&mut cur, "v6_interval.start")?;
            let end = read_u128(&mut cur, "v6_interval.end")?;
            if start > end {
                return Err(DrbError::InvalidInterval("IPv6 start > end"));
            }
            v6.push((start, end));
        }

        // Prefixes
        let prefix_count = read_u32(&mut cur, "prefix_count")? as usize;
        let mut prefixes = Vec::with_capacity(prefix_count);
        for _ in 0..prefix_count {
            let kind = read_u8(&mut cur, "prefix.kind")?;
            let prefix_len = read_u8(&mut cur, "prefix.len")?;
            match kind {
                4 => {
                    let addr_bytes = read_slice(&mut cur, 4, "ipv4_addr")?;
                    let octets: [u8; 4] = addr_bytes.try_into().unwrap();
                    let net = ipnet::Ipv4Net::new(Ipv4Addr::from(octets), prefix_len)
                        .map_err(|_| DrbError::InvalidPrefix("invalid ipv4 prefix length"))?;
                    prefixes.push(IpNet::V4(net));
                }
                6 => {
                    let addr_bytes = read_slice(&mut cur, 16, "ipv6_addr")?;
                    let octets: [u8; 16] = addr_bytes.try_into().unwrap();
                    let net = ipnet::Ipv6Net::new(Ipv6Addr::from(octets), prefix_len)
                        .map_err(|_| DrbError::InvalidPrefix("invalid ipv6 prefix length"))?;
                    prefixes.push(IpNet::V6(net));
                }
                _other => return Err(DrbError::InvalidPrefix("unknown IP version in prefix")),
            }
        }

        // Domain Full
        let full_count = read_u32(&mut cur, "domain_full_count")? as usize;
        let mut domain_full = Vec::with_capacity(full_count);
        for _ in 0..full_count {
            let len = read_u16(&mut cur, "domain_full.len")? as usize;
            let b = read_slice(&mut cur, len, "domain_full")?;
            domain_full.push(
                std::str::from_utf8(b)
                    .map_err(|_| DrbError::InvalidUtf8("domain_full"))?
                    .to_owned(),
            );
        }

        // Domain Suffix
        let suffix_count = read_u32(&mut cur, "domain_suffix_count")? as usize;
        let mut domain_suffix = Vec::with_capacity(suffix_count);
        for _ in 0..suffix_count {
            let scope_b = read_u8(&mut cur, "domain_suffix.scope")?;
            let scope = match scope_b {
                0 => SuffixScope::SelfAndSubdomains,
                1 => SuffixScope::SubdomainsOnly,
                _ => return Err(DrbError::ParseError("invalid suffix scope".to_owned())),
            };
            let len = read_u16(&mut cur, "domain_suffix.len")? as usize;
            let b = read_slice(&mut cur, len, "domain_suffix")?;
            domain_suffix.push((
                std::str::from_utf8(b)
                    .map_err(|_| DrbError::InvalidUtf8("domain_suffix"))?
                    .to_owned(),
                scope,
            ));
        }

        // Domain Keyword
        let keyword_count = read_u32(&mut cur, "domain_keyword_count")? as usize;
        let mut domain_keyword = Vec::with_capacity(keyword_count);
        for _ in 0..keyword_count {
            let len = read_u16(&mut cur, "domain_keyword.len")? as usize;
            let b = read_slice(&mut cur, len, "domain_keyword")?;
            domain_keyword.push(
                std::str::from_utf8(b)
                    .map_err(|_| DrbError::InvalidUtf8("domain_keyword"))?
                    .to_owned(),
            );
        }

        // Domain Regex
        let regex_count = read_u32(&mut cur, "domain_regex_count")? as usize;
        let mut domain_regex = Vec::with_capacity(regex_count);
        for _ in 0..regex_count {
            let len = read_u16(&mut cur, "domain_regex.len")? as usize;
            let b = read_slice(&mut cur, len, "domain_regex")?;
            domain_regex.push(
                std::str::from_utf8(b)
                    .map_err(|_| DrbError::InvalidUtf8("domain_regex"))?
                    .to_owned(),
            );
        }

        Ok(Self {
            name,
            v4,
            v6,
            prefixes,
            domain_full,
            domain_suffix,
            domain_keyword,
            domain_regex,
        })
    }

    /// Inspects bytes and produces a summary without holding the entire collection in memory.
    pub fn inspect_bytes(bytes: &[u8]) -> Result<DrbSummary, DrbError> {
        if bytes.len() < DRB_HEADER_SIZE {
            return Err(DrbError::Truncated {
                field: "header",
                needed: DRB_HEADER_SIZE,
                available: bytes.len(),
            });
        }
        let set = Self::decode(bytes)?;
        let total_domains = set.domain_full.len()
            + set.domain_suffix.len()
            + set.domain_keyword.len()
            + set.domain_regex.len();

        let timestamp = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let checksum_bytes: [u8; 32] = bytes[24..56].try_into().unwrap();

        Ok(DrbSummary {
            name: set.name,
            version: DRB_VERSION,
            created_at: timestamp,
            checksum: hex::encode(checksum_bytes),
            v4_intervals: set.v4.len(),
            v6_intervals: set.v6.len(),
            prefixes: set.prefixes.len(),
            domain_full: set.domain_full.len(),
            domain_suffix: set.domain_suffix.len(),
            domain_keyword: set.domain_keyword.len(),
            domain_regex: set.domain_regex.len(),
            total_domains,
            file_size: bytes.len(),
        })
    }

    /// Builds an [`IpIndex`] directly from pre-merged intervals.
    pub fn to_ip_index(&self) -> Option<IpIndex> {
        if self.v4.is_empty() && self.v6.is_empty() && self.prefixes.is_empty() {
            None
        } else {
            Some(IpIndex::from_merged(
                self.v4.clone(),
                self.v6.clone(),
                self.prefixes.clone(),
            ))
        }
    }

    /// Builds a [`DomainIndex`] directly from pre-classified domain patterns.
    pub fn to_domain_index(&self) -> Option<DomainIndex> {
        if self.domain_full.is_empty()
            && self.domain_suffix.is_empty()
            && self.domain_keyword.is_empty()
            && self.domain_regex.is_empty()
        {
            None
        } else {
            Some(DomainIndex::from_composite(
                &self.domain_full,
                &self.domain_suffix,
                &self.domain_keyword,
                &self.domain_regex,
            ))
        }
    }

    /// Lowers this rule set into [`MatchSet`]s.
    ///
    /// If both IP and Domain predicates exist, IP is connected via `LogicalOr` to Domain,
    /// so that traffic matching either operand satisfies the rule.
    pub fn to_match_sets(&self, target: &MatchTarget, negated: bool) -> Vec<MatchSet> {
        let mut sets = Vec::new();
        let ip_idx = self.to_ip_index();
        let dom_idx = self.to_domain_index();

        match (ip_idx, dom_idx) {
            (Some(ip), Some(dom)) => {
                sets.push(MatchSet {
                    value: MatchValue::IpSet(ip),
                    target: MatchTarget::logical_or(target.mark(), target.must()),
                    negated,
                });
                sets.push(MatchSet {
                    value: MatchValue::Domain(dom),
                    target: target.clone(),
                    negated,
                });
            }
            (Some(ip), None) => {
                sets.push(MatchSet {
                    value: MatchValue::IpSet(ip),
                    target: target.clone(),
                    negated,
                });
            }
            (None, Some(dom)) => {
                sets.push(MatchSet {
                    value: MatchValue::Domain(dom),
                    target: target.clone(),
                    negated,
                });
            }
            (None, None) => {}
        }
        sets
    }
}

/// A read-only pool of preloaded `DrbSet`s, indexed by tag.
#[derive(Debug, Clone, Default)]
pub struct RuleProviderPool {
    providers: std::collections::HashMap<String, Arc<DrbSet>>,
}

impl RuleProviderPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tag: impl Into<String>, set: DrbSet) {
        self.providers.insert(tag.into(), Arc::new(set));
    }

    pub fn get(&self, tag: &str) -> Option<&Arc<DrbSet>> {
        self.providers.get(tag)
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.providers.contains_key(tag)
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Arc<DrbSet>)> {
        self.providers.iter()
    }
}

// Helpers for decoding

fn read_u8(cur: &mut &[u8], field: &'static str) -> Result<u8, DrbError> {
    if cur.is_empty() {
        return Err(DrbError::Truncated {
            field,
            needed: 1,
            available: 0,
        });
    }
    let val = cur[0];
    *cur = &cur[1..];
    Ok(val)
}

fn read_u16(cur: &mut &[u8], field: &'static str) -> Result<u16, DrbError> {
    if cur.len() < 2 {
        return Err(DrbError::Truncated {
            field,
            needed: 2,
            available: cur.len(),
        });
    }
    let val = u16::from_le_bytes(cur[0..2].try_into().unwrap());
    *cur = &cur[2..];
    Ok(val)
}

fn read_u32(cur: &mut &[u8], field: &'static str) -> Result<u32, DrbError> {
    if cur.len() < 4 {
        return Err(DrbError::Truncated {
            field,
            needed: 4,
            available: cur.len(),
        });
    }
    let val = u32::from_le_bytes(cur[0..4].try_into().unwrap());
    *cur = &cur[4..];
    Ok(val)
}

fn read_u128(cur: &mut &[u8], field: &'static str) -> Result<u128, DrbError> {
    if cur.len() < 16 {
        return Err(DrbError::Truncated {
            field,
            needed: 16,
            available: cur.len(),
        });
    }
    let val = u128::from_le_bytes(cur[0..16].try_into().unwrap());
    *cur = &cur[16..];
    Ok(val)
}

fn read_slice<'a>(
    cur: &mut &'a [u8],
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], DrbError> {
    if cur.len() < len {
        return Err(DrbError::Truncated {
            field,
            needed: len,
            available: cur.len(),
        });
    }
    let slice = &cur[..len];
    *cur = &cur[len..];
    Ok(slice)
}

fn parse_prefix(val: &str) -> Result<IpNet, DrbError> {
    if let Ok(net) = IpNet::from_str(val) {
        return Ok(net);
    }
    if let Ok(addr) = IpAddr::from_str(val) {
        return Ok(match addr {
            IpAddr::V4(a) => IpNet::V4(ipnet::Ipv4Net::new(a, 32).unwrap()),
            IpAddr::V6(a) => IpNet::V6(ipnet::Ipv6Net::new(a, 128).unwrap()),
        });
    }
    Err(DrbError::InvalidPrefix("not an IP or CIDR"))
}

fn parse_suffix(val: &str) -> (String, SuffixScope) {
    let lowered = val.to_ascii_lowercase();
    if let Some(bare) = lowered.strip_prefix('.') {
        (bare.to_owned(), SuffixScope::SubdomainsOnly)
    } else if let Some(bare) = lowered.strip_prefix('+') {
        (bare.to_owned(), SuffixScope::SelfAndSubdomains)
    } else {
        (lowered, SuffixScope::SelfAndSubdomains)
    }
}

/// Canonicalises one pattern collection: trim, map, sort, dedupe.
///
/// Sorting and deduplication are part of the artifact's identity, not a nicety: two inputs that
/// name the same pattern set in a different order must produce byte-identical DRB files, or a
/// content hash cannot be used to decide whether a provider changed.
fn normalize<T, K>(items: Vec<T>, mut key: impl FnMut(&T) -> K) -> Vec<T>
where
    K: Ord,
{
    let mut keyed: Vec<(K, T)> = items.into_iter().map(|item| (key(&item), item)).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    keyed.into_iter().map(|(_, item)| item).collect()
}

type CompiledIntervals = (Vec<(u32, u32)>, Vec<(u128, u128)>);

fn compile_intervals(prefixes: &[IpNet]) -> CompiledIntervals {
    let mut v4_ranges = Vec::new();
    let mut v6_ranges = Vec::new();

    for prefix in prefixes {
        match prefix {
            IpNet::V4(net) => {
                let length = net.prefix_len();
                let host_bits = 32u32.saturating_sub(u32::from(length));
                let base = u32::from(net.addr()) & mask_u32(host_bits);
                let end = base | low_mask_u32(host_bits);
                v4_ranges.push((base, end));
            }
            IpNet::V6(net) => {
                let length = net.prefix_len();
                let host_bits = 128u32.saturating_sub(u32::from(length));
                let base = u128::from(net.addr()) & mask_u128(host_bits);
                let end = base | low_mask_u128(host_bits);
                v6_ranges.push((base, end));
            }
        }
    }

    (merge_ranges(v4_ranges), merge_ranges(v6_ranges))
}

fn mask_u32(host_bits: u32) -> u32 {
    if host_bits >= 32 {
        0
    } else {
        !0u32 << host_bits
    }
}

fn low_mask_u32(host_bits: u32) -> u32 {
    if host_bits >= 32 {
        !0u32
    } else {
        (1u32 << host_bits).wrapping_sub(1)
    }
}

fn mask_u128(host_bits: u32) -> u128 {
    if host_bits >= 128 {
        0
    } else {
        !0u128 << host_bits
    }
}

fn low_mask_u128(host_bits: u32) -> u128 {
    if host_bits >= 128 {
        !0u128
    } else {
        (1u128 << host_bits).wrapping_sub(1)
    }
}

fn merge_ranges<T: Ord + Copy + StepRange>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    if ranges.len() < 2 {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    let mut current = ranges[0];
    for (start, end) in ranges.into_iter().skip(1) {
        if start <= current.1 || current.1.succ().is_some_and(|next| start <= next) {
            if end > current.1 {
                current.1 = end;
            }
        } else {
            merged.push(current);
            current = (start, end);
        }
    }
    merged.push(current);
    merged
}

trait StepRange: Sized {
    fn succ(&self) -> Option<Self>;
}

impl StepRange for u32 {
    fn succ(&self) -> Option<Self> {
        self.checked_add(1)
    }
}

impl StepRange for u128 {
    fn succ(&self) -> Option<Self> {
        self.checked_add(1)
    }
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let mut s = String::with_capacity(bytes.as_ref().len() * 2);
        for &b in bytes.as_ref() {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drb_roundtrip_encode_decode() {
        let text = r#"
            # Direct intranet & bypass rules
            name: custom-bypass
            ip: 192.168.1.0/24
            ip: 192.168.2.0/24
            10.0.0.1
            full: api.internal.local
            suffix: example.com
            .sub.example.com
            keyword: local-gw
            regex: ^.*\.lan$
        "#;

        let set = DrbSet::from_text("custom-bypass", text).expect("text parses");
        assert_eq!(set.name, "custom-bypass");
        assert_eq!(set.domain_full, vec!["api.internal.local"]);
        assert_eq!(set.domain_keyword, vec!["local-gw"]);
        assert_eq!(set.domain_regex, vec!["^.*\\.lan$"]);
        assert!(set.domain_suffix.iter().any(|(s, _)| s == "example.com"));

        let bytes = set.encode();
        assert!(bytes.len() > DRB_HEADER_SIZE);

        let decoded = DrbSet::decode(&bytes).expect("decodes successfully");
        assert_eq!(set, decoded);
    }

    #[test]
    fn drb_fails_on_corrupted_checksum() {
        let set = DrbSet::from_text("test", "ip: 1.1.1.0/24\nexample.com").unwrap();
        let mut bytes = set.encode();

        // Corrupt payload byte
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;

        let err = DrbSet::decode(&bytes).expect_err("must fail on checksum mismatch");
        assert!(matches!(err, DrbError::ChecksumMismatch { .. }));
    }

    #[test]
    fn drb_fails_on_invalid_magic() {
        let set = DrbSet::from_text("test", "ip: 1.1.1.0/24").unwrap();
        let mut bytes = set.encode();
        bytes[0] = b'X';
        let err = DrbSet::decode(&bytes).expect_err("must fail on invalid magic");
        assert_eq!(err, DrbError::InvalidMagic);
    }

    #[test]
    fn drb_to_match_sets_evaluates_correctly() {
        let text = "ip: 192.168.1.0/24\nsuffix: corp.internal";
        let set = DrbSet::from_text("corp", text).unwrap();
        let target = MatchTarget::Outbound(crate::outbound::Outbound::new("direct"));
        let sets = set.to_match_sets(&target, false);

        assert_eq!(sets.len(), 2);
        assert!(matches!(sets[0].value, MatchValue::IpSet(_)));
        assert!(matches!(sets[1].value, MatchValue::Domain(_)));

        // Test matching through matcher
        let mut facts = crate::matcher::MatchFacts {
            source_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dest_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
            source_port: 1234,
            dest_port: 80,
            l4proto: crate::values::L4ProtoMask::TCP,
            domain: None,
            process_name: crate::values::ProcessName::default(),
            dscp: 0,
            mac: daer_common::net::MacAddr([0; 6]),
        };

        // IP hit
        let hit = crate::matcher::first_hit(&sets, &facts);
        assert!(hit.is_some());
        assert_eq!(&*hit.unwrap().outbound.name, "direct");

        // Domain hit
        facts.dest_addr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        facts.domain = Some("portal.corp.internal");
        let hit = crate::matcher::first_hit(&sets, &facts);
        assert!(hit.is_some());
        assert_eq!(&*hit.unwrap().outbound.name, "direct");

        // Miss
        facts.domain = Some("other.com");
        let hit = crate::matcher::first_hit(&sets, &facts);
        assert!(hit.is_none());
    }
}
