// SPDX-License-Identifier: AGPL-3.0-only

//! daer Rule Binary (DRB v2) specification and engine (ADR-0031, ADR-0032).
//!
//! A `.drb` artifact is a compiled, immutable binary rule set with three sections:
//!
//! * **IPv4/IPv6 closed intervals** — sorted, merged, non-adjacent. Half the size of the
//!   retired CIDR-plus-interval pair, and `binary_search` over contiguous memory.
//! * **Domain table** — every pattern stored once, sorted by *reversed label order*, with the
//!   shared prefix front-coded away, plus a 64-entry rank index that narrows the search to a
//!   contiguous span. Reverse-label sorting is what makes both properties true at once: a
//!   suffix rule sits next to the names it covers, so a scan of the span answers
//!   `example.com` for `www.example.com` by walking left until the key no longer matches.
//!
//! # Why not a radix trie
//!
//! An earlier revision stored a 16-byte node per label. Measured on the published corpus it
//! produced 110,448 nodes for 110,189 rules — a node-to-rule ratio of 1.002, i.e. **no node
//! sharing at all** — and the artifact grew 61% larger than the format it replaced. The labels
//! are mostly unique, so a tree pays per-label overhead to represent what is really a flat list.
//! Front-coding the same list removes 24% instead. See ADR-0032.
//!
//! # Cost model this file is written against
//!
//! Domain matching runs **once per connection** in the userspace evaluator (the datapath
//! defers any rule containing a `domain(...)` predicate, so eBPF never matches names). The
//! binding constraint is therefore artifact size — every client re-downloads these daily — not
//! per-lookup nanoseconds. The lookup below is a short linear walk over one contiguous span; it
//! is allocation-free and cache-resident, which is the right shape for a once-per-connection cost.
//!
//! # Invariants
//! * `[INV-DRB-01]`: decoding merges no intervals and mutates no pattern.
//! * `[INV-DRB-02]`: byte-for-byte deterministic; identical rules produce identical files.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use daer_rule_ast::{DomainPattern, DomainRule, RuleSet};
use sha2::{Digest, Sha256};

use crate::domain::{DomainTable, SuffixScope};
use crate::error::RoutingError;
use crate::ipset::IpIndex;
use crate::matcher::{MatchSet, MatchValue};
use crate::outbound::MatchTarget;

/// Fixed 8-byte magic for DRB v2 artifacts.
pub const DRB_MAGIC: &[u8; 8] = b"DAERDRB2";

/// DRB format version implemented by this build.
pub const DRB_VERSION: u32 = 2;

/// Fixed header size: exactly 128 bytes (two 64-byte cache lines).
pub const DRB_HEADER_SIZE: usize = 128;

/// A DRB artifact that could not be read.
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
    InvalidLayout(&'static str),
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
            Self::InvalidMagic => write!(
                f,
                "invalid DRB magic header (this build reads DRB v2, b\"DAERDRB2\")"
            ),
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
            Self::InvalidLayout(reason) => write!(f, "invalid DRB layout: {reason}"),
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

/// One domain pattern in a flags byte.
pub mod domain_flags {
    /// Matches the name exactly.
    pub const FULL: u8 = 0x01;
    /// Matches the name and every subdomain (`suffix: example.com`).
    pub const SUFFIX_SELF_AND_SUB: u8 = 0x02;
    /// Matches subdomains only (`suffix: .example.com`).
    pub const SUFFIX_SUB_ONLY: u8 = 0x04;
}

/// A decoded DRB v2 rule set.
///
/// The domain table is kept in its encoded form and interpreted in place: there is one
/// allocation per section, no per-pattern `String`, and no intermediate node array.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DrbSet {
    pub name: String,
    pub v4_intervals: Vec<(u32, u32)>,
    pub v6_intervals: Vec<(u128, u128)>,
    /// The domain rules, in the one flat table everything shares (ADR-0033).
    domains: DomainTable,
}

/// Metadata summary of a DRB file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrbSummary {
    pub name: String,
    pub version: u32,
    pub checksum: String,
    pub v4_intervals: usize,
    pub v6_intervals: usize,
    pub domain_patterns: usize,
    pub file_size: usize,
}

/// Returns a range inside the artifact's payload, refusing offsets that point into the
/// header or past the end of the file.
///
/// A `.drb` artifact is downloaded from a provider, so every offset and count in its header
/// is untrusted input. The checksum covers the payload only, which means it cannot protect the
/// header itself; without this check a corrupted offset is a panic in the daemon rather than a
/// rejected rule set.
fn payload_slice<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    field: &'static str,
) -> Result<&'a [u8], DrbError> {
    let Some(payload) = bytes.get(DRB_HEADER_SIZE..) else {
        return Err(DrbError::Truncated {
            field,
            needed: DRB_HEADER_SIZE,
            available: bytes.len(),
        });
    };
    let Some(start) = offset.checked_sub(DRB_HEADER_SIZE) else {
        return Err(DrbError::InvalidLayout(field));
    };
    let Some(end) = start.checked_add(length) else {
        return Err(DrbError::InvalidLayout(field));
    };
    payload.get(start..end).ok_or(DrbError::Truncated {
        field,
        needed: length,
        available: payload.len().saturating_sub(start),
    })
}

impl DrbSet {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            v4_intervals: Vec::new(),
            v6_intervals: Vec::new(),
            domains: DomainTable::default(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4_intervals.is_empty() && self.v6_intervals.is_empty() && self.domains.is_empty()
    }

    /// How many domain keys the set holds (after coverage pruning).
    #[must_use]
    pub fn domain_patterns(&self) -> usize {
        self.domains.len()
    }

    /// Compiles a `DrbSet` directly from Canonical Rule Source text.
    pub fn from_text(name: &str, source: &str) -> Result<Self, DrbError> {
        let mut rules =
            RuleSet::parse(source).map_err(|err| DrbError::ParseError(err.to_string()))?;
        if !name.is_empty() {
            rules.set_name(name);
        }
        Ok(Self::from_rule_set(&rules))
    }

    /// Compiles a `DrbSet` from the neutral rule set. This is the only writer entry point.
    #[must_use]
    pub fn from_rule_set(rules: &RuleSet) -> Self {
        let mut set = Self::new(rules.name());
        set.v4_intervals = rules.v4_intervals().to_vec();
        set.v6_intervals = rules.v6_intervals().to_vec();
        set.build_domain_table(rules.domains());
        set
    }

    fn build_domain_table(&mut self, domains: &[DomainRule]) {
        let entries: Vec<(String, u8)> = domains
            .iter()
            .map(|rule| {
                let flag = match &rule.pattern {
                    DomainPattern::Full(_) => domain_flags::FULL,
                    DomainPattern::Suffix(_, SuffixScope::SelfAndSubdomains) => {
                        domain_flags::SUFFIX_SELF_AND_SUB
                    }
                    DomainPattern::Suffix(_, SuffixScope::SubdomainsOnly) => {
                        domain_flags::SUFFIX_SUB_ONLY
                    }
                };
                (rule.pattern.value().to_owned(), flag)
            })
            .collect();
        self.domains = DomainTable::from_classified(entries);
    }

    /// Serializes this rule set into the deterministic DRB v2 binary format.
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // 1. IPv4 intervals
        let v4_offset = DRB_HEADER_SIZE as u32;
        let v4_count = self.v4_intervals.len() as u32;
        for &(start, end) in &self.v4_intervals {
            payload.extend_from_slice(&start.to_le_bytes());
            payload.extend_from_slice(&end.to_le_bytes());
        }

        // 2. IPv6 intervals (16-byte aligned)
        pad_to_16(&mut payload);
        let v6_offset = (DRB_HEADER_SIZE + payload.len()) as u32;
        let v6_count = self.v6_intervals.len() as u32;
        for &(start, end) in &self.v6_intervals {
            payload.extend_from_slice(&start.to_le_bytes());
            payload.extend_from_slice(&end.to_le_bytes());
        }

        // 3. Domain table: front-coded records
        pad_to_16(&mut payload);
        let domain_offset = (DRB_HEADER_SIZE + payload.len()) as u32;
        let (record_bytes, domain_count) = self.domains.encode_records();
        let records_bytes = record_bytes.len() as u32;
        payload.extend_from_slice(&record_bytes);

        // 4. Name pool
        let name_offset = (DRB_HEADER_SIZE + payload.len()) as u32;
        let name_len = self.name.len() as u32;
        payload.extend_from_slice(self.name.as_bytes());

        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let checksum: [u8; 32] = hasher.finalize().into();

        let mut header = [0u8; DRB_HEADER_SIZE];
        header[0..8].copy_from_slice(DRB_MAGIC);
        header[8..12].copy_from_slice(&DRB_VERSION.to_le_bytes());

        let mut flags = 0u32;
        if v4_count > 0 {
            flags |= 0x01;
        }
        if v6_count > 0 {
            flags |= 0x02;
        }
        if domain_count > 0 {
            flags |= 0x04;
        }
        header[12..16].copy_from_slice(&flags.to_le_bytes());

        header[16..20].copy_from_slice(&v4_offset.to_le_bytes());
        header[20..24].copy_from_slice(&v4_count.to_le_bytes());
        header[24..28].copy_from_slice(&v6_offset.to_le_bytes());
        header[28..32].copy_from_slice(&v6_count.to_le_bytes());
        header[32..36].copy_from_slice(&domain_offset.to_le_bytes());
        header[36..40].copy_from_slice(&domain_count.to_le_bytes());
        header[40..44].copy_from_slice(&records_bytes.to_le_bytes());
        header[44..48].copy_from_slice(&name_offset.to_le_bytes());
        header[48..52].copy_from_slice(&name_len.to_le_bytes());
        header[64..96].copy_from_slice(&checksum);

        let mut out = Vec::with_capacity(DRB_HEADER_SIZE + payload.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&payload);
        out
    }

    /// Deserializes a DRB v2 artifact.
    pub fn decode(bytes: &[u8]) -> Result<Self, DrbError> {
        if bytes.len() < DRB_HEADER_SIZE {
            return Err(DrbError::Truncated {
                field: "header",
                needed: DRB_HEADER_SIZE,
                available: bytes.len(),
            });
        }
        if &bytes[0..8] != DRB_MAGIC {
            return Err(DrbError::InvalidMagic);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != DRB_VERSION {
            return Err(DrbError::UnsupportedVersion(version));
        }

        let v4_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let v4_count = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        let v6_offset = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        let v6_count = u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
        let domain_offset = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
        let domain_count = u32::from_le_bytes(bytes[36..40].try_into().unwrap()) as usize;
        let records_bytes = u32::from_le_bytes(bytes[40..44].try_into().unwrap()) as usize;
        let name_offset = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(bytes[48..52].try_into().unwrap()) as usize;

        let expected: [u8; 32] = bytes[64..96].try_into().unwrap();
        let payload = &bytes[DRB_HEADER_SIZE..];
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let actual: [u8; 32] = hasher.finalize().into();
        if expected != actual {
            return Err(DrbError::ChecksumMismatch {
                expected: hex::encode(expected),
                actual: hex::encode(actual),
            });
        }

        let name = payload_slice(bytes, name_offset, name_len, "name")?;
        let name = std::str::from_utf8(name)
            .map_err(|_| DrbError::InvalidUtf8("name"))?
            .to_owned();

        let v4_bytes = v4_count
            .checked_mul(8)
            .ok_or(DrbError::InvalidLayout("IPv4 interval count overflows"))?;
        let mut v4_intervals = Vec::with_capacity(v4_count);
        let mut cur = payload_slice(bytes, v4_offset, v4_bytes, "IPv4 intervals")?;
        for _ in 0..v4_count {
            let start = u32::from_le_bytes(cur[0..4].try_into().unwrap());
            let end = u32::from_le_bytes(cur[4..8].try_into().unwrap());
            cur = &cur[8..];
            if start > end {
                return Err(DrbError::InvalidInterval("IPv4 start > end"));
            }
            v4_intervals.push((start, end));
        }

        let v6_bytes = v6_count
            .checked_mul(32)
            .ok_or(DrbError::InvalidLayout("IPv6 interval count overflows"))?;
        let mut v6_intervals = Vec::with_capacity(v6_count);
        let mut cur = payload_slice(bytes, v6_offset, v6_bytes, "IPv6 intervals")?;
        for _ in 0..v6_count {
            let start = u128::from_le_bytes(cur[0..16].try_into().unwrap());
            let end = u128::from_le_bytes(cur[16..32].try_into().unwrap());
            cur = &cur[32..];
            if start > end {
                return Err(DrbError::InvalidInterval("IPv6 start > end"));
            }
            v6_intervals.push((start, end));
        }

        let records = payload_slice(bytes, domain_offset, records_bytes, "domain records")?;
        let domains = DomainTable::decode_records(records, domain_count)?;

        Ok(Self {
            name,
            v4_intervals,
            v6_intervals,
            domains,
        })
    }

    /// Verifies and summarises an artifact without building the set.
    pub fn inspect_bytes(bytes: &[u8]) -> Result<DrbSummary, DrbError> {
        let set = Self::decode(bytes)?;
        let checksum: [u8; 32] = bytes[64..96].try_into().unwrap();
        Ok(DrbSummary {
            name: set.name,
            version: DRB_VERSION,
            checksum: hex::encode(checksum),
            v4_intervals: set.v4_intervals.len(),
            v6_intervals: set.v6_intervals.len(),
            domain_patterns: set.domains.len(),
            file_size: bytes.len(),
        })
    }

    /// Converts back into the neutral rule set, so a release is auditable and re-compilable.
    #[must_use]
    pub fn to_rule_set(&self) -> RuleSet {
        let mut rules = RuleSet::new(&self.name);
        for &(start, end) in &self.v4_intervals {
            rules.push_v4_range(start, end);
        }
        for &(start, end) in &self.v6_intervals {
            rules.push_v6_range(start, end);
        }
        for (value, scope) in self.domains.iter_rules() {
            let pattern = match scope {
                None => DomainPattern::Full(value),
                Some(scope) => DomainPattern::Suffix(value, scope),
            };
            rules.push_domain(DomainRule::new(pattern));
        }
        let fallback = rules.clone();
        rules.canonical().unwrap_or(fallback)
    }

    /// True when `addr` falls inside any interval in this set.
    #[must_use]
    pub fn contains_ip(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.contains_v4(u32::from(v4)),
            IpAddr::V6(v6) => {
                if let Some(mapped) = v6.to_ipv4_mapped()
                    && self.contains_v4(u32::from(mapped))
                {
                    return true;
                }
                self.contains_v6(u128::from(v6))
            }
        }
    }

    #[must_use]
    pub fn contains_v4(&self, target: u32) -> bool {
        let index = self
            .v4_intervals
            .partition_point(|&(start, _)| start <= target);
        index > 0 && target <= self.v4_intervals[index - 1].1
    }

    #[must_use]
    pub fn contains_v6(&self, target: u128) -> bool {
        let index = self
            .v6_intervals
            .partition_point(|&(start, _)| start <= target);
        index > 0 && target <= self.v6_intervals[index - 1].1
    }

    /// True when `domain` matches a rule in this set.
    ///
    /// The name is rewritten to reversed-label form, then each of its *label-boundary prefixes*
    /// (`com`, `com.example`, `com.example.www` for `www.example.com`) is binary-searched in the
    /// sorted table. Those prefixes are exactly the suffixes that could cover the name, so the
    /// search is `O(depth · log n)` over contiguous memory, allocation-free — and a miss costs
    /// the same as a hit instead of walking every engine the way a four-way dispatcher did.
    ///
    /// The work happens in [`DomainTable::matches`]; this is the artifact's entry point.
    #[must_use]
    pub fn matches_domain(&self, domain: &str) -> bool {
        self.domains.matches(domain)
    }

    /// Builds an [`IpIndex`], deriving the CIDR form kernel LPM needs on demand.
    pub fn to_ip_index(&self) -> Option<IpIndex> {
        if self.v4_intervals.is_empty() && self.v6_intervals.is_empty() {
            None
        } else {
            Some(IpIndex::from_intervals(
                self.v4_intervals.clone(),
                self.v6_intervals.clone(),
            ))
        }
    }

    /// The domain table, for the evaluator to match names against directly.
    ///
    /// One domain structure serves the whole process (ADR-0033): the artifact decodes into it, a
    /// config's inline `domain(...)` compiles into it, and the evaluator queries it directly.
    /// No per-generation rebuild, and no second structure to keep in agreement.
    #[must_use]
    pub fn domains(&self) -> &DomainTable {
        &self.domains
    }

    /// Lowers into [`MatchSet`]s. IP and domain both present means either satisfies the rule.
    pub fn to_match_sets(&self, target: &MatchTarget, negated: bool) -> Vec<MatchSet> {
        let mut sets = Vec::new();
        let ip_index = self.to_ip_index();
        let has_domain = !self.domains.is_empty();

        match (ip_index, has_domain) {
            (Some(ip), true) => {
                sets.push(MatchSet {
                    value: MatchValue::IpSet(ip),
                    target: MatchTarget::logical_or(target.mark(), target.must()),
                    negated,
                });
                sets.push(MatchSet {
                    value: MatchValue::Domain(self.domains.clone()),
                    target: target.clone(),
                    negated,
                });
            }
            (Some(ip), false) => sets.push(MatchSet {
                value: MatchValue::IpSet(ip),
                target: target.clone(),
                negated,
            }),
            (None, true) => sets.push(MatchSet {
                value: MatchValue::Domain(self.domains.clone()),
                target: target.clone(),
                negated,
            }),
            (None, false) => {}
        }
        sets
    }
}

fn pad_to_16(vec: &mut Vec<u8>) {
    let remainder = vec.len() % 16;
    if remainder != 0 {
        vec.extend(std::iter::repeat_n(0, 16 - remainder));
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
    fn round_trips_intervals_and_domains() {
        let text = "name: corp\n\
                    ip: 192.168.1.0/24\n\
                    ip: 10.0.0.1\n\
                    =api.internal.local\n\
                    example.com\n\
                    .sub.example.com\n";
        let set = DrbSet::from_text("corp", text).expect("parses");
        let bytes = set.encode();
        let decoded = DrbSet::decode(&bytes).expect("decodes");
        assert_eq!(set, decoded);
    }

    #[test]
    fn an_enclosing_suffix_absorbs_the_names_it_covers() {
        // `example.com` already answers all three; storing them would be dead weight.
        let set = DrbSet::from_text("t", "example.com\n=a.example.com\nb.example.com\n").unwrap();
        assert_eq!(
            set.domain_patterns(),
            1,
            "patterns under a covering suffix must be dropped: {:?}",
            set.domains()
        );
        assert!(set.matches_domain("a.example.com"));
        assert!(set.matches_domain("b.example.com"));
    }

    #[test]
    fn a_subdomains_only_suffix_does_not_cover_the_bare_name() {
        let set = DrbSet::from_text("t", ".corp.example\n").unwrap();
        assert!(set.matches_domain("a.corp.example"));
        assert!(
            !set.matches_domain("corp.example"),
            "`.corp.example` must not match the bare name"
        );
    }

    #[test]
    fn lookups_agree_with_the_rules_that_produced_them() {
        let text = "name: t\n\
                    example.com\n\
                    .only-sub.example.org\n\
                    =exact.example.com\n";
        let set = DrbSet::from_text("t", text).unwrap();

        assert!(
            set.matches_domain("example.com"),
            "self-and-sub matches bare"
        );
        assert!(set.matches_domain("www.example.com"));
        assert!(set.matches_domain("a.b.example.com"));
        assert!(set.matches_domain("exact.example.com"), "= exact is stored");
        assert!(
            !set.matches_domain("only-sub.example.org"),
            "subdomains-only must not match the bare name"
        );
        assert!(set.matches_domain("x.only-sub.example.org"));
        assert!(!set.matches_domain("other.com"));
    }

    #[test]
    fn front_coding_survives_a_key_that_is_a_prefix_of_the_next() {
        // `com.a` and `com.ab` share three bytes; decoding must not confuse them.
        let set = DrbSet::from_text("t", "=a.com\n=ab.com\n=abc.com\n").unwrap();
        let decoded = DrbSet::decode(&set.encode()).unwrap();
        assert!(decoded.matches_domain("a.com"));
        assert!(decoded.matches_domain("ab.com"));
        assert!(decoded.matches_domain("abc.com"));
        assert!(!decoded.matches_domain("abcd.com"));
    }

    #[test]
    fn decoding_rejects_a_corrupted_checksum() {
        let set = DrbSet::from_text("t", "ip: 1.1.1.0/24\n").unwrap();
        let mut bytes = set.encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert!(matches!(
            DrbSet::decode(&bytes),
            Err(DrbError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn decoding_rejects_header_offsets_that_point_outside_the_payload() {
        // The checksum covers the payload, not the header. A provider can serve an artifact
        // whose offsets are corrupt even though the payload hash still matches, so every
        // header field must be bounds-checked before it is used as a slice index.
        let set = DrbSet::from_text("t", "ip: 1.1.1.0/24\nexample.com\n").unwrap();
        let encoded = set.encode();
        let header = |absolute: usize, value: u32| {
            let mut bytes = encoded.clone();
            bytes[absolute..absolute + 4].copy_from_slice(&value.to_le_bytes());
            bytes
        };

        // Offset into the fixed header is not a payload range.
        let bytes = header(16, 0);
        assert!(
            matches!(DrbSet::decode(&bytes), Err(DrbError::InvalidLayout(_))),
            "a v4 offset inside the header must be refused"
        );

        // Out-of-file offset and impossible count both fail closed.
        for (offset, value, field) in [
            (16, u32::MAX, "v4 offset"),
            (20, u32::MAX, "v4 count"),
            (24, u32::MAX, "v6 offset"),
            (32, u32::MAX, "domain offset"),
            (40, u32::MAX, "domain byte count"),
            (44, u32::MAX, "name offset"),
        ] {
            let bytes = header(offset, value);
            assert!(
                matches!(DrbSet::decode(&bytes), Err(DrbError::Truncated { .. })),
                "{field} must be rejected rather than used as a slice index"
            );
        }
    }

    #[test]
    fn decoding_rejects_a_v1_artifact() {
        let mut bytes = vec![0u8; DRB_HEADER_SIZE];
        bytes[0..8].copy_from_slice(b"DAER_DRB");
        assert!(matches!(
            DrbSet::decode(&bytes),
            Err(DrbError::InvalidMagic)
        ));
    }
}
