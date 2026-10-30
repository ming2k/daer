// SPDX-License-Identifier: AGPL-3.0-only

//! Domain pattern matching, compiled into indexes.
//!
//! Semantics (unchanged, and asserted by the tests below):
//!
//! * the queried name is lowercased and a trailing dot is removed;
//! * `full` is an exact match;
//! * `suffix` matches the name itself and any subdomain, but not
//!   `abcexample.com`; a pattern that starts with `.` matches subdomains only;
//! * `keyword` is a substring match;
//! * `regex` keeps its original case and is applied to the normalized name;
//! * patterns containing characters outside `[0-9a-z._^-]` are rejected for
//!   full/suffix/keyword, and broken regexes are rejected, instead of silently
//!   matching everything.
//!
//! # Why this is an index and not a list
//!
//! A `geosite:cn` expansion is ~110,000 domains. Evaluating that as a linear scan
//! per flow costs hundreds of microseconds, which is the difference between a
//! proxy that scales and one that does not. Each key therefore gets the structure
//! its semantics call for:
//!
//! | key | structure | cost per query |
//! | --- | --- | --- |
//! | `full` | hash set | one hash |
//! | `suffix` | pattern hash set + label walk | one hash per label (≤ ~5) |
//! | `keyword` | Aho–Corasick automaton | one pass, no allocation |
//! | `regex` | combined `RegexSet` | one pass over the alternation |
//!
//! The suffix walk is the important one to get right. A name matches a suffix
//! pattern iff one of its *label-boundary* suffixes is that pattern, so the query
//! is "does any of `a.b.example.com`, `b.example.com`, `example.com`, `com` appear
//! in the set?" — at most `labels + 1` lookups, independent of how many patterns
//! were compiled.
//!
//! Normalization is allocation-free for every name that fits a DNS name (≤255
//! bytes); the `String` fallback exists only so a hostile over-long input cannot
//! be silently truncated.

use std::collections::{HashMap, HashSet};

use aho_corasick::AhoCorasick;
use regex::RegexSet;

use crate::error::RoutingError;

/// Longest name we normalize on the stack. A DNS name is at most 255 bytes.
const STACK_DOMAIN_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DomainKey {
    Full,
    /// The default when a rule writes `domain(...)` without a key.
    #[default]
    Suffix,
    Keyword,
    Regex,
}

impl DomainKey {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Suffix => "suffix",
            Self::Keyword => "keyword",
            Self::Regex => "regex",
        }
    }

    /// Parses the key written in `domain(key: value)`.
    ///
    /// An empty or `domain` key means suffix only after the alias optimizer has
    /// run; lowering validates the authoritative spelling here, exactly like
    /// the Go registration callback.
    pub fn parse(key: &str) -> Result<Self, RoutingError> {
        match key {
            "full" => Ok(Self::Full),
            "suffix" => Ok(Self::Suffix),
            "keyword" => Ok(Self::Keyword),
            "regex" => Ok(Self::Regex),
            other => Err(RoutingError::new(format!(
                "addDomain: unsupported key: {other}"
            ))),
        }
    }
}

/// Whether a suffix pattern also matches the bare name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuffixScope {
    /// `example.com`: matches `example.com` and `a.example.com`.
    SelfAndSubdomains,
    /// `.example.com`: matches only `a.example.com`.
    SubdomainsOnly,
}

impl SuffixScope {
    /// The wider of two scopes. A key declared both ways matches both ways.
    fn widen(self, other: Self) -> Self {
        if self == Self::SelfAndSubdomains || other == Self::SelfAndSubdomains {
            Self::SelfAndSubdomains
        } else {
            Self::SubdomainsOnly
        }
    }
}

/// A compiled set of domain patterns for one `domain(...)` match set.
///
/// Construction is where all the work happens: the query path does no allocation
/// and no work proportional to the number of patterns.
#[derive(Debug, Clone, Default)]
pub struct DomainIndex {
    key: DomainKey,
    /// Accepted patterns, in configuration order, for diagnostics. For `suffix`
    /// these keep their leading dot so the report reads back as written.
    patterns: Vec<Box<str>>,
    exact: HashSet<Box<str>>,
    suffix: HashMap<Box<str>, SuffixScope>,
    keyword: Option<AhoCorasick>,
    regex: Option<RegexSet>,
}

impl DomainIndex {
    /// Compiles `patterns`. Rejected patterns are reported through `warnings`
    /// and are not applied, matching the Go matcher.
    pub fn new(key: DomainKey, patterns: &[&str], warnings: &mut Vec<String>) -> Self {
        let mut index = Self {
            key,
            ..Self::default()
        };
        let mut keywords: Vec<Box<str>> = Vec::new();
        let mut regexes: Vec<Box<str>> = Vec::new();

        for pattern in patterns {
            match key {
                DomainKey::Full | DomainKey::Suffix | DomainKey::Keyword => {
                    let lowered = pattern.to_ascii_lowercase();
                    if let Some(bad) = lowered.chars().find(|ch| !is_valid_domain_char(*ch)) {
                        warnings.push(format!(
                            "domain matcher: skipped invalid {} pattern \"{pattern}\" \
                             (unexpected character {bad:?})",
                            key.as_str()
                        ));
                        continue;
                    }
                    match key {
                        DomainKey::Full => {
                            index.exact.insert(lowered.as_str().into());
                            index.patterns.push(lowered.into_boxed_str());
                        }
                        DomainKey::Suffix => {
                            // `.example.com` and `example.com` are the same key with
                            // different scopes; a leading dot is the only thing that
                            // distinguishes them.
                            let (bare, scope) = match lowered.strip_prefix('.') {
                                Some(bare) => (bare, SuffixScope::SubdomainsOnly),
                                None => (lowered.as_str(), SuffixScope::SelfAndSubdomains),
                            };
                            if bare.is_empty() {
                                warnings.push(format!(
                                    "domain matcher: skipped suffix pattern \"{pattern}\": \
                                     no name after the leading dot"
                                ));
                                continue;
                            }
                            index
                                .suffix
                                .entry(bare.into())
                                .and_modify(|existing| *existing = existing.widen(scope))
                                .or_insert(scope);
                            index.patterns.push(lowered.into_boxed_str());
                        }
                        DomainKey::Keyword => {
                            let boxed: Box<str> = lowered.into_boxed_str();
                            keywords.push(boxed.clone());
                            index.patterns.push(boxed);
                        }
                        DomainKey::Regex => unreachable!("regex is handled in its own arm"),
                    }
                }
                DomainKey::Regex => match regex::Regex::new(pattern) {
                    Ok(_) => {
                        regexes.push(Box::from(*pattern));
                        index.patterns.push(Box::from(*pattern));
                    }
                    Err(err) => {
                        warnings.push(format!(
                            "domain matcher: skipped invalid regex \"{pattern}\": {err}"
                        ));
                    }
                },
            }
        }

        if !keywords.is_empty() {
            match AhoCorasick::new(keywords.iter().map(AsRef::as_ref)) {
                Ok(ac) => index.keyword = Some(ac),
                Err(err) => warnings.push(format!(
                    "domain matcher: could not build the keyword automaton: {err}"
                )),
            }
        }
        if !regexes.is_empty() {
            match RegexSet::new(regexes.iter().map(AsRef::as_ref)) {
                Ok(set) => index.regex = Some(set),
                Err(err) => warnings.push(format!(
                    "domain matcher: could not compile the regex set: {err}"
                )),
            }
        }

        index
    }

    pub fn key(&self) -> DomainKey {
        self.key
    }

    pub fn patterns(&self) -> &[Box<str>] {
        &self.patterns
    }

    /// How many patterns were accepted, for a report that must not print them all.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Matches a queried domain name.
    ///
    /// Allocation-free for every name that fits in a DNS name.
    pub fn matches(&self, domain: &str) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        with_normalized(domain, |normalized| self.matches_normalized(normalized))
    }

    /// The query path, over an already-normalized (lowercased, dot-stripped) name.
    fn matches_normalized(&self, normalized: &str) -> bool {
        if normalized.is_empty() {
            return false;
        }
        match self.key {
            DomainKey::Full => self.exact.contains(normalized),
            DomainKey::Suffix => self.matches_suffix(normalized),
            DomainKey::Keyword => self
                .keyword
                .as_ref()
                .is_some_and(|ac| ac.is_match(normalized)),
            DomainKey::Regex => self
                .regex
                .as_ref()
                .is_some_and(|set| set.is_match(normalized)),
        }
    }

    /// Walks the label boundaries of `normalized`, checking each candidate.
    ///
    /// `a.b.example.com` is tried as itself, then `b.example.com`, then
    /// `example.com`, then `com`. The first candidate is the whole name, so a
    /// `SubdomainsOnly` pattern must not match there.
    fn matches_suffix(&self, normalized: &str) -> bool {
        if self.suffix.is_empty() {
            return false;
        }
        let mut candidate = normalized;
        let mut is_whole_name = true;
        loop {
            if let Some(scope) = self.suffix.get(candidate) {
                let acceptable = match scope {
                    SuffixScope::SelfAndSubdomains => true,
                    SuffixScope::SubdomainsOnly => !is_whole_name,
                };
                if acceptable {
                    return true;
                }
            }
            match candidate.find('.') {
                Some(dot) => {
                    candidate = &candidate[dot + 1..];
                    is_whole_name = false;
                    if candidate.is_empty() {
                        return false;
                    }
                }
                None => return false,
            }
        }
    }
}

/// Calls `f` with the lowercased, trailing-dot-stripped form of `domain`.
///
/// The common case is a stack buffer, so the hot path allocates nothing. A name
/// longer than a DNS name is normalized on the heap rather than truncated: a
/// truncated comparison could report a match that does not exist.
fn with_normalized<R>(domain: &str, f: impl FnOnce(&str) -> R) -> R {
    let stripped = domain.trim_end_matches('.');
    if stripped.len() <= STACK_DOMAIN_LEN && stripped.is_ascii() {
        let mut buffer = [0u8; STACK_DOMAIN_LEN];
        let bytes = &mut buffer[..stripped.len()];
        bytes.copy_from_slice(stripped.as_bytes());
        bytes.make_ascii_lowercase();
        // SAFETY-free: the input was ASCII, and ASCII lowercasing preserves it.
        let normalized = std::str::from_utf8(bytes).expect("ASCII is valid UTF-8");
        f(normalized)
    } else {
        f(&stripped.to_ascii_lowercase())
    }
}

fn is_valid_domain_char(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-' | '_' | '^')
}

impl PartialEq for DomainIndex {
    /// Two indexes are equal when they were compiled from the same key and the
    /// same accepted patterns; the internal structures are an implementation
    /// detail of that.
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.patterns == other.patterns
    }
}

impl Eq for DomainIndex {}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(key: DomainKey, values: &[&str]) -> DomainIndex {
        let mut warnings = Vec::new();
        let patterns = DomainIndex::new(key, values, &mut warnings);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        patterns
    }

    #[test]
    fn full_matches_exactly_and_case_insensitively() {
        let matcher = patterns(DomainKey::Full, &["example.com"]);
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("Example.COM"));
        assert!(matcher.matches("example.com."));
        assert!(!matcher.matches("a.example.com"));
    }

    #[test]
    fn suffix_matches_the_name_and_subdomains_only() {
        let matcher = patterns(DomainKey::Suffix, &["example.com"]);
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("a.b.example.com"));
        assert!(!matcher.matches("abcexample.com"));
        assert!(!matcher.matches("example.com.evil"));
    }

    #[test]
    fn suffix_with_a_leading_dot_matches_subdomains_only() {
        let matcher = patterns(DomainKey::Suffix, &[".example.com"]);
        assert!(matcher.matches("a.example.com"));
        assert!(!matcher.matches("example.com"));
    }

    #[test]
    fn a_key_declared_both_ways_matches_both_ways() {
        // `.example.com` narrows one declaration but must not narrow the other.
        let matcher = patterns(DomainKey::Suffix, &[".example.com", "example.com"]);
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("a.example.com"));
    }

    #[test]
    fn suffix_does_not_match_a_shared_label_boundary() {
        // The label walk must not accept `ample.com` inside `example.com`.
        let matcher = patterns(DomainKey::Suffix, &["ample.com"]);
        assert!(!matcher.matches("example.com"));
        assert!(matcher.matches("x.ample.com"));
    }

    #[test]
    fn suffix_handles_deep_names_and_single_labels() {
        let matcher = patterns(DomainKey::Suffix, &["com", "b.example.com"]);
        assert!(matcher.matches("a.b.example.com"));
        assert!(matcher.matches("com"));
        assert!(matcher.matches("anything.com"));
        assert!(!matcher.matches("comm"));
    }

    #[test]
    fn keyword_is_a_case_insensitive_substring() {
        let matcher = patterns(DomainKey::Keyword, &["google"]);
        assert!(matcher.matches("www.google.com"));
        assert!(matcher.matches("GOOGLE"));
        assert!(!matcher.matches("example.com"));
    }

    #[test]
    fn several_keywords_match_any_of_them() {
        let matcher = patterns(DomainKey::Keyword, &["google", "adsrv"]);
        assert!(matcher.matches("x.adsrv.example"));
        assert!(!matcher.matches("example.com"));
    }

    #[test]
    fn regex_keeps_its_case() {
        let matcher = patterns(DomainKey::Regex, &["^ad[0-9]*\\.example\\.com$"]);
        assert!(matcher.matches("ad1.example.com"));
        // The queried name is lowercased before matching; only the pattern keeps
        // its case, so an uppercase query still matches.
        assert!(matcher.matches("AD1.example.com"));
        assert!(!matcher.matches("ad.example.org"));
    }

    #[test]
    fn rejects_patterns_with_forbidden_characters() {
        let mut warnings = Vec::new();
        let matcher = DomainIndex::new(
            DomainKey::Suffix,
            &["exa mple.com", "ok.com"],
            &mut warnings,
        );
        assert_eq!(warnings.len(), 1);
        assert_eq!(matcher.patterns(), [Box::from("ok.com")]);
    }

    #[test]
    fn rejects_broken_regexes() {
        let mut warnings = Vec::new();
        let matcher = DomainIndex::new(DomainKey::Regex, &["["], &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(!matcher.matches("anything"));
    }

    #[test]
    fn parses_keys() {
        assert_eq!(DomainKey::parse("suffix"), Ok(DomainKey::Suffix));
        assert!(DomainKey::parse("").is_err());
        assert!(DomainKey::parse("contains").is_err());
    }

    #[test]
    fn an_empty_index_matches_nothing() {
        let matcher = patterns(DomainKey::Suffix, &[]);
        assert!(!matcher.matches("example.com"));
        assert!(matcher.is_empty());
    }

    #[test]
    fn an_over_long_name_is_normalized_not_truncated() {
        // Longer than the stack buffer: the heap path must still be exact.
        let long = format!("{}.example.com", "a".repeat(300));
        let matcher = patterns(DomainKey::Suffix, &["example.com"]);
        assert!(matcher.matches(&long));

        let other = format!("{}.example.org", "a".repeat(300));
        assert!(!matcher.matches(&other));
    }

    #[test]
    fn normalization_is_case_and_dot_insensitive() {
        let matcher = patterns(DomainKey::Full, &["example.com"]);
        for probe in [
            "example.com",
            "EXAMPLE.com",
            "example.COM.",
            "Example.Com..",
        ] {
            assert!(matcher.matches(probe), "{probe}");
        }
    }
}
