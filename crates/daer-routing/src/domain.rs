// SPDX-License-Identifier: AGPL-3.0-only

//! Domain matching over one flat, sorted, front-coded table.
//!
//! # Vocabulary
//!
//! Two pattern kinds, because they are the two questions a routing rule can ask:
//!
//! * `full: name`   — does this exact name appear?
//! * `suffix: name` — is this name, or any name under it, listed? A leading dot
//!   (`.name`) narrows that to subdomains only.
//!
//! `keyword:` and `regex:` were removed (ADR-0032, ADR-0033). They existed because the V2Ray
//! geodata format had four domain codes and each got its own engine; the routing hot path
//! carried an Aho-Corasick automaton and a regex set for a corpus in which the measured
//! distribution was 99.99% suffix, zero keyword, and eight regexes across every published set.
//! Substring and regex matching are a *data-cleaning* concern: expand them upstream, into the
//! `.rules` a producer compiles. Anything a routing rule needs to express, it can express as
//! full and suffix patterns.
//!
//! # Structure
//!
//! One table, sorted by **reversed label** (`www.example.com` → `com.example.www`) and
//! front-coded: each record stores only the bytes it adds to its predecessor. Reversed-label
//! order is what makes both properties work at once:
//!
//! * **size** — sibling names share their TLD and often their domain, and sorting puts them
//!   next to each other, so the shared bytes are stored once;
//! * **lookup** — every suffix that could cover a name is a *label-boundary prefix* of that
//!   name's reversed key, so the query is a handful of binary searches rather than a trie walk
//!   or a scan.
//!
//! Keys live in a single arena rather than one `String` each, so a binary search walks
//! contiguous memory instead of chasing 110,000 separate allocations.
//!
//! # Cost model
//!
//! A `DomainTable` is built once per generation and read once per connection (the datapath
//! defers any rule containing a domain predicate, so eBPF never matches names). Construction may
//! allocate; lookup does not.

use std::fmt;

use daer_rule_ast::is_valid_domain_char;

use crate::error::RoutingError;

/// Longest key the lookup accepts, in bytes of reversed-label form.
///
/// A DNS name is at most 253 characters and reversal preserves length, so this is generous.
/// A longer input is refused rather than truncated: a truncated key could match the wrong
/// suffix, which is worse than a miss.
const MAX_KEY_LEN: usize = 512;

/// Most labels a lookup can walk.
const MAX_LABELS: usize = 128;

// `SuffixScope` has exactly one definition, in `daer-rule-ast`, so a producer and the runtime
// cannot disagree about what `.example.com` means (ADR-0023, ADR-0033).
pub use daer_rule_ast::SuffixScope;

/// Per-record flags: which predicates the pattern at this key satisfies.
mod flags {
    pub const FULL: u8 = 0x01;
    pub const SUFFIX_SELF_AND_SUB: u8 = 0x02;
    pub const SUFFIX_SUB_ONLY: u8 = 0x04;
}

/// One key in the table: where it lives in the arena, and what it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record {
    offset: u32,
    len: u32,
    flags: u8,
}

/// A compiled set of domain patterns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainTable {
    /// How this table was written, for diagnostics: the accepted pattern spellings in the order
    /// they were declared. Suffix patterns keep their leading dot so a report reads back as the
    /// operator wrote it.
    patterns: Vec<Box<str>>,
    /// Records in reversed-label sort order.
    records: Vec<Record>,
    /// Every key, concatenated.
    arena: Vec<u8>,
}

impl DomainTable {
    /// Compiles patterns written as the routing vocabulary.
    ///
    /// Each entry is `kind: value` (`full:` / `suffix:`), or a bare name read as a suffix — the
    /// same fallback the rule text reader uses, so `domain(example.com)` and `suffix: example.com`
    /// mean the same thing.
    ///
    /// Rejected patterns are reported through `warnings` and not applied. A pattern the matcher
    /// cannot represent is a rule that would never fire, so it must be visible rather than
    /// silently dropped.
    pub fn compile(patterns: &[&str], warnings: &mut Vec<String>) -> Self {
        let mut accepted: Vec<(String, u8)> = Vec::with_capacity(patterns.len());
        let mut declared: Vec<Box<str>> = Vec::with_capacity(patterns.len());

        for pattern in patterns {
            let text = pattern.trim();
            if text.is_empty() {
                warnings.push("domain matcher: skipped an empty pattern".to_owned());
                continue;
            }
            let (kind, value) = match text.split_once(':') {
                Some((kind, value)) => (kind.trim(), value.trim()),
                None => ("suffix", text),
            };
            let value = value.trim_start_matches('+');

            let (bare, flag) = match kind {
                "full" => (value, flags::FULL),
                "suffix" | "domain" | "root_domain" => {
                    // `.example.com` and `example.com` are one key with two scopes; the leading
                    // dot is the only thing that distinguishes them.
                    match value.strip_prefix('.') {
                        Some(bare) if !bare.starts_with('.') => (bare, flags::SUFFIX_SUB_ONLY),
                        _ => (value, flags::SUFFIX_SELF_AND_SUB),
                    }
                }
                other => {
                    warnings.push(format!(
                        "domain matcher: skipped \"{pattern}\": `{other}:` is not a routing \
                         predicate (ADR-0033 accepts `full:` and `suffix:`); expand it into \
                         concrete patterns upstream"
                    ));
                    continue;
                }
            };

            let lowered = bare.to_ascii_lowercase();
            if let Some(bad) = lowered.chars().find(|ch| !is_valid_domain_char(*ch)) {
                warnings.push(format!(
                    "domain matcher: skipped invalid pattern \"{pattern}\" (unexpected character {bad:?})"
                ));
                continue;
            }
            declared.push(text.into());
            accepted.push((lowered, flag));
        }

        let mut table = Self {
            patterns: declared,
            ..Self::default()
        };
        table.build(accepted);
        table
    }

    /// Builds directly from classified patterns. Used by the DRB decoder, which already knows
    /// each key's flags.
    pub(crate) fn from_classified(mut entries: Vec<(String, u8)>) -> Self {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut table = Self::default();
        table.build(entries);
        // Derive the diagnostic spelling from the built table rather than from the input, so a
        // table equals the one `decode` reconstructs from its own bytes.
        table.patterns = table
            .iter_rules()
            .map(|(value, scope)| {
                let spelling = match scope {
                    None => format!("full: {value}"),
                    Some(scope) => format!("suffix: {}{value}", scope.marker()),
                };
                spelling.into_boxed_str()
            })
            .collect();
        table
    }

    fn build(&mut self, entries: Vec<(String, u8)>) {
        // 1. Group by reversed-label key, merging predicates that name the same key.
        let mut by_key: std::collections::BTreeMap<String, u8> = std::collections::BTreeMap::new();
        for (value, flag) in entries {
            if value.is_empty() {
                continue;
            }
            let mut labels: Vec<&str> = value.split('.').collect();
            labels.reverse();
            *by_key.entry(labels.join(".")).or_insert(0) |= flag;
        }

        // 2. Drop every record that an enclosing self-and-subdomains suffix already answers.
        //
        // `BTreeMap` yields keys in sorted order, so "under a suffix" is "immediately after
        // it". Removing them shrinks the artifact and means the lookup never has to consider a
        // rule a broader rule already covers.
        let mut kept: Vec<(String, u8)> = Vec::with_capacity(by_key.len());
        let mut covering: Option<(String, bool)> = None;
        for (key, flag) in by_key {
            if let Some((suffix_key, include_self)) = &covering
                && is_under(&key, suffix_key, *include_self)
            {
                continue;
            }
            covering = if flag & flags::SUFFIX_SELF_AND_SUB != 0 {
                Some((key.clone(), true))
            } else if flag & flags::SUFFIX_SUB_ONLY != 0 {
                // Covers strictly longer keys, but not the bare name.
                Some((key.clone(), false))
            } else {
                None
            };
            kept.push((key, flag));
        }

        // 3. Pack the keys into one arena, preserving sort order so front-coding applies.
        let mut records = Vec::with_capacity(kept.len());
        let mut arena = Vec::new();
        for (key, flag) in kept {
            let offset = arena.len() as u32;
            let len = key.len() as u32;
            arena.extend_from_slice(key.as_bytes());
            records.push(Record {
                offset,
                len,
                flags: flag,
            });
        }
        self.records = records;
        self.arena = arena;
    }

    fn key_of(&self, record: &Record) -> &str {
        let start = record.offset as usize;
        let end = start + record.len as usize;
        std::str::from_utf8(&self.arena[start..end]).expect("keys were UTF-8 when stored")
    }

    fn find(&self, key: &str) -> Option<&Record> {
        self.records
            .binary_search_by(|record| self.key_of(record).cmp(key))
            .ok()
            .map(|index| &self.records[index])
    }

    /// The patterns this table was built from, as written, for diagnostics.
    #[must_use]
    pub fn patterns(&self) -> &[Box<str>] {
        &self.patterns
    }

    /// How many keys the table holds after coverage pruning.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether `domain` matches any pattern in this table.
    ///
    /// Allocation-free and bounded: at most one binary search per label plus one for the whole
    /// name.
    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        if self.records.is_empty() {
            return false;
        }
        let trimmed = domain.trim().trim_end_matches('.');
        if trimmed.is_empty() || trimmed.len() > MAX_KEY_LEN {
            return false;
        }

        let mut buffer = [0u8; MAX_KEY_LEN];
        let mut length = 0usize;
        // Where each label starts in the reversed key, so every candidate suffix is a slice.
        let mut starts = [0usize; MAX_LABELS];
        let mut labels = 0usize;
        for label in trimmed.rsplit('.') {
            if label.is_empty() {
                return false;
            }
            if labels > 0 {
                if length >= MAX_KEY_LEN {
                    return false;
                }
                buffer[length] = b'.';
                length += 1;
            }
            if labels >= MAX_LABELS {
                return false;
            }
            starts[labels] = length;
            labels += 1;
            for byte in label.bytes() {
                if length >= MAX_KEY_LEN {
                    return false;
                }
                buffer[length] = byte.to_ascii_lowercase();
                length += 1;
            }
        }
        let key = std::str::from_utf8(&buffer[..length]).expect("ASCII lowercasing keeps UTF-8");

        // The whole name: a `full` or a self-and-subdomains rule on it.
        if let Some(record) = self.find(key)
            && record.flags & (flags::FULL | flags::SUFFIX_SELF_AND_SUB) != 0
        {
            return true;
        }

        // Every shorter prefix is a candidate suffix: the first `i` labels, for `i` in
        // `1..labels`. That ends one byte before label `i` starts (dropping its separator).
        for &start in &starts[1..labels] {
            if let Some(record) = self.find(&key[..start - 1])
                && record.flags & (flags::SUFFIX_SELF_AND_SUB | flags::SUFFIX_SUB_ONLY) != 0
            {
                return true;
            }
        }
        false
    }

    /// The rules this table holds, as `(value, scope)` pairs for a producer to re-emit.
    ///
    /// `full` and suffix are distinguished; a key that is both is yielded twice, because they
    /// are two predicates even though they share a key.
    pub fn iter_rules(&self) -> impl Iterator<Item = (String, Option<SuffixScope>)> + '_ {
        self.records.iter().flat_map(move |record| {
            let value = reverse_labels(self.key_of(record));
            let mut out: Vec<(String, Option<SuffixScope>)> = Vec::with_capacity(3);
            if record.flags & flags::FULL != 0 {
                out.push((value.clone(), None));
            }
            if record.flags & flags::SUFFIX_SELF_AND_SUB != 0 {
                out.push((value.clone(), Some(SuffixScope::SelfAndSubdomains)));
            }
            if record.flags & flags::SUFFIX_SUB_ONLY != 0 {
                out.push((value, Some(SuffixScope::SubdomainsOnly)));
            }
            out.into_iter()
        })
    }

    /// Serializes into the DRB front-coded record stream.
    ///
    /// `shared` is the byte count this key shares with the previous one; because the records are
    /// sorted, that prefix is always the predecessor's.
    pub(crate) fn encode_records(&self) -> (Vec<u8>, u32) {
        let mut out = Vec::new();
        let mut previous: &str = "";
        for record in &self.records {
            let key = self.key_of(record);
            let shared = common_prefix_len(previous, key);
            let suffix = &key[shared..];
            out.push(record.flags);
            out.extend_from_slice(&(shared as u16).to_le_bytes());
            out.extend_from_slice(&(suffix.len() as u16).to_le_bytes());
            out.extend_from_slice(suffix.as_bytes());
            previous = key;
        }
        let count = self.records.len() as u32;
        (out, count)
    }

    /// Rebuilds from the encoded record stream and the name that was stored with it.
    pub(crate) fn decode_records(bytes: &[u8], count: usize) -> Result<Self, crate::drb::DrbError> {
        use crate::drb::DrbError;

        let mut records = Vec::with_capacity(count);
        let mut arena: Vec<u8> = Vec::new();
        let mut cur = bytes;
        let mut previous = String::new();
        for _ in 0..count {
            if cur.len() < 5 {
                return Err(DrbError::Truncated {
                    field: "domain record header",
                    needed: 5,
                    available: cur.len(),
                });
            }
            let flag = cur[0];
            let shared = u16::from_le_bytes(cur[1..3].try_into().unwrap()) as usize;
            let suffix_len = u16::from_le_bytes(cur[3..5].try_into().unwrap()) as usize;
            cur = &cur[5..];
            if shared > previous.len() || cur.len() < suffix_len {
                return Err(DrbError::Truncated {
                    field: "domain record body",
                    needed: shared + suffix_len,
                    available: previous.len() + cur.len(),
                });
            }
            let mut key = String::with_capacity(shared + suffix_len);
            key.push_str(&previous[..shared]);
            key.push_str(
                std::str::from_utf8(&cur[..suffix_len])
                    .map_err(|_| DrbError::InvalidUtf8("domain label"))?,
            );
            cur = &cur[suffix_len..];
            let offset = arena.len() as u32;
            let len = key.len() as u32;
            arena.extend_from_slice(key.as_bytes());
            previous = key;
            records.push(Record {
                offset,
                len,
                flags: flag,
            });
        }

        let mut table = Self {
            patterns: Vec::new(),
            records,
            arena,
        };
        table.patterns = table
            .iter_rules()
            .map(|(value, scope)| {
                let spelling = match scope {
                    None => format!("full: {value}"),
                    Some(scope) => format!("suffix: {}{value}", scope.marker()),
                };
                spelling.into_boxed_str()
            })
            .collect();
        Ok(table)
    }
}

/// Whether `key` is `suffix_key` or descends from it in reversed-label order.
fn is_under(key: &str, suffix_key: &str, include_self: bool) -> bool {
    if key == suffix_key {
        return include_self;
    }
    key.len() > suffix_key.len()
        && key.starts_with(suffix_key)
        && key.as_bytes()[suffix_key.len()] == b'.'
}

fn reverse_labels(key: &str) -> String {
    let mut labels: Vec<&str> = key.split('.').collect();
    labels.reverse();
    labels.join(".")
}

fn common_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

impl fmt::Display for DomainTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} domain pattern(s)", self.records.len())
    }
}

/// Validates that every pattern is representable, for a caller that wants errors instead of
/// warnings (the configuration path).
pub fn validate_patterns(patterns: &[&str]) -> Result<(), RoutingError> {
    let mut warnings = Vec::new();
    let table = DomainTable::compile(patterns, &mut warnings);
    if warnings.is_empty() {
        let _ = table;
        Ok(())
    } else {
        Err(RoutingError::new(warnings.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(values: &[&str]) -> DomainTable {
        let mut warnings = Vec::new();
        let table = DomainTable::compile(values, &mut warnings);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        table
    }

    #[test]
    fn full_and_suffix_answer_the_questions_a_rule_asks() {
        let t = table(&["suffix: example.com", "full: api.other.com"]);
        assert!(t.matches("example.com"), "suffix includes the bare name");
        assert!(t.matches("www.example.com"));
        assert!(t.matches("a.b.example.com"));
        assert!(t.matches("api.other.com"));
        assert!(!t.matches("other.com"), "full is exact");
        assert!(!t.matches("abcexample.com"), "a label boundary is required");
        assert!(!t.matches("elsewhere.com"));
    }

    #[test]
    fn a_bare_name_is_a_suffix() {
        assert!(table(&["example.com"]).matches("x.example.com"));
    }

    #[test]
    fn a_leading_dot_narrows_to_subdomains_only() {
        let t = table(&["suffix: .corp.example"]);
        assert!(t.matches("a.corp.example"));
        assert!(
            !t.matches("corp.example"),
            "`.corp.example` excludes the bare name"
        );
    }

    #[test]
    fn a_broader_suffix_absorbs_the_patterns_under_it() {
        let t = table(&[
            "suffix: example.com",
            "full: a.example.com",
            "suffix: b.example.com",
        ]);
        assert_eq!(t.len(), 1, "covered records must be pruned: {t:?}");
        assert!(t.matches("a.example.com"));
        assert!(t.matches("b.example.com"));
    }

    #[test]
    fn keyword_and_regex_are_refused_by_name() {
        let mut warnings = Vec::new();
        DomainTable::compile(&["keyword: ads", "regex: ^a.*z$"], &mut warnings);
        assert_eq!(warnings.len(), 2);
        assert!(
            warnings[0].contains("not a routing predicate"),
            "{warnings:?}"
        );
        assert!(warnings[0].contains("expand it"), "{warnings:?}");
    }

    #[test]
    fn invalid_characters_are_refused_with_the_offending_character() {
        let mut warnings = Vec::new();
        DomainTable::compile(&["suffix: bad domain"], &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains('\''), "{warnings:?}");
    }

    #[test]
    fn round_trips_through_the_encoded_record_stream() {
        let t = table(&[
            "suffix: example.com",
            "full: api.example.com",
            "suffix: .sub.other.org",
        ]);
        let (bytes, count) = t.encode_records();
        let decoded = DomainTable::decode_records(&bytes, count as usize).expect("decodes");
        assert_eq!(decoded.len(), t.len());
        for name in [
            "example.com",
            "api.example.com",
            "x.sub.other.org",
            "nope.test",
        ] {
            assert_eq!(decoded.matches(name), t.matches(name), "{name}");
        }
    }

    #[test]
    fn a_key_that_prefixes_another_survives_front_coding() {
        let t = table(&["full: a.com", "full: ab.com", "full: abc.com"]);
        let (bytes, count) = t.encode_records();
        let decoded = DomainTable::decode_records(&bytes, count as usize).expect("decodes");
        for name in ["a.com", "ab.com", "abc.com"] {
            assert!(decoded.matches(name), "{name} must survive front-coding");
        }
        assert!(!decoded.matches("abcd.com"));
    }

    #[test]
    fn iter_rules_reports_both_predicates_when_a_key_serves_both() {
        let t = table(&["full: example.com", "suffix: example.com"]);
        let rules: Vec<_> = t.iter_rules().collect();
        assert_eq!(rules.len(), 2, "{rules:?}");
        assert!(rules.contains(&("example.com".to_owned(), None)));
        assert!(rules.contains(&(
            "example.com".to_owned(),
            Some(SuffixScope::SelfAndSubdomains)
        )));
    }

    #[test]
    fn an_over_long_name_is_refused_rather_than_truncated() {
        let t = table(&["suffix: example.com"]);
        let long = format!("{}.example.com", "a".repeat(600));
        assert!(!t.matches(&long));
    }
}
