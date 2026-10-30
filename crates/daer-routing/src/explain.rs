// SPDX-License-Identifier: AGPL-3.0-only

//! Why a rule did *not* fire.
//!
//! [`explain`] answers the question the data path cannot afford to answer: for every
//! rule, which predicate held and which did not.
//!
//! # Why this is a separate pass
//!
//! Recording every predicate costs an allocation per rule, which is not acceptable per
//! packet. The data path stays as it is, and this module replays the evaluation for one
//! flow on demand — the same trade-off `daer route explain` already makes by compiling
//! a generation.
//!
//! # How the lowered program is read back
//!
//! The lowering encodes two nestings in a flat array, and both matter here:
//!
//! ```text
//!   MatchSet            target
//!   ─────────────────   ──────────────────
//!   value 0             LogicalOr         ┐ one predicate with two values:
//!   value 1             LogicalAnd          `dip(a, b)` — true when *any* value hits
//!   value 2             LogicalOr         ┐ next predicate of the same rule
//!   value 3             Outbound            ┘ the rule ends here
//! ```
//!
//! * a `LogicalOr` target means "another value of the *same* predicate";
//! * a `LogicalAnd` target means "another predicate of the *same* rule";
//! * an `Outbound` target ends the rule.
//!
//! Grouping on those two boundaries is what makes the report match the configuration
//! instead of exposing internal indices. Both grouping rules have tests, because a
//! diagnostic that misgroups predicates is worse than no diagnostic.
//!
//! # The two things that are easy to get wrong
//!
//! * **Negation belongs to the predicate, not to the rule.** `!dip(a) && dip(b)` must
//!   report each predicate's own result; a rule is decided by the conjunction.
//! * **The decided rule is the first *fired* rule**, not the last, and `must_rules` /
//!   `control_plane_routing` are markers rather than outbounds.

use std::fmt;

use crate::matcher::{MatchFacts, MatchSet, MatchValue, matches_value};
use crate::outbound::{CONTROL_PLANE_ROUTING, MUST_RULES, Outbound};

/// One predicate of one rule, as the configuration wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateTrace {
    /// The predicate spelled the way the configuration spells it, e.g.
    /// `dip(geoip: private)`. The optimizer rewrites the function name, so this is
    /// what the engine evaluated.
    pub predicate: String,
    /// Whether any of the predicate's values matched. Negation is *not* applied here.
    pub matched: bool,
    /// Whether the configuration negated the predicate with `!`.
    pub negated: bool,
}

impl PredicateTrace {
    /// True when this predicate did not stand in its rule's way.
    ///
    /// For a negated predicate a non-match is what the rule wanted, so "matched" and
    /// "held" are different questions and both are reported.
    #[must_use]
    pub const fn held(&self) -> bool {
        self.matched != self.negated
    }
}

/// Why one rule did or did not fire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTrace {
    /// 0-based index into `NormalizedProgram::rules`.
    pub rule: usize,
    /// The predicates in evaluation order.
    pub predicates: Vec<PredicateTrace>,
    /// True when the rule's predicates all held.
    pub fired: bool,
    /// True when the rule would have fired but an earlier rule decided first.
    ///
    /// Recorded rather than omitted: "rule 4 would have matched, but rule 1 fired
    /// first" is the answer to a large class of surprises, and it cannot be derived
    /// from the surviving predicates alone.
    pub shadowed: bool,
    /// True for the internal `must_rules` / `control_plane_routing` markers, which are
    /// not outbounds an operator can name.
    pub internal: bool,
}

impl RuleTrace {
    /// The first predicate that prevented the rule from firing.
    ///
    /// `None` for a rule that fired, was shadowed, or is an internal marker.
    #[must_use]
    pub fn blocking(&self) -> Option<&PredicateTrace> {
        if self.internal || self.fired || self.shadowed {
            return None;
        }
        self.predicates.iter().find(|predicate| !predicate.held())
    }

    /// A one-line reason, for logs and for `route explain --why` output.
    #[must_use]
    pub fn reason(&self) -> String {
        if self.internal {
            return "internal marker".to_owned();
        }
        if self.fired {
            return "fired".to_owned();
        }
        if self.shadowed {
            return "would have fired, but an earlier rule decided first".to_owned();
        }
        match self.blocking() {
            Some(predicate) => format!("{} did not match", predicate.predicate),
            // Every predicate held but the rule did not fire: only possible for a
            // marker, which is handled above.
            None => "did not fire".to_owned(),
        }
    }
}

/// The complete explanation of one flow's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    pub rules: Vec<RuleTrace>,
    /// The rule that decided, if any.
    pub decided_by: Option<usize>,
    /// The outbound chosen, or `None` when the fallback applies.
    pub outbound: Option<Outbound>,
}

impl Trace {
    /// The rule trace that decided.
    #[must_use]
    pub fn decided(&self) -> Option<&RuleTrace> {
        self.decided_by
            .and_then(|rule| self.rules.iter().find(|trace| trace.rule == rule))
    }

    /// Rules that would have matched but were preceded by the rule that decided.
    ///
    /// Empty for a well-ordered configuration; a non-empty list is usually the answer
    /// to "why did my rule never fire?".
    #[must_use]
    pub fn shadowed(&self) -> Vec<&RuleTrace> {
        self.rules.iter().filter(|trace| trace.shadowed).collect()
    }
}

impl fmt::Display for Trace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for trace in &self.rules {
            if trace.internal {
                continue;
            }
            let status = if trace.fired {
                "fired"
            } else if trace.shadowed {
                "shadowed"
            } else {
                "skipped"
            };
            writeln!(f, "rule {} [{status}]", trace.rule)?;
            for predicate in &trace.predicates {
                let mark = if predicate.held() { "v" } else { "x" };
                let negation = if predicate.negated { "!" } else { "" };
                writeln!(f, "  {mark} {negation}{}", predicate.predicate)?;
            }
            if !trace.fired && !trace.shadowed {
                writeln!(f, "  -> {}", trace.reason())?;
            }
        }
        Ok(())
    }
}

/// Replays the evaluation and records why each rule did or did not fire.
///
/// `decided_by` and `outbound` agree with
/// [`first_hit`](crate::first_hit) and [`evaluate`](crate::evaluate) on the same input;
/// the equivalence is asserted by tests, because a diagnostic that disagrees with the
/// data path is worse than none.
#[must_use]
pub fn explain(sets: &[MatchSet], facts: &MatchFacts<'_>) -> Trace {
    let mut rules: Vec<RuleTrace> = Vec::new();
    let mut predicates: Vec<PredicateTrace> = Vec::new();
    // Values of the predicate currently being accumulated.
    let mut predicate_name: Option<String> = None;
    let mut predicate_matched = false;
    let mut predicate_negated = false;
    let mut forced_must = false;
    let mut decided_by: Option<usize> = None;
    let mut outbound: Option<Outbound> = None;

    for (index, set) in sets.iter().enumerate() {
        if predicate_name.is_none() {
            predicate_name = Some(describe_rule(set, facts));
            predicate_negated = set.negated;
        }
        predicate_matched |= matches_value(&set.value, facts);

        // `LogicalOr` means another value of the same predicate: keep accumulating.
        if set.target.is_logical_or() {
            continue;
        }

        predicates.push(PredicateTrace {
            predicate: predicate_name.take().unwrap_or_default(),
            matched: predicate_matched,
            negated: predicate_negated,
        });
        predicate_matched = false;
        predicate_negated = false;

        // `LogicalAnd` means another predicate of the same rule.
        if set.target.is_logical_and() {
            continue;
        }

        // The rule ended.
        let all_held = predicates.iter().all(PredicateTrace::held);
        let rule = rule_ordinal(sets, index);
        let target = set.target.name();
        let internal = matches!(target, Some(MUST_RULES | CONTROL_PLANE_ROUTING));

        if all_held && internal && matches!(target, Some(MUST_RULES)) {
            forced_must = true;
        }
        let fired = all_held && !internal && decided_by.is_none();
        if fired {
            decided_by = Some(rule);
            outbound = Some(Outbound {
                name: std::sync::Arc::from(target.unwrap_or_default()),
                mark: set.target.mark(),
                must: set.target.must() || forced_must,
            });
        }

        rules.push(RuleTrace {
            rule,
            predicates: std::mem::take(&mut predicates),
            fired,
            shadowed: all_held && !internal && !fired,
            internal,
        });
    }

    Trace {
        rules,
        decided_by,
        outbound,
    }
}

/// The rule ordinal a terminating match set belongs to.
///
/// The number of rule terminators up to and including `index`, minus one. Kept here
/// rather than imported so this module has no dependency on evaluation order beyond
/// what it verifies itself.
fn rule_ordinal(sets: &[MatchSet], index: usize) -> usize {
    sets[..=index.min(sets.len().saturating_sub(1))]
        .iter()
        .filter(|set| !set.target.is_logical())
        .count()
        .saturating_sub(1)
}

/// A predicate rendered the way the configuration spells it.
fn describe_rule(set: &MatchSet, facts: &MatchFacts<'_>) -> String {
    match &set.value {
        MatchValue::IpSet(index) => format!("dip({})", join_prefixes(index.prefixes())),
        MatchValue::SourceIpSet(index) => format!("sip({})", join_prefixes(index.prefixes())),
        MatchValue::Mac(macs) => format!("mac({})", join(macs)),
        MatchValue::Port(range) => format!("port({range})"),
        MatchValue::SourcePort(range) => format!("sport({range})"),
        MatchValue::L4Proto(mask) => format!("l4proto({})", describe_l4(*mask, facts)),
        MatchValue::IpVersion(mask) => format!("ipversion({})", describe_ip_version(*mask)),
        MatchValue::ProcessName(name) => format!("pname({name})"),
        MatchValue::Dscp(value) => format!("dscp({value})"),
        MatchValue::Domain(patterns) => describe_domain(patterns),
    }
}

/// A `domain(...)` predicate, summarized when it came from geodata.
///
/// A `geosite:cn` expansion is ~110,000 patterns; printing them inside a routing
/// trace would bury the answer in a megabyte of text and make the diagnostic
/// useless at exactly the moment it is needed. The summary names the key, the
/// count, and enough examples to identify the rule.
fn describe_domain(patterns: &crate::domain::DomainIndex) -> String {
    const SHOWN: usize = 3;
    let key = patterns.key().as_str();
    let all = patterns.patterns();
    let listed = if all.len() <= SHOWN {
        all.iter()
            .map(|pattern| pattern.as_ref())
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        let head = all[..SHOWN]
            .iter()
            .map(|pattern| pattern.as_ref())
            .collect::<Vec<_>>()
            .join(", ");
        format!("{head}, … ({} total)", all.len())
    };
    if key == "full" {
        format!("domain({listed})")
    } else {
        format!("domain({key}: {listed})")
    }
}

/// Renders a prefix list, summarized when a geodata expansion made it huge.
fn join_prefixes(prefixes: &[ipnet::IpNet]) -> String {
    const SHOWN: usize = 3;
    if prefixes.len() <= SHOWN {
        return join(prefixes);
    }
    let head = join(&prefixes[..SHOWN]);
    format!("{head}, … ({} total)", prefixes.len())
}

fn describe_l4(mask: crate::values::L4ProtoMask, _facts: &MatchFacts<'_>) -> &'static str {
    use crate::values::L4ProtoMask;
    match mask {
        L4ProtoMask::TCP => "tcp",
        L4ProtoMask::UDP => "udp",
        _ => "tcp+udp",
    }
}

fn describe_ip_version(mask: crate::values::IpVersionMask) -> &'static str {
    use crate::values::IpVersionMask;
    match mask {
        IpVersionMask::V4 => "4",
        IpVersionMask::V6 => "6",
        _ => "4+6",
    }
}

fn join<T: fmt::Display>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{RecordingSink, RulesBuilder};
    use crate::values::L4ProtoMask;
    use daer_common::MacAddr;
    use std::net::{IpAddr, Ipv4Addr};

    /// Lowers rules the way the configuration does, without an alias rewrite, so the
    /// predicate text in the report matches the fixture.
    fn sets(rules: &[&str]) -> Vec<MatchSet> {
        let parsed: Vec<_> = rules
            .iter()
            .map(|rule| daer_config::parse_rule_expr(rule).expect("parses"))
            .collect();
        let mut sink = RecordingSink::default();
        {
            let mut builder = RulesBuilder::new(&mut sink);
            builder.apply(&parsed).expect("lowers");
        }
        sink.matches
    }

    fn facts(dest_port: u16) -> MatchFacts<'static> {
        MatchFacts {
            source_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            dest_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            source_port: 40_000,
            dest_port,
            l4proto: L4ProtoMask::TCP,
            domain: None,
            process_name: crate::values::ProcessName::from_bytes_truncated(b""),
            dscp: 0,
            mac: MacAddr([0; 6]),
        }
    }

    #[test]
    fn the_report_agrees_with_the_data_path() {
        // The only property that matters: a diagnostic that disagrees with the engine
        // is worse than no diagnostic.
        let sets = sets(&["port(443) -> block", "port(80) -> direct"]);
        for port in [80u16, 443, 8080] {
            let probe = facts(port);
            let trace = explain(&sets, &probe);
            let hit = crate::first_hit(&sets, &probe);
            assert_eq!(
                trace.decided_by,
                hit.as_ref().map(|hit| hit.rule),
                "decision for port {port}"
            );
            assert_eq!(
                trace.outbound.map(|outbound| outbound.name),
                hit.map(|hit| hit.outbound.name),
                "outbound for port {port}"
            );
        }
    }

    #[test]
    fn a_skipped_rule_names_the_predicate_that_blocked_it() {
        let sets = sets(&["port(443) -> block", "port(80) -> direct"]);
        let trace = explain(&sets, &facts(80));

        assert_eq!(trace.decided_by, Some(1));
        let skipped = &trace.rules[0];
        assert_eq!(skipped.rule, 0);
        assert!(!skipped.fired);
        assert!(!skipped.shadowed);
        let blocking = skipped.blocking().expect("a blocking predicate");
        assert_eq!(blocking.predicate, "port(443)");
        assert!(!blocking.matched);
        assert!(
            skipped.reason().contains("port(443)"),
            "{}",
            skipped.reason()
        );
    }

    #[test]
    fn negation_is_reported_per_predicate_not_per_rule() {
        // `!port(443) && port(80)` — the negation belongs to the first predicate only.
        let sets = sets(&["!port(443) && port(80) -> direct"]);
        let trace = explain(&sets, &facts(80));

        let rule = &trace.rules[0];
        assert_eq!(rule.rule, 0);
        assert_eq!(rule.predicates.len(), 2, "{:?}", rule.predicates);

        let negated = &rule.predicates[0];
        assert!(negated.negated, "the first predicate is the negated one");
        assert!(!negated.matched, "port 80 is not port 443");
        assert!(negated.held(), "a negated non-match holds");

        let plain = &rule.predicates[1];
        assert!(!plain.negated);
        assert!(plain.matched);
        assert!(rule.fired);
    }

    #[test]
    fn several_values_of_one_predicate_are_one_predicate() {
        // `port(80, 8080)` lowers to two match sets joined by LogicalOr; the rule has
        // one predicate, not two, and reporting them separately would misrepresent it.
        let sets = sets(&["port(80, 8080) -> direct"]);
        assert!(sets.len() > 1, "the fixture must lower to several sets");

        let trace = explain(&sets, &facts(8080));
        let rule = &trace.rules[0];
        assert_eq!(
            rule.predicates.len(),
            1,
            "one predicate, whatever its value count: {:?}",
            rule.predicates
        );
        assert!(rule.predicates[0].matched);
        assert!(rule.fired);
    }

    #[test]
    fn two_predicates_in_one_rule_are_two_predicates() {
        let sets = sets(&["port(80) && l4proto(tcp) -> direct"]);
        let trace = explain(&sets, &facts(80));
        let rule = &trace.rules[0];
        assert_eq!(rule.predicates.len(), 2, "{:?}", rule.predicates);
        assert!(rule.predicates.iter().all(PredicateTrace::held));
        assert!(rule.fired);
    }

    #[test]
    fn a_later_matching_rule_is_reported_as_shadowed() {
        let sets = sets(&["port(443) -> block", "l4proto(tcp) -> direct"]);
        let trace = explain(&sets, &facts(443));

        assert_eq!(trace.decided_by, Some(0));
        let shadowed = trace.shadowed();
        assert_eq!(shadowed.len(), 1, "{:?}", trace.rules);
        assert_eq!(shadowed[0].rule, 1);
        assert!(
            shadowed[0].reason().contains("earlier rule"),
            "{}",
            shadowed[0].reason()
        );
    }

    #[test]
    fn nothing_matching_leaves_the_decision_to_the_caller() {
        let sets = sets(&["port(443) -> block"]);
        let trace = explain(&sets, &facts(80));
        assert_eq!(trace.decided_by, None);
        assert!(trace.outbound.is_none());
        assert!(trace.rules.iter().all(|rule| !rule.fired));
        assert!(trace.shadowed().is_empty());
    }

    #[test]
    fn the_display_is_readable_and_names_every_rule() {
        let sets = sets(&["port(443) -> block", "port(80) -> direct"]);
        let rendered = explain(&sets, &facts(80)).to_string();
        assert!(rendered.contains("rule 0 [skipped]"), "{rendered}");
        assert!(rendered.contains("rule 1 [fired]"), "{rendered}");
        assert!(rendered.contains("x port(443)"), "{rendered}");
        assert!(
            rendered.contains("-> port(443) did not match"),
            "{rendered}"
        );
    }
}
