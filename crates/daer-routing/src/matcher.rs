// SPDX-License-Identifier: AGPL-3.0-only

//! Lowered match sets and the userspace evaluator.
//!
//! The decision loop is a direct port of `RoutingMatcher.Match` in
//! `control/routing_matcher_userspace.go`, which is itself a copy of the loop in
//! `control/kern/tproxy.c`. Keep the three in sync.
//!
//! # Why the values are compiled types
//!
//! A match set holds an *index*, not a list. `IpIndex` and `DomainIndex` do their
//! work at construction, so a decision costs one hash per distinct prefix length
//! and one hash per label instead of one comparison per prefix or pattern. The
//! semantics of the loop below are unchanged; only the cost of asking a predicate
//! "do you match?" is.

use std::net::IpAddr;
use std::sync::Arc;

use daer_common::{MacAddr, PortRange};

use crate::domain::DomainIndex;
use crate::error::RoutingError;
use crate::ipset::IpIndex;
use crate::outbound::{CONTROL_PLANE_ROUTING, MUST_RULES, MatchTarget, Outbound};
use crate::values::{IpVersionMask, L4ProtoMask, ProcessName};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchValue {
    IpSet(IpIndex),
    SourceIpSet(IpIndex),
    Mac(Vec<MacAddr>),
    Port(PortRange),
    SourcePort(PortRange),
    L4Proto(L4ProtoMask),
    IpVersion(IpVersionMask),
    ProcessName(ProcessName),
    Dscp(u8),
    Domain(DomainIndex),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchSet {
    pub value: MatchValue,
    pub target: MatchTarget,
    /// Set by the `!` operator on the function that produced this set.
    pub negated: bool,
}

/// The packet facts a routing decision is made from.
#[derive(Debug, Clone, Copy)]
pub struct MatchFacts<'a> {
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub source_port: u16,
    pub dest_port: u16,
    pub l4proto: L4ProtoMask,
    pub domain: Option<&'a str>,
    pub process_name: ProcessName,
    pub dscp: u8,
    pub mac: MacAddr,
}

impl MatchFacts<'_> {
    fn ip_version(&self) -> IpVersionMask {
        IpVersionMask::of(self.dest_addr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingResult {
    pub outbound: Outbound,
}

/// The rule that decided a flow, and what it decided.
///
/// The index is what makes a routing decision explainable: "this flow went to
/// `proxy`" is only actionable when you can also say *which* rule sent it there,
/// or that the fallback did. It is the first thing a bug report needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// 0-based index into the normalized program's rules.
    ///
    /// Deliberately not the match-set index: one rule lowers to several match sets
    /// (one per predicate), so a match-set index would be an internal detail no
    /// operator can map back to their configuration. This ordinal is
    /// `NormalizedProgram::rules[self.rule]`.
    pub rule: usize,
    pub outbound: Outbound,
}

impl Hit {
    /// `rule 7` for a rule, `fallback` when nothing matched.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("rule {}", self.rule)
    }
}

/// Evaluates the match sets in order and returns the first hit.
///
/// The fallback is `None`: a configuration's fallback is a rule that always
/// applies, so the caller decides what an unmatched flow becomes. [`evaluate`]
/// keeps the stricter signature for callers that treat "no match" as a bug.
///
/// # Errors
///
/// Returns an error when no rule matches (the caller then applies the program's
/// fallback) or when the set array is empty.
pub fn evaluate(sets: &[MatchSet], facts: &MatchFacts<'_>) -> Result<RoutingResult, RoutingError> {
    if sets.is_empty() {
        return Err(RoutingError::new("no compiled routing match set"));
    }
    first_hit(sets, facts)
        .map(|hit| RoutingResult {
            outbound: hit.outbound,
        })
        .ok_or_else(|| RoutingError::new("no match set hit"))
}

/// The first matching rule, or `None` when no rule applies.
///
/// This is the data-path entry point: a flow that matches nothing is not an error,
/// it is the fallback, and the caller supplies that.
///
/// The walk is allocation-free: the returned [`Outbound`] is a cheap clone of an
/// identity that was built once, at generation time.
#[must_use]
pub fn first_hit(sets: &[MatchSet], facts: &MatchFacts<'_>) -> Option<Hit> {
    let mut good_subrule = false;
    let mut bad_rule = false;
    let mut forced_must = false;
    // Counts rule terminators as they are passed. The old `rule_ordinal` re-scanned
    // the array prefix for every candidate, which made the walk quadratic in the
    // number of match sets — invisible at 10 rules, fatal at 1,500.
    let mut ordinal = 0usize;

    for set in sets {
        if !bad_rule && !good_subrule && matches_value(&set.value, facts) {
            good_subrule = true;
        }

        if !set.target.is_logical_or() {
            // The subrule reached its end: it holds only when the accumulated
            // match result differs from the negation flag.
            if good_subrule == set.negated {
                bad_rule = true;
            }
            good_subrule = false;
        }

        if set.target.is_logical() {
            continue;
        }

        // This set terminates a rule, so it is the `ordinal`-th terminator. The
        // ordinal is captured before the increment, because the rule being decided
        // is this one, not the next.
        let rule = ordinal;
        ordinal += 1;

        if bad_rule {
            bad_rule = false;
            continue;
        }

        match set.target.name() {
            Some(MUST_RULES) => {
                forced_must = true;
                continue;
            }
            Some(CONTROL_PLANE_ROUTING) => continue,
            _ => {}
        }

        let mut outbound = set.target.outbound()?.clone();
        outbound.must |= forced_must;
        return Some(Hit { rule, outbound });
    }

    None
}

/// Evaluates one match set's value against the facts.
///
/// Public because the explain pass has to replay exactly this evaluation; a second
/// implementation would be a second answer to the same question.
#[must_use]
pub fn matches_value(value: &MatchValue, facts: &MatchFacts<'_>) -> bool {
    match value {
        MatchValue::IpSet(index) => index.contains(facts.dest_addr),
        MatchValue::SourceIpSet(index) => index.contains(facts.source_addr),
        MatchValue::Mac(macs) => macs.contains(&facts.mac),
        MatchValue::Port(range) => range.contains(facts.dest_port),
        MatchValue::SourcePort(range) => range.contains(facts.source_port),
        MatchValue::L4Proto(mask) => facts.l4proto.intersects(*mask),
        MatchValue::IpVersion(mask) => facts.ip_version().intersects(*mask),
        MatchValue::ProcessName(name) => {
            !facts.process_name.is_unspecified() && *name == facts.process_name
        }
        MatchValue::Dscp(value) => facts.dscp == *value,
        MatchValue::Domain(patterns) => facts
            .domain
            .is_some_and(|domain| !domain.is_empty() && patterns.matches(domain)),
    }
}

/// Interns an outbound identity once per generation.
///
/// `Arc<str>` because an outbound name is immutable and shared by every flow that
/// selects it: cloning one is an atomic increment, not an allocation, which is what
/// keeps the decision path free of heap traffic.
#[must_use]
pub fn intern_outbound(name: &str, mark: u32, must: bool) -> Outbound {
    Outbound {
        name: Arc::from(name),
        mark,
        must,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::outbound::MatchTarget;

    #[test]
    fn a_hit_names_the_rule_not_the_match_set() {
        // Two rules, the first of which lowers to three match sets (two predicates
        // and a terminator). A match-set index would report 2 here; the rule the
        // operator wrote is 0, and that is what must be reported.
        let mut sink = crate::builder::RecordingSink::default();
        {
            let mut builder = crate::builder::RulesBuilder::new(&mut sink);
            // Two predicates in the first rule, so the lowered program has more
            // match sets than rules — the whole point of the assertion below.
            let rules = vec![
                daer_config::parse_rule_expr("port(80) && l4proto(tcp) -> direct").expect("parses"),
                daer_config::parse_rule_expr("port(443) -> block").expect("parses"),
            ];
            builder.apply(&rules).expect("lowers");
        }
        assert!(sink.matches.len() > 2, "{:?}", sink.matches.len());

        let mut facts = facts();
        facts.dest_port = 80;
        let hit = first_hit(&sink.matches, &facts).expect("hits");
        assert_eq!(hit.rule, 0, "first rule, whatever its match-set count");
        assert_eq!(&*hit.outbound.name, "direct");

        facts.dest_port = 443;
        let hit = first_hit(&sink.matches, &facts).expect("hits");
        assert_eq!(hit.rule, 1);
        assert_eq!(&*hit.outbound.name, "block");
    }

    #[test]
    fn no_hit_is_a_value_not_an_error() {
        // The data path needs "nothing matched" as a value: the fallback applies.
        // `evaluate` keeps the stricter signature for callers that treat it as a
        // bug, and both must agree on the same match sets.
        let sets: Vec<MatchSet> = Vec::new();
        let facts = facts();
        assert!(first_hit(&sets, &facts).is_none());
        assert!(evaluate(&sets, &facts).is_err());
    }

    fn facts() -> MatchFacts<'static> {
        MatchFacts {
            source_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            dest_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            source_port: 12345,
            dest_port: 443,
            l4proto: L4ProtoMask::TCP,
            domain: Some("example.com"),
            process_name: ProcessName::from_bytes_truncated(b"firefox"),
            dscp: 0,
            mac: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        }
    }

    fn set(value: MatchValue, target: MatchTarget, negated: bool) -> MatchSet {
        MatchSet {
            value,
            target,
            negated,
        }
    }

    fn outbound(name: &str) -> MatchTarget {
        MatchTarget::Outbound(intern_outbound(name, 0, false))
    }

    #[test]
    fn single_set_hits() {
        let sets = [set(
            MatchValue::Port(PortRange::single(443)),
            outbound("direct"),
            false,
        )];
        let result = evaluate(&sets, &facts()).expect("hits");
        assert_eq!(&*result.outbound.name, "direct");
    }

    #[test]
    fn a_miss_falls_through_to_a_later_rule() {
        let sets = [
            set(
                MatchValue::Port(PortRange::single(80)),
                outbound("block"),
                false,
            ),
            set(
                MatchValue::Port(PortRange::single(443)),
                outbound("direct"),
                false,
            ),
        ];
        let result = evaluate(&sets, &facts()).expect("hits");
        assert_eq!(&*result.outbound.name, "direct");
    }

    #[test]
    fn and_requires_every_function() {
        // port(443) && domain(suffix:example.com) -> direct
        let sets = [
            set(
                MatchValue::Port(PortRange::single(443)),
                MatchTarget::logical_and(0, false),
                false,
            ),
            set(MatchValue::Dscp(7), outbound("direct"), false),
        ];
        let error = evaluate(&sets, &facts()).expect_err("second function misses");
        assert_eq!(error.message, "no match set hit");

        let sets = [
            set(
                MatchValue::Port(PortRange::single(443)),
                MatchTarget::logical_and(0, false),
                false,
            ),
            set(MatchValue::Dscp(0), outbound("direct"), false),
        ];
        assert_eq!(&*evaluate(&sets, &facts()).unwrap().outbound.name, "direct");
    }

    #[test]
    fn or_within_one_function() {
        // port(80, 443) lowers to two sets: the first is LogicalOr.
        let sets = [
            set(
                MatchValue::Port(PortRange::single(80)),
                MatchTarget::logical_or(0, false),
                false,
            ),
            set(
                MatchValue::Port(PortRange::single(443)),
                outbound("direct"),
                false,
            ),
        ];
        assert_eq!(&*evaluate(&sets, &facts()).unwrap().outbound.name, "direct");
    }

    #[test]
    fn negation_inverts_the_subrule() {
        let sets = [set(
            MatchValue::Port(PortRange::single(443)),
            outbound("direct"),
            true,
        )];
        assert!(evaluate(&sets, &facts()).is_err());

        let sets = [set(
            MatchValue::Port(PortRange::single(80)),
            outbound("direct"),
            true,
        )];
        assert_eq!(&*evaluate(&sets, &facts()).unwrap().outbound.name, "direct");
    }

    #[test]
    fn must_rules_sets_force_the_must_flag() {
        let sets = [
            set(MatchValue::Dscp(0), outbound(MUST_RULES), false),
            set(MatchValue::Dscp(0), outbound("direct"), false),
        ];
        let result = evaluate(&sets, &facts()).expect("hits");
        assert_eq!(&*result.outbound.name, "direct");
        assert!(result.outbound.must);
    }

    #[test]
    fn empty_set_array_is_an_error() {
        assert!(evaluate(&[], &facts()).is_err());
    }

    #[test]
    fn the_rule_ordinal_is_counted_not_rescanned() {
        // Three rules with several match sets each: every ordinal must be exact.
        let mut sink = crate::builder::RecordingSink::default();
        {
            let mut builder = crate::builder::RulesBuilder::new(&mut sink);
            let rules = vec![
                daer_config::parse_rule_expr("port(1) && l4proto(tcp) && dscp(0) -> block")
                    .expect("parses"),
                daer_config::parse_rule_expr("port(2, 3) -> direct").expect("parses"),
                daer_config::parse_rule_expr("port(4) -> proxy").expect("parses"),
            ];
            builder.apply(&rules).expect("lowers");
        }
        for (port, expected_rule, expected_name) in
            [(1u16, 0usize, "block"), (3, 1, "direct"), (4, 2, "proxy")]
        {
            let mut facts = facts();
            facts.dest_port = port;
            let hit = first_hit(&sink.matches, &facts).expect("hits");
            assert_eq!(hit.rule, expected_rule, "port {port}");
            assert_eq!(&*hit.outbound.name, expected_name, "port {port}");
        }
    }
}
