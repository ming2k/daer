// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical form and interval decomposition are the two properties every DRB artifact and
//! every kernel policy table depend on ([INV-DRB-01], [INV-PARTITION-01]).
//!
//! The falsifiers are concrete:
//!
//! * two rule sets with the same members but different insertion order must render identical
//!   bytes, or "deterministic artifacts" is false;
//! * a decomposition must cover the requested interval exactly and contiguously, because a
//!   gap silently stops matching an address the operator wrote;
//! * canonicalisation must be idempotent and survive a render/parse round trip, because a
//!   reload compares the canonical form, not the source text.
//!
//! The interval corpus is generated with a fixed linear congruential sequence rather than a
//! property-testing dependency: the seed is in the test, so a failure is reproducible.

use std::str::FromStr;

use daer_rule_ast::{
    DomainPattern, DomainRule, RuleSet, decompose_v4_interval, decompose_v6_interval,
};

fn domain(text: &str) -> DomainRule {
    DomainRule::new(DomainPattern::from_str(text).expect("domain pattern parses"))
}

/// A fixed-seed LCG. The point is reproducibility, not statistical quality.
fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

#[test]
fn canonical_form_does_not_depend_on_insertion_order() {
    let mut forward = RuleSet::new("order");
    forward.push_v4_range(10, 20);
    forward.push_v4_range(0, 9);
    forward.push_v4_range(5, 15);
    forward.push_v4_range(30, 40);
    forward.push_v4_range(22, 29);
    forward.push_domain(domain("Example.COM"));
    forward.push_domain(domain(".EXAMPLE.com"));
    forward.push_domain(domain("example.com"));
    forward.push_domain(domain("=Api.Example.com"));

    let mut backward = RuleSet::new("order");
    backward.push_domain(domain("=Api.Example.com"));
    backward.push_domain(domain("example.com"));
    backward.push_domain(domain(".EXAMPLE.com"));
    backward.push_domain(domain("Example.COM"));
    backward.push_v4_range(22, 29);
    backward.push_v4_range(30, 40);
    backward.push_v4_range(5, 15);
    backward.push_v4_range(0, 9);
    backward.push_v4_range(10, 20);

    let forward = forward.canonical().expect("canonicalises");
    let backward = backward.canonical().expect("canonicalises");

    assert_eq!(
        forward.v4_intervals(),
        &[(0, 20), (22, 40)],
        "overlapping and adjacent ranges must collapse to the same merged intervals"
    );
    assert_eq!(
        forward, backward,
        "the canonical form must not depend on insertion order"
    );
    assert_eq!(forward.render(), backward.render());
    assert_eq!(
        forward.domains().len(),
        3,
        "the duplicate suffix must be removed while the distinct scopes stay"
    );

    let reparsed = RuleSet::parse(&forward.render())
        .expect("canonical output must parse")
        .canonical()
        .expect("canonicalises again");
    assert_eq!(forward, reparsed, "canonicalisation must be idempotent");
}

#[test]
fn every_decomposed_ipv4_range_is_exact_contiguous_and_bounded() {
    let mut state = 0x5eed_1234_abcd_0001;
    for _ in 0..512 {
        let a = next(&mut state) as u32;
        let b = next(&mut state) as u32;
        let (start, end) = if a <= b { (a, b) } else { (b, a) };

        let cidrs = decompose_v4_interval(start, end);
        assert!(!cidrs.is_empty(), "a non-empty range must decompose");

        let mut cursor = u64::from(start);
        for cidr in &cidrs {
            let network = u64::from(u32::from(cidr.network()));
            let size = 1u64 << (32 - cidr.prefix_len());
            assert_eq!(
                network, cursor,
                "the decomposition has a gap or an overlap at {start}..={end}"
            );
            assert_eq!(
                network % size,
                0,
                "a CIDR must be aligned to its own size: {cidr}"
            );
            cursor = network + size;
        }
        assert_eq!(
            cursor - 1,
            u64::from(end),
            "the decomposition must end exactly at the requested end"
        );
        assert!(
            cidrs.len() <= 64,
            "a minimal decomposition of a 32-bit interval needs at most 2*32 CIDRs, got {}",
            cidrs.len()
        );
    }
}

#[test]
fn every_decomposed_ipv6_range_is_exact_contiguous_and_bounded() {
    let mut state = 0xfeed_0000_0000_00aa;
    for _ in 0..512 {
        let high = u128::from(next(&mut state)) << 64;
        let low = u128::from(next(&mut state));
        let a = high | low;
        let high = u128::from(next(&mut state)) << 64;
        let low = u128::from(next(&mut state));
        let b = high | low;
        let (start, end) = if a <= b { (a, b) } else { (b, a) };

        // A full-space random range can be enormous; 512 deterministic samples stay fast and
        // still exercise alignment, adjacency and crossing bit boundaries.
        let cidrs = decompose_v6_interval(start, end);
        assert!(!cidrs.is_empty(), "a non-empty range must decompose");

        let mut cursor = start;
        for cidr in &cidrs {
            let network = cidr.network();
            assert_eq!(
                u128::from(network),
                cursor,
                "the decomposition has a gap or an overlap at {start}..={end}"
            );
            let size = 1u128 << (128 - cidr.prefix_len());
            assert_eq!(
                u128::from(network) % size,
                0,
                "a CIDR must be aligned to its own size: {cidr}"
            );
            let Some(next) = cursor.checked_add(size) else {
                break;
            };
            cursor = next;
        }

        if let Some(last) = cidrs.last() {
            let size = 1u128 << (128 - last.prefix_len());
            let last_end = u128::from(last.network()).saturating_add(size - 1);
            assert_eq!(
                last_end, end,
                "the decomposition must end exactly at the requested end"
            );
        }
        assert!(
            cidrs.len() <= 256,
            "a minimal decomposition of a 128-bit interval needs at most 2*128 CIDRs, got {}",
            cidrs.len()
        );
    }
}
