// SPDX-License-Identifier: AGPL-3.0-only

//! The kernel policy table, against the userspace evaluator (ADR-0005).
//!
//! This is the test the ADR's acceptance criterion names, and it is built so that it can fail:
//!
//! 1. [`kernel_eval`] is a line-by-line transcription of `route_loop_cb` +
//!    `route_eval_match` + `route_finalize_match` from `ebpf/kern/tproxy.c`, reading the bytes
//!    [`daer_routing::kernel::compile`] produced. It knows nothing about `MatchSet`.
//! 2. A corpus of flows is generated from the same rules the policy was compiled from.
//! 3. For every flow the transcription and [`daer_routing::first_hit`] must agree on the
//!    outbound, and the policy must say it is `equivalent` (or must defer for *every* flow).
//!
//! Two failure modes are covered and they are different:
//!
//! * the encoder writes a layout the C would misread (caught when the transcription and
//!   `first_hit` disagree);
//! * the encoder claims equivalence for something it dropped (caught by the `equivalent`
//!   assertion plus the deferral check).
//!
//! Without a compiled object the layout assertions skip, exactly like `daer-ebpf`'s object
//! tests; the equivalence assertions never skip, because they are pure logic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use daer_common::{MacAddr, PortRange};
use daer_ebpf::abi::{MAX_MATCH_SET_LEN, MatchSet as KernelMatchSet, match_type, outbound};
use daer_routing::kernel::{self, DeferReason, Policy};
use daer_routing::{
    L4ProtoMask, MatchFacts, MatchSet, NormalizedProgram, Outbound, ProcessName, RecordingSink,
    RulesBuilder,
};

/// The compiled table.
///
/// The reverse outbound mapping now lives *in* the policy (`Policy::outbounds`), so a test cannot
/// build a second table that disagrees with what the encoder produced.
struct Compiled {
    policy: Policy,
}

/// Lowers `rules` exactly as the daemon does, then compiles the kernel table.
fn compile(rules: &[&str], fallback: &str) -> (Vec<MatchSet>, Outbound, Compiled) {
    let parsed: Vec<_> = rules
        .iter()
        .map(|rule| daer_config::parse_rule_expr(rule).expect("rule parses"))
        .collect();
    let program = NormalizedProgram::new(
        &parsed,
        daer_config::FunctionOrString::Name(fallback.to_owned()),
        &[
            &daer_routing::AliasOptimizer,
            &daer_routing::MergeAndSortOptimizer,
            &daer_routing::DeduplicateParamsOptimizer,
        ],
    )
    .expect("normalizes");

    let mut sink = RecordingSink::default();
    let mut builder = RulesBuilder::new(&mut sink);
    let fallback_outbound = Outbound {
        name: std::sync::Arc::from(fallback),
        mark: 0,
        must: false,
    };
    program
        .lower(&mut builder, |_| Ok(()))
        .expect("lowers the rules");

    // The rule a match-set index belongs to. The lowering emits sets in rule order, one per
    // predicate operand, so walking the rules and counting their operands recovers it.
    let mut boundaries = Vec::with_capacity(parsed.len());
    let mut accumulated = 0usize;
    for rule in &parsed {
        accumulated += operand_count(rule);
        boundaries.push(accumulated);
    }
    let rule_of = move |index: usize| {
        boundaries
            .iter()
            .position(|boundary| index < *boundary)
            .unwrap_or(boundaries.len())
    };

    let policy = kernel::compile(&sink.matches, &fallback_outbound, rule_of);
    (sink.matches, fallback_outbound, Compiled { policy })
}

/// How many match sets one rule lowers to.
///
/// One per `(function, parameter key)` group, which is the same count `RulesBuilder` emits. The
/// factors are counted the same way the builder groups them: by parameter key.
fn operand_count(rule: &daer_config::RoutingRule) -> usize {
    rule.and_functions
        .iter()
        .map(|function| {
            let mut keys: Vec<&str> = Vec::new();
            for param in &function.params {
                if !keys.contains(&param.key.as_str()) {
                    keys.push(param.key.as_str());
                }
            }
            keys.len().max(1)
        })
        .sum()
}

// ---------------------------------------------------------------------------------------------
// The transcription of the C.
// ---------------------------------------------------------------------------------------------

/// One flow, in the terms the datapath has.
///
/// `l4proto` is the C's `enum L4ProtoType` — a **bitmask** (`TCP = 1`, `UDP = 2`), not an IP
/// protocol number. Getting that wrong is not a detail: `6 & 2` is nonzero, so a corpus that
/// fed `IPPROTO_TCP` here would make every `l4proto(udp)` rule appear to match TCP and the
/// equivalence test would fail on a rule set that is actually correct.
#[derive(Clone, Copy)]
struct Flow {
    saddr: IpAddr,
    daddr: IpAddr,
    sport: u16,
    dport: u16,
    l4proto: u8,
    ip_version: u8,
    dscp: u8,
    mac: MacAddr,
    pname: ProcessName,
}

/// What the transcription decided.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The datapath's `route()` returned a verdict: the outbound byte plus flags.
    Routed { outbound: u8, mark: u32, must: bool },
    /// No rule hit: `route()` returns `-EPERM`, which every caller turns into `TC_ACT_SHOT`.
    Drop,
    /// The datapath asked the control plane to decide (`OUTBOUND_CONTROL_PLANE_ROUTING`).
    Defer,
}

/// `route_loop_cb` + `route_eval_match` + `route_finalize_match`, transcribed.
fn kernel_eval(policy: &Policy, flow: &Flow) -> Verdict {
    let mut good_subrule = false;
    let mut bad_rule = false;
    let mut is_must = false;

    for (index, set) in policy.entries.iter().enumerate() {
        let index = index as u32;

        if !bad_rule && !good_subrule && eval_match(policy, set, index, flow) {
            good_subrule = true;
        }

        if set.outbound == outbound::LOGICAL_OR {
            // The C only resets the subrule when the marker is *not* LOGICAL_OR.
            continue;
        }

        if good_subrule == set.negated {
            bad_rule = true;
        }
        good_subrule = false;

        if set.outbound & outbound::LOGICAL_OR != outbound::LOGICAL_OR {
            // Tail of a rule.
            if !bad_rule {
                if set.outbound == outbound::MUST_RULES {
                    is_must = true;
                    continue;
                }
                is_must |= set.must;
                if set.outbound == outbound::CONTROL_PLANE_ROUTING {
                    return Verdict::Defer;
                }
                return Verdict::Routed {
                    outbound: set.outbound,
                    mark: set.mark,
                    must: is_must,
                };
            }
            bad_rule = false;
        }
    }
    Verdict::Drop
}

/// `route_eval_match`, per `MatchType`.
fn eval_match(policy: &Policy, set: &KernelMatchSet, index: u32, flow: &Flow) -> bool {
    match set.kind {
        match_type::IP_SET => lpm_contains(policy, index, flow.daddr),
        match_type::SOURCE_IP_SET => lpm_contains(policy, index, flow.saddr),
        match_type::MAC => lpm_contains_mac(policy, index, flow.mac),
        match_type::PORT => {
            let (start, end) = set.port_range().expect("a port set carries a range");
            flow.dport >= start && flow.dport <= end
        }
        match_type::SOURCE_PORT => {
            let (start, end) = set.port_range().expect("a source-port set carries a range");
            flow.sport >= start && flow.sport <= end
        }
        match_type::L4_PROTO => {
            let mask = set.operand[0];
            flow.l4proto & mask != 0
        }
        match_type::IP_VERSION => {
            let mask = set.operand[0];
            flow.ip_version & mask != 0
        }
        match_type::DSCP => flow.dscp == set.operand[0],
        match_type::PROCESS_NAME => {
            !flow.pname.is_unspecified() && set.operand[..16] == flow.pname.0[..]
        }
        // `MatchType_Fallback` always matches; a DomainSet needs `domain_routing_map`, which a
        // deferring policy never publishes (and a split policy never contains).
        match_type::FALLBACK => true,
        match_type::DOMAIN_SET => panic!("a split policy must not contain a domain set"),
        other => panic!("unexpected match type {other}"),
    }
}

/// Longest-prefix membership in one entry's trie, with the datapath's fixed-width search key.
fn lpm_contains(policy: &Policy, index: u32, addr: IpAddr) -> bool {
    let keys = policy
        .lpms
        .iter()
        .find(|(entry, _)| *entry == index)
        .map(|(_, keys)| keys.as_slice())
        .unwrap_or(&[]);
    let lookup = kernel::lookup_key(addr);
    keys.iter().any(|entry| prefix_covers(entry, &lookup))
}

fn lpm_contains_mac(policy: &Policy, index: u32, mac: MacAddr) -> bool {
    let keys = policy
        .lpms
        .iter()
        .find(|(entry, _)| *entry == index)
        .map(|(_, keys)| keys.as_slice())
        .unwrap_or(&[]);
    let lookup = daer_ebpf::abi::LpmKey::lookup_mac(mac);
    keys.iter().any(|entry| prefix_covers(entry, &lookup))
}

/// Does a trie entry match a lookup key? The kernel compares the first `prefix_len` bits.
fn prefix_covers(entry: &daer_ebpf::abi::LpmKey, lookup: &daer_ebpf::abi::LpmKey) -> bool {
    let bits = entry.prefix_len as usize;
    if bits > 128 {
        return false;
    }
    let whole = bits / 8;
    let rest = bits % 8;
    if entry.data[..whole] != lookup.data[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    entry.data[whole] & mask == lookup.data[whole] & mask
}

// ---------------------------------------------------------------------------------------------
// The corpus.
// ---------------------------------------------------------------------------------------------

fn facts(flow: &Flow) -> MatchFacts<'static> {
    MatchFacts {
        source_addr: flow.saddr,
        dest_addr: flow.daddr,
        source_port: flow.sport,
        dest_port: flow.dport,
        // The C's mask and the userspace mask use the same bit values, so this is a
        // translation of *representation*, not of meaning.
        l4proto: match flow.l4proto {
            L4_TCP => L4ProtoMask::TCP,
            L4_UDP => L4ProtoMask::UDP,
            other => L4ProtoMask(other),
        },
        domain: None,
        process_name: flow.pname,
        dscp: flow.dscp,
        mac: flow.mac,
    }
}

/// The datapath's `L4ProtoType` values.
const L4_TCP: u8 = 1;
const L4_UDP: u8 = 2;

fn flows() -> Vec<Flow> {
    let mut out = Vec::new();
    let dests = [
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    let sources = [
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 9)),
    ];
    let pnames = [
        ProcessName::from_bytes_truncated(b"firefox"),
        ProcessName::from_bytes_truncated(b"curl"),
    ];
    let macs = [
        MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        MacAddr::UNSPECIFIED,
    ];
    for daddr in dests {
        for saddr in sources {
            for dport in [22u16, 53, 80, 443, 8080] {
                for l4proto in [L4_TCP, L4_UDP] {
                    for dscp in [0u8, 10] {
                        for pname in pnames {
                            for mac in macs {
                                out.push(Flow {
                                    saddr,
                                    daddr,
                                    sport: 40000,
                                    dport,
                                    l4proto,
                                    ip_version: if daddr.is_ipv4() { 1 } else { 2 },
                                    dscp,
                                    mac,
                                    pname,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The assertions.
// ---------------------------------------------------------------------------------------------

/// For a rule set the kernel can represent, every flow must get the same answer both ways.
#[test]
fn the_kernel_and_userspace_agree_on_every_representable_rule_set() {
    let rule_sets: &[(&[&str], &str)] = &[
        (
            &["dport(53) -> direct", "dip(10.0.0.0/8) -> block"],
            "proxy",
        ),
        (
            &["dip(192.168.0.0/16) -> direct", "sip(10.0.0.0/8) -> block"],
            "proxy",
        ),
        (&["l4proto(udp) -> block", "dport(443) -> proxy"], "direct"),
        (&["ipversion(4) && dport(80) -> block"], "proxy"),
        (&["dscp(10) -> block"], "direct"),
        (&[r#"mac("aa:bb:cc:dd:ee:ff") -> block"#], "direct"),
        (&["pname(firefox) -> direct"], "proxy"),
        (&["dip(2001:db8::/32) -> block"], "proxy"),
        (&["port(22, 80, 443) -> direct"], "block"),
        (&["!dip(10.0.0.0/8) && dport(443) -> proxy"], "direct"),
    ];

    for (rules, fallback) in rule_sets {
        let (sets, fallback_outbound, compiled) = compile(rules, fallback);
        let policy = &compiled.policy;

        if !policy.equivalent {
            // Not representable: the *whole* table must defer, otherwise a flow would be
            // decided by a kernel that does not have the rules it claims to have.
            assert!(
                policy.entries.len() == 1
                    && policy.entries[0].kind == match_type::FALLBACK
                    && policy.entries[0].outbound == outbound::CONTROL_PLANE_ROUTING,
                "a non-equivalent policy must be exactly the defer entry, got {:?}",
                policy.entries
            );
            for flow in flows() {
                assert_eq!(
                    kernel_eval(policy, &flow),
                    Verdict::Defer,
                    "{rules:?}: a deferring table must defer every flow"
                );
            }
            continue;
        }

        let ids = &policy.outbounds;
        for flow in flows() {
            let kernel = kernel_eval(policy, &flow);
            let userspace = daer_routing::first_hit(&sets, &facts(&flow))
                .map(|hit| hit.outbound)
                .unwrap_or_else(|| fallback_outbound.clone());

            match kernel {
                Verdict::Defer => panic!("{rules:?}: a split table must not defer"),
                Verdict::Drop => panic!(
                    "{rules:?}: the kernel would drop a flow userspace sends to {}",
                    userspace.name
                ),
                Verdict::Routed {
                    outbound: id,
                    mark,
                    must,
                } => {
                    let name = ids.name(id).map_or_else(
                        || match id {
                            outbound::DIRECT => "direct".to_owned(),
                            outbound::BLOCK => "block".to_owned(),
                            other => panic!("kernel returned reserved id {other}"),
                        },
                        ToOwned::to_owned,
                    );
                    assert_eq!(
                        name,
                        *userspace.name,
                        "{rules:?}: flow {:?}->{:?}:{} dport {} l4 {}: kernel says {name}, \
                         userspace says {}",
                        flow.saddr,
                        flow.daddr,
                        flow.sport,
                        flow.dport,
                        flow.l4proto,
                        userspace.name
                    );
                    assert_eq!(mark, userspace.mark, "{rules:?}: mark differs");
                    assert_eq!(must, userspace.must, "{rules:?}: must differs");
                }
            }
        }
    }
}

/// A rule the kernel cannot represent defers the *whole* program, with a reason that names it.
#[test]
fn a_domain_rule_defers_and_says_why() {
    let (_sets, _fallback, compiled) = compile(&["domain(suffix:example.com) -> direct"], "proxy");
    let policy = &compiled.policy;
    assert!(!policy.equivalent);
    assert_eq!(
        policy.reasons,
        vec![DeferReason::Domain { rule: 0 }],
        "the reason must name the rule that forced the deferral"
    );
    for flow in flows() {
        assert_eq!(kernel_eval(policy, &flow), Verdict::Defer);
    }
}

#[test]
fn a_process_name_rule_defers_and_says_why() {
    let (_sets, _fallback, compiled) = compile(&["pname(firefox) -> direct"], "proxy");
    assert!(!compiled.policy.equivalent);
    assert_eq!(
        compiled.policy.reasons,
        vec![DeferReason::ProcessName { rule: 0 }]
    );
}

/// A deferring policy still cannot be mistaken for a decision: its only entry is the marker.
#[test]
fn a_defer_entry_is_recognisably_a_deferral() {
    let policy = Policy::defer(vec![DeferReason::Domain { rule: 2 }]);
    assert_eq!(policy.rules_len(), 1);
    assert_eq!(policy.entries[0].kind, match_type::FALLBACK);
    assert_eq!(policy.entries[0].outbound, outbound::CONTROL_PLANE_ROUTING);
    assert!(!policy.is_split());
    assert!(policy.reasons[0].to_string().contains("rule 2"));
}

/// The fallback must be an entry, or the kernel's last resort is `-EPERM` → drop.
#[test]
fn an_unmatched_flow_reaches_the_fallback_instead_of_being_dropped() {
    // No rule can match a flow with this shape, so userspace falls back — and the kernel must
    // do the same, through the `MatchType_Fallback` entry, rather than returning EPERM.
    let (_sets, _fallback, compiled) = compile(&["dport(1) -> block"], "proxy");
    let flow = Flow {
        saddr: IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        daddr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        sport: 40000,
        dport: 443,
        l4proto: L4_TCP,
        ip_version: 1,
        dscp: 0,
        mac: MacAddr::UNSPECIFIED,
        pname: ProcessName::from_bytes_truncated(b"curl"),
    };
    // `compile` allocates ids as it encodes, so the reverse map has to be used from the policy
    // itself — a second table built by the test could disagree and prove nothing.
    let ids = &compiled.policy.outbounds;
    match kernel_eval(&compiled.policy, &flow) {
        Verdict::Routed { outbound: id, .. } => {
            assert_eq!(
                ids.name(id),
                Some("proxy"),
                "the fallback entry must select the configured fallback"
            );
        }
        other => panic!("expected the fallback to route, got {other:?}"),
    }
}

/// The routing table key is `slot * MAX_MATCH_SET_LEN + index`, and both tables use it.
#[test]
fn the_table_keys_are_what_the_datapath_computes() {
    assert_eq!(Policy::key(0, 0), 0);
    assert_eq!(Policy::key(0, 1023), 1023);
    assert_eq!(Policy::key(1, 0), MAX_MATCH_SET_LEN as u32);
    assert_eq!(Policy::key(1, 5), MAX_MATCH_SET_LEN as u32 + 5);
    // `lpm_array_map` is addressed identically; a divergence here would make every IP rule
    // read another rule's trie.
    for slot in 0..2u32 {
        for index in [0u32, 1, 1023] {
            assert_eq!(Policy::lpm_key(slot, index), Policy::key(slot, index));
        }
    }
}

/// The outbound id window is the datapath's, and exhausting it is a deferral, not a wrap.
#[test]
fn outbound_ids_stay_inside_the_datapaths_window() {
    let mut ids = kernel::OutboundIds::default();
    let count = usize::from(outbound::LAST_GROUP - outbound::FIRST_GROUP) + 1;
    for index in 0..count {
        let outbound = Outbound {
            name: std::sync::Arc::from(format!("g{index}").as_str()),
            mark: 0,
            must: false,
        };
        let id = ids
            .id_for_test(&outbound)
            .unwrap_or_else(|| panic!("id {index} must fit"));
        assert!((outbound::FIRST_GROUP..=outbound::LAST_GROUP).contains(&id));
    }
    let overflow = Outbound {
        name: std::sync::Arc::from("one-too-many"),
        mark: 0,
        must: false,
    };
    assert!(
        ids.id_for_test(&overflow).is_none(),
        "the id window must not wrap"
    );
}

/// The encoder's byte layout is the object's, read from the object itself when there is one.
#[test]
fn the_encoded_bytes_are_the_objects_layout() {
    let Some(object) = object() else {
        eprintln!("skipping the object half: build it with `cargo xtask ebpf`");
        return;
    };

    let routing = object
        .maps
        .get(daer_ebpf::names::map::ROUTING)
        .expect("the object has routing_map");
    assert_eq!(
        routing.value_size(),
        daer_ebpf::abi::MATCH_SET_SIZE as u32,
        "struct match_set is not {} bytes in this object",
        daer_ebpf::abi::MATCH_SET_SIZE
    );

    // The slot count and the per-slot bound are what the grader and the encoder assume.
    let expected =
        u32::try_from(MAX_MATCH_SET_LEN).expect("fits") * daer_ebpf::abi::ROUTING_EPOCH_SLOTS;
    assert_eq!(
        routing.max_entries(),
        expected,
        "the object was built with a different MAX_MATCH_SET_LEN; rebuild with -DMAX_MATCH_SET_LEN={MAX_MATCH_SET_LEN}"
    );
}

/// A compiled policy's bytes round-trip through the object's widths.
#[test]
fn every_entry_is_exactly_one_match_set_wide() {
    let (_sets, _fallback, compiled) = compile(&["dport(443) -> proxy"], "direct");
    for entry in &compiled.policy.entries {
        assert_eq!(entry.to_bytes().len(), daer_ebpf::abi::MATCH_SET_SIZE);
    }
    for (_, keys) in &compiled.policy.lpms {
        for key in keys {
            assert_eq!(key.to_bytes().len(), daer_ebpf::abi::LPM_KEY_SIZE);
        }
    }
}

/// `PortRange` is the two `__u16`s the C reads, at the offset the union starts at.
#[test]
fn a_port_operand_is_two_native_u16s() {
    // `port(8000, 8100)` lowers to **one set per range**, with all but the last marked
    // `LogicalOr` — so this is also a check that the marker does not eat its own operand.
    let (_sets, _fallback, compiled) = compile(&["port(8000, 8100) -> direct"], "block");
    let ranges: Vec<_> = compiled
        .policy
        .entries
        .iter()
        .filter(|entry| entry.kind == match_type::PORT)
        .filter_map(daer_ebpf::abi::MatchSet::port_range)
        .collect();
    assert_eq!(ranges, vec![(8000, 8000), (8100, 8100)]);

    // The range occupies bytes 0..4 of the union, which is where the C's `port_range` starts.
    let entry = compiled
        .policy
        .entries
        .iter()
        .find(|entry| entry.kind == match_type::PORT)
        .expect("a port entry");
    let mut expected = [0u8; 4];
    expected[0..2].copy_from_slice(&8000u16.to_ne_bytes());
    expected[2..4].copy_from_slice(&8000u16.to_ne_bytes());
    assert_eq!(&entry.operand[..4], &expected);
    assert_eq!(PortRange::new(8000, 8100).start, 8000);
}

/// ADR-0011 ([INV-PARTITION-01]): prefix rules execute in kernel; unencodable rules defer.
#[test]
fn a_partitioned_policy_executes_prefix_in_kernel_and_defers_suffix() {
    let rules = &[
        "dport(22) -> direct",
        "dip(192.168.0.0/16) -> direct",
        "domain(suffix: example.com) -> proxy",
        "dip(10.0.0.0/8) -> block",
    ];
    let (_sets, _fallback, compiled) = compile(rules, "proxy");
    let policy = &compiled.policy;

    // Policy is partitioned: not globally equivalent, but has active prefix entries.
    assert!(!policy.equivalent);
    assert!(policy.is_partitioned());
    assert_eq!(policy.reasons.len(), 1);
    assert!(matches!(policy.reasons[0], DeferReason::Domain { rule: 2 }));

    // Rule 0 (dport 22) + Rule 1 (dip 192.168.0.0/16) + Deferral Gate = 3 entries.
    assert_eq!(policy.entries.len(), 3);
    assert_eq!(policy.entries[2].kind, match_type::FALLBACK);
    assert_eq!(policy.entries[2].outbound, outbound::CONTROL_PLANE_ROUTING);

    // 1. Flow matching Rule 0 (dport 22): must be routed directly in kernel!
    let flow_ssh = Flow {
        saddr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        daddr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        sport: 40000,
        dport: 22,
        l4proto: L4_TCP,
        ip_version: 1,
        dscp: 0,
        mac: MacAddr::UNSPECIFIED,
        pname: ProcessName::default(),
    };
    match kernel_eval(policy, &flow_ssh) {
        Verdict::Routed { outbound: id, .. } => {
            assert_eq!(
                id,
                outbound::DIRECT,
                "SSH traffic must route direct in kernel"
            );
        }
        other => panic!("expected kernel Routed, got {other:?}"),
    }

    // 2. Flow matching Rule 1 (192.168.1.100:80): must be routed directly in kernel!
    let flow_lan = Flow {
        saddr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        daddr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        sport: 40000,
        dport: 80,
        l4proto: L4_TCP,
        ip_version: 1,
        dscp: 0,
        mac: MacAddr::UNSPECIFIED,
        pname: ProcessName::default(),
    };
    match kernel_eval(policy, &flow_lan) {
        Verdict::Routed { outbound: id, .. } => {
            assert_eq!(
                id,
                outbound::DIRECT,
                "LAN traffic must route direct in kernel"
            );
        }
        other => panic!("expected kernel Routed, got {other:?}"),
    }

    // 3. Flow not matching Rule 0 or Rule 1 (1.1.1.1:443): must hit deferral gate!
    let flow_wan = Flow {
        saddr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        daddr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        sport: 40000,
        dport: 443,
        l4proto: L4_TCP,
        ip_version: 1,
        dscp: 0,
        mac: MacAddr::UNSPECIFIED,
        pname: ProcessName::default(),
    };
    assert_eq!(
        kernel_eval(policy, &flow_wan),
        Verdict::Defer,
        "traffic passing prefix rules must hit deferral gate"
    );
}

fn object() -> Option<aya_obj::Object> {
    let path = std::env::var("DAER_EBPF_OBJECT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/ebpf/datapath.o")
        });
    if !path.is_file() {
        return None;
    }
    let bytes = std::fs::read(&path).expect("reads the object");
    let bytes = daer_ebpf::normalize_section_names(&bytes).expect("normalizes sections");
    Some(aya_obj::Object::parse(&bytes).expect("parses"))
}
