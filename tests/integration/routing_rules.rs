// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end routing tests: config text -> decode -> optimize -> lower ->
//! userspace decision.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use daer_config::{Config, OutboundAction};
use daer_primitives::{MacAddr, PortRange};
use daer_routing::{
    DeduplicateParamsOptimizer, L4ProtoMask, MatchFacts, NormalizedProgram, PolicyEpoch,
    PolicyIdentity, ProcessName, RecordingSink, RulesBuilder, SortFunctionsOptimizer, evaluate,
};

const CONFIG: &str = r#"
[[group]]
name = "pool"

[[election]]
name = "proxy"
group = "pool"
type = "random"

[[election]]
name = "my_group"
group = "pool"
type = "random"

[routing]
default = "my_group"

[routing.sniff]
enabled = true
timeout = "30ms"

[[routing.rule]]
name = "network-manager"
match = "pname(NetworkManager)"
action = "direct"

[[routing.rule]]
name = "multicast"
match = "dip(224.0.0.0/3, 'ff00::/8')"
action = "direct"

[[routing.rule]]
name = "quic"
match = "l4proto(udp) && dport(443)"
action = "block"

[[routing.rule]]
name = "example-proxy"
match = "domain(example.com)"
action = "proxy"
"#;

fn config(src: &str) -> Config {
    daer_config::toml_config::load_str(src).expect("loads")
}

fn program() -> NormalizedProgram {
    let config = config(CONFIG);
    NormalizedProgram::new(
        &config.routing.rule,
        config.routing.default.clone(),
        &[&SortFunctionsOptimizer, &DeduplicateParamsOptimizer],
    )
    .expect("normalizes")
}

fn base_facts() -> MatchFacts<'static> {
    MatchFacts {
        source_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        dest_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        source_port: 40000,
        dest_port: 80,
        l4proto: L4ProtoMask::TCP,
        domain: None,
        process_name: ProcessName::from_bytes_truncated(b"firefox"),
        dscp: 0,
        mac: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    }
}

fn decide(
    program: &NormalizedProgram,
    facts: &MatchFacts<'_>,
) -> Option<(std::sync::Arc<str>, u32, bool)> {
    let mut sink = RecordingSink::default();
    {
        let mut builder = RulesBuilder::new(&mut sink);
        program
            .lower(&mut builder, |_fallback| Ok(()))
            .expect("lowers");
    }
    assert!(sink.warnings.is_empty(), "warnings: {:?}", sink.warnings);
    evaluate(&sink.matches, facts).ok().map(|result| {
        (
            result.outbound.name,
            result.outbound.mark,
            result.outbound.must,
        )
    })
}

#[test]
fn matches_process_name() {
    let program = program();
    let mut facts = base_facts();
    facts.process_name = ProcessName::from_bytes_truncated(b"NetworkManager");
    assert_eq!(
        decide(&program, &facts),
        Some((std::sync::Arc::from("direct"), 0, false))
    );
}

#[test]
fn matches_multicast_by_lpm_prefix() {
    let program = program();
    let mut facts = base_facts();
    facts.dest_addr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
    assert_eq!(
        decide(&program, &facts),
        Some((std::sync::Arc::from("direct"), 0, false))
    );

    let mut facts = base_facts();
    facts.dest_addr = IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1));
    assert_eq!(
        decide(&program, &facts),
        Some((std::sync::Arc::from("direct"), 0, false))
    );
}

#[test]
fn matches_and_of_l4proto_and_port() {
    let program = program();
    let mut facts = base_facts();
    facts.l4proto = L4ProtoMask::UDP;
    facts.dest_port = 443;
    assert_eq!(
        decide(&program, &facts),
        Some((std::sync::Arc::from("block"), 0, false))
    );

    // TCP on the same port must not hit the block rule.
    facts.l4proto = L4ProtoMask::TCP;
    assert_eq!(decide(&program, &facts), None);
}

#[test]
fn matches_domain_and_carries_mark_and_must() {
    let program = program();
    let mut facts = base_facts();
    facts.domain = Some("a.b.example.com");
    assert_eq!(
        decide(&program, &facts),
        Some((std::sync::Arc::from("proxy"), 0, false))
    );
}

#[test]
fn unmatched_flows_fall_through() {
    let program = program();
    assert_eq!(decide(&program, &base_facts()), None);
    assert_eq!(
        program.fallback,
        OutboundAction::Election("my_group".to_owned())
    );
}

#[test]
fn port_ranges_match_inclusively() {
    let config = config(
        "[routing]\ndefault = \"block\"\n[[routing.rule]]\nname = \"range\"\n\
             match = \"dport(8000-8010)\"\naction = \"direct\"\n",
    );
    let program = NormalizedProgram::new(
        &config.routing.rule,
        config.routing.default.clone(),
        &[&SortFunctionsOptimizer],
    )
    .expect("normalizes");

    for (port, expected) in [
        (7999, None),
        (8000, Some("direct")),
        (8010, Some("direct")),
        (8011, None),
    ] {
        let mut facts = base_facts();
        facts.dest_port = port;
        assert_eq!(
            decide(&program, &facts).map(|(name, _, _)| name),
            expected.map(std::sync::Arc::from),
            "port {port}"
        );
    }
}

#[test]
fn source_port_and_source_ip_are_supported() {
    let config = config(
        "[routing]\ndefault = \"block\"\n[[routing.rule]]\nname = \"source\"\n\
         match = \"sip(10.0.0.0/8) && sport(1024-2048)\"\naction = \"direct\"\n",
    );
    let program = NormalizedProgram::new(
        &config.routing.rule,
        config.routing.default.clone(),
        &[&SortFunctionsOptimizer],
    )
    .expect("normalizes");

    let mut facts = base_facts();
    facts.source_addr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    facts.source_port = 1500;
    assert_eq!(
        decide(&program, &facts).map(|(name, _, _)| name),
        Some(std::sync::Arc::from("direct"))
    );

    facts.source_port = 3000;
    assert_eq!(decide(&program, &facts), None);
}

#[test]
fn ip_version_matching() {
    let config = config(
        "[routing]\ndefault = \"block\"\n[[routing.rule]]\nname = \"v6\"\n\
         match = \"ipversion(6)\"\naction = \"direct\"\n",
    );
    let program = NormalizedProgram::new(
        &config.routing.rule,
        config.routing.default.clone(),
        &[&SortFunctionsOptimizer],
    )
    .expect("normalizes");

    let mut facts = base_facts();
    facts.dest_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert_eq!(
        decide(&program, &facts).map(|(name, _, _)| name),
        Some(std::sync::Arc::from("direct"))
    );

    facts.dest_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert_eq!(decide(&program, &facts), None);
}

#[test]
fn policy_identity_tracks_rule_changes() {
    let first = PolicyIdentity::new(PolicyEpoch(1), &program()).expect("hash");
    let second = PolicyIdentity::new(PolicyEpoch(2), &program()).expect("hash");
    assert_eq!(first.hash(), second.hash());

    let changed = {
        let config = config(
            "[routing]\ndefault = \"direct\"\n[[routing.rule]]\nname = \"https\"\n\
                 match = \"dport(443)\"\naction = \"direct\"\n",
        );
        NormalizedProgram::new(
            &config.routing.rule,
            config.routing.default.clone(),
            &[&SortFunctionsOptimizer],
        )
        .expect("normalizes")
    };
    let third = PolicyIdentity::new(PolicyEpoch(3), &changed).expect("hash");
    assert_ne!(first.hash(), third.hash());
}

#[test]
fn port_range_type_is_shared_with_the_abi() {
    // The same type is used for `struct port_range` in the kernel ABI.
    let range: PortRange = "8000-9000".parse().expect("parses");
    assert_eq!(std::mem::size_of_val(&range), 4);
    assert!(range.contains(8000) && range.contains(9000) && !range.contains(9001));
}
