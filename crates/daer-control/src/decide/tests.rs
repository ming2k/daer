use super::*;

#[test]
fn the_trace_and_the_verdict_never_disagree() {
    // Two ways of asking the same question must not diverge: the trace is what a
    // bug report is diagnosed with, the verdict is what the data path acts on.
    let router = router(TWO_RULES);
    for port in [80u16, 443, 8080] {
        let (source, destination) = flow(port);
        let verdict = router.verdict_for(source, destination);
        let trace = router.trace(source, destination);
        assert_eq!(trace.decided_by, verdict.rule, "port {port}");
        assert_eq!(
            trace.outbound.map(|outbound| outbound.name),
            Some(verdict.outbound.name),
            "the trace must report the effective outbound, fallback included (port {port})"
        );
    }
}

#[test]
fn the_explanation_carries_the_predicate_that_blocked_a_rule() {
    let router = router(TWO_RULES);
    let (source, destination) = flow(80);
    let explanation = router.explain(source, destination);

    let skipped = &explanation.trace.rules[0];
    assert_eq!(skipped.rule, 0);
    let blocking = skipped.blocking().expect("a blocking predicate");
    assert_eq!(blocking.predicate, "dport(443)");
}

fn router(src: &str) -> Router {
    let config = daer_config::toml_config::load_str(src).expect("config loads");
    Router::new(&config, GenerationId::new(7), &RouterOptions::default()).expect("router builds")
}

fn flow(destination_port: u16) -> (SocketAddr, SocketAddr) {
    (
        "192.168.1.10:41234".parse().expect("source"),
        SocketAddr::from(([93, 184, 216, 34], destination_port)),
    )
}

const TWO_RULES: &str = r#"
[routing]
fallback = "direct"

[[routing.rule]]
name = "https-block"
match = "dport(443)"
action = "block"

[[routing.rule]]
name = "http-direct"
match = "dport(80)"
action = "direct"
"#;

#[test]
fn a_verdict_names_the_rule_that_decided() {
    let router = router(TWO_RULES);

    let (source, destination) = flow(443);
    let verdict = router.verdict_for(source, destination);
    assert_eq!(verdict.rule, Some(0));
    assert_eq!(&*verdict.outbound.name, "block");
    assert_eq!(verdict.describe(), "rule 0");

    let (source, destination) = flow(80);
    let verdict = router.verdict_for(source, destination);
    assert_eq!(verdict.rule, Some(1));
    assert_eq!(&*verdict.outbound.name, "direct");
    assert_eq!(verdict.describe(), "rule 1");
}

#[test]
fn an_unmatched_flow_is_attributed_to_the_fallback() {
    let router = router(TWO_RULES);
    let (source, destination) = flow(8080);
    let verdict = router.verdict_for(source, destination);
    assert_eq!(verdict.rule, None, "no rule matched");
    assert_eq!(verdict.describe(), "fallback");
    assert_eq!(&*verdict.outbound.name, "direct");
}

#[test]
fn an_explanation_names_the_configured_rule() {
    let router = router(TWO_RULES);
    let (source, destination) = flow(443);
    let explanation = router.explain(source, destination);

    assert_eq!(explanation.rule, Some(0));
    assert_eq!(explanation.rule_name.as_deref(), Some("https-block"));
    // The explanation reports the rule as written: canonical predicate name and
    // typed action, not an internal index.
    assert_eq!(
        explanation.rule_text, "dport(443) -> block",
        "the evaluated rule text, not an internal index"
    );
    assert_eq!(&*explanation.outbound.name, "block");

    let rendered = explanation.to_string();
    assert!(rendered.contains("decided by"), "{rendered}");
    assert!(rendered.contains("dport(443) -> block"), "{rendered}");
    assert!(rendered.contains("gen7"), "{rendered}");
}

#[test]
fn an_explanation_of_a_fallback_says_so() {
    let router = router(TWO_RULES);
    let (source, destination) = flow(8080);
    let explanation = router.explain(source, destination);
    assert_eq!(explanation.rule, None);
    assert_eq!(explanation.rule_text, "fallback -> direct");
    assert_eq!(&*explanation.outbound.name, "direct");
    // The fallback is a rule like any other; naming it is not a failure.
    assert!(explanation.to_string().contains("fallback -> direct"));
}

#[test]
fn an_explanation_lists_the_groups_that_exist() {
    let router = router(
        r#"
[[node]]
tag = "n1"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[election]]
name = "proxy"
node = "n1"
type = "manual"

[routing]
fallback = { election = "proxy" }
"#,
    );
    let (source, destination) = flow(80);
    let explanation = router.explain(source, destination);
    assert_eq!(explanation.elections, ["proxy"]);
    assert_eq!(&*explanation.outbound.name, "proxy");
}

#[test]
fn a_domain_rule_only_matches_when_a_domain_is_supplied() {
    // The property the data path depends on: without a sniffed name a `domain(...)`
    // rule cannot fire, so it cannot route by a guess.
    let router = router(
        r#"
[routing.sniff]
enabled = true
timeout = "30ms"
[routing]
fallback = "direct"
[[routing.rule]]
name = "example-block"
match = "domain(example.com)"
action = "block"
"#,
    );
    let (source, destination) = flow(443);

    let without = router.verdict_with_domain(source, destination, None);
    assert_eq!(&*without.outbound.name, "direct", "no domain, no match");
    assert_eq!(without.rule, None);

    let with = router.verdict_with_domain(source, destination, Some("www.example.com"));
    assert_eq!(&*with.outbound.name, "block");
    assert_eq!(with.describe(), "rule 0", "the domain rule fired");

    let other = router.verdict_with_domain(source, destination, Some("example.org"));
    assert_eq!(
        &*other.outbound.name, "direct",
        "a different name does not match"
    );
}

#[test]
fn sniffing_is_enabled_only_when_the_generation_asks_for_it() {
    // The plan is built once per generation; a configuration without domain rules
    // spends no syscall and no wait on name acquisition.
    let with_domain = router(
        "[routing.sniff]\nenabled = true\ntimeout = \"30ms\"\n[routing]\nfallback = \
             \"direct\"\n[[routing.rule]]\nname = \"domain\"\nmatch = \"domain(a)\"\n\
             action = \"direct\"\n",
    );
    assert!(with_domain.domain_plan().sniff_enabled());

    let without_domain = router(TWO_RULES);
    assert!(
        !without_domain.domain_plan().sniff_enabled(),
        "no domain rule, no sniffing cost"
    );
}

#[test]
fn a_domain_rule_without_an_explicit_answer_is_rejected() {
    let config = daer_config::toml_config::load_str(
        "[routing]\nfallback = \"direct\"\n[[routing.rule]]\nname = \"domain\"\n\
             match = \"domain(a)\"\naction = \"direct\"\n",
    )
    .expect_err("the loader must reject the missing answer");
    assert!(
        config.to_string().contains("routing.sniff.enabled"),
        "{config}"
    );
}

#[test]
fn an_explanation_can_show_what_a_sniffed_name_changed() {
    let router = router(
        r#"
[routing.sniff]
enabled = true
timeout = "30ms"
[routing]
fallback = "direct"
[[routing.rule]]
name = "example-block"
match = "domain(example.com)"
action = "block"
"#,
    );
    let (source, destination) = flow(443);
    let explanation = router.explain_with_domain(source, destination, Some("api.example.com"));
    assert_eq!(explanation.rule, Some(0));
    assert_eq!(explanation.rule_text, "domain(example.com) -> block");
    assert_eq!(&*explanation.outbound.name, "block");
}

#[test]
fn the_router_reports_the_generation_it_serves() {
    let router = router(TWO_RULES);
    assert_eq!(router.generation(), GenerationId::new(7));
    assert_eq!(router.generation().to_string(), "gen7");
}

#[test]
fn facts_carry_the_tuple_and_leave_the_unknowns_unknown() {
    let (source, destination) = flow(443);
    let facts = facts_with_kernel(
        source,
        destination,
        None,
        L4ProtoMask::TCP,
        KernelFacts::default(),
    );
    assert_eq!(facts.source_port, 41_234);
    assert_eq!(facts.dest_port, 443);
    assert_eq!(facts.l4proto, L4ProtoMask::TCP);
    // The ingress cannot know these; a rule that needs them must not match.
    assert!(facts.domain.is_none());
    assert!(facts.process_name.is_unspecified());
    assert_eq!(facts.dscp, 0);
    assert_eq!(facts.mac, MacAddr([0; 6]));
}

/// An observer that reports fixed facts, standing in for the datapath's map.
#[derive(Debug)]
struct FixedObserver(KernelFacts);

impl KernelObserver for FixedObserver {
    fn observe(
        &self,
        _source: SocketAddr,
        _destination: SocketAddr,
        _l4proto: u8,
    ) -> Option<KernelFacts> {
        Some(self.0)
    }
}

#[test]
fn a_mac_rule_matches_only_when_the_datapath_supplied_the_mac() {
    // The falsifier for the silently-inert rule class. `mac(...)` was compiled into the
    // userspace half of a partitioned policy, and `MatchFacts` was built with `[0; 6]`, so
    // the rule could never fire: a configuration that read "this device goes direct"
    // proxied it instead, with no warning and no log line.
    let source = r#"
[[node]]
name = "n1"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[election]]
name = "proxy"
node = "n1"
type = "manual"

[routing]
fallback = { election = "proxy" }
[[routing.rule]]
name = "mac-block"
match = "mac(00:11:22:33:44:55)"
action = "block"
"#;
    let (from, to) = flow(443);

    // Without an observer: the rule cannot fire, and the fallback applies.
    let blind = router(source);
    assert_eq!(
        &*blind.verdict_for_flow(from, to, None).outbound.name,
        "proxy"
    );

    // With the datapath's facts: the rule fires.
    let mut name = [0u8; daer_routing::TASK_COMM_LEN];
    name[..4].copy_from_slice(b"curl");
    let observer = Arc::new(FixedObserver(KernelFacts {
        mac: MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        dscp: 0,
        process_name: daer_routing::ProcessName::from_bytes_truncated(&name),
    }));
    let config = daer_config::toml_config::load_str(source).expect("config loads");
    let seeing = Router::new(
        &config,
        GenerationId::new(7),
        &RouterOptions::default().with_kernel_observer(Some(observer)),
    )
    .expect("router builds");
    assert_eq!(
        &*seeing.verdict_for_flow(from, to, None).outbound.name,
        "block"
    );
}

#[test]
fn a_pname_rule_matches_only_when_the_datapath_supplied_the_process() {
    let source = r#"
[[node]]
name = "n1"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[election]]
name = "proxy"
node = "n1"
type = "manual"

[routing]
fallback = { election = "proxy" }
[[routing.rule]]
name = "curl-block"
match = "pname(curl)"
action = "block"
"#;
    let (from, to) = flow(443);
    let mut name = [0u8; daer_routing::TASK_COMM_LEN];
    name[..4].copy_from_slice(b"curl");

    let observer = Arc::new(FixedObserver(KernelFacts {
        mac: MacAddr([0; 6]),
        dscp: 0,
        process_name: daer_routing::ProcessName::from_bytes_truncated(&name),
    }));
    let config = daer_config::toml_config::load_str(source).expect("config loads");
    let router = Router::new(
        &config,
        GenerationId::new(7),
        &RouterOptions::default().with_kernel_observer(Some(observer)),
    )
    .expect("router builds");
    assert_eq!(
        &*router.verdict_for_flow(from, to, None).outbound.name,
        "block"
    );

    // A different process name must not match, which is what proves the rule is reading
    // the fact rather than the presence of an observer.
    let other = Arc::new(FixedObserver(KernelFacts::default()));
    let config = daer_config::toml_config::load_str(source).expect("config loads");
    let router = Router::new(
        &config,
        GenerationId::new(7),
        &RouterOptions::default().with_kernel_observer(Some(other)),
    )
    .expect("router builds");
    assert_eq!(
        &*router.verdict_for_flow(from, to, None).outbound.name,
        "proxy"
    );
}

#[test]
fn a_pid_of_zero_reports_the_process_name_as_unknown() {
    // `pid == 0` means the process was not observed for this socket even when the
    // cgroup hooks are attached, and the C leaves `pname` empty. Treating the empty
    // array as a name would let `pname()` match an empty string.
    let result = daer_ebpf::abi::RoutingResult {
        pid: 0,
        pname: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
        mac: [1, 2, 3, 4, 5, 6],
        dscp: 46,
        ..daer_ebpf::abi::RoutingResult::default()
    };
    let facts = KernelFacts::from_handoff(&result);
    assert!(facts.process_name.is_unspecified());
    // The MAC and DSCP are still real: they come from the packet, not from the hooks.
    assert_eq!(facts.mac, MacAddr([1, 2, 3, 4, 5, 6]));
    assert_eq!(facts.dscp, 46);
}

#[test]
fn a_runtime_election_overrides_the_configured_rule() {
    let router = router(
        "schema = 5\n\n\
             [[node]]\nname = \"n1\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\n\
             [[node]]\nname = \"n2\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\n\n\
             [[group]]\nname = \"pool\"\n\n\
             [[election]]\nname = \"proxy\"\ngroup = \"pool\"\ntype = \"min\"\n\n\
             [routing]\nfallback = { election = \"proxy\" }\n",
    );
    router.elect("proxy", "n2").expect("n2 is a candidate");
    assert_eq!(router.node_identity("proxy").unwrap().node, "n2");
    assert!(router.elect("proxy", "missing").is_err());
    router.reset_election("proxy").expect("resets");
    assert!(router.node_identity("proxy").is_some());
    assert!(router.reset_election("missing").is_err());
}

#[test]
fn a_detoured_node_reports_its_inner_hop() {
    let router = router(
        "schema = 5\n\n\
             [[node]]\nname = \"inner\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\n\
             [[node]]\nname = \"outer\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\ndetour = \"inner\"\n\n\
             [[group]]\nname = \"proxy-pool\"\nfilters = [\"name(outer)\"]\n\n\
             [[election]]\nname = \"proxy\"\ngroup = \"proxy-pool\"\ntype = \"random\"\n\n\
             [routing]\nfallback = { election = \"proxy\" }\n",
    );
    let identity = router.node_identity("proxy").expect("selection");
    assert_eq!(identity.node, "outer");
    assert_eq!(identity.detour.as_deref(), Some("inner"));
    let nodes = router.nodes();
    assert_eq!(nodes.len(), 2, "both resources are visible: {nodes:#?}");
    let outer = nodes
        .iter()
        .find(|node| node.node == "outer")
        .expect("outer is in the catalog");
    assert_eq!(outer.detour.as_deref(), Some("inner"));
}

#[test]
fn a_broken_detour_fails_the_generation_instead_of_dropping_the_node() {
    let config = daer_config::toml_config::load_str(
            "schema = 5\n\n\
             [[node]]\nname = \"outer\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\ndetour = \"missing\"\n\n\
             [[group]]\nname = \"proxy-pool\"\nfilters = [\"name(outer)\"]\n\n\
             [[election]]\nname = \"proxy\"\ngroup = \"proxy-pool\"\ntype = \"random\"\n\n\
             [routing]\nfallback = { election = \"proxy\" }\n",
        )
        .expect("parses");
    let error = Router::new(&config, GenerationId::new(7), &RouterOptions::default())
        .expect_err("an explicitly named missing hop is not an unselectable leaf");
    assert!(error.to_string().contains("missing"), "{error}");
}
