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
default = "direct"

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
name = "n1"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[election]]
name = "proxy"
node = "n1"
type = "manual"

[routing]
default = "proxy"
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
default = "direct"
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
        "[routing.sniff]\nenabled = true\ntimeout = \"30ms\"\n[routing]\ndefault = \
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
        "[routing]\ndefault = \"direct\"\n[[routing.rule]]\nname = \"domain\"\n\
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
default = "direct"
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
default = "proxy"
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
default = "proxy"
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
        "schema = 6\n\n\
             [[node]]\nname = \"n1\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\n\
             [[node]]\nname = \"n2\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\n\n\
             [[group]]\nname = \"pool\"\n\n\
             [[election]]\nname = \"proxy\"\ngroup = \"pool\"\ntype = \"min\"\n\n\
             [routing]\ndefault = \"proxy\"\n",
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
        "schema = 6\n\n\
             [[node]]\nname = \"inner\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\n\
             [[node]]\nname = \"outer\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\ndetour = \"inner\"\n\n\
             [[group]]\nname = \"proxy-pool\"\nfilters = [\"name(outer)\"]\n\n\
             [[election]]\nname = \"proxy\"\ngroup = \"proxy-pool\"\ntype = \"random\"\n\n\
             [routing]\ndefault = \"proxy\"\n",
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
            "schema = 6\n\n\
             [[node]]\nname = \"outer\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1081\ndetour = \"missing\"\n\n\
             [[group]]\nname = \"proxy-pool\"\nfilters = [\"name(outer)\"]\n\n\
             [[election]]\nname = \"proxy\"\ngroup = \"proxy-pool\"\ntype = \"random\"\n\n\
             [routing]\ndefault = \"proxy\"\n",
        )
        .expect("parses");
    let error = Router::new(&config, GenerationId::new(7), &RouterOptions::default())
        .expect_err("an explicitly named missing hop is not an unselectable leaf");
    assert!(error.to_string().contains("missing"), "{error}");
}

#[tokio::test]
async fn direct_unwraps_fake_ip_to_real_upstream_address_and_preserves_literal_ips() {
    #[derive(Debug)]
    struct StaticUpstream(std::net::Ipv4Addr);

    impl daer_dns::Upstream for StaticUpstream {
        fn exchange<'a>(&'a self, query: &'a daer_dns::Message) -> daer_dns::ExchangeFuture<'a> {
            let mut reply = daer_dns::Message::reply_to(query, daer_dns::ResponseCode::NOERROR);
            if let Some(question) = query.questions.first() {
                reply.answers.push(daer_dns::Record {
                    name: question.name.clone(),
                    rtype: daer_dns::RecordType::A,
                    class: question.qclass,
                    ttl: 60,
                    rdata: self.0.octets().to_vec(),
                });
            }
            Box::pin(async move { Ok(reply) })
        }
    }

    let config = daer_config::toml_config::load_str(
        r#"
schema = 6

[dns]
bind = "127.0.0.1"
upstream = ["cn:udp://223.5.5.5:53"]

[dns.fake-ip]
enabled = true
inet = "198.18.0.0/15"

[dns.request]
rules = []
default = "cn"

[dns.response]
rules = []
default = "accept"

[routing]
default = "direct"
"#,
    )
    .expect("parses");

    let real_ip: std::net::Ipv4Addr = "220.181.38.148".parse().expect("real ip");
    let resolver = Arc::new(
        daer_dns::Resolver::new(
            &config,
            [(
                "cn".to_owned(),
                Arc::new(StaticUpstream(real_ip)) as Arc<dyn daer_dns::Upstream>,
            )],
        )
        .expect("resolver builds"),
    );
    let options = RouterOptions::default()
        .with_fake_ip(Some(Arc::clone(resolver.fake_ip())))
        .with_dns_snooper(Some(Arc::clone(resolver.snooper())))
        .with_dns_resolver(Some(Arc::clone(&resolver)));
    let router = Router::new(&config, GenerationId::new(1), &options).expect("router builds");

    let fake_ip = resolver.fake_ip().allocate("www.baidu.com");
    let fake_dest = SocketAddr::new(std::net::IpAddr::V4(fake_ip), 443);

    // 1. Fake-IP + domain -> resolves to real upstream IP (never dials 198.18.x.x).
    let resolved = router
        .resolve_direct_destination(
            daer_observe::FlowId::new(1),
            fake_dest,
            Some("www.baidu.com"),
            Some(DomainSource::FakeIp),
        )
        .await
        .expect("fake-ip unwraps to real ip");
    assert_eq!(
        resolved,
        SocketAddr::new(std::net::IpAddr::V4(real_ip), 443)
    );

    // 2. Real IP (e.g. DnsSnooper / Sniff) -> preserved literally without re-resolving.
    let literal_dest: SocketAddr = "1.2.3.4:443".parse().expect("literal");
    let preserved = router
        .resolve_direct_destination(
            daer_observe::FlowId::new(2),
            literal_dest,
            Some("www.baidu.com"),
            Some(DomainSource::DnsSnooper),
        )
        .await
        .expect("literal ip preserved");
    assert_eq!(preserved, literal_dest);

    // 3. Negative control: Fake-IP with no domain mapping fails fast instead of dialing 198.18.x.x.
    let err = router
        .resolve_direct_destination(daer_observe::FlowId::new(3), fake_dest, None, None)
        .await
        .expect_err("fake-ip without domain must fail");
    assert!(err.to_string().contains("no domain mapping"), "{err}");
}

async fn minimal_socks5_server() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("socks5 binds");
    let addr = listener.local_addr().expect("socks5 addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                if stream.read_exact(&mut hdr).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; hdr[1] as usize];
                if stream.read_exact(&mut methods).await.is_err() {
                    return;
                }
                // Reply: version 5, no auth.
                if stream.write_all(&[5, 0]).await.is_err() {
                    return;
                }
                let mut req = [0u8; 4];
                if stream.read_exact(&mut req).await.is_err() {
                    return;
                }
                let rest_len = match req[3] {
                    1 => 4 + 2,
                    4 => 16 + 2,
                    3 => {
                        let mut len = [0u8; 1];
                        if stream.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        len[0] as usize + 2
                    }
                    _ => return,
                };
                let mut rest = vec![0u8; rest_len];
                if stream.read_exact(&mut rest).await.is_err() {
                    return;
                }
                // Reply: succeeded, IPv4 0.0.0.0:0.
                let _ = stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn router_passive_cooldown_fails_over_after_threshold_and_respects_zero_disable() {
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds dead port");
    let dead_addr = dead_listener.local_addr().expect("addr");
    drop(dead_listener);

    let live_addr = minimal_socks5_server().await;
    let config_for = |threshold: u32| {
        format!(
            r#"
schema = 6
dial-timeout = "2s"
tcp-keepalive = "15s"

[[node]]
name = "dead"
type = "socks5"
server = "{}"
port = {}

[[node]]
name = "live"
type = "socks5"
server = "{}"
port = {}

[[group]]
name = "pool"

[[election]]
name = "proxy"
group = "pool"
type = "min"
interval = "30s"
failure-threshold = {threshold}
cooldown = "30s"

[routing]
default = "proxy"
"#,
            dead_addr.ip(),
            dead_addr.port(),
            live_addr.ip(),
            live_addr.port(),
        )
    };

    let dest: SocketAddr = "93.184.216.34:443".parse().expect("dest");

    // 1. threshold = 2 -> two failures trip cooldown and fail over cleanly to "live".
    let r = router(&config_for(2));
    assert!(
        r.record(
            "proxy",
            DialerId(0),
            true,
            Some(daer_config::TimeSpan::from_millis(1))
        )
        .is_ok()
    );
    assert!(
        r.record(
            "proxy",
            DialerId(1),
            true,
            Some(daer_config::TimeSpan::from_millis(50))
        )
        .is_ok()
    );
    assert!(
        r.connect_through_election(
            daer_observe::FlowId::new(1),
            dest,
            "proxy",
            "93.184.216.34:443"
        )
        .await
        .is_err()
    );
    assert!(
        r.connect_through_election(
            daer_observe::FlowId::new(2),
            dest,
            "proxy",
            "93.184.216.34:443"
        )
        .await
        .is_err()
    );
    assert_eq!(
        r.node_identity("proxy").map(|n| n.node),
        Some("live".to_owned()),
        "dead node in cooldown must yield to healthy candidate"
    );
    r.connect_through_election(
        daer_observe::FlowId::new(3),
        dest,
        "proxy",
        "93.184.216.34:443",
    )
    .await
    .expect("3rd flow fails over to healthy node");

    // 2. Falsifier: failure-threshold = 0 disables cooldown, so 3rd attempt still picks "dead".
    let disabled = router(&config_for(0));
    assert!(
        disabled
            .record(
                "proxy",
                DialerId(0),
                true,
                Some(daer_config::TimeSpan::from_millis(1))
            )
            .is_ok()
    );
    assert!(
        disabled
            .record(
                "proxy",
                DialerId(1),
                true,
                Some(daer_config::TimeSpan::from_millis(50))
            )
            .is_ok()
    );
    for i in 1..=3 {
        assert!(
            disabled
                .connect_through_election(
                    daer_observe::FlowId::new(i),
                    dest,
                    "proxy",
                    "93.184.216.34:443"
                )
                .await
                .is_err()
        );
    }
    assert_eq!(
        disabled.node_identity("proxy").map(|n| n.node),
        Some("dead".to_owned())
    );
}
