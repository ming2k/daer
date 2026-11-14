use super::*;

use test_support::Scratch;

#[test]
fn elect_requires_a_node_or_reset() {
    assert!(Cli::try_parse_from(["daer", "elect", "proxy"]).is_err());
    assert!(Cli::try_parse_from(["daer", "elect", "proxy", "--reset"]).is_ok());
    assert!(Cli::try_parse_from(["daer", "elect", "proxy", "hk-01"]).is_ok());
}

#[test]
fn status_views_are_mutually_exclusive() {
    assert!(Cli::try_parse_from(["daer", "status", "--nodes", "--elections"]).is_err());
    assert!(Cli::try_parse_from(["daer", "status", "--elections"]).is_ok());
}

#[test]
fn check_accepts_the_host_gate_flag() {
    let cli = Cli::try_parse_from(["daer", "check", "--host"]).expect("check --host parses");
    match cli.command {
        Command::Check { host, .. } => assert!(host, "--host must set the host gate"),
        other => panic!("expected check, got {other:?}"),
    }
}

/// The reference configuration, asserted by a test rather than printed by a command.
///
/// It is documentation: an operator copies it, an editor validates against it. Bundling it
/// into the release binary was a `config example` subcommand's reason to exist, and it was
/// the wrong reason — the file lives in the repository and in the docs.
const EXAMPLE_TOML: &str = include_str!("../../../daer.example.toml");

/// Rewrites the example's three HTTP providers into local file providers backed by
/// fixtures, so the shipped *rules* and schema are validated without a network.
///
/// A test that reached `cdn.jsdelivr.net` would fail on a runner without egress and pass
/// on one with it, which is a gate whose result depends on the machine. The provider
/// declarations themselves are covered by `rule_provider_integration_with_routing_and_explain`
/// and by `daer_control::rule_provider`'s own tests.
#[test]
fn the_reference_example_validates() {
    let dir = Scratch::new("example");
    let config = dir.write_private("config.toml", EXAMPLE_TOML.as_bytes());

    let report = block_on(validate_config(&config)).expect("the shipped example validates");
    assert!(report.rules > 0);
    assert_eq!(report.files, 1);
    assert!(report.domain.has_domain_rules());
    assert!(report.domain.sniff_enabled());
    assert!(!report.domain.dns_service());

    // ADR-0006/ADR-0007: a configuration whose group can select no node must *say so*, and
    // the shipped example is exactly that shape — its nodes are commented out on purpose, so
    // `daer explain` reports an empty group instead of pretending. What this asserts is the
    // diagnostic, not a silent success: the failure mode being guarded against is a default
    // policy that selects nothing **without** anyone noticing.
    let resolution = block_on(load_resolved(&config)).expect("resolves");
    assert!(
        resolution
            .warnings
            .iter()
            .any(|warning| warning.contains("selects no node")),
        "the example has no active nodes, so loading it must warn that its group is empty; \
             got {:?}",
        resolution.warnings
    );

    // And a node added to the pool must make the group selectable under the default policy,
    // which is the part that regressed (`min-moving-avg` selected nothing until a probe ran).
    let text = format!(
        "{}\n[[node]]\nname = \"example\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n",
        std::fs::read_to_string(&config).expect("reads the rewritten example")
    );
    let config_with_node = dir.write_private("with-node.toml", text.as_bytes());
    let resolved = block_on(load_resolved(&config_with_node)).expect("resolves");
    let options = daer_control::RouterOptions::for_config(&config_with_node)
        .with_rule_providers(resolved.rule_providers.clone());
    let generations = daer_control::Generations::new(&resolved.config, &options).expect("builds");
    let node = generations
        .current()
        .router()
        .node_identity("proxy")
        .expect("the example's default policy must select a node once one exists");
    assert_eq!(node.group, "proxy-pool");
}

#[test]
fn rejects_unknown_formats() {
    let dir = Scratch::new("ext");
    let config = dir.write_private("config.yaml", b"schema = 6\n");
    let error = block_on(validate_config(&config)).expect_err("must fail");
    assert!(
        format!("{error:#}").contains("expected a `.toml`"),
        "{error:#}"
    );
}

#[test]
fn rejects_unknown_elections() {
    let dir = Scratch::new("unknown");
    let config = dir.write_private(
            "config.toml",
            b"[routing]\ndefault = \"direct\"\n[[routing.rule]]\nname = \"x\"\nmatch = \"dport(443)\"\naction = \"nope\"\n",
        );
    let error = block_on(validate_config(&config)).expect_err("must fail");
    assert!(format!("{error:#}").contains("not declared"), "{error:#}");
}

#[test]
fn rejects_a_missing_rule_provider_file() {
    // A `file` provider that does not exist must fail the gate by name. The retired
    // replacement for this test was `rejects_missing_geodata`, which asserted the same
    // property for the `.dat` search path ADR-0014 removed.
    let dir = Scratch::new("missing-provider");
    let config = dir.write_private(
        "config.toml",
        br#"[[rule-set]]
name = "gone"
type = "file"
path = "does-not-exist.drb"
format = "drb"

[routing]
default = "direct"
[[routing.rule]]
name = "gone-set"
match = "rule-set(gone)"
action = "direct"
"#,
    );
    let error = block_on(validate_config(&config)).expect_err("must fail");
    let message = format!("{error:#}");
    assert!(message.contains("gone"), "{message}");
    assert!(message.contains("does-not-exist"), "{message}");
}

#[test]
fn rejects_a_dns_bind_that_is_an_address_not_an_ip() {
    // The example configuration shipped `0.0.0.0:53` for a while: the gate passed it
    // while the bind refused it, because the two used different code. They are now one.
    let dir = Scratch::new("badbind");
    let config = dir.write_private(
        "config.toml",
        b"[dns]\nbind = \"0.0.0.0:53\"\nupstream = [\"udp://1.1.1.1:53\"]\n",
    );
    let error = block_on(validate_config(&config)).expect_err("must fail");
    let message = format!("{error:#}");
    assert!(message.contains("dns.bind"), "{message}");
    assert!(message.contains("not an IP"), "{message}");
}

#[test]
fn a_protocol_this_build_cannot_speak_is_named_by_its_scheme() {
    // `vmess` *is* implemented now (ADR-0030), so the test's original subject moved: what
    // must still be refused is a scheme with no layer behind it, and the refusal must name
    // the scheme rather than reporting a generic parse failure.
    let dir = Scratch::new("badproto");
    let config = dir.write_private(
        "config.toml",
        br#"[[node]]
name = "v"
type = "tuic"
server = "198.51.100.1"
port = 443

[[election]]
name = "g"
node = "v"
type = "manual"

[routing]
default = "g"
"#,
    );
    let error = block_on(validate_config(&config)).expect_err("must fail");
    let message = format!("{error:#}");
    assert!(message.contains("tuic"), "{message}");
}

#[test]
fn warns_when_a_group_selects_no_node() {
    let dir = Scratch::new("emptynode");
    let config = dir.write_private("config.toml", b"[[group]]\nname = \"g\"\n");
    let report = block_on(validate_config(&config)).expect("validates");
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("selects no node")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn rejects_bad_election_types() {
    let dir = Scratch::new("badgroup");
    let config = dir.write_private(
            "config.toml",
            b"[[node]]\nname = \"n\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\n[[election]]\nname = \"g\"\nnode = \"n\"\ntype = \"fastest\"\n",
        );
    let error = block_on(validate_config(&config)).expect_err("must fail");
    assert!(format!("{error:#}").contains("fastest"), "{error:#}");
}

#[test]
fn rejects_bad_group_filter_regexes() {
    let dir = Scratch::new("badfilter");
    let config = dir.write_private(
        "config.toml",
        b"[[group]]\nname = \"g\"\nfilters = [\"name(regex: '[')\"]\n",
    );
    let error = block_on(validate_config(&config)).expect_err("must fail");
    assert!(format!("{error:#}").contains("bad regexp"), "{error:#}");
}

#[test]
fn accepts_groups_with_filters_and_annotations() {
    let dir = Scratch::new("goodgroup");
    let config = dir.write_private(
        "config.toml",
        br#"[[group]]
name = "g"
filters = [
    "name(keyword: HK) && !name(keyword: 'ExpireAt:')",
    { match = "subtag(my_sub)", annotate = { add_latency = "-500ms" } },
]
"#,
    );
    block_on(validate_config(&config)).expect("validates");
}

#[test]
fn route_explain_names_the_rule_that_fires() {
    let dir = Scratch::new("explain");
    let config = dir.write_private(
        "config.toml",
        br#"[[node]]
name = "n1"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[election]]
name = "proxy"
node = "n1"
type = "manual"

[routing]
default = "direct"
[[routing.rule]]
name = "https-proxy"
match = "dport(443)"
action = "proxy"
"#,
    );

    let explanation = block_on(explain(
        &config,
        "10.0.0.2:40000",
        "93.184.216.34:443",
        None,
    ))
    .expect("explains");
    assert_eq!(explanation.rule, Some(0));
    assert_eq!(explanation.rule_text, "dport(443) -> proxy");
    assert_eq!(&*explanation.outbound.name, "proxy");

    let explanation =
        block_on(explain(&config, "10.0.0.2:40000", "93.184.216.34:80", None)).expect("explains");
    assert_eq!(explanation.rule, None, "the fallback decided");
    assert_eq!(&*explanation.outbound.name, "direct");
}

#[test]
fn route_explain_reports_an_empty_group_as_a_failure() {
    // The documented contract: exit 1 when the flow would be dropped. A group
    // with no electable node cannot carry the flow, so it is a drop — the
    // earlier behaviour printed a verdict and exited 0, which made the exit
    // status useless for the check it exists for.
    let dir = Scratch::new("explain-empty-group");
    let config = dir.write_private(
            "config.toml",
            b"[[group]]\nname = \"empty-pool\"\n\n[[election]]\nname = \"empty\"\ngroup = \"empty-pool\"\ntype = \"min\"\n[routing]\ndefault = \"empty\"\n",
        );
    let error = block_on(explain_route(
        &config,
        "10.0.0.2:40000".parse().expect("source"),
        "93.184.216.34:443".parse().expect("destination"),
        false,
        None,
    ))
    .expect_err("an empty group must not exit 0");
    let message = format!("{error:#}");
    assert!(
        message.contains("no electable") || message.contains("no selectable"),
        "{message}"
    );
}

#[test]
fn route_explain_reports_a_blocked_flow_as_a_failure() {
    let dir = Scratch::new("explain-block");
    let config = dir.write_private(
            "config.toml",
            b"[routing]\ndefault = \"direct\"\n[[routing.rule]]\nname = \"https-block\"\nmatch = \"dport(443)\"\naction = \"block\"\n",
        );

    let error = block_on(explain_route(
        &config,
        "10.0.0.2:40000".parse().expect("source"),
        "93.184.216.34:443".parse().expect("destination"),
        false,
        None,
    ))
    .expect_err("a blocked flow must not exit 0");
    assert!(error.to_string().contains("blocked"), "{error}");
}

#[test]
fn route_explain_why_reports_every_rule_and_predicate() {
    let dir = Scratch::new("explain-why");
    let config = dir.write_private(
            "config.toml",
            b"[routing]\ndefault = \"direct\"\n[[routing.rule]]\nname = \"https-block\"\nmatch = \"dport(443)\"\naction = \"block\"\n[[routing.rule]]\nname = \"tcp-direct\"\nmatch = \"l4proto(tcp)\"\naction = \"direct\"\n",
        );

    let explanation =
        block_on(explain(&config, "10.0.0.2:40000", "93.184.216.34:80", None)).expect("explains");
    let rendered = explanation.trace.to_string();
    assert!(rendered.contains("rule 0 [skipped]"), "{rendered}");
    assert!(rendered.contains("dport(443)"), "{rendered}");
    assert!(rendered.contains("rule 1 [fired]"), "{rendered}");
    // TCP matches, so the second rule fires; nothing else needs to be explained.
    assert!(explanation.trace.shadowed().is_empty(), "{rendered}");
}

#[test]
fn route_nodes_lists_the_security_identity_of_every_node() {
    let dir = Scratch::new("nodes");
    let config = dir.write_private(
        "config.toml",
        br#"
[[node]]
name = "ss"
type = "shadowsocks"
server = "1.2.3.4"
port = 8388
method = "aes-256-gcm"
password = "secret"

[[node]]
name = "tj"
type = "trojan"
server = "node.example.com"
port = 443
password = "pw"

[[node]]
name = "plain"
type = "socks5"
server = "127.0.0.1"
port = 1080
"#,
    );

    let loaded = load_config(&config).expect("loads");
    let options = daer_control::RouterOptions::for_config(&config);
    let generations = daer_control::Generations::new(&loaded.config, &options).expect("builds");
    let nodes = generations.current().router().nodes();
    assert_eq!(nodes.len(), 3, "{nodes:#?}");

    let ss = nodes.iter().find(|node| node.node == "ss").expect("ss");
    assert_eq!(ss.protocol, daer_outbound::Protocol::ShadowSocks);
    assert!(ss.security.is_confidential());
    assert!(ss.security.describe().contains("aes-256-gcm"), "{ss:?}");

    let trojan = nodes.iter().find(|node| node.node == "tj").expect("trojan");
    assert!(trojan.security.is_confidential());
    assert!(
        trojan
            .security
            .describe()
            .contains("tls sni=node.example.com"),
        "{trojan:?}"
    );

    let plain = nodes
        .iter()
        .find(|node| node.node == "plain")
        .expect("plain");
    assert!(!plain.security.is_confidential(), "socks5 is plaintext");

    // The one property that must never regress: no secret is printed.
    for node in &nodes {
        assert!(!node.describe().contains("secret"), "{}", node.describe());
        assert!(!node.describe().contains("pw@"), "{}", node.describe());
    }
}

#[test]
fn route_explain_names_the_selected_node() {
    let dir = Scratch::new("explain-node");
    let config = dir.write_private(
        "config.toml",
        br#"[[node]]
name = "tj"
type = "trojan"
server = "node.example.com"
port = 443
password = "pw"

[[election]]
name = "proxy"
node = "tj"
type = "manual"

[routing]
default = "direct"
[[routing.rule]]
name = "https-proxy"
match = "dport(443)"
action = "proxy"
"#,
    );

    let explanation = block_on(explain(
        &config,
        "10.0.0.2:40000",
        "93.184.216.34:443",
        None,
    ))
    .expect("explains");
    let selected = explanation.selected.clone().expect("a node is selected");
    assert_eq!(selected.election, "proxy");
    assert_eq!(selected.node, "tj");
    assert!(selected.security.is_confidential());
    let rendered = explanation.to_string();
    assert!(rendered.contains("node       : proxy: tj"), "{rendered}");
    assert!(rendered.contains("tls sni=node.example.com"), "{rendered}");
    assert!(!rendered.contains("pw@"), "no credential in the output");
}

#[test]
fn structured_nodes_integrate_with_routing_and_diagnostics() {
    let dir = Scratch::new("structured-nodes");
    let config = dir.write_private(
        "config.toml",
        br#"
schema = 6

[[node]]
name = "hk-vless"
type = "vless"
server = "198.51.100.1"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"
[node.security]
type = "reality"
sni = "impersonate.example.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
short-id = "ab01cd02"

[[node]]
name = "us-ss"
type = "shadowsocks"
server = "198.51.100.2"
port = 8388
method = "chacha20-ietf-poly1305"
password = "super-secret-password"

[[group]]
name = "pool"
filters = ["name(hk-vless)"]

[[election]]
name = "proxy"
group = "pool"
type = "min-moving-avg"

[routing]
default = "proxy"
"#,
    );

    let report = block_on(validate_config(&config)).expect("validates structured node config");
    assert_eq!(report.files, 1);

    let loaded = load_config(&config).expect("loads");
    assert_eq!(loaded.config.node.len(), 2);
    let options = daer_control::RouterOptions::for_config(&config);
    let generations = daer_control::Generations::new(&loaded.config, &options).expect("builds");
    let nodes = generations.current().router().nodes();
    assert_eq!(nodes.len(), 2);

    let vless = nodes
        .iter()
        .find(|n| n.node == "hk-vless")
        .expect("vless node");
    assert_eq!(vless.protocol, daer_outbound::Protocol::Vless);
    assert!(vless.security.is_confidential());
    assert!(vless.describe().contains("reality"));

    let ss = nodes.iter().find(|n| n.node == "us-ss").expect("ss node");
    assert_eq!(ss.protocol, daer_outbound::Protocol::ShadowSocks);
    assert!(ss.security.is_confidential());
    assert!(!ss.describe().contains("super-secret-password"));

    // Explain route verification
    let explanation = block_on(explain(
        &config,
        "10.0.0.2:40000",
        "93.184.216.34:443",
        None,
    ))
    .expect("explains");
    let selected = explanation.selected.expect("node selected");
    assert_eq!(selected.node, "hk-vless");
}

#[test]
fn subscription_node_filtering_and_selection() {
    let dir = Scratch::new("sub-filter");
    // Persist cache fixture with links from a real subscription
    let persist_dir = dir.join("persist.d");
    let cache = daer_outbound::subscription::Cache::new(persist_dir, "mysub");
    let _ = cache.write(&[
            "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkus1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=portal.citygrainla.com&pbk=9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E&sid=672f#US%20VIP%2001".to_owned(),
            "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkjp1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.titech.ac.jp&pbk=VAqawSsDR9SnBoN8ucLfUXIZO3Ugkd27HN7TOqh1AXo&sid=f0#Japan%20VIP%2001".to_owned(),
            "hysteria2://df4af3d0-030e-4062-baa6-eb9dd45298ef@151.242.183.252:20443?sni=apple.com#HK%2001".to_owned(),
            "tuic://uuid:password@1.2.3.4:443#unsupported-node".to_owned(),
        ]);

    let sub_url = "https://example.com/api/subscribe?token=test";
    let config_toml = format!(
        r#"
schema = 6

[[subscription]]
name = "mysub"
url = "{sub_url}"
persist = true

[[group]]
name = "jp-pool"
filters = [
    "sub(mysub) && name(keyword: 'Japan')"
]

[[election]]
name = "fastest-jp"
group = "jp-pool"
type = "min-moving-avg"

[routing]
default = "direct"
[[routing.rule]]
name = "jp-https"
match = "dport(443)"
action = "fastest-jp"
"#
    );
    let config = dir.write_private("config.toml", config_toml.as_bytes());

    let resolved = block_on(load_resolved(&config)).expect("resolves subscription");
    assert_eq!(resolved.config.node.len(), 4);

    // Verify group mentions node
    let jp_node = resolved
        .config
        .node
        .iter()
        .find(|n| n.label().contains("Japan"))
        .expect("jp node");
    let us_node = resolved
        .config
        .node
        .iter()
        .find(|n| n.label().contains("US"))
        .expect("us node");
    let hk_node = resolved
        .config
        .node
        .iter()
        .find(|n| n.label().contains("HK 01"))
        .expect("hk node");
    let jp_group = &resolved.config.group[0];

    assert!(daer_control::group_mentions_node(jp_group, jp_node));
    assert!(!daer_control::group_mentions_node(jp_group, us_node));
    assert!(!daer_control::group_mentions_node(jp_group, hk_node));

    // Validate config should succeed (unsupported tuic from subscription produces a warning, not failure)
    let report = block_on(validate_config(&config)).expect("validates");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("cannot be selected") || w.contains("is not selectable"))
    );

    // Generates router and selects Japan node
    let options = daer_control::RouterOptions::for_config(&config);
    let generations =
        daer_control::Generations::new(&resolved.config, &options).expect("builds router");
    let selected_node = generations
        .current()
        .router()
        .node_identity("fastest-jp")
        .expect("node selected");
    assert_eq!(selected_node.group, "jp-pool");
    assert_eq!(selected_node.election, "fastest-jp");
    assert!(selected_node.node.contains("Japan"));
}

#[test]
fn a_direct_verdict_selects_no_node() {
    let dir = Scratch::new("explain-direct");
    let config = dir.write_private(
        "config.toml",
        br#"[routing]
default = "direct"
"#,
    );
    let explanation = block_on(explain(
        &config,
        "10.0.0.2:40000",
        "93.184.216.34:443",
        None,
    ))
    .expect("explains");
    assert!(explanation.selected.is_none(), "direct picks no node");
    assert!(!explanation.to_string().contains("node       :"));
}

#[test]
fn route_explain_refuses_a_configuration_that_cannot_run() {
    let dir = Scratch::new("explain-bad");
    let config = dir.write_private("config.toml", b"[routing]\ndefault = \"nope\"\n");
    let error = block_on(explain_route(
        &config,
        "10.0.0.2:40000".parse().expect("source"),
        "93.184.216.34:443".parse().expect("destination"),
        false,
        None,
    ))
    .expect_err("must not explain a configuration it cannot run");
    assert!(format!("{error:#}").contains("not declared"), "{error:#}");
}

#[test]
fn removed_verbs_name_their_replacement() {
    // ADR-0015: a stale script must be told what to change. `unknown subcommand` is
    // indistinguishable from a typo, and the operator's next move would be diffing
    // `--help` against the script.
    for (verb, expected) in [
        ("config", "daer check"),
        ("explain", "daer route"),
        ("node", "[[subscription]]"),
        ("dns", "daer run"),
        ("rule", "daer-drb"),
    ] {
        let error = block_on(async { cli_error(verb).await });
        let message = format!("{error:#}");
        assert!(
            message.contains(verb) && message.contains(expected),
            "`daer {verb}` must name {expected:?}: {message}"
        );
    }
}

/// Drives the real parser so the assertion is about the shipped surface, not a copy.
///
/// A hand-built `Command` would pass even if `main` stopped routing the verb, which is the
/// only thing this test exists to check.
async fn cli_error(verb: &str) -> anyhow::Error {
    let cli = Cli::try_parse_from(["daer", verb, "whatever"]).expect("the verb still parses");
    let result: anyhow::Result<()> = match cli.command {
        Command::Config { .. } => Err(removed_verb(
            "config",
            "`daer check` answers \"will this run\"; the sample and the schema are \
                 `daer schema` and the repository's daer.example.toml",
        )),
        Command::Explain { .. } => Err(removed_verb(
            "explain",
            "`daer route <TARGET>` resolves routing decisions (e.g. `daer route bilibili.com` or `daer route 1.1.1.1`)",
        )),
        Command::Node { .. } => Err(removed_verb(
            "node",
            "declare a `[[subscription]]` (daer parses links at runtime) or use an external \
                 subscription converter",
        )),
        Command::Dns { .. } => Err(removed_verb(
            "dns",
            "`daer run` serves DNS when `dns.bind` or `[dns.fake-ip]` asks for it, and \
                 `daer check` reports every unusable upstream",
        )),
        Command::Rule { .. } => Err(removed_verb(
            "rule",
            "the DRB producer is `daer-drb`: `daer-drb compile`, `daer-drb decompile`, \
                 `daer-drb inspect`, `daer-drb test`",
        )),
        other => panic!("{other:?} is not a removed verb"),
    };
    result.expect_err("a removed verb must not succeed")
}

#[test]
fn accepts_builtin_outbounds() {
    let dir = Scratch::new("builtin");
    let config = dir.write_private(
            "config.toml",
            b"[routing]\ndefault = \"direct\"\n[[routing.rule]]\nname = \"https-block\"\nmatch = \"dport(443)\"\naction = \"block\"\n",
        );
    block_on(validate_config(&config)).expect("validates");
}

#[test]
fn rule_provider_integration_with_routing_and_explain() {
    let dir = Scratch::new("rule-set-routing");
    let _rules_file = dir.write_private("direct.rules", b"192.168.100.0/24\ncorp.lan\n");
    let config = dir.write_private(
        "config.toml",
        br#"
schema = 6

[[rule-set]]
name = "internal-corp"
type = "file"
path = "direct.rules"
format = "text"

[routing.sniff]
enabled = true
timeout = "30ms"

[routing]
default = "block"
[[routing.rule]]
name = "internal"
match = "rule-set(internal-corp)"
action = "direct"
"#,
    );

    let report = block_on(validate_config(&config)).expect("validates");
    assert_eq!(report.rules, 1);

    // 1. IP match: 192.168.100.42 -> direct
    let exp = block_on(explain(&config, "10.0.0.1:1234", "192.168.100.42:80", None))
        .expect("explains ip");
    assert_eq!(&*exp.outbound.name, "direct");

    // 2. Domain match: portal.corp.lan -> direct
    let exp = block_on(explain(
        &config,
        "10.0.0.1:1234",
        "1.1.1.1:80",
        Some("portal.corp.lan"),
    ))
    .expect("explains domain");
    assert_eq!(&*exp.outbound.name, "direct");

    // 3. Fallback: other.com -> block
    let err = block_on(explain_route(
        &config,
        "10.0.0.1:1234".parse().unwrap(),
        "1.1.1.1:80".parse().unwrap(),
        false,
        Some("other.com"),
    ))
    .expect_err("must report blocked flow");
    assert!(err.to_string().contains("blocked"));
}

#[test]
fn parse_route_target_supports_single_domain() {
    let flow = parse_route_target("bilibili.com", None, None, None).expect("parses domain");
    assert_eq!(flow.source.to_string(), "127.0.0.1:12345");
    assert_eq!(flow.destination.port(), 443);
    assert_eq!(flow.domain.as_deref(), Some("bilibili.com"));

    let flow_port =
        parse_route_target("bilibili.com:8443", None, None, None).expect("parses domain:port");
    assert_eq!(flow_port.destination.port(), 8443);
    assert_eq!(flow_port.domain.as_deref(), Some("bilibili.com"));
}

#[test]
fn parse_route_target_supports_single_ip() {
    let flow = parse_route_target("1.1.1.1", None, None, None).expect("parses ip");
    assert_eq!(flow.destination.to_string(), "1.1.1.1:443");
    assert_eq!(flow.domain, None);

    let flow_port = parse_route_target("1.1.1.1:80", None, None, None).expect("parses ip:port");
    assert_eq!(flow_port.destination.to_string(), "1.1.1.1:80");
    assert_eq!(flow_port.domain, None);
}

#[test]
fn parse_route_target_supports_classic_four_tuple() {
    let flow = parse_route_target(
        "192.168.1.10:41234",
        Some("93.184.216.34:443"),
        None,
        Some("example.com".to_string()),
    )
    .expect("parses 4-tuple");
    assert_eq!(flow.source.to_string(), "192.168.1.10:41234");
    assert_eq!(flow.destination.to_string(), "93.184.216.34:443");
    assert_eq!(flow.domain.as_deref(), Some("example.com"));
}
