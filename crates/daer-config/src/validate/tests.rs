use super::*;

fn valid() -> Config {
    Config::default()
}

#[test]
fn rejects_an_unknown_schema() {
    let mut config = valid();
    config.schema = 99;
    let error = normalize(&mut config).expect_err("must fail");
    assert_eq!(error.field, "schema");
}

#[test]
fn an_unknown_http_method_is_rejected() {
    let mut config = valid();
    config.election = vec![crate::model::Election {
        name: "proxy".to_owned(),
        group: None,
        node: Some("n".to_owned()),
        kind: crate::model::ElectionKind::Min,
        mode: None,
        url: None,
        method: Some("BREW".to_owned()),
        udp_dns: None,
        interval: Some(crate::TimeSpan::from_secs(30)),
        timeout: Some(crate::TimeSpan::from_secs(5)),
        tolerance: None,
    }];
    let error = normalize(&mut config).expect_err("must fail");
    assert_eq!(error.field, "election.method");
}

#[test]
fn an_election_url_mode_requires_a_url() {
    let mut config = valid();
    config.election = vec![crate::model::Election {
        name: "proxy".to_owned(),
        group: None,
        node: Some("n".to_owned()),
        kind: crate::model::ElectionKind::Min,
        mode: Some(crate::model::ProbeMode::Url),
        url: None,
        method: None,
        udp_dns: None,
        interval: Some(crate::TimeSpan::from_secs(30)),
        timeout: Some(crate::TimeSpan::from_secs(5)),
        tolerance: None,
    }];
    let error = normalize(&mut config).expect_err("url mode needs a URL");
    assert_eq!(error.field, "election.url");
}

#[test]
fn a_server_mode_election_cannot_carry_a_url() {
    let mut config = valid();
    config.election = vec![crate::model::Election {
        name: "proxy".to_owned(),
        group: None,
        node: Some("n".to_owned()),
        kind: crate::model::ElectionKind::Min,
        mode: Some(crate::model::ProbeMode::Server),
        url: Some("https://example.com/".to_owned()),
        method: None,
        udp_dns: None,
        interval: Some(crate::TimeSpan::from_secs(30)),
        timeout: Some(crate::TimeSpan::from_secs(5)),
        tolerance: None,
    }];
    let error = normalize(&mut config).expect_err("server mode cannot carry a URL");
    assert_eq!(error.field, "election.url");
}

#[test]
fn a_latency_election_cannot_disable_probing() {
    let mut config = valid();
    config.election = vec![crate::model::Election {
        name: "proxy".to_owned(),
        group: None,
        node: Some("n".to_owned()),
        kind: crate::model::ElectionKind::Min,
        mode: None,
        url: None,
        method: None,
        udp_dns: None,
        interval: Some(crate::TimeSpan::ZERO),
        timeout: None,
        tolerance: None,
    }];
    let error = normalize(&mut config).expect_err("a latency election needs probes");
    assert_eq!(error.field, "election.interval");
}

#[test]
fn a_manual_election_rejects_probe_settings() {
    let mut config = valid();
    config.election = vec![crate::model::Election {
        name: "proxy".to_owned(),
        group: None,
        node: Some("n".to_owned()),
        kind: crate::model::ElectionKind::Manual,
        mode: Some(crate::model::ProbeMode::Server),
        url: None,
        method: None,
        udp_dns: None,
        interval: None,
        timeout: None,
        tolerance: None,
    }];
    let error = normalize(&mut config).expect_err("a manual election is never probed");
    assert_eq!(error.field, "election.probe");
    assert!(error.message.contains("manual"), "{error}");
}

#[test]
fn tolerance_belongs_to_the_moving_average_policy() {
    let mut config = valid();
    config.election = vec![crate::model::Election {
        name: "proxy".to_owned(),
        group: None,
        node: Some("n".to_owned()),
        kind: crate::model::ElectionKind::Min,
        mode: None,
        url: None,
        method: None,
        udp_dns: None,
        interval: Some(crate::TimeSpan::from_secs(30)),
        timeout: None,
        tolerance: Some(crate::TimeSpan::from_secs(1)),
    }];
    let error = normalize(&mut config).expect_err("only min-moving-avg uses tolerance");
    assert_eq!(error.field, "election.tolerance");

    // The control: the same field is accepted by the policy that consumes it.
    let mut config = valid();
    config.election = vec![crate::model::Election {
        name: "proxy".to_owned(),
        group: None,
        node: Some("n".to_owned()),
        kind: crate::model::ElectionKind::MinMovingAvg,
        mode: None,
        url: None,
        method: None,
        udp_dns: None,
        interval: Some(crate::TimeSpan::from_secs(30)),
        timeout: None,
        tolerance: Some(crate::TimeSpan::from_secs(1)),
    }];
    normalize(&mut config).expect("min-moving-avg consumes tolerance");
}

#[test]
fn dns_defaults_are_populated() {
    let mut config = valid();
    assert!(config.dns.request.default.is_none());
    normalize(&mut config).expect("valid");
    assert_eq!(
        config.dns.request.default,
        Some(FunctionOrString::Name("asis".to_owned()))
    );
    assert_eq!(
        config.dns.response.default,
        Some(FunctionOrString::Name("accept".to_owned()))
    );
}

#[test]
fn fake_ip_requires_an_explicit_dns_bind() {
    let error =
        crate::toml_config::load_str("[dns.fake-ip]\nenabled = true\n").expect_err("must fail");
    let message = error.to_string();
    assert!(message.contains("dns.fake-ip.enabled"), "{message}");
}

#[test]
fn dns_bind_requires_an_upstream() {
    let error =
        crate::toml_config::load_str("[dns]\nbind = \"127.0.0.1\"\n").expect_err("must fail");
    let message = error.to_string();
    assert!(message.contains("dns.upstream"), "{message}");
}

#[test]
fn a_domain_rule_requires_an_explicit_sniff_answer() {
    let error = crate::toml_config::load_str(
        "[routing]\ndefault = \"direct\"\n[[routing.rule]]\nname = \"d\"\nmatch = \
             \"domain(example.com)\"\naction = \"direct\"\n",
    )
    .expect_err("must fail");
    let message = error.to_string();
    assert!(message.contains("routing.sniff.enabled"), "{message}");
}

#[test]
fn disabled_sniff_without_dns_is_no_name_source() {
    let error = crate::toml_config::load_str(
        "[routing.sniff]\nenabled = false\n[routing]\ndefault = \"direct\"\n\
             [[routing.rule]]\nname = \"d\"\nmatch = \"domain(example.com)\"\n\
             action = \"direct\"\n",
    )
    .expect_err("must fail");
    let message = error.to_string();
    assert!(message.contains("no name source"), "{message}");
}

#[test]
fn sniff_timeout_shape_is_enforced() {
    let error = crate::toml_config::load_str("[routing.sniff]\nenabled = true\n")
        .expect_err("enabled needs a timeout");
    assert!(
        error.to_string().contains("routing.sniff.timeout"),
        "{error}"
    );

    let error =
        crate::toml_config::load_str("[routing.sniff]\nenabled = false\ntimeout = \"30ms\"\n")
            .expect_err("disabled forbids a timeout");
    assert!(
        error.to_string().contains("routing.sniff.timeout"),
        "{error}"
    );
}

#[test]
fn duplicate_and_empty_group_names_are_rejected() {
    let mut config = valid();
    config.group = vec![
        crate::model::Group {
            name: "a".to_owned(),
            filters: Vec::new(),
        },
        crate::model::Group {
            name: "a".to_owned(),
            filters: Vec::new(),
        },
    ];
    assert!(normalize(&mut config).is_err());
}

/// A group may not shadow a builtin outbound.
///
/// The falsifier is the observed divergence: `[[group]] name = "direct"` with one node
/// pointing at a dead SOCKS port loaded fine, `daer route` reported that node as the
/// selected outbound, and the daemon dialled the flow *directly* and returned the origin's
/// bytes. Either the name is the builtin everywhere or it is an error everywhere; the
/// configuration is not allowed to mean two things.
/// An empty `wan-interface` is rejected here, not only by the daemon.
///
/// The falsifier is one command pair: `printf 'schema = 6\nwan-interface = []\n'`
/// used to be `check` → `ok` and `run` → exit 1, so the gate that promises "will this
/// configuration run" disagreed with the process that runs it. The default is `"auto"`,
/// which is why a plain `schema = 6` file still passes.
#[test]
fn an_empty_wan_interface_fails_validation_even_though_the_default_is_not_empty() {
    let mut config = valid();
    config.wan_interface = WanInterface::Named(Vec::new());
    let error = normalize(&mut config).expect_err("the daemon cannot honour this");
    assert_eq!(error.field, "wan-interface");

    // The control: the defaults pass, so the check is about the empty list and not about
    // `wan-interface` being present at all.
    let mut config = valid();
    normalize(&mut config).expect("the default \"auto\" must still validate");

    // And a blank entry, which `run` would otherwise try to resolve as an interface name.
    let mut config = valid();
    config.wan_interface = WanInterface::Named(vec!["  ".to_owned()]);
    let error = normalize(&mut config).expect_err("a blank interface name is not a name");
    assert_eq!(error.field, "wan-interface");
}

#[test]
fn a_repeated_wan_interface_is_rejected() {
    let mut config = valid();
    config.wan_interface = WanInterface::Named(vec!["eth0".to_owned(), "eth0".to_owned()]);
    let error = normalize(&mut config).expect_err("a duplicate would attach twice");
    assert_eq!(error.field, "wan-interface");
    assert!(error.message.contains("more than once"), "{error}");
}

#[test]
fn a_group_may_not_shadow_a_builtin_outbound() {
    for name in ["direct", "block", "must_rules", "<OR>", "<AND>"] {
        let mut config = valid();
        config.group = vec![crate::model::Group {
            name: name.to_owned(),
            filters: Vec::new(),
        }];
        let error = normalize(&mut config)
            .expect_err("a group named after a builtin outbound must be rejected");
        assert_eq!(error.field, "group.name", "{name}: {error}");
        assert!(
            error.message.contains("built-in"),
            "{name}: the message must say why: {error}"
        );

        // The control: the same group under a name that is not reserved loads.
        let mut config = valid();
        config.group = vec![crate::model::Group {
            name: format!("proxy-{name}"),
            filters: Vec::new(),
        }];
        normalize(&mut config).expect("a non-reserved name is fine");
    }
}

#[test]
fn one_interface_cannot_be_both_lan_and_wan() {
    let mut config = valid();
    config.lan_interface = vec!["eth0".to_owned()];
    config.wan_interface = WanInterface::Named(vec!["eth0".to_owned()]);
    let error = normalize(&mut config).expect_err("one interface cannot carry both roles");
    assert_eq!(error.field, "lan-interface");
    assert!(error.message.contains("both"), "{error}");

    // The control: separate interfaces are the supported topology.
    let mut config = valid();
    config.lan_interface = vec!["eth1".to_owned()];
    config.wan_interface = WanInterface::Named(vec!["eth0".to_owned()]);
    normalize(&mut config).expect("separate roles are valid");
}

fn node(name: &str, detour: Option<&str>) -> crate::model::Node {
    let mut node = crate::model::Node::from_link(&format!("socks5://127.0.0.1:1080#{name}"))
        .expect("node parses");
    node.detour = detour.map(str::to_owned);
    node
}

#[test]
fn a_detour_chain_is_a_valid_dag() {
    let mut config = valid();
    config.node = vec![node("outer", Some("inner")), node("inner", None)];
    normalize(&mut config).expect("parses");
    validate_chain_graph(&config).expect("a two-node chain is acyclic");
}

#[test]
fn an_unknown_detour_target_is_rejected_after_resolution() {
    let mut config = valid();
    config.node = vec![node("outer", Some("missing"))];
    // The first pass cannot decide existence: a subscription may add the target later.
    normalize(&mut config).expect("syntactically usable");
    let error = validate_chain_graph(&config).expect_err("no such node");
    assert_eq!(error.field, "node.detour");
    assert!(error.message.contains("missing"), "{error}");
}

#[test]
fn a_detour_cycle_is_rejected_with_the_path() {
    let mut config = valid();
    config.node = vec![node("a", Some("b")), node("b", Some("a"))];
    normalize(&mut config).expect("syntactically usable");
    let error = validate_chain_graph(&config).expect_err("cycle");
    assert_eq!(error.field, "node.detour");
    assert!(error.message.contains("cycle"), "{error}");
    assert!(error.message.contains("a"), "{error}");
    assert!(error.message.contains("b"), "{error}");
}

#[test]
fn a_node_cannot_detour_through_itself() {
    let mut config = valid();
    config.node = vec![node("a", Some("a"))];
    let error = normalize(&mut config).expect_err("self detour");
    assert_eq!(error.field, "node.detour");
    assert!(error.message.contains("itself"), "{error}");
}

#[test]
fn routing_rule_names_are_unique() {
    let mut config = valid();
    config.routing.rule = vec![
        crate::model::RoutingRule {
            name: "same".to_owned(),
            match_expr: crate::expr::parse_match_expr("dport(443)").expect("parses"),
            action: crate::model::OutboundAction::Builtin(crate::model::BuiltinOutbound::Direct),
        },
        crate::model::RoutingRule {
            name: "same".to_owned(),
            match_expr: crate::expr::parse_match_expr("dport(80)").expect("parses"),
            action: crate::model::OutboundAction::Builtin(crate::model::BuiltinOutbound::Direct),
        },
    ];
    let error = normalize(&mut config).expect_err("duplicate names are ambiguous");
    assert_eq!(error.field, "routing.rule.name");
}

#[test]
fn a_group_is_not_a_routing_action() {
    let mut config = valid();
    config.group = vec![crate::model::Group {
        name: "pool".to_owned(),
        filters: Vec::new(),
    }];
    config.routing.default = crate::model::OutboundAction::Election("pool".to_owned());
    let error = normalize(&mut config).expect_err("a group is not an action");
    assert_eq!(error.field, "routing.default");
    assert!(error.message.contains("candidate pool"), "{error}");
}

#[test]
fn an_election_action_is_accepted() {
    let mut config = valid();
    config.election = vec![crate::model::Election {
        name: "proxy".to_owned(),
        node: Some("missing".to_owned()),
        group: None,
        kind: crate::model::ElectionKind::Manual,
        mode: None,
        url: None,
        method: None,
        udp_dns: None,
        interval: None,
        timeout: None,
        tolerance: None,
    }];
    config.routing.default = crate::model::OutboundAction::Election("proxy".to_owned());
    normalize(&mut config).expect("an election action is valid");
}

#[test]
fn a_node_cannot_take_a_builtin_policy_name() {
    for name in ["direct", "block", "must_rules", "<OR>", "<AND>"] {
        let mut config = valid();
        let mut node = node("actual", None);
        node.name = Some(name.to_owned());
        config.node = vec![node];
        let error = normalize(&mut config).expect_err("built-in names are reserved");
        assert_eq!(error.field, "node.name");
        assert!(error.message.contains("built-in routing policy"), "{error}");
    }

    // The control: an ordinary name is accepted.
    let mut config = valid();
    config.node = vec![node("edge", None)];
    normalize(&mut config).expect("an ordinary node name is fine");
}

#[test]
fn duplicate_node_names_are_rejected_because_detour_needs_one_target() {
    let mut config = valid();
    config.node = vec![node("same", None), node("same", None)];
    let error = normalize(&mut config).expect_err("ambiguous target");
    assert_eq!(error.field, "node.name");
    // The control: a chain with distinct names is accepted.
    config.node = vec![node("a", Some("b")), node("b", None)];
    normalize(&mut config).expect("distinct names are fine");
}
