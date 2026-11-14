use super::*;

fn config(toml: &str) -> Config {
    toml::from_str(toml).expect("parses")
}

#[test]
fn defaults_apply_and_unknown_keys_are_rejected() {
    let parsed = config("");
    assert_eq!(parsed.schema, SCHEMA_VERSION);
    assert_eq!(
        parsed.routing.default,
        OutboundAction::Builtin(BuiltinOutbound::Direct)
    );

    let error = toml::from_str::<Config>("tproxy-port = 1\n").expect_err("unknown key must fail");
    assert!(
        error.to_string().contains("tproxy-port"),
        "unexpected error: {error}"
    );

    // Certificate verification is a node property. A daemon-wide switch would let one
    // self-signed node weaken every other node, so the key does not exist at process scope.
    let error = toml::from_str::<Config>("allow-insecure = true\n")
        .expect_err("a process-wide allow-insecure must be rejected");
    assert!(
        error.to_string().contains("allow-insecure"),
        "unexpected error: {error}"
    );

    // Schema 5 removed the wrapper. `[global]` must fail by name, not silently nest
    // the host keys somewhere the daemon no longer reads.
    let error = toml::from_str::<Config>("[global]\nwan-interface = \"auto\"\n")
        .expect_err("[global] must be rejected");
    assert!(
        error.to_string().contains("global"),
        "unexpected error: {error}"
    );

    // The socket mark is an internal loop-evasion identity, not site policy. The
    // default is self-describing and the value must stay consistent with the
    // datapath's `PARAM.socket_mark`, so configuration cannot change it.
    let error =
        toml::from_str::<Config>("so-mark = 1\n").expect_err("the socket mark is not configurable");
    assert!(
        error.to_string().contains("so-mark"),
        "unexpected error: {error}"
    );
}

#[test]
fn rule_set_table_rejects_legacy_rule_provider_and_rule() {
    let parsed = config("[[rule-set]]\nname = \"cn\"\npath = \"/tmp/cn.drb\"\n");
    assert_eq!(parsed.rule_provider.len(), 1);
    assert_eq!(parsed.rule_provider[0].name, "cn");

    let error =
        toml::from_str::<Config>("[[rule-provider]]\nname = \"cn\"\npath = \"/tmp/cn.drb\"\n")
            .expect_err("[[rule-provider]] must be rejected");
    assert!(error.to_string().contains("rule-provider"), "{error}");

    // `[[rule]]` is deliberately not an alias: a rule is the predicate and
    // action in `[routing].rules`, while a rule set is its named data source.
    let error = toml::from_str::<Config>("[[rule]]\nname = \"cn\"\n")
        .expect_err("[[rule]] must be rejected");
    assert!(error.to_string().contains("rule"), "{error}");
}

/// The defaults must be a configuration `daer run` accepts.
///
/// `daer run` refuses an empty `wan-interface` ("daer cannot know which interface carries
/// proxied traffic"), so the default has to be a value `run` can resolve. The falsifier is
/// one command: `printf 'schema = 6\n' > c.toml && daer run -c c.toml --no-datapath` would
/// fail if the default were `Named(Vec::new())`.
#[test]
fn the_defaults_are_a_configuration_the_daemon_can_run() {
    let parsed = config("");
    assert_eq!(
        parsed.wan_interface,
        WanInterface::Auto,
        "an empty configuration must name a WAN interface the daemon can resolve"
    );
    // And the default survives semantic validation, which is what `run` performs first.
    let mut validated = parsed;
    crate::validate::normalize(&mut validated).expect("the defaults must validate");
    assert_eq!(validated.wan_interface, WanInterface::Auto);
}

#[test]
fn wan_interface_is_auto_or_an_explicit_list() {
    let parsed = config("wan-interface = \"auto\"\n");
    assert_eq!(parsed.wan_interface, WanInterface::Auto);

    let parsed = config("wan-interface = [\"eth0\", \"wg0\"]\n");
    assert_eq!(
        parsed.wan_interface,
        WanInterface::Named(vec!["eth0".to_owned(), "wg0".to_owned()])
    );

    // `auto` is not a list element: the old sentinel spelling is rejected at parse time.
    let error = toml::from_str::<Config>("wan-interface = [\"auto\"]\n")
        .expect_err("auto must not be mixed into a list");
    assert!(
        error.to_string().contains("bare string"),
        "unexpected error: {error}"
    );

    // A bare name is not `auto`; it must be a list so the multi-interface shape is explicit.
    let error = toml::from_str::<Config>("wan-interface = \"eth0\"\n")
        .expect_err("a bare interface name is not a valid shorthand");
    assert!(error.to_string().contains("bare string"), "{error}");
}

#[test]
fn routing_rules_are_named_tables_with_typed_actions() {
    let parsed = config(
        "[routing]\ndefault = \"direct\"\n\
             [[routing.rule]]\nname = \"https-proxy\"\n\
             match = \"domain(a.com) && dport(443)\"\naction = \"proxy\"\n",
    );
    let rule = &parsed.routing.rule[0];
    assert_eq!(rule.name, "https-proxy");
    assert_eq!(rule.match_expr.and_functions.len(), 2);
    assert_eq!(rule.action, OutboundAction::Election("proxy".to_owned()));

    let error = toml::from_str::<Config>(
            "[routing]\ndefault = \"direct\"\n\
             [[routing.rule]]\nname = \"bad\"\nmatch = \"domain(a) -> direct\"\naction = \"direct\"\n",
        )
        .expect_err("an action arrow is not part of the match");
    assert!(error.to_string().contains("unexpected"), "{error}");

    let error = toml::from_str::<Config>(
        "[routing]\ndefault = \"direct\"\n\
             [[routing.rule]]\nname = \"bad\"\nmatch = \"domain(a)\"\naction = { election = \"proxy\" }\n",
    )
    .expect_err("table action wrapper is no longer accepted");
    assert!(error.to_string().contains("string"), "{error}");
}

#[test]
fn durations_require_units() {
    let parsed = config(
        "[[election]]\nname = \"e\"\ntype = \"min-moving-avg\"\n\
             interval = \"45s\"\ntolerance = \"-1s\"\n",
    );
    assert_eq!(parsed.election[0].interval, Some(TimeSpan::from_secs(45)));
    assert!(
        parsed.election[0]
            .tolerance
            .is_some_and(|tolerance| tolerance.is_negative())
    );

    let error =
        toml::from_str::<Config>("[[election]]\nname = \"e\"\ntype = \"min\"\ninterval = \"45\"\n")
            .expect_err("a unitless duration must fail");
    assert!(error.to_string().contains("invalid duration"), "{error}");
}

#[test]
fn subscriptions_accept_both_shapes_and_nodes_require_structured_tables() {
    let plain = config("subscription = [\"https://a/sub\"]\n");
    assert_eq!(plain.subscription[0].name, None);
    assert!(!plain.subscription[0].persist);

    let tables = config(
        "[[subscription]]\nname = \"b\"\nurl = \"https://b/sub\"\npersist = true\n\
             [[node]]\nname = \"n1\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n",
    );
    assert_eq!(tables.subscription[0].name.as_deref(), Some("b"));
    assert!(tables.subscription[0].persist);
    assert_eq!(tables.node[0].name.as_deref(), Some("n1"));

    // Legacy `tag` alias is rejected
    let err =
        toml::from_str::<Config>("[[subscription]]\ntag = \"b_leg\"\nurl = \"https://b/sub\"\n")
            .expect_err("legacy tag key on subscription must fail");
    assert!(err.to_string().contains("tag"), "{err}");

    let err = toml::from_str::<Config>(
        "[[node]]\ntag = \"n_leg\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n",
    )
    .expect_err("legacy tag key on node must fail");
    assert!(err.to_string().contains("tag"), "{err}");

    // Legacy bare URL strings in node are rejected with clear explanation
    let err =
        toml::from_str::<Config>("node = [\"ss://x\"]\n").expect_err("bare url array must fail");
    assert!(
        err.to_string()
            .contains("bare URL strings in 'node' have been retired"),
        "{err}"
    );

    // Legacy `url = "..."` in [[node]] is rejected with clear explanation
    let err = toml::from_str::<Config>("[[node]]\ntag = \"n1\"\nurl = \"ss://x\"\n")
        .expect_err("url in node must fail");
    assert!(
        err.to_string()
            .contains("the 'url' field in [[node]] has been retired"),
        "{err}"
    );
}

#[test]
fn structured_node_from_link_converts_real_world_links() {
    // Real-world VLESS REALITY link from user's subscription (note: omits fp=, should default to chrome).
    let vless_link = "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkus1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=portal.citygrainla.com&pbk=9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E&sid=672f&type=tcp&udp=1&tfo=1#US%20VIP%2001";
    let structured = StructuredNode::from_link(vless_link).expect("converts vless link");
    match structured {
        StructuredNode::Vless(vless) => {
            assert_eq!(vless.name.as_deref(), Some("US VIP 01"));
            assert_eq!(vless.server, "fkus1keria.itknowledgeblog.com");
            assert_eq!(vless.port, 443);
            assert_eq!(vless.uuid, "df4af3d0-030e-4062-baa6-eb9dd45298ef");
            assert_eq!(vless.flow, Flow::Vision);
            let SecurityConfig::Reality(reality) = &vless.security else {
                panic!(
                    "expected a REALITY security layer, got {:?}",
                    vless.security
                );
            };
            assert_eq!(reality.sni, "portal.citygrainla.com");
            assert_eq!(
                reality.public_key,
                "9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E"
            );
            assert_eq!(reality.short_id.as_deref(), Some("672f"));
            // The transport layer is its own axis now (ADR-0028): `type=tcp` in the
            // link is `TransportConfig::Tcp`, not a field on the REALITY layer.
            assert_eq!(vless.transport, TransportConfig::Tcp);
        }
        other => panic!("unexpected variant: {other:?}"),
    }

    // Real-world Shadowsocks link with base64 userinfo
    let ss_link =
        "ss://YWVzLTEyOC1nY206bm9uZQ==@127.0.0.1:1080?udp=0#Website%3A%20user.totorofree.com";
    let structured = StructuredNode::from_link(ss_link).expect("converts ss link");
    match structured {
        StructuredNode::Shadowsocks(ss) => {
            assert_eq!(ss.name.as_deref(), Some("Website: user.totorofree.com"));
            assert_eq!(ss.server, "127.0.0.1");
            assert_eq!(ss.port, 1080);
            // The fixture spelled the cipher `aes-128-grm` — a typo the test asserted
            // as if correct. `from_link` now validates, so it has to be a real cipher;
            // the assertion follows the link's base64 rather than the old typo.
            assert_eq!(ss.method, "aes-128-gcm");
            assert_eq!(ss.password, "none");
        }
        other => panic!("unexpected variant: {other:?}"),
    }

    // SOCKS5 and Trojan
    let socks_link = "socks5://user:pass@127.0.0.1:1080#my-socks";
    let structured = StructuredNode::from_link(socks_link).expect("converts socks link");
    assert_eq!(structured.name(), Some("my-socks"));

    let trojan_link = "trojan://password@node.example.com:443?sni=sni.example.com#my-trojan";
    let structured = StructuredNode::from_link(trojan_link).expect("converts trojan link");
    assert_eq!(structured.name(), Some("my-trojan"));

    let anytls_link = "anytls://secret-pass@anytls.example.com:443?sni=sni.example.com&allowInsecure=1&idle_sessions=3#my-anytls";
    let structured = StructuredNode::from_link(anytls_link).expect("converts anytls link");
    match structured {
        StructuredNode::AnyTls(anytls) => {
            assert_eq!(anytls.name.as_deref(), Some("my-anytls"));
            assert_eq!(anytls.server, "anytls.example.com");
            assert_eq!(anytls.port, 443);
            assert_eq!(anytls.password, "secret-pass");
            assert_eq!(anytls.tls.sni.as_deref(), Some("sni.example.com"));
            assert!(anytls.tls.allow_insecure);
            assert_eq!(anytls.idle_sessions, 3);
        }
        other => panic!("unexpected variant: {other:?}"),
    }

    let hy2_link = "hysteria2://secret-hy2@hy2.example.com:443?sni=sni.example.com&insecure=1&upmbps=50&downmbps=100&obfs=salamander&obfs-password=cry_me_a_r1ver#my-hy2";
    let structured = StructuredNode::from_link(hy2_link).expect("converts hysteria2 link");
    match structured {
        StructuredNode::Hysteria2(hy2) => {
            assert_eq!(hy2.name.as_deref(), Some("my-hy2"));
            assert_eq!(hy2.server, "hy2.example.com");
            assert_eq!(hy2.ports.ranges, vec![(443, 443)]);
            assert_eq!(hy2.password, "secret-hy2");
            assert_eq!(hy2.tls.sni.as_deref(), Some("sni.example.com"));
            assert!(hy2.tls.allow_insecure);
            assert_eq!(hy2.bandwidth.up_mbps, 50);
            assert_eq!(hy2.bandwidth.down_mbps, 100);
            // `obfs=salamander` with no password is refused at link-parse time, so the
            // fixture carries one and the layer survives with its key.
            assert_eq!(
                hy2.obfs,
                Some(Hysteria2Obfs::Salamander {
                    password: "cry_me_a_r1ver".to_owned()
                })
            );
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn filters_accept_a_string_or_a_table() {
    let parsed = config(
        "[[group]]\nname = \"g\"\n\
             filters = [\"subtag(a) && !name(keyword: 'x')\", { match = \"name(n1)\", annotate = { mark = \"1\" } }]\n",
    );
    assert_eq!(parsed.group[0].filters.len(), 2);
    assert_eq!(parsed.group[0].filters[0].functions.len(), 2);
    assert_eq!(parsed.group[0].filters[1].annotate[0].key, "mark");
}

#[test]
fn structured_nodes_parse_validate_and_generate_canonical_links() {
    let toml_str = r#"
[[node]]
name = "hk-vless"
type = "vless"
server = "198.51.100.1"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"
[node.security]
type = "reality"
sni = "example.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
short-id = "ab01cd02"

[[node]]
name = "us-ss"
type = "shadowsocks"
server = "198.51.100.2"
port = 8388
method = "chacha20-ietf-poly1305"
password = "secret-password"

[[node]]
name = "jp-trojan"
type = "trojan"
server = "198.51.100.3"
port = 443
password = "my-password"

[node.tls]
sni = "trojan.example.com"
allow-insecure = true

[[node]]
name = "local-socks5"
type = "socks5"
server = "127.0.0.1"
port = 1080
username = "admin"
password = "123"

[[node]]
name = "local-http"
type = "http"
server = "127.0.0.1"
port = 8080

[[node]]
name = "local-socks5-alt"
type = "socks5"
server = "127.0.0.1"
port = 1081
"#;
    let parsed = config(toml_str);
    assert_eq!(parsed.node.len(), 6);

    // hk-vless
    let n0 = &parsed.node[0];
    assert_eq!(n0.name.as_deref(), Some("hk-vless"));
    assert!(matches!(n0.endpoint, NodeEndpoint::Vless(_)));
    let link0 = n0.to_link();
    assert!(
        link0.starts_with("vless://b831381d-6324-4d53-ad4f-8cda48b30811@198.51.100.1:443?"),
        "link: {}",
        link0
    );
    assert!(link0.contains("security=reality"));
    assert!(link0.contains("sni=example.com"));
    assert!(link0.contains("pbk=f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"));
    assert!(link0.contains("sid=ab01cd02"));
    assert!(link0.contains("flow=xtls-rprx-vision"));

    // us-ss
    let n1 = &parsed.node[1];
    assert_eq!(n1.name.as_deref(), Some("us-ss"));
    assert!(matches!(n1.endpoint, NodeEndpoint::Shadowsocks(_)));
    let link1 = n1.to_link();
    assert!(link1.starts_with("ss://"));
    assert!(link1.contains("@198.51.100.2:8388"));

    // jp-trojan
    let n2 = &parsed.node[2];
    assert_eq!(n2.name.as_deref(), Some("jp-trojan"));
    assert!(matches!(n2.endpoint, NodeEndpoint::Trojan(_)));
    assert_eq!(
        n2.to_link(),
        "trojan://my-password@198.51.100.3:443?sni=trojan.example.com&allowInsecure=1"
    );

    // local-socks5
    let n3 = &parsed.node[3];
    assert_eq!(n3.name.as_deref(), Some("local-socks5"));
    assert!(matches!(n3.endpoint, NodeEndpoint::Socks5(_)));
    assert_eq!(n3.to_link(), "socks5://admin:123@127.0.0.1:1080");

    // local-http
    let n4 = &parsed.node[4];
    assert_eq!(n4.name.as_deref(), Some("local-http"));
    assert!(matches!(n4.endpoint, NodeEndpoint::Http(_)));
    assert_eq!(n4.to_link(), "http://127.0.0.1:8080");

    // local-socks5-alt
    let n5 = &parsed.node[5];
    assert_eq!(n5.name.as_deref(), Some("local-socks5-alt"));
    assert!(matches!(n5.endpoint, NodeEndpoint::Socks5(_)));
    assert_eq!(n5.to_link(), "socks5://127.0.0.1:1081");

    // Serialization roundtrip preserves structured representation
    let rendered = toml::to_string(&parsed).expect("serializes");
    let reparsed = config(&rendered);
    assert_eq!(parsed, reparsed);
}

#[test]
fn a_converted_node_reloads_as_the_configuration_it_came_from() {
    // The falsifier for `daer node convert`: its output is only useful if pasting it
    // into a configuration *loads*. Two defects made that impossible, and neither was
    // visible in the printed text — both surfaced as a TOML error from a file the tool
    // had just written:
    //
    // 1. a nested table was rendered as `[reality]` instead of `[node.reality]`;
    // 2. `Node` carries `tag` and so does its flattened endpoint, so the block held
    //    `tag` twice and TOML rejected it as a duplicate key.
    //
    // The test asserts the round trip through the *real* loader, not through
    // `toml::from_str`: the loader is what `config validate` and `daer run` use.
    let links = [
        "vless://3141d7ca-f74d-46ad-bda6-a5b32a9ae991@212.50.249.175:443?security=reality&encryption=none&pbk=Ka8Bf3HpMgsAeQVmlFAIXrzlEpBsXck-QQn4RA6z_EE&headerType=none&fp=chrome&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni=cdn.softbank.jp&sid=8e3af867d5ffc09f#bwg-jp",
        "ss://YWVzLTEyOC1nY206bm9uZQ==@127.0.0.1:1080#Website",
        "trojan://my-password@198.51.100.3:443?sni=trojan.example.com#tj",
        "socks5://admin:123@127.0.0.1:1080#local",
        "http://127.0.0.1:8080#local-http",
        "anytls://secret@anytls.example.com:443?sni=sni.example.com#anytls-node",
        "hysteria2://secret-hy2@hy2.example.com:443?sni=sni.example.com#my-hy2",
    ];
    for link in links {
        let endpoint = NodeEndpoint::from_link(link).expect("link converts");
        let rendered = endpoint.to_toml_node().expect("renders");
        // A nested table is legal TOML *and* wrong here: the node's sub-table is
        // `[node.reality]`, and a bare `[reality]` is a key the schema does not have.
        assert!(
            !rendered.lines().any(|line| line.starts_with("[reality]")),
            "the sub-table must be scoped to the node:\n{rendered}"
        );
        let document = format!("schema = 6\n\n{rendered}");
        let parsed: Config =
            toml::from_str(&document).unwrap_or_else(|error| panic!("{link}\n{rendered}\n{error}"));
        assert_eq!(
            parsed.node.len(),
            1,
            "one block must be one node:\n{rendered}"
        );
        // The loader keeps the tag on the `Node`, not on the endpoint, so the
        // comparison is on the two things the block carries: the tag and the protocol
        // fields. Comparing endpoints directly would fail on `tag: Some/None` while
        // every other field matched, which is a difference in where the loader stores
        // the value, not in what was written.
        assert_eq!(
            parsed.node[0].name.as_deref(),
            endpoint.name(),
            "\n{rendered}"
        );
        let mut expected = endpoint.clone();
        match &mut expected {
            NodeEndpoint::Socks5(n) => n.name = None,
            NodeEndpoint::Http(n) => n.name = None,
            NodeEndpoint::Shadowsocks(n) => n.name = None,
            NodeEndpoint::Trojan(n) => n.name = None,
            NodeEndpoint::AnyTls(n) => n.name = None,
            NodeEndpoint::Hysteria2(n) => n.name = None,
            NodeEndpoint::Vless(n) => n.name = None,
            NodeEndpoint::Vmess(n) => n.name = None,
            NodeEndpoint::Unsupported { .. } => {}
        }
        assert_eq!(parsed.node[0].endpoint, expected, "\n{rendered}");
    }
}

#[test]
fn intrinsic_tls_and_hysteria_layers_are_nested() {
    let parsed = config(
        "[[node]]\nname = \"t\"\ntype = \"trojan\"\nserver = \"203.0.113.1\"\nport = 443\n\
             password = \"pw\"\n[node.tls]\nsni = \"example.com\"\nallow-insecure = true\n",
    );
    let NodeEndpoint::Trojan(trojan) = &parsed.node[0].endpoint else {
        panic!("expected trojan");
    };
    assert_eq!(trojan.tls.sni.as_deref(), Some("example.com"));
    assert!(trojan.tls.allow_insecure);

    // Flat TLS keys are not a second spelling; the layer table is the only one.
    let error = toml::from_str::<Config>(
        "[[node]]\nname = \"t\"\ntype = \"trojan\"\nserver = \"203.0.113.1\"\nport = 443\n\
             password = \"pw\"\nsni = \"example.com\"\n",
    )
    .expect_err("flat sni must be rejected");
    assert!(error.to_string().contains("sni"), "{error}");

    let parsed = config(
        "[[node]]\nname = \"h\"\ntype = \"hysteria2\"\nserver = \"203.0.113.2\"\n\
             ports = \"443,20000-20002\"\npassword = \"pw\"\n\
             [node.tls]\nsni = \"hy2.example.com\"\n\
             [node.bandwidth]\nup-mbps = 100\ndown-mbps = 200\n\
             [node.quic]\ncongestion = \"brutal\"\nmax-idle-timeout = \"30s\"\n\
             [node.port-hopping]\ninterval = \"30s\"\n",
    );
    let NodeEndpoint::Hysteria2(hysteria) = &parsed.node[0].endpoint else {
        panic!("expected hysteria2");
    };
    assert_eq!(hysteria.ports.ranges, vec![(443, 443), (20_000, 20_002)]);
    assert_eq!(hysteria.tls.sni.as_deref(), Some("hy2.example.com"));
    assert_eq!(hysteria.bandwidth.up_mbps, 100);
    assert_eq!(hysteria.quic.congestion, Hysteria2Congestion::Brutal);
    assert_eq!(hysteria.quic.max_idle_timeout, TimeSpan::from_secs(30));
    assert!(hysteria.port_hopping.is_enabled());
}

#[test]
fn structured_node_negative_controls() {
    // A chain is not "a link with an arrow": it is a routing topology this build does not
    // implement, and truncating it to the first hop would silently proxy somewhere the
    // operator did not write.
    let err = StructuredNode::from_link("socks5://127.0.0.1:1080 -> socks5://127.0.0.1:1081")
        .expect_err("chained link must fail");
    assert!(err.contains("chained links"), "{err}");

    let err = toml::from_str::<Config>(
        "[[node]]\ntype = \"socks5\"\nserver = \"1.1.1.1\"\nport = 1080\nunknown_field = 1\n",
    )
    .expect_err("unknown field must fail");
    assert!(err.to_string().contains("unknown_field"), "{err}");

    // Unknown field inside a layer table fails. `deny_unknown_fields` on an internally
    // tagged enum is not something serde provides, so `SecurityConfig::deserialize`
    // reads the table itself; this is the test that keeps that hand-written check
    // honest.
    let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"b831381d-6324-4d53-ad4f-8cda48b30811\"\n[node.security]\ntype = \"reality\"\nsni = \"s\"\npublic-key = \"k\"\nextra = \"bad\"\n",
        )
        .expect_err("unknown field in the security layer must fail");
    assert!(err.to_string().contains("extra"), "{err}");

    // The retired `[node.reality]` table is gone (ADR-0028 moved it under
    // `[node.security]`), and the error is a plain unknown-field error naming the key.
    let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"b831381d-6324-4d53-ad4f-8cda48b30811\"\n[node.reality]\nsni = \"s\"\npublic-key = \"k\"\n",
        )
        .expect_err("the retired [node.reality] table must fail");
    assert!(err.to_string().contains("reality"), "{err}");

    // Having 'url' fails with retirement explanation
    let err = toml::from_str::<Config>("[[node]]\nurl = \"socks5://1.1.1.1:1080\"\n")
        .expect_err("url field must fail");
    assert!(
        err.to_string()
            .contains("the 'url' field in [[node]] has been retired"),
        "{err}"
    );

    // Missing type fails
    let err = toml::from_str::<Config>("[[node]]\ntag = \"lonely\"\n")
        .expect_err("missing type must fail");
    assert!(
        err.to_string().contains("missing 'type' in [[node]] table"),
        "{err}"
    );

    // Port 0 fails
    let err =
        toml::from_str::<Config>("[[node]]\ntype = \"socks5\"\nserver = \"1.1.1.1\"\nport = 0\n")
            .expect_err("port 0 must fail");
    assert!(err.to_string().contains("port"), "{err}");

    // Empty server fails
    let err =
        toml::from_str::<Config>("[[node]]\ntype = \"socks5\"\nserver = \"   \"\nport = 1080\n")
            .expect_err("empty server must fail");
    assert!(err.to_string().contains("server"), "{err}");

    // A VLESS node needs no security layer at all now (ADR-0028), but it does need a
    // UUID: the id is what authenticates the session, and a malformed one produces a
    // generic node rejection with nothing to attribute it to.
    let err = toml::from_str::<Config>(
        "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"u\"\n",
    )
    .expect_err("a malformed vless uuid must fail");
    assert!(err.to_string().contains("UUID"), "{err}");

    // A malformed REALITY public key is refused only at dial time today, but the
    // missing `sni` is a load-time error because REALITY impersonates a named site.
    let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"b831381d-6324-4d53-ad4f-8cda48b30811\"\n[node.security]\ntype = \"reality\"\npublic-key = \"k\"\n",
        )
        .expect_err("reality without sni must fail");
    assert!(err.to_string().contains("sni"), "{err}");

    // Vision needs a record layer it can splice. The reference rejects this on both
    // ends; accepting it would produce a session that authenticates and deadlocks.
    let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"vless\"\nserver = \"1.1.1.1\"\nport = 443\nuuid = \"b831381d-6324-4d53-ad4f-8cda48b30811\"\nflow = \"xtls-rprx-vision\"\n",
        )
        .expect_err("vision without a security layer must fail");
    assert!(err.to_string().contains("security layer"), "{err}");

    // Shadowsocks with legacy cipher fails with clear explanation
    let err = toml::from_str::<Config>(
            "[[node]]\ntype = \"shadowsocks\"\nserver = \"1.1.1.1\"\nport = 8388\nmethod = \"aes-128-cfb\"\npassword = \"p\"\n",
        )
        .expect_err("legacy cipher must fail");
    assert!(err.to_string().contains("insecure legacy cipher"), "{err}");

    // Shadowsocks 2022 with valid 16-byte base64 key succeeds
    let valid_2022 = toml::from_str::<Config>(
        "[[node]]\nname = \"ss22\"\ntype = \"shadowsocks\"\nserver = \"1.1.1.1\"\nport = 8388\nmethod = \"2022-blake3-aes-128-gcm\"\npassword = \"3L69X4PF2eSL/JSLkoWnXg==\"\n",
    );
    assert!(valid_2022.is_ok(), "{valid_2022:?}");

    // Shadowsocks 2022 with wrong key length fails
    let err = toml::from_str::<Config>(
            "[[node]]\nname = \"ss22\"\ntype = \"shadowsocks\"\nserver = \"1.1.1.1\"\nport = 8388\nmethod = \"2022-blake3-aes-128-gcm\"\npassword = \"bm90MTZieXRlcw==\"\n",
        )
        .expect_err("wrong key length must fail");
    assert!(err.to_string().contains("requires a 16-byte"), "{err}");

    // Shadowsocks 2022 with invalid base64 fails
    let err = toml::from_str::<Config>(
            "[[node]]\nname = \"ss22\"\ntype = \"shadowsocks\"\nserver = \"1.1.1.1\"\nport = 8388\nmethod = \"2022-blake3-aes-128-gcm\"\npassword = \"not-valid-base64!\"\n",
        )
        .expect_err("invalid base64 must fail");
    assert!(err.to_string().contains("valid base64"), "{err}");
}

#[test]
fn every_field_round_trips_through_the_serializer() {
    let original = config(
        "schema = 6\n\
             [tls]\nprofile = \"chrome\"\n\
             [[subscription]]\nname = \"s\"\nurl = \"https://s\"\n\
             [[node]]\nname = \"n\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n\
             [[group]]\nname = \"g\"\n\
             [[election]]\nname = \"e\"\ngroup = \"g\"\ntype = \"random\"\ninterval = \"10s\"\n\
             [routing]\ndefault = \"e\"\n\
             [[routing.rule]]\nname = \"nm\"\nmatch = \"pname(NetworkManager)\"\naction = \"direct\"\n\
             [dns]\nupstream = [\"udp://1.1.1.1:53\"]\n[dns.fixed-domain-ttl]\n\"example.com\" = \"60s\"\n",
    );
    let rendered = toml::to_string(&original).expect("serializes");
    let reparsed = config(&rendered);
    assert_eq!(original, reparsed, "rendered:\n{rendered}");
}
