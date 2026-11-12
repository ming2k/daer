// SPDX-License-Identifier: AGPL-3.0-only

//! Enforces ADR-0031: DRB v2 and Canonical Rule Source (CRS v1) boundaries.
//!
//! 1. `daer-rule-ast` is neutral: links no networking, routing, or ebpf crates.
//! 2. `daer-routing` links no Protobuf and no `daer-geodata`.
//! 3. Deterministic builds: identical rules produce identical `.drb` byte sequences.
//! 4. Bi-directional identity: `compile(decompile(drb)) == drb`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use daer_routing::DrbSet;
use daer_rule_ast::{DomainPattern, DomainRule, RuleSet, SuffixScope};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn dependency_closure(package: &str) -> BTreeSet<String> {
    let root = workspace_root();
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(&root)
        .output()
        .expect("runs cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("metadata is JSON");
    let packages = value["packages"].as_array().expect("packages");
    let nodes = value["resolve"]["nodes"].as_array().expect("resolve nodes");

    let id = packages
        .iter()
        .find(|entry| entry["name"].as_str() == Some(package))
        .and_then(|entry| entry["id"].as_str())
        .unwrap_or_else(|| panic!("{package} is in the workspace"));

    let mut seen = BTreeSet::new();
    let mut queue: Vec<String> = vec![id.to_owned()];
    while let Some(current) = queue.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        if let Some(node) = nodes
            .iter()
            .find(|node| node["id"].as_str() == Some(&current))
        {
            queue.extend(
                node["deps"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|dep| dep["pkg"].as_str())
                    .map(str::to_owned),
            );
        }
    }

    seen.iter()
        .filter_map(|id| {
            packages
                .iter()
                .find(|entry| entry["id"].as_str() == Some(id.as_str()))
                .and_then(|entry| entry["name"].as_str())
                .map(str::to_owned)
        })
        .collect()
}

#[test]
fn the_ast_depends_on_nothing_of_ours() {
    let closure = dependency_closure("daer-rule-ast");
    for forbidden in ["daer-routing", "daer-geodata", "daer-config", "daer-ebpf"] {
        assert!(
            !closure.contains(forbidden),
            "`daer-rule-ast` links `{forbidden}`. The intermediate form must be neutral. Closure: {closure:?}"
        );
    }
}

#[test]
fn the_writer_cannot_read_protobuf() {
    let closure = dependency_closure("daer-routing");
    assert!(
        !closure.contains("daer-geodata"),
        "`daer-routing` links `daer-geodata`. Closure: {closure:?}"
    );
}

#[test]
fn the_daemon_links_neither_reader_nor_writer() {
    let closure = dependency_closure("daer-cli");
    for forbidden in ["daer-geodata", "daer-drb"] {
        assert!(
            !closure.contains(forbidden),
            "`daer-cli` links `{forbidden}` (ADR-0015). Closure: {closure:?}"
        );
    }
}

#[test]
fn text_and_programmatic_construction_produce_identical_bytes() {
    let text = "\
---
name: corp
---
10.0.0.0/8
192.168.1.0/24
example.com
.sub.example.com
=api.corp.internal
";
    let from_text = RuleSet::parse(text).expect("parses");

    let mut from_code = RuleSet::new("corp");
    from_code.push_v4_range(0x0a000000, 0x0affffff); // 10.0.0.0/8
    from_code.push_v4_range(0xc0a80100, 0xc0a801ff); // 192.168.1.0/24
    from_code.push_domain(DomainRule::new(DomainPattern::Suffix(
        "example.com".into(),
        SuffixScope::SelfAndSubdomains,
    )));
    from_code.push_domain(DomainRule::new(DomainPattern::Suffix(
        "sub.example.com".into(),
        SuffixScope::SubdomainsOnly,
    )));
    from_code.push_domain(DomainRule::new(DomainPattern::Full(
        "api.corp.internal".into(),
    )));
    let from_code = from_code.canonical().expect("canonical");

    assert_eq!(
        from_text, from_code,
        "the AST must not depend on how it was built"
    );
    assert_eq!(
        DrbSet::from_rule_set(&from_text).encode(),
        DrbSet::from_rule_set(&from_code).encode(),
        "one writer over one canonical form must produce identical bytes"
    );
}

#[test]
fn deterministic_builds_without_timestamp_divergence() {
    let text1 = "---\nname: set\n---\n1.1.1.0/24\na.com\n";
    let text2 = "---\nname: set\n---\na.com\n1.1.1.0/24\n";

    let drb1 = DrbSet::from_rule_set(&RuleSet::parse(text1).unwrap()).encode();
    let drb2 = DrbSet::from_rule_set(&RuleSet::parse(text2).unwrap()).encode();

    assert_eq!(
        drb1, drb2,
        "reordering rules must produce 100% byte-for-byte identical binary artifacts (ADR-0031)"
    );
}

#[test]
fn an_artifact_round_trips_through_text() {
    let original = RuleSet::parse(
        "---\nname: rt\n---\n192.0.2.0/24\nexample.com\n.sub.example.com\n=api.example.com\n",
    )
    .expect("parses");

    let artifact = DrbSet::from_rule_set(&original).encode();
    let recovered_rules = DrbSet::decode(&artifact).expect("decodes").to_rule_set();
    let recompiled = DrbSet::from_rule_set(&recovered_rules).encode();

    assert_eq!(
        artifact, recompiled,
        "an artifact that cannot be recompiled to itself cannot be audited"
    );
}
