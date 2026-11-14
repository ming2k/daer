// SPDX-License-Identifier: AGPL-3.0-only

//! Enforces ADR-0015: the daemon binary is a runtime, not a build toolchain.
//!
//! `daer --help` promising four verbs is a documentation claim. The claim that actually
//! matters is structural: **`daer-cli` must not be able to regrow a producer without failing
//! CI**, because the day it can, `daer rule convert` comes back and the daemon links the
//! Protobuf reader again.
//!
//! Two independent checks, because either one alone is bypassable:
//!
//! 1. **The dependency graph.** `cargo metadata` is the compiler's own answer to "what does
//!    this crate link". A `daer-geodata` edge anywhere in the normal dependency closure of
//!    `daer-cli` fails, as does any crate whose name starts with `prost`/`protobuf`.
//! 2. **The source.** A removed verb that comes back as a *visible* clap subcommand is not a
//!    build-tool regression, but it is the same surface regression, and the enum is the thing
//!    a reviewer reads. The test asserts the four verbs exist and that the removed ones stay
//!    `hide`n.

use std::collections::BTreeSet;
use std::process::Command;

/// Crates that must not appear in `daer-cli`'s normal dependency closure.
const PRODUCER_CRATES: &[&str] = &["daer-geodata", "daer-drb"];

/// Protobuf readers: the format ADR-0014 exists to retire, and the reason `daer-geodata`
/// exists at all. A daemon that links one can decode a rule set it should only consume.
const PROTOBUF_PREFIXES: &[&str] = &["prost", "protobuf", "quick-protobuf"];

fn daer_cli_dependencies() -> BTreeSet<String> {
    let metadata = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(
            crate::common::crate_dir("daer-cli")
                .join("Cargo.toml")
                .to_str()
                .expect("utf-8 path"),
        )
        .output()
        .expect("runs cargo metadata");

    assert!(
        metadata.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );

    let json = String::from_utf8(metadata.stdout).expect("metadata is UTF-8");
    let value: serde_json::Value = serde_json::from_str(&json).expect("metadata is JSON");

    let packages = value["packages"].as_array().expect("packages array");
    let resolve = &value["resolve"];
    let nodes = resolve["nodes"].as_array().expect("resolve nodes");

    // Find the node for this package by its manifest path: the workspace has several
    // packages and `name` alone would not pin the one whose Cargo.toml we asked about.
    let manifest_path = crate::common::crate_dir("daer-cli").join("Cargo.toml");
    let manifest = manifest_path.to_str().expect("utf-8 path");
    let id = packages
        .iter()
        .find(|package| package["manifest_path"].as_str() == Some(manifest))
        .and_then(|package| package["id"].as_str())
        .expect("daer-cli is in the metadata");

    let root = nodes
        .iter()
        .find(|node| node["id"].as_str() == Some(id))
        .expect("daer-cli has a resolve node");

    // Normal dependencies only. A dev-dependency on a producer would be tolerable in
    // principle, but this crate's dev-dependencies are the test harness, so the simpler and
    // stricter rule — no edge at all — is the one that cannot rot.
    let mut seen = BTreeSet::new();
    let mut queue: Vec<&str> = root["deps"]
        .as_array()
        .expect("deps array")
        .iter()
        .filter_map(|dep| dep["pkg"].as_str())
        .collect();
    while let Some(current) = queue.pop() {
        if !seen.insert(current.to_owned()) {
            continue;
        }
        if let Some(node) = nodes
            .iter()
            .find(|node| node["id"].as_str() == Some(current))
        {
            queue.extend(
                node["deps"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|dep| dep["pkg"].as_str()),
            );
        }
    }

    seen.iter()
        .filter_map(|id| {
            packages
                .iter()
                .find(|package| package["id"].as_str() == Some(id.as_str()))
                .and_then(|package| package["name"].as_str())
                .map(str::to_owned)
        })
        .collect()
}

/// The macro firewall from ADR-0040: `tracing` is an implementation detail of the diagnostic
/// plane, not an API every crate can reach for. `tracing-subscriber` is the CLI's sink and is
/// allowed only there.
#[test]
fn only_the_observe_plane_depends_on_tracing() {
    let metadata = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(
            crate::common::crate_dir("daer-cli")
                .join("Cargo.toml")
                .to_str()
                .expect("utf-8 path"),
        )
        .output()
        .expect("runs cargo metadata");
    assert!(metadata.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("metadata is JSON");
    let packages = value["packages"].as_array().expect("packages");
    for package in packages {
        let name = package["name"].as_str().unwrap_or_default();
        if !name.starts_with("daer-") && name != "xtask" {
            continue;
        }
        let deps = package["dependencies"].as_array().expect("dependencies");
        for dep in deps {
            let dep_name = dep["name"].as_str().unwrap_or_default();
            if dep["kind"].as_str().is_some_and(|kind| kind != "normal") {
                continue;
            }
            assert!(
                !(dep_name == "tracing" && name != "daer-observe"),
                "{name} depends on `tracing` directly; use daer-observe's EventCode macros"
            );
            assert!(
                !(dep_name == "tracing-subscriber" && name != "daer-cli"),
                "{name} installs a subscriber; only the binary owns process-wide logging"
            );
        }
    }
}

#[test]
fn the_daemon_links_no_producer() {
    let dependencies = daer_cli_dependencies();

    for forbidden in PRODUCER_CRATES {
        assert!(
            !dependencies.contains(*forbidden),
            "`daer-cli` links `{forbidden}`, which is a build-time producer (ADR-0015). \
             The DRB compiler lives in `daer-drb`; the daemon consumes `.drb` and never reads \
             Protobuf. Full closure: {dependencies:?}"
        );
    }

    for prefix in PROTOBUF_PREFIXES {
        let offenders: Vec<&String> = dependencies
            .iter()
            .filter(|name| name.starts_with(prefix))
            .collect();
        assert!(
            offenders.is_empty(),
            "`daer-cli` links a Protobuf reader ({offenders:?}), which means it can decode \
             the format ADR-0014 retires. A runtime consumes compiled artifacts. \
             Full closure: {dependencies:?}"
        );
    }
}

/// The defined CLI verbs, read from the shipped clap definition rather than from a doc comment.
///
/// This is the falsifier: adding an undeclared command fails here, and so does re-publishing a removed one.
#[test]
fn the_surface_is_clean_verbs() {
    let help = Command::new(crate::common::daer())
        .arg("--help")
        .output()
        .expect("runs daer --help");
    assert!(help.status.success(), "daer --help must succeed");

    let stdout = String::from_utf8(help.stdout).expect("help is UTF-8");
    let commands = stdout
        .split_once("Commands:")
        .map(|(_, rest)| rest)
        .expect("help lists commands");

    // The list ends at the next section header (`Options:`), otherwise the option names would
    // be read as verbs.
    let commands = commands
        .split_once("\nOptions:")
        .map_or(commands, |(head, _)| head);

    let mut listed: Vec<&str> = commands
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('-'))
        .filter_map(|line| line.split_whitespace().next())
        .collect();

    // clap sorts nothing: the order is declaration order, which is the order an operator
    // reads. Assert the set, and assert the removed families are absent.
    listed.sort_unstable();
    assert_eq!(
        listed,
        [
            "check", "elect", "probe", "route", "run", "schema", "status", "version"
        ],
        "the surface is `run`, `check`, `route`, `probe`, `status`, `elect`, `schema`, `version`"
    );
}

/// A removed verb must still parse, so it can explain itself instead of printing
/// `unknown subcommand`.
#[test]
fn a_removed_verb_explains_itself() {
    for verb in ["config", "explain", "node", "dns", "rule"] {
        let output = Command::new(crate::common::daer())
            .args([verb, "whatever"])
            .output()
            .expect("runs daer");
        assert!(
            !output.status.success(),
            "`daer {verb}` must fail as a removed verb"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("was removed") || stderr.contains("was replaced"),
            "`daer {verb}` must say it was removed/replaced, not print `unknown subcommand`: {stderr}"
        );
        assert!(
            !stderr.contains("unrecognized subcommand"),
            "`daer {verb}` fell back to clap's generic error: {stderr}"
        );
    }
}
