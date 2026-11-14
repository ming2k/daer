// SPDX-License-Identifier: AGPL-3.0-only

//! The machine-readable CLI surface: `check --json` and `route --json`.
//!
//! These are the commands a deployment gate and a script consume. The falsifier is a
//! document that parses as JSON but disagrees with the human output or with the exit code:
//! a `block` verdict must be nonzero in both forms, a partitioned policy must say
//! `partitioned` rather than `full_deferral`, and a decision must name the rule that fired.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("daer-cli-json-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("creates the temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn daer() -> Command {
    Command::new(crate::common::daer())
}

/// A config with an IP rule before a domain rule, so the policy is partitioned.
fn partitioned_config(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        r#"
schema = 6
wan-interface = ["lo"]
disable-waiting-network = true

[routing.sniff]
enabled = true
timeout = "30ms"

[routing]
default = "direct"

[[routing.rule]]
name = "private"
match = "dip(10.0.0.0/8)"
action = "direct"

[[routing.rule]]
name = "named"
match = "domain(example.com)"
action = "direct"
"#,
    )
    .expect("writes the config");
    path
}

#[test]
fn check_json_is_versioned_and_reports_the_kernel_tier() {
    let dir = TempDir::new("check");
    let config = partitioned_config(&dir);

    let output = daer()
        .args(["check", "--json", "--object", "none", "--config"])
        .arg(&config)
        .output()
        .expect("runs daer check --json");
    assert!(
        output.status.success(),
        "check --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("check --json is JSON");
    assert_eq!(value["schema"], 1);
    assert_eq!(value["kind"], "check");
    assert_eq!(value["rules"], 2);
    assert_eq!(value["files"], 1);
    assert_eq!(value["kernel_policy"]["tier"], "partitioned");
    assert!(
        value["kernel_policy"]["reasons"]
            .as_array()
            .is_some_and(|reasons| !reasons.is_empty()),
        "a partitioned policy must name why the suffix defers: {value}"
    );
    assert!(value["domain"].as_str().is_some_and(|d| d.contains("dns=")));
    assert!(value["object"].is_null(), "--object none must be explicit");
    assert!(value["host"].is_null(), "host checks were not requested");
    assert!(value["warnings"].is_array(), "{value}");

    // The machine-readable form must not silently accept a human-only view.
    let conflict = daer()
        .args(["check", "--json", "--nodes", "--object", "none", "--config"])
        .arg(&config)
        .output()
        .expect("runs daer check --json --nodes");
    assert!(!conflict.status.success(), "--nodes is not a JSON contract");
    assert!(
        String::from_utf8_lossy(&conflict.stderr).contains("cannot be used with"),
        "the conflict must be named: {}",
        String::from_utf8_lossy(&conflict.stderr)
    );
}

#[test]
fn route_json_names_the_rule_and_keeps_the_exit_code() {
    let dir = TempDir::new("route");
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        r#"
schema = 6

[routing]
default = "direct"

[[routing.rule]]
name = "private"
match = "dip(10.0.0.0/8)"
action = "direct"

[[routing.rule]]
name = "https-block"
match = "dport(443)"
action = "block"
"#,
    )
    .expect("writes the config");

    let direct = daer()
        .args(["route", "--json", "--config"])
        .arg(&config)
        .arg("10.1.2.3:80")
        .output()
        .expect("runs daer route --json");
    assert!(
        direct.status.success(),
        "a direct verdict must exit zero: {}",
        String::from_utf8_lossy(&direct.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&direct.stdout).expect("route --json is JSON");
    assert_eq!(value["schema"], 1);
    assert_eq!(value["kind"], "route");
    assert_eq!(value["outbound"]["kind"], "direct");
    assert_eq!(value["rule"]["name"], "private");
    assert_eq!(value["actionable"], true);
    assert!(
        value["trace"]
            .as_array()
            .is_some_and(|trace| !trace.is_empty()),
        "the machine form must carry the trace: {value}"
    );

    let blocked = daer()
        .args(["route", "--json", "--config"])
        .arg(&config)
        .arg("8.8.8.8:443")
        .output()
        .expect("runs daer route --json for a blocked flow");
    assert!(
        !blocked.status.success(),
        "a block verdict must keep the nonzero exit status"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&blocked.stdout).expect("the JSON must be printed before the error");
    assert_eq!(value["outbound"]["kind"], "block");
    assert_eq!(value["rule"]["name"], "https-block");
    assert_eq!(value["actionable"], false);
}
