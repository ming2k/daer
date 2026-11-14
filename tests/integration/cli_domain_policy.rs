// SPDX-License-Identifier: AGPL-3.0-only

//! The CLI gate for the explicit domain-acquisition policy.
//!
//! `daer check` is the deployment contract, so it must reject the combinations the daemon
//! rejects and print the effective plan for a valid one. A unit test on `DomainPlan` proves
//! the policy; these tests prove the binary an operator runs uses it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("daer-cli-domain-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("creates temp dir");
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

fn daer_cmd() -> Command {
    Command::new(crate::common::daer())
}

fn write_config(dir: &TempDir, text: &str) -> PathBuf {
    let path = dir.path().join("config.toml");
    fs::write(&path, text).expect("writes config");
    path
}

fn check(config: &Path) -> std::process::Output {
    daer_cmd()
        .args([
            "check",
            "-c",
            config.to_str().expect("utf-8 path"),
            "--object",
            "none",
        ])
        .output()
        .expect("runs daer check")
}

#[test]
fn check_rejects_a_domain_rule_without_an_explicit_sniff_answer() {
    let dir = TempDir::new("missing-answer");
    let config = write_config(
        &dir,
        r#"
schema = 5
[routing]
fallback = "direct"
[[routing.rule]]
name = "domain"
match = "domain(example.com)"
action = "direct"
"#,
    );

    let output = check(&config);
    assert!(
        !output.status.success(),
        "a domain rule with no sniff answer must fail the gate"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("routing.sniff.enabled"),
        "the refusal must name the field: {stderr}"
    );
}

#[test]
fn check_rejects_disabled_sniff_with_no_dns_name_source() {
    let dir = TempDir::new("no-name-source");
    let config = write_config(
        &dir,
        r#"
schema = 5
[routing]
fallback = "direct"
[routing.sniff]
enabled = false
[[routing.rule]]
name = "domain"
match = "domain(example.com)"
action = "direct"
"#,
    );

    let output = check(&config);
    assert!(
        !output.status.success(),
        "domain rules with no DNS and sniff disabled cannot be served"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no name source"),
        "the refusal must explain the missing source: {stderr}"
    );
}

#[test]
fn check_reports_the_effective_domain_acquisition_plan() {
    let dir = TempDir::new("plan");
    let config = write_config(
        &dir,
        r#"
schema = 5
[routing]
fallback = "direct"
[routing.sniff]
enabled = true
timeout = "30ms"
[[routing.rule]]
name = "domain"
match = "domain(example.com)"
action = "direct"
"#,
    );

    let output = check(&config);
    assert!(
        output.status.success(),
        "a domain rule with an explicit sniff budget is valid; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            "domain acquisition: dns=off, fake-ip=off, domain-rules=yes, sniff=tcp 30ms, \
             udp first datagram"
        ),
        "the effective plan must be visible: {stdout}"
    );
}

#[test]
fn check_rejects_fake_ip_without_an_explicit_dns_bind() {
    let dir = TempDir::new("fake-ip-bind");
    let config = write_config(
        &dir,
        r#"
schema = 5
[dns.fake-ip]
enabled = true
"#,
    );

    let output = check(&config);
    assert!(
        !output.status.success(),
        "Fake-IP without a listener is a load error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dns.fake-ip.enabled"),
        "the refusal must name the field: {stderr}"
    );
}
