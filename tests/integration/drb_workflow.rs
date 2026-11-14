// SPDX-License-Identifier: AGPL-3.0-only

//! The producer's public workflow: compile `.rules` to a DRB artifact, inspect it, decompile it,
//! and read it back through the routing crate ([INV-DRB-01]).
//!
//! The binary is the contract an operator builds against, so this test drives
//! `daer-drb` itself rather than only the library functions. The falsifier is a round trip that
//! reports success while the artifact's counts, name, or decompiled rules disagree with the
//! source.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("daer-drb-test-{name}-{}", std::process::id()));
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

fn drb_cmd() -> Command {
    Command::new(crate::common::daer_drb())
}

#[test]
fn compile_inspect_decompile_and_test_workflow() {
    let temp_dir = TempDir::new("compile-test");
    let rules_path = temp_dir.path().join("test.rules");
    let drb_path = temp_dir.path().join("test.drb");
    let decompile_path = temp_dir.path().join("decompiled.rules");

    let rule_content = r#"
---
name: my-test-rules
---

# IP directives
192.168.1.0/24
10.0.0.0/8
172.16.1.10..172.16.1.20

# Domain patterns
=login.example.com
example.com
.sub.corp.local
"#;

    fs::write(&rules_path, rule_content).expect("rules written");

    // 1. daer-drb compile
    let compile_status = drb_cmd()
        .args([
            "compile",
            rules_path.to_str().unwrap(),
            "-o",
            drb_path.to_str().unwrap(),
        ])
        .status()
        .expect("runs daer-drb compile");
    assert!(compile_status.success(), "compile must succeed");

    // 2. daer-drb inspect
    let inspect_out = drb_cmd()
        .args(["inspect", drb_path.to_str().unwrap()])
        .output()
        .expect("runs daer-drb inspect");
    assert!(inspect_out.status.success(), "inspect must succeed");
    let inspect_str = String::from_utf8(inspect_out.stdout).expect("utf8 inspect");
    assert!(inspect_str.contains("name:             my-test-rules"));
    assert!(inspect_str.contains("version:          2"));
    assert!(inspect_str.contains("v4 intervals:     3"));

    // 3. daer-drb decompile
    let decompile_status = drb_cmd()
        .args([
            "decompile",
            drb_path.to_str().unwrap(),
            "-o",
            decompile_path.to_str().unwrap(),
        ])
        .status()
        .expect("runs daer-drb decompile");
    assert!(decompile_status.success(), "decompile must succeed");

    // Re-compile decompiled rules; binary bytes must match 100% (deterministic build)
    let recompile_drb = temp_dir.path().join("recompile.drb");
    let recomp_status = drb_cmd()
        .args([
            "compile",
            decompile_path.to_str().unwrap(),
            "-o",
            recompile_drb.to_str().unwrap(),
        ])
        .status()
        .expect("recompiles");
    assert!(recomp_status.success());
    let orig_bytes = fs::read(&drb_path).unwrap();
    let recomp_bytes = fs::read(&recompile_drb).unwrap();
    assert_eq!(
        orig_bytes, recomp_bytes,
        "decompile -> compile must be an exact fixed point"
    );

    // 4. daer-drb test - IP matches
    let test_ip = drb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "192.168.1.100"])
        .output()
        .expect("runs test IP");
    assert!(test_ip.status.success(), "IP 192.168.1.100 should match");

    let test_range = drb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "172.16.1.15"])
        .output()
        .expect("runs test range");
    assert!(test_range.status.success(), "IP 172.16.1.15 should match");

    // 5. daer-drb test - IP does not match
    let test_ip_fail = drb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "172.16.2.1"])
        .output()
        .expect("runs test IP fail");
    assert!(!test_ip_fail.status.success(), "IP 172.16.2.1 should fail");

    // 6. daer-drb test - Domain full match
    let test_dom_full = drb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "login.example.com"])
        .output()
        .expect("runs test domain full");
    assert!(test_dom_full.status.success());

    // 7. daer-drb test - Domain suffix match
    let test_dom_suffix = drb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "api.example.com"])
        .output()
        .expect("runs test domain suffix");
    assert!(test_dom_suffix.status.success());

    // 8. daer-drb test - Domain subdomains-only suffix
    let test_sub_ok = drb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "a.sub.corp.local"])
        .output()
        .expect("runs test sub domain");
    assert!(test_sub_ok.status.success());

    let test_sub_bare = drb_cmd()
        .args(["test", drb_path.to_str().unwrap(), "sub.corp.local"])
        .output()
        .expect("runs test sub bare domain");
    assert!(
        !test_sub_bare.status.success(),
        "bare domain should not match SubdomainsOnly suffix"
    );
}
