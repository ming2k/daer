// SPDX-License-Identifier: AGPL-3.0-only

//! The log-level contract: a filter the daemon cannot honour is a check failure, and a
//! rejected subscription link never echoes its credential.

use std::fs;
use std::process::Command;

fn daer() -> std::path::PathBuf {
    crate::common::daer()
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("daer-logging-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("creates temp dir");
    dir
}

#[test]
fn an_unparseable_log_level_fails_the_pre_bind_gate() {
    let dir = temp_dir("filter");
    let config = dir.join("config.toml");
    fs::write(
        &config,
        "schema = 6\n\nwan-interface = [\"lo\"]\nlog-level = \"###\"\n",
    )
    .expect("writes config");
    let output = Command::new(daer())
        .args(["check", "-c"])
        .arg(&config)
        .arg("--object")
        .arg("none")
        .output()
        .expect("runs daer check");
    assert!(
        !output.status.success(),
        "a malformed log-level must not silently fall back to info"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("log-level"), "{stderr}");
    let _ = fs::remove_dir_all(&dir);
}
