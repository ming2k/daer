// SPDX-License-Identifier: AGPL-3.0-only

//! `daer status` is a read-only client with a live-socket path and a state-file fallback
//! (ADR-0041). These tests pin the fallback because it is the path a crashed daemon leaves
//! behind, and the bundle because it is the artifact an incident record attaches.

use std::fs;
use std::process::Command;

fn daer() -> &'static str {
    env!("CARGO_BIN_EXE_daer")
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("daer-status-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("creates temp dir");
    dir
}

fn state_file(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("state.json");
    fs::write(
        &path,
        serde_json::json!({
            "schema": 1,
            "run_id": "r0000000000000001",
            "pid": 42,
            "uptime_secs": 7,
            "generation": {
                "id": "gen2",
                "policy_hash": "sha256:00",
                "rules": 3,
                "groups": 1,
                "nodes": 2,
                "warnings": [],
            },
            "datapath": {"attached": true, "namespace": "daer0ns", "port": 12345},
            "flows": {"in_flight": 1, "accepted": 9, "failed": 2, "rejected": 0, "exhausted": 0, "panicked": 0},
            "dns": {"hits": 1, "stale_hits": 0, "misses": 2, "upstream_errors": 0},
            "datagram": {"sessions_opened": 1, "to_upstream": 4, "to_client": 5, "dropped_full": 0, "dropped_failed": 0},
        })
        .to_string(),
    )
    .expect("writes state");
    path
}

#[test]
fn the_file_fallback_answers_and_says_it_is_a_file() {
    let dir = temp_dir("fallback");
    let state = state_file(&dir);
    let socket = dir.join("nonexistent.sock");

    let output = Command::new(daer())
        .arg("status")
        .env("DAER_STATUS_STATE", &state)
        .env("DAER_STATUS_SOCKET", &socket)
        .output()
        .expect("runs daer status");

    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("file ("), "{stdout}");
    assert!(stdout.contains("gen2"), "{stdout}");
    assert!(stdout.contains("accepted=9"), "{stdout}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn json_is_the_versioned_snapshot_and_bundle_is_self_contained() {
    let dir = temp_dir("bundle");
    let state = state_file(&dir);
    let socket = dir.join("nonexistent.sock");
    let bundle = dir.join("bundle");

    let output = Command::new(daer())
        .arg("status")
        .arg("--json")
        .arg("--bundle")
        .arg(&bundle)
        .env("DAER_STATUS_STATE", &state)
        .env("DAER_STATUS_SOCKET", &socket)
        .output()
        .expect("runs daer status --json --bundle");
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("snapshot.json")).expect("snapshot"))
            .expect("snapshot JSON");
    assert_eq!(snapshot["run_id"], "r0000000000000001");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("manifest.json")).expect("manifest"))
            .expect("manifest JSON");
    assert_eq!(manifest["schema"], 1);
    assert_eq!(manifest["redaction"]["secrets_removed"], true);
    let readme = fs::read_to_string(bundle.join("README.txt")).expect("readme");
    assert!(readme.contains("credentials"), "{readme}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_flow_id_selects_its_events_from_the_json_stream() {
    let dir = temp_dir("flow");
    let events = dir.join("events.jsonl");
    fs::write(
        &events,
        concat!(
            r#"{"fields":{"event":"flow.accepted","flow_id":"f0000000000000001","message":"accepted"}}"#,
            "\n",
            r#"{"fields":{"event":"flow.accepted","flow_id":"f0000000000000002","message":"accepted"}}"#,
            "\n",
            r#"{"fields":{"event":"flow.closed","flow_id":"f0000000000000001","message":"closed"}}"#,
            "\n",
        ),
    )
    .expect("writes events");

    let output = Command::new(daer())
        .args(["status", "--flow", "f0000000000000001"])
        .env("DAER_STATUS_EVENTS", &events)
        .output()
        .expect("runs daer status --flow");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let event_lines = stdout.lines().filter(|line| line.starts_with('{')).count();
    assert_eq!(event_lines, 2, "{stdout}");
    assert!(!stdout.contains("f0000000000000002"), "{stdout}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn no_socket_and_no_state_is_a_named_error_not_a_panic() {
    let dir = temp_dir("missing");
    let output = Command::new(daer())
        .arg("status")
        .env("DAER_STATUS_STATE", dir.join("missing.json"))
        .env("DAER_STATUS_SOCKET", dir.join("missing.sock"))
        .output()
        .expect("runs daer status");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("is `daer run` running?"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    let _ = fs::remove_dir_all(&dir);
}
