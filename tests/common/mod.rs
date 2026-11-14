// SPDX-License-Identifier: AGPL-3.0-only

//! Shared fixtures for the workspace-level integration and E2E test binaries.
//!
//! Both `tests/integration/main.rs` and `tests/e2e/main.rs` compile this module through
//! `#[path = "../common/mod.rs"]`. The helpers themselves live in `test-support` so the
//! in-crate unit tests can use the same scratch-directory and nonce rules.

#![allow(dead_code, unused_imports)]

use std::path::PathBuf;
use std::process::Command;

pub use test_support::{
    Scratch, binary, daer, daer_drb, nonce, read_workspace, unused_port, wait_until,
    workspace_path, workspace_root,
};

/// The `daer` binary as a `Command`.
#[must_use]
pub fn daer_cmd() -> Command {
    Command::new(daer())
}

/// The `daer-drb` binary as a `Command`.
#[must_use]
pub fn daer_drb_cmd() -> Command {
    Command::new(daer_drb())
}

/// The source tree of one workspace crate.
#[must_use]
pub fn crate_dir(name: &str) -> PathBuf {
    workspace_path("crates").join(name)
}

/// Writes a TOML document to a scratch directory and returns its path.
pub fn write_config(scratch: &Scratch, name: &str, text: &str) -> PathBuf {
    scratch.write(name, text)
}

/// Runs `cargo metadata --no-deps --locked` and returns the parsed JSON.
///
/// Architecture tests use the compiler's own dependency graph rather than parsing manifests
/// by hand. The workspace root is the package manifest of this harness.
pub fn cargo_metadata() -> serde_json::Value {
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(workspace_root())
        .output()
        .expect("runs cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata is JSON")
}

/// True for a source file that exists only to hold tests.
///
/// The architecture tests scan production sources for forbidden calls. Unit tests may stand
/// up a local listener or a rustls server, so a test-only module must be excluded from that
/// scan. The convention is `src/<module>/tests.rs`, `src/tests.rs`, or `*_tests.rs`.
#[must_use]
pub fn is_test_source(path: &std::path::Path) -> bool {
    if path
        .components()
        .any(|component| component.as_os_str() == "tests")
    {
        return true;
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
}
