// SPDX-License-Identifier: AGPL-3.0-only

//! The test architecture is itself a test: no ignored test without an owner, no crate-local
//! external test directory, no production dependency on the dev-only test-support crate, and
//! both harness layers selected in CI.
//!
//! This replaces the former `cargo xtask test --audit`. Keeping it here means it runs under
//! the same nextest invocation as every other integration test, and it cannot quietly stop
//! being part of CI.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::common::{cargo_metadata, workspace_path, workspace_root};

const CI_WORKFLOW: &str = ".github/workflows/ci.yml";

#[test]
fn the_test_support_crate_is_dev_only() {
    let metadata = cargo_metadata();
    let mut offenders = Vec::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let name = package["name"].as_str().unwrap_or("<unnamed>");
        for dependency in package["dependencies"].as_array().into_iter().flatten() {
            let dependency_name = dependency["name"].as_str().unwrap_or_default();
            if dependency_name != "test-support" {
                continue;
            }
            // `kind` is null for a normal dependency and "dev" for a dev-dependency.
            if dependency["kind"].is_null() {
                offenders.push(name.to_owned());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "test-support must be a dev-dependency only; normal dependents: {offenders:?}"
    );
}

#[test]
fn every_external_test_lives_in_the_workspace_harness() {
    let crates = workspace_path("crates");
    let mut offenders = Vec::new();
    for entry in fs::read_dir(&crates).expect("workspace crates are readable") {
        let crate_dir = entry.expect("crate entry").path();
        if crate_dir.join("tests").is_dir() {
            offenders.push(crate_dir.join("tests").display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "crate-local external tests belong in tests/integration or tests/e2e: {offenders:?}"
    );
}

#[test]
fn the_harness_has_exactly_the_integration_and_e2e_targets() {
    let metadata = cargo_metadata();
    let root = workspace_root();
    let mut found = BTreeSet::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let manifest = Path::new(package["manifest_path"].as_str().unwrap_or_default());
        if manifest != root.join("Cargo.toml") {
            continue;
        }
        for target in package["targets"].as_array().into_iter().flatten() {
            let is_test = target["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|kind| kind.as_str() == Some("test"));
            if is_test && let Some(name) = target["name"].as_str() {
                found.insert(name.to_owned());
            }
        }
    }
    let expected: BTreeSet<String> = ["e2e".to_owned(), "integration".to_owned()]
        .into_iter()
        .collect();
    assert_eq!(
        found, expected,
        "the root harness must expose exactly the integration and e2e test binaries"
    );
}

#[test]
fn every_ignored_test_names_its_prerequisite() {
    let mut failures = Vec::new();
    let mut files = rust_files(&workspace_path("crates"));
    files.extend(rust_files(&workspace_path("tests")));
    for file in files {
        let text = fs::read_to_string(&file).expect("source is UTF-8");
        for (line_number, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.starts_with("#[ignore") {
                continue;
            }
            let location = format!(
                "{}:{}",
                file.strip_prefix(workspace_root())
                    .unwrap_or(&file)
                    .display(),
                line_number + 1
            );
            match reason(trimmed) {
                None => failures.push(format!("{location}: `#[ignore]` has no reason")),
                Some(reason) if reason.trim().len() < 12 => failures.push(format!(
                    "{location}: `#[ignore = \"{reason}\"]` is too short to name a prerequisite"
                )),
                Some(_) => {}
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn ci_runs_both_harness_layers() {
    let workflow =
        fs::read_to_string(workspace_path(CI_WORKFLOW)).expect("CI workflow is readable");
    for needle in ["binary(integration)", "binary(e2e)"] {
        assert!(
            workflow.contains(needle),
            "CI does not run nextest filter `{needle}`; the layer is not gated"
        );
    }
}

fn reason(line: &str) -> Option<&str> {
    let (_, rest) = line.split_once('=')?;
    let rest = rest.trim_start().strip_prefix('"')?;
    let (reason, _) = rest.split_once('"')?;
    Some(reason)
}

fn rust_files(directory: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(directory, &mut out);
    out
}

fn collect(directory: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// A convenience used by other modules that need the per-package metadata map.
#[allow(dead_code)]
pub fn packages_by_name() -> BTreeMap<String, serde_json::Value> {
    let metadata = cargo_metadata();
    let mut packages = BTreeMap::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        if let Some(name) = package["name"].as_str() {
            packages.insert(name.to_owned(), package.clone());
        }
    }
    packages
}
