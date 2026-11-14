// SPDX-License-Identifier: AGPL-3.0-only

//! The test architecture is itself a test: no ignored test without an owner, no crate-local
//! external test directory, no production dependency on the dev-only test-support crate, and
//! no `DAER_REQUIRE` key that no script emits.
//!
//! This replaces the former `cargo xtask test --audit`. Keeping it here means it runs under
//! the same nextest invocation as every other integration test, and it cannot quietly stop
//! being part of CI.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::common::{cargo_metadata, workspace_path, workspace_root};

const VERIFY_SCRIPTS: &str = "scripts/verify";
const CI_WORKFLOW: &str = ".github/workflows/ci.yml";

/// Skip keys deliberately not required in CI, each with the reason.
const MANUAL_SKIP_KEYS: &[(&str, &str)] = &[(
    "3-udp",
    "the single-namespace IPv4 UDP fixture is invalid; control_transparent_udp4/6 own the \
     two-namespace datagram paths",
)];

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
fn every_daer_require_key_is_emitted_by_a_script() {
    let emitted = emitted_skip_keys();
    let required = required_ci_keys();

    let mut failures = Vec::new();
    for key in &required {
        if !emitted.contains(key) {
            failures.push(format!(
                "CI requires `{key}` but no script emits it; the gate could never fail for the \
                 reason it claims"
            ));
        }
    }

    let manual: BTreeSet<&str> = MANUAL_SKIP_KEYS.iter().map(|(key, _)| *key).collect();
    for key in &emitted {
        if required.contains(key) || manual.contains(key.as_str()) {
            continue;
        }
        failures.push(format!(
            "`{key}` can be skipped but no CI job requires it and it is not in \
             MANUAL_SKIP_KEYS"
        ));
    }
    for (key, _) in MANUAL_SKIP_KEYS {
        if required.contains(*key) {
            failures.push(format!(
                "`{key}` is listed as manual but CI requires it; one list is stale"
            ));
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

fn emitted_skip_keys() -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for entry in fs::read_dir(workspace_path(VERIFY_SCRIPTS)).expect("verify scripts are readable")
    {
        let path = entry.expect("script entry").path();
        if path.extension().is_none_or(|extension| extension != "sh") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("script is UTF-8");
        for line in text.lines() {
            let line = line.trim_start();
            let Some(rest) = line.strip_prefix("skip ") else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix('"') else {
                continue;
            };
            let Some((key, _)) = rest.split_once('"') else {
                panic!("{}: a skip call has no closing quote", path.display());
            };
            keys.insert(key.to_owned());
        }
    }
    keys
}

fn required_ci_keys() -> BTreeSet<String> {
    let text = fs::read_to_string(workspace_path(CI_WORKFLOW)).expect("CI workflow is readable");
    let mut keys = BTreeSet::new();
    for line in text.lines() {
        let Some((_, value)) = line.split_once("DAER_REQUIRE:") else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value);
        for key in value
            .split(',')
            .map(str::trim)
            .filter(|key| !key.is_empty())
        {
            keys.insert(key.to_owned());
        }
    }
    assert!(!keys.is_empty(), "CI declares no DAER_REQUIRE keys");
    keys
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
