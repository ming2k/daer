// SPDX-License-Identifier: AGPL-3.0-only

//! Fails when a configuration key is accepted but never consumed outside `daer-config` (ADR-0006).
//!
//! A field is consumed when its name appears as a member access (`.field`) somewhere outside
//! `daer-config`'s own `model.rs`/`schema.rs`/`validate.rs`.
//!
//! ADR-0006 allows a key exactly one of:
//! 1. **implemented** — some code reads it;
//! 2. **removed** — it is not in the model, so `deny_unknown_fields` rejects it by name;
//! 3. **documented as a gap** — keep and document when removing breaks existing configs.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const CONFIG_STRUCTS: &[&str] = &[
    "Global",
    "Tls",
    "HealthCheck",
    "HealthCheckOverride",
    "Dns",
    "FakeIpConfig",
    "DnsRouting",
    "Routing",
    "Group",
    "Filter",
    "Node",
    "Subscription",
    "Config",
];

const SKIP: &[&str] = &[
    // The schema gate: enforced by `daer-config`'s validator by construction.
    "schema",
    // A loader directive, consumed inside `daer-config::toml_config` while assembling the tree.
    "include",
];

fn method_aliases(field: &str) -> &'static [&'static str] {
    match field {
        "bootstrap_resolver" => &["bootstrap_resolvers"],
        _ => &[],
    }
}

fn fields_of(struct_name: &str, source: &str) -> Vec<String> {
    let prefix = format!("pub struct {struct_name} {{");
    let Some(start) = source.find(&prefix) else {
        return Vec::new();
    };
    let rest = &source[start + prefix.len()..];
    let Some(end) = rest.find("\n}") else {
        return Vec::new();
    };
    let body = &rest[..end];

    let mut fields = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("pub ") && trimmed.contains(':') {
            let field_part = trimmed["pub ".len()..].split(':').next().unwrap().trim();
            if !field_part.is_empty()
                && field_part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                fields.push(field_part.to_string());
            }
        }
    }
    fields
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
}

#[test]
fn every_configuration_key_has_a_consumer() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_crates = manifest_dir.parent().expect("crates directory");
    let model_rs_path = manifest_dir.join("src/model.rs");
    let model_source = fs::read_to_string(&model_rs_path).expect("read model.rs");

    // Collect all Rust source files outside daer-config's model/schema/validate
    let mut rs_files = Vec::new();
    collect_rs_files(workspace_crates, &mut rs_files);

    let mut corpus = Vec::new();
    for path in rs_files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let is_in_daer_config = path.components().any(|c| c.as_os_str() == "daer-config");
        if is_in_daer_config && matches!(name, "model.rs" | "schema.rs" | "validate.rs") {
            continue;
        }
        if let Ok(content) = fs::read_to_string(&path) {
            corpus.push(content);
        }
    }

    let skip_set: HashSet<&str> = SKIP.iter().copied().collect();
    let mut dead = Vec::new();
    let mut total = 0;

    for &struct_name in CONFIG_STRUCTS {
        let fields = fields_of(struct_name, &model_source);
        assert!(
            !fields.is_empty(),
            "no fields found for {struct_name}; the parser drifted from the model"
        );

        for field in fields {
            if skip_set.contains(field.as_str()) {
                continue;
            }
            total += 1;

            let mut patterns = vec![format!(".{field}")];
            for alias in method_aliases(&field) {
                patterns.push(format!(".{alias}"));
            }

            let is_consumed = corpus
                .iter()
                .any(|code| patterns.iter().any(|pat| code.contains(pat)));

            if !is_consumed {
                dead.push((struct_name, field));
            }
        }
    }

    if !dead.is_empty() {
        let mut msg = format!(
            "\n[ADR-0006 VIOLATION] {} of {total} configuration keys are accepted and never consumed:\n",
            dead.len()
        );
        for (st, f) in &dead {
            msg.push_str(&format!("  {st}.{f}\n"));
        }
        msg.push_str("\nA key the schema accepts must either take effect or not exist.\n");
        msg.push_str(
            "Implement it, or remove it from `model.rs` so `deny_unknown_fields` rejects it.\n",
        );
        panic!("{msg}");
    }

    assert_eq!(
        total, 63,
        "expected exactly 63 configuration fields to be verified"
    );
}
