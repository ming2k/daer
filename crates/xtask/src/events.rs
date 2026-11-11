// SPDX-License-Identifier: AGPL-3.0-only

//! `cargo xtask events` — generate the diagnostic event catalog (ADR-0040).
//!
//! One declaration, three outputs:
//!
//! | Output | Consumer |
//! | --- | --- |
//! | `crates/daer-observe/src/generated.rs` | the `EventCode` enum and its metadata |
//! | `docs/reference/events.md` | the operator/contributor reference |
//! | this check | duplicate codes, missing severity metadata, raw `tracing` calls |
//!
//! `--check` regenerates into memory and diffs against what is committed. It also scans the
//! workspace for a raw `tracing` macro or a call-site level that disagrees with the catalog.
//! That scan is the mechanism behind `[INV-EVENT-01]`; without it the macro firewall is a
//! convention.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, serde::Deserialize)]
pub struct Catalog {
    pub schema: u32,
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Event {
    pub name: String,
    pub code: String,
    pub level: String,
    pub message: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub counter: Option<String>,
    #[serde(default)]
    pub rate: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
}

const CATALOG: &str = "crates/daer-observe/events.toml";
const RUST_OUT: &str = "crates/daer-observe/src/generated.rs";
const DOCS_OUT: &str = "docs/reference/events.md";

/// Runs the generator.
///
/// # Errors
///
/// Returns a message naming the first invalid declaration, the first drift, or the first raw
/// `tracing` call.
pub fn run(root: &Path, check: bool) -> Result<(), String> {
    let catalog = load(root)?;
    validate(&catalog)?;
    let rust = render_rust(&catalog);
    let docs = render_docs(&catalog);

    if check {
        check_file(&root.join(RUST_OUT), &rust)?;
        check_file(&root.join(DOCS_OUT), &docs)?;
        check_sources(root, &catalog)?;
        println!("event catalog is current");
    } else {
        std::fs::write(root.join(RUST_OUT), rust)
            .map_err(|error| format!("cannot write {RUST_OUT}: {error}"))?;
        std::fs::write(root.join(DOCS_OUT), docs)
            .map_err(|error| format!("cannot write {DOCS_OUT}: {error}"))?;
        println!("wrote {RUST_OUT} and {DOCS_OUT}");
    }
    Ok(())
}

/// The set of declared event codes, for the incident checker.
pub fn event_codes(root: &Path) -> Result<BTreeSet<String>, String> {
    let catalog = load(root)?;
    validate(&catalog)?;
    Ok(catalog.events.into_iter().map(|event| event.code).collect())
}

fn load(root: &Path) -> Result<Catalog, String> {
    let path = root.join(CATALOG);
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

fn validate(catalog: &Catalog) -> Result<(), String> {
    if catalog.schema != 1 {
        return Err(format!(
            "{CATALOG}: unsupported schema {}; this build understands 1",
            catalog.schema
        ));
    }
    if catalog.events.is_empty() {
        return Err(format!("{CATALOG}: no events declared"));
    }

    let mut names = BTreeSet::new();
    let mut codes = BTreeSet::new();
    for event in &catalog.events {
        if !names.insert(event.name.as_str()) {
            return Err(format!("{CATALOG}: duplicate event name {}", event.name));
        }
        if !codes.insert(event.code.as_str()) {
            return Err(format!("{CATALOG}: duplicate event code {}", event.code));
        }
        if !is_code(&event.code) {
            return Err(format!(
                "{CATALOG}: event {} has invalid code {:?}; use dotted lower-case",
                event.name, event.code
            ));
        }
        if !matches!(
            event.level.as_str(),
            "error" | "warn" | "info" | "debug" | "trace"
        ) {
            return Err(format!(
                "{CATALOG}: event {} has unknown level {:?}",
                event.name, event.level
            ));
        }
        if event.message.trim().is_empty() {
            return Err(format!(
                "{CATALOG}: event {} has an empty message",
                event.name
            ));
        }
        if matches!(event.level.as_str(), "warn" | "error") {
            if event.counter.as_deref().is_none_or(str::is_empty) {
                return Err(format!(
                    "{CATALOG}: {} is {} but declares no counter",
                    event.name, event.level
                ));
            }
            if event.rate.as_deref().is_none_or(str::is_empty) {
                return Err(format!(
                    "{CATALOG}: {} is {} but declares no rate-limit group",
                    event.name, event.level
                ));
            }
            if event.remediation.as_deref().is_none_or(str::is_empty) {
                return Err(format!(
                    "{CATALOG}: {} is {} but declares no remediation",
                    event.name, event.level
                ));
            }
        }
    }
    Ok(())
}

fn is_code(code: &str) -> bool {
    let mut parts = code.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    if first.is_empty() {
        return false;
    }
    code.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_')
        && !code.ends_with('.')
        && code.matches('.').count() >= 1
}

fn render_rust(catalog: &Catalog) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "// Code generated by `cargo xtask events` from crates/daer-observe/events.toml; DO NOT EDIT."
    );
    let _ = writeln!(
        out,
        "//\n// `cargo xtask events --check` fails when this file and the catalog disagree (ADR-0040).\n"
    );
    let _ = writeln!(
        out,
        "use crate::code::Severity;\n\n/// One stable diagnostic event code.\n#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub enum EventCode {{"
    );
    for event in &catalog.events {
        let _ = writeln!(
            out,
            "    /// `{}` — {}",
            event.code,
            one_line(&event.message)
        );
        let _ = writeln!(out, "    {},", event.name);
    }
    let _ = writeln!(out, "}}\n");
    let _ = writeln!(out, "impl EventCode {{");
    let _ = writeln!(
        out,
        "    /// Every code in the catalog, in declaration order.\n    pub const ALL: &'static [Self] = &["
    );
    for event in &catalog.events {
        let _ = writeln!(out, "        Self::{},", event.name);
    }
    let _ = writeln!(out, "    ];\n");

    let _ = writeln!(
        out,
        "    /// The stable dotted code.\n    #[must_use]\n    pub const fn as_str(self) -> &'static str {{\n        match self {{"
    );
    for event in &catalog.events {
        let _ = writeln!(out, "            Self::{} => {:?},", event.name, event.code);
    }
    let _ = writeln!(out, "        }}\n    }}\n");

    let _ = writeln!(
        out,
        "    /// The severity the catalog declares.\n    #[must_use]\n    pub const fn level(self) -> Severity {{\n        match self {{"
    );
    for event in &catalog.events {
        let level = match event.level.as_str() {
            "error" => "Severity::Error",
            "warn" => "Severity::Warn",
            "info" => "Severity::Info",
            "debug" => "Severity::Debug",
            "trace" => "Severity::Trace",
            _ => unreachable!("validated"),
        };
        let _ = writeln!(out, "            Self::{} => {level},", event.name);
    }
    let _ = writeln!(out, "        }}\n    }}\n");

    let _ = writeln!(
        out,
        "    /// The human message. Presentation only; the code is the contract.\n    #[must_use]\n    pub const fn message(self) -> &'static str {{\n        match self {{"
    );
    for event in &catalog.events {
        let _ = writeln!(
            out,
            "            Self::{} => {:?},",
            event.name, event.message
        );
    }
    let _ = writeln!(out, "        }}\n    }}\n");

    let _ = writeln!(
        out,
        "    /// What an operator should do, for events that can fail a client.\n    #[must_use]\n    pub const fn remediation(self) -> Option<&'static str> {{\n        match self {{"
    );
    for event in &catalog.events {
        match &event.remediation {
            Some(remediation) => {
                let _ = writeln!(
                    out,
                    "            Self::{} => Some({:?}),",
                    event.name, remediation
                );
            }
            None => {
                let _ = writeln!(out, "            Self::{} => None,", event.name);
            }
        }
    }
    let _ = writeln!(out, "        }}\n    }}\n");

    let _ = writeln!(
        out,
        "    /// The exact counter this event increments, when it has one.\n    #[must_use]\n    pub const fn counter(self) -> Option<&'static str> {{\n        match self {{"
    );
    for event in &catalog.events {
        match &event.counter {
            Some(counter) => {
                let _ = writeln!(
                    out,
                    "            Self::{} => Some({:?}),",
                    event.name, counter
                );
            }
            None => {
                let _ = writeln!(out, "            Self::{} => None,", event.name);
            }
        }
    }
    let _ = writeln!(out, "        }}\n    }}\n");

    let _ = writeln!(
        out,
        "    /// The rate-limit group for a high-volume failure event.\n    #[must_use]\n    pub const fn rate_limit(self) -> Option<&'static str> {{\n        match self {{"
    );
    for event in &catalog.events {
        match &event.rate {
            Some(rate) => {
                let _ = writeln!(out, "            Self::{} => Some({:?}),", event.name, rate);
            }
            None => {
                let _ = writeln!(out, "            Self::{} => None,", event.name);
            }
        }
    }
    let _ = writeln!(out, "        }}\n    }}\n");

    let _ = writeln!(
        out,
        "    /// The fields a complete event carries.\n    #[must_use]\n    pub const fn required_fields(self) -> &'static [&'static str] {{\n        match self {{"
    );
    for event in &catalog.events {
        let fields = event
            .fields
            .iter()
            .map(|field| format!("{field:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "            Self::{} => &[{}],", event.name, fields);
    }
    let _ = writeln!(out, "        }}\n    }}\n}}\n");

    let _ = writeln!(
        out,
        "/// A catalog entry as data, for `xtask` and the reference.\n#[derive(Debug, Clone, Copy)]\npub struct EventSpec {{\n    pub code: EventCode,\n    pub name: &'static str,\n    pub level: Severity,\n    pub message: &'static str,\n    pub fields: &'static [&'static str],\n    pub counter: Option<&'static str>,\n    pub rate: Option<&'static str>,\n    pub remediation: Option<&'static str>,\n}}\n"
    );
    let _ = writeln!(
        out,
        "/// Every catalog entry, for a test or a generated reference.\npub const SPECS: &[EventSpec] = &["
    );
    for event in &catalog.events {
        let fields = event
            .fields
            .iter()
            .map(|field| format!("{field:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "    EventSpec {{ code: EventCode::{}, name: {:?}, level: EventCode::{}.level(), message: EventCode::{}.message(), fields: &[{}], counter: EventCode::{}.counter(), rate: EventCode::{}.rate_limit(), remediation: EventCode::{}.remediation() }},",
            event.name,
            event.name,
            event.name,
            event.name,
            fields,
            event.name,
            event.name,
            event.name
        );
    }
    let _ = writeln!(out, "];\n");
    out
}

fn render_docs(catalog: &Catalog) -> String {
    let mut out = String::new();
    writeln!(out, "# Diagnostic Event Reference").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "This file is generated from `crates/daer-observe/events.toml` by `cargo xtask events`."
    )
    .unwrap();
    writeln!(
        out,
        "The **code** is the stable contract; the message is presentation. An event with a"
    )
    .unwrap();
    writeln!(
        out,
        "`warn` or `error` severity always has a counter, a rate-limit group and a remediation."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Run `cargo xtask events --check` to fail on catalog drift."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "| Code | Level | Message | Required fields | Counter | Rate | Remediation |"
    )
    .unwrap();
    writeln!(out, "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |").unwrap();
    for event in &catalog.events {
        writeln!(
            out,
            "| `{}` | `{}` | {} | {} | {} | {} | {} |",
            event.code,
            event.level,
            table(&event.message),
            if event.fields.is_empty() {
                "—".to_owned()
            } else {
                event
                    .fields
                    .iter()
                    .map(|field| format!("`{field}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            event
                .counter
                .as_deref()
                .map_or_else(|| "—".to_owned(), |counter| format!("`{counter}`")),
            event
                .rate
                .as_deref()
                .map_or_else(|| "—".to_owned(), |rate| format!("`{rate}`")),
            event
                .remediation
                .as_deref()
                .map_or_else(|| "—".to_owned(), table),
        )
        .unwrap();
    }
    writeln!(out).unwrap();
    writeln!(out, "## How to read this table").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "- **Code** is what you filter, count, link from an incident, and test. It does not change"
    )
    .unwrap();
    writeln!(
        out,
        "  when a message is reworded. A rename is a contract change and needs a new code."
    )
    .unwrap();
    writeln!(
        out,
        "- **Level** is the catalog's severity, not a call-site choice. `cargo xtask events --check`"
    )
    .unwrap();
    writeln!(
        out,
        "  compares the macro used at the call site with this table."
    )
    .unwrap();
    writeln!(
        out,
        "- **Counter** is exact even when the log line is rate-limited. Volume comes from counters,"
    )
    .unwrap();
    writeln!(out, "  never from counting sampled lines.").unwrap();
    writeln!(
        out,
        "- **Remediation** is the operator's next action. It is not a restatement of the message."
    )
    .unwrap();
    out
}

fn one_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ").trim().to_owned()
}

fn table(text: &str) -> String {
    one_line(text).replace('|', "\\|")
}

fn check_file(path: &Path, expected: &str) -> Result<(), String> {
    let actual = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if actual == expected {
        return Ok(());
    }
    let first = actual
        .lines()
        .zip(expected.lines())
        .enumerate()
        .find(|(_, (a, b))| a != b)
        .map_or_else(
            || {
                format!(
                    "length differs ({} vs {})",
                    actual.lines().count(),
                    expected.lines().count()
                )
            },
            |(index, (a, b))| format!("line {}:\n  committed: {a}\n  generated: {b}", index + 1),
        );
    Err(format!(
        "{} is stale; run `cargo xtask events --write`\n{first}",
        path.display()
    ))
}

/// Scans the workspace for raw `tracing` macros and call-site level mismatches.
fn check_sources(root: &Path, catalog: &Catalog) -> Result<(), String> {
    let levels: BTreeMap<&str, &str> = catalog
        .events
        .iter()
        .map(|event| (event.name.as_str(), event.level.as_str()))
        .collect();
    let mut errors = Vec::new();

    for path in source_files(root) {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let relative = relative.to_string_lossy();
        let allowed = relative.starts_with("crates/daer-observe/src/")
            || relative == "crates/daer-cli/src/main.rs"
            || relative.starts_with("crates/daer-cli/src/diagnostics/")
            || relative == "crates/xtask/src/events.rs";
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            if !allowed && line.contains("tracing::") {
                // Comments are allowed to name the old mechanism; a macro invocation is not.
                let code = line.split("//").next().unwrap_or("");
                if code.contains("tracing::") {
                    errors.push(format!(
                        "{}:{line_number}: raw tracing macro; use daer_observe::EventCode",
                        relative
                    ));
                }
            }
            for macro_name in ["trace", "debug", "info", "warn", "error"] {
                let needle = format!("daer_observe::{macro_name}!(");
                if line.contains(&needle) {
                    // A call may put the code on the next line. Search the next few lines,
                    // not the whole file: a missing code must not borrow the next event's.
                    let window = text
                        .lines()
                        .skip(index)
                        .take(6)
                        .collect::<Vec<_>>()
                        .join("\n");
                    let Some(code_at) = window.find("EventCode::") else {
                        errors.push(format!(
                            "{}:{line_number}: daer_observe::{macro_name}! without an EventCode",
                            relative
                        ));
                        continue;
                    };
                    let rest = &window[code_at + "EventCode::".len()..];
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    match levels.get(name.as_str()) {
                        Some(level) if *level == macro_name => {}
                        Some(level) => errors.push(format!(
                            "{}:{line_number}: {name} is declared {level} but emitted with {macro_name}!",
                            relative
                        )),
                        None => errors.push(format!(
                            "{}:{line_number}: {name} is not in the event catalog",
                            relative
                        )),
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        errors.sort();
        errors.dedup();
        Err(errors.join("\n"))
    }
}

fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for crate_dir in std::fs::read_dir(root.join("crates")).into_iter().flatten() {
        let Ok(crate_dir) = crate_dir else {
            continue;
        };
        let src = crate_dir.path().join("src");
        if !src.is_dir() {
            continue;
        }
        collect_rs(&src, &mut out);
    }
    out.sort();
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_is_valid_and_has_no_duplicate_codes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let catalog = load(root).expect("catalog parses");
        validate(&catalog).expect("catalog validates");
    }

    #[test]
    fn every_warn_and_error_has_operator_content() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let catalog = load(root).expect("catalog parses");
        for event in &catalog.events {
            if matches!(event.level.as_str(), "warn" | "error") {
                assert!(event.counter.is_some(), "{} has no counter", event.name);
                assert!(event.rate.is_some(), "{} has no rate group", event.name);
                assert!(
                    event.remediation.is_some(),
                    "{} has no remediation",
                    event.name
                );
            }
        }
    }
}
