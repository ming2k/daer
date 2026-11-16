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

/// Scans the workspace for raw `tracing` macros, severity mismatches, and missing catalog fields.
fn check_sources(root: &Path, catalog: &Catalog) -> Result<(), String> {
    let spec_by_name: BTreeMap<&str, &Event> = catalog
        .events
        .iter()
        .map(|event| (event.name.as_str(), event))
        .collect();
    let mut errors = Vec::new();

    for path in source_files(root) {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let relative = relative.to_string_lossy();
        let allow_raw_tracing = relative.starts_with("crates/daer-observe/src/")
            || relative == "crates/daer-cli/src/main.rs"
            || relative.starts_with("crates/daer-cli/src/diagnostics/")
            || relative == "crates/xtask/src/events.rs";
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        check_source_text(
            &relative,
            &text,
            allow_raw_tracing,
            &spec_by_name,
            &mut errors,
        );
    }

    if errors.is_empty() {
        Ok(())
    } else {
        errors.sort();
        errors.dedup();
        Err(errors.join("\n"))
    }
}

fn check_source_text(
    relative: &str,
    text: &str,
    allow_raw_tracing: bool,
    spec_by_name: &BTreeMap<&str, &Event>,
    errors: &mut Vec<String>,
) {
    if !allow_raw_tracing {
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            if line.contains("tracing::") {
                // Comments are allowed to name the old mechanism; a macro invocation is not.
                let code = line.split("//").next().unwrap_or("");
                if code.contains("tracing::") {
                    errors.push(format!(
                        "{relative}:{line_number}: raw tracing macro; use daer_observe::EventCode",
                    ));
                }
            }
        }
    }

    let invocations = scan_event_invocations(text);
    for inv in invocations {
        let line_number = inv.line;
        let macro_name = inv.macro_name;
        let args = split_top_level_args(&inv.args_body);
        let Some(first_arg) = args.first() else {
            errors.push(format!(
                "{relative}:{line_number}: daer_observe::{macro_name}! without arguments",
            ));
            continue;
        };
        let Some(code_at) = first_arg.find("EventCode::") else {
            errors.push(format!(
                "{relative}:{line_number}: daer_observe::{macro_name}! without an EventCode",
            ));
            continue;
        };
        let rest = &first_arg[code_at + "EventCode::".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let Some(event) = spec_by_name.get(name.as_str()).copied() else {
            errors.push(format!(
                "{relative}:{line_number}: {name} is not in the event catalog",
            ));
            continue;
        };
        if event.level != macro_name {
            errors.push(format!(
                "{relative}:{line_number}: {name} is declared {} but emitted with {macro_name}!",
                event.level
            ));
        }

        let supplied = extract_supplied_fields(&args[1..]);
        let missing: Vec<&str> = event
            .fields
            .iter()
            .map(String::as_str)
            .filter(|required| !supplied.contains(*required))
            .collect();
        if !missing.is_empty() {
            errors.push(format!(
                "{relative}:{line_number}: {name} is missing catalog field(s): {}",
                missing.join(", ")
            ));
        }
    }
}

struct EventInvocation {
    line: usize,
    macro_name: &'static str,
    args_body: String,
}

fn scan_event_invocations(text: &str) -> Vec<EventInvocation> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;

    while i < bytes.len() {
        if let Some((next, lines_added)) = skip_non_code_token(text, i) {
            line += lines_added;
            i = next;
            continue;
        }
        if bytes[i] == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if let Some((macro_name, open_paren_at)) = match_macro_at(text, i) {
            let call_line = line;
            if let Some((close_at, span_lines)) = find_matching_paren(text, open_paren_at) {
                out.push(EventInvocation {
                    line: call_line,
                    macro_name,
                    args_body: text[open_paren_at + 1..close_at].to_owned(),
                });
                line += span_lines;
                i = close_at + 1;
                continue;
            }
        }
        i += 1;
    }

    out
}

fn match_macro_at(text: &str, at: usize) -> Option<(&'static str, usize)> {
    // Require word/path boundary so e.g. `foo_daer_observe::warn!(` cannot match accidentally.
    if at > 0 {
        let prev = text.as_bytes()[at - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
            return None;
        }
    }
    let tail = text.get(at..)?;
    let rest = tail.strip_prefix("daer_observe::")?;
    for macro_name in ["trace", "debug", "info", "warn", "error"] {
        if let Some(after_name) = rest.strip_prefix(macro_name) {
            let mut offset = "daer_observe::".len() + macro_name.len();
            let after_ws = after_name.trim_start();
            offset += after_name.len() - after_ws.len();
            if let Some(after_bang) = after_ws.strip_prefix('!') {
                offset += 1;
                let after_bang_ws = after_bang.trim_start();
                offset += after_bang.len() - after_bang_ws.len();
                if after_bang_ws.starts_with('(') {
                    return Some((macro_name, at + offset));
                }
            }
        }
    }
    None
}

fn find_matching_paren(text: &str, open_at: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut i = open_at + 1;
    let mut depth = 1usize;
    let mut lines = 0usize;

    while i < bytes.len() {
        if let Some((next, added)) = skip_non_code_token(text, i) {
            lines += added;
            i = next;
            continue;
        }
        match bytes[i] {
            b'\n' => lines += 1,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((i, lines));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Skips strings, raw strings, line comments, and block comments starting at `at`.
fn skip_non_code_token(text: &str, at: usize) -> Option<(usize, usize)> {
    let tail = text.get(at..)?;
    let bytes = tail.as_bytes();
    if bytes.starts_with(b"//") {
        let end = tail.find('\n').map_or(text.len(), |off| at + off);
        return Some((end, 0));
    }
    if bytes.starts_with(b"/*") {
        let mut depth = 1usize;
        let mut idx = 2usize;
        let mut lines = 0usize;
        while idx < bytes.len() && depth > 0 {
            if bytes[idx..].starts_with(b"/*") {
                depth += 1;
                idx += 2;
            } else if bytes[idx..].starts_with(b"*/") {
                depth -= 1;
                idx += 2;
            } else {
                if bytes[idx] == b'\n' {
                    lines += 1;
                }
                idx += 1;
            }
        }
        return Some((at + idx, lines));
    }
    if bytes.starts_with(b"\"") || bytes.starts_with(b"b\"") {
        let start = if bytes.starts_with(b"b\"") { 2 } else { 1 };
        let mut idx = start;
        let mut lines = 0usize;
        while idx < bytes.len() {
            if bytes[idx] == b'\\' {
                if idx + 1 < bytes.len() && bytes[idx + 1] == b'\n' {
                    lines += 1;
                }
                idx = (idx + 2).min(bytes.len());
                continue;
            }
            if bytes[idx] == b'"' {
                return Some((at + idx + 1, lines));
            }
            if bytes[idx] == b'\n' {
                lines += 1;
            }
            idx += 1;
        }
        return Some((text.len(), lines));
    }
    if bytes.starts_with(b"r\"") || bytes.starts_with(b"r#") {
        let mut hashes = 0usize;
        let mut idx = 1usize;
        while idx < bytes.len() && bytes[idx] == b'#' {
            hashes += 1;
            idx += 1;
        }
        if idx < bytes.len() && bytes[idx] == b'"' {
            idx += 1;
            let mut lines = 0usize;
            while idx < bytes.len() {
                if bytes[idx] == b'"'
                    && bytes[idx + 1..].len() >= hashes
                    && bytes[idx + 1..idx + 1 + hashes].iter().all(|&b| b == b'#')
                {
                    return Some((at + idx + 1 + hashes, lines));
                }
                if bytes[idx] == b'\n' {
                    lines += 1;
                }
                idx += 1;
            }
            return Some((text.len(), lines));
        }
    }
    None
}

fn split_top_level_args(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut args = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut depth = 0usize;

    while i < bytes.len() {
        if let Some((next, _)) = skip_non_code_token(body, i) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                args.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if !body[start..].trim().is_empty() {
        args.push(&body[start..]);
    }
    args
}

fn strip_leading_comments_and_ws(mut s: &str) -> &str {
    loop {
        s = s.trim_start();
        if let Some(rest) = s.strip_prefix("//") {
            s = rest.split_once('\n').map_or("", |(_, after)| after);
            continue;
        }
        if let Some(rest) = s.strip_prefix("/*") {
            s = rest.split_once("*/").map_or("", |(_, after)| after);
            continue;
        }
        return s;
    }
}

fn extract_supplied_fields(args: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for &raw in args {
        let trimmed = strip_leading_comments_and_ws(raw).trim_end();
        if trimmed.is_empty() {
            continue;
        }
        // Once the trailing message format string literal starts, remaining args are format
        // arguments rather than structured tracing fields.
        if trimmed.starts_with('"') || trimmed.starts_with("r\"") || trimmed.starts_with("r#\"") {
            break;
        }
        if let Some(eq_at) = find_top_level_assignment(trimmed) {
            let lhs = strip_leading_comments_and_ws(&trimmed[..eq_at]).trim();
            let normalized: String = lhs.chars().filter(|c| !c.is_whitespace()).collect();
            if !normalized.is_empty() {
                out.insert(normalized);
            }
            continue;
        }
        let shorthand = trimmed
            .strip_prefix('%')
            .or_else(|| trimmed.strip_prefix('?'))
            .unwrap_or(trimmed);
        let shorthand = strip_leading_comments_and_ws(shorthand);
        let name: String = shorthand
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

fn find_top_level_assignment(expr: &str) -> Option<usize> {
    let bytes = expr.as_bytes();
    let mut i = 0usize;
    let mut depth = 0usize;
    while i < bytes.len() {
        if let Some((next, _)) = skip_non_code_token(expr, i) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b'=' if depth == 0 => {
                let prev = i.checked_sub(1).map(|idx| bytes[idx]);
                let next = bytes.get(i + 1).copied();
                if !matches!(prev, Some(b'=' | b'!' | b'<' | b'>'))
                    && !matches!(next, Some(b'=' | b'>'))
                {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
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

    fn event_fixture(name: &'static str, level: &'static str, fields: &[&'static str]) -> Event {
        Event {
            name: name.to_owned(),
            code: format!("test.{name}"),
            level: level.to_owned(),
            message: name.to_owned(),
            fields: fields.iter().map(|s| (*s).to_owned()).collect(),
            counter: None,
            rate: None,
            remediation: None,
        }
    }

    #[test]
    fn check_source_text_accepts_valid_multiline_and_shorthand_fields() {
        let ev = event_fixture(
            "FlowClosed",
            "debug",
            &["flow_id", "destination", "outcome", "reaped"],
        );
        let specs = BTreeMap::from([(ev.name.as_str(), &ev)]);
        let src = r#"
            // daer_observe::warn!(EventCode::FlowClosed, "comment must be ignored");
            daer_observe::debug!(
                daer_observe::EventCode::FlowClosed,
                flow_id = %id,
                %destination,
                outcome = "clean",
                // field comment
                reaped,
                "flow closed: {}",
                extra_fmt
            );
        "#;
        let mut errors = Vec::new();
        check_source_text("test.rs", src, false, &specs, &mut errors);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn check_source_text_rejects_missing_catalog_field() {
        // Falsifier for field enforcement: omitting `error_code` must be caught even when
        // severity and EventCode match.
        let ev = event_fixture(
            "FlowDialFailed",
            "warn",
            &["flow_id", "stage", "error_code", "detail"],
        );
        let specs = BTreeMap::from([(ev.name.as_str(), &ev)]);
        let src = r#"
            daer_observe::warn!(
                daer_observe::EventCode::FlowDialFailed,
                flow_id = %id,
                stage = "tcp",
                detail = %err,
                "flow dial failed"
            );
        "#;
        let mut errors = Vec::new();
        check_source_text("test.rs", src, false, &specs, &mut errors);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("error_code"), "{errors:?}");
    }
}
