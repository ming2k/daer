// SPDX-License-Identifier: AGPL-3.0-only

//! `cargo xtask incident --check` — enforce the post-bug review record (ADR-0040).
//!
//! A markdown template is an aspiration. This check is the mechanism: it parses the
//! frontmatter, resolves every event code against the catalog, and resolves every regression
//! reference to a real test function. An incident record without a detection signal or a
//! falsifier is rejected.

use std::collections::BTreeSet;
use std::path::Path;

const DIRECTORY: &str = "docs/dev/incidents";

#[derive(Debug, Default)]
struct Incident {
    id: Option<String>,
    title: Option<String>,
    status: Option<String>,
    date: Option<String>,
    signal: Vec<String>,
    regression: Vec<String>,
    events_added: Vec<String>,
}

/// Runs the check.
///
/// # Errors
///
/// Returns a newline-separated list of every violation. It does not stop at the first one:
/// an incident author should see the whole record's problems in one pass.
pub fn run(root: &Path) -> Result<(), String> {
    let directory = root.join(DIRECTORY);
    if !directory.is_dir() {
        return Err(format!("{} is missing", directory.display()));
    }
    let codes = crate::events::event_codes(root)?;
    let index = std::fs::read_to_string(directory.join("index.md")).unwrap_or_default();
    let mut errors = Vec::new();
    let mut seen_ids = BTreeSet::new();

    for entry in std::fs::read_dir(&directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
        .flatten()
    {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.ends_with(".md") || file_name == "index.md" {
            continue;
        }
        if !file_name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_digit())
        {
            errors.push(format!(
                "{file_name}: incident file names start with a number"
            ));
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let incident = parse_frontmatter(&text, file_name, &mut errors);
        validate(&incident, file_name, root, &codes, &mut errors);
        if let Some(id) = &incident.id {
            if !seen_ids.insert(id.clone()) {
                errors.push(format!("{file_name}: duplicate incident id {id}"));
            }
            if !index.contains(id) {
                errors.push(format!("{file_name}: {id} is not listed in index.md"));
            }
        }
    }

    if errors.is_empty() {
        println!("incident records are valid");
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

fn parse_frontmatter(text: &str, file: &str, errors: &mut Vec<String>) -> Incident {
    let mut incident = Incident::default();
    let Some(rest) = text.strip_prefix("---\n") else {
        errors.push(format!("{file}: missing frontmatter"));
        return incident;
    };
    let Some((front, _)) = rest.split_once("\n---") else {
        errors.push(format!("{file}: unterminated frontmatter"));
        return incident;
    };
    let mut current_list: Option<&str> = None;
    for line in front.lines() {
        if let Some(item) = line.strip_prefix("  - ") {
            let value = unquote(item.trim());
            match current_list {
                Some("signal") => incident.signal.push(value),
                Some("regression") => incident.regression.push(value),
                Some("events_added") => incident.events_added.push(value),
                _ => errors.push(format!("{file}: list item {value:?} has no list key")),
            }
            continue;
        }
        current_list = None;
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "id" => incident.id = Some(unquote(value)),
            "title" => incident.title = Some(unquote(value)),
            "status" => incident.status = Some(unquote(value)),
            "date" => incident.date = Some(unquote(value)),
            "signal" => {
                if value.is_empty() {
                    current_list = Some("signal");
                } else {
                    incident.signal.extend(inline_list(value));
                }
            }
            "regression" => {
                if value.is_empty() {
                    current_list = Some("regression");
                } else {
                    incident.regression.extend(inline_list(value));
                }
            }
            "events_added" => {
                if value.is_empty() {
                    current_list = Some("events_added");
                } else {
                    incident.events_added.extend(inline_list(value));
                }
            }
            _ => {}
        }
    }
    incident
}

fn validate(
    incident: &Incident,
    file: &str,
    root: &Path,
    codes: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for (key, value) in [
        ("id", &incident.id),
        ("title", &incident.title),
        ("status", &incident.status),
        ("date", &incident.date),
    ] {
        if value.as_deref().is_none_or(str::is_empty) {
            errors.push(format!("{file}: missing {key}"));
        }
    }
    if let Some(status) = &incident.status
        && !matches!(
            status.as_str(),
            "draft" | "investigating" | "resolved" | "superseded"
        )
    {
        errors.push(format!("{file}: unknown status {status:?}"));
    }
    if let Some(date) = &incident.date {
        let valid = date.len() == 10
            && date.as_bytes().get(4) == Some(&b'-')
            && date.as_bytes().get(7) == Some(&b'-')
            && date
                .chars()
                .enumerate()
                .all(|(index, c)| index == 4 || index == 7 || c.is_ascii_digit());
        if !valid {
            errors.push(format!("{file}: date {date:?} is not YYYY-MM-DD"));
        }
    }
    if incident.signal.is_empty() {
        errors.push(format!(
            "{file}: a detection signal (event: or counter:) is mandatory"
        ));
    }
    for signal in &incident.signal {
        if let Some(code) = signal.strip_prefix("event:") {
            check_code(code.trim(), file, codes, errors);
        } else if let Some(counter) = signal.strip_prefix("counter:") {
            if counter.trim().is_empty() {
                errors.push(format!("{file}: empty counter signal"));
            }
        } else {
            errors.push(format!(
                "{file}: signal {signal:?} must be `event: <code>` or `counter: <name>`"
            ));
        }
    }
    if incident.regression.is_empty() {
        errors.push(format!(
            "{file}: at least one regression reference is mandatory"
        ));
    }
    for reference in &incident.regression {
        check_regression(reference, file, root, errors);
    }
    for code in &incident.events_added {
        check_code(code, file, codes, errors);
    }
}

fn check_code(code: &str, file: &str, codes: &BTreeSet<String>, errors: &mut Vec<String>) {
    if !codes.contains(code) {
        errors.push(format!(
            "{file}: event code {code:?} is not in crates/daer-observe/events.toml"
        ));
    }
}

fn check_regression(reference: &str, file: &str, root: &Path, errors: &mut Vec<String>) {
    let (path, test) = reference
        .split_once("::")
        .map_or((reference, None), |(path, test)| (path, Some(test)));
    let source = root.join(path);
    let Ok(text) = std::fs::read_to_string(&source) else {
        errors.push(format!("{file}: regression source {path:?} does not exist"));
        return;
    };
    if let Some(test) = test {
        let needles = [format!("fn {test}("), format!("fn {test}<")];
        if !needles.iter().any(|needle| text.contains(needle)) {
            errors.push(format!(
                "{file}: regression test {test:?} is not defined in {path}"
            ));
        }
    }
}

fn inline_list(value: &str) -> Vec<String> {
    let value = value.trim().trim_start_matches('[').trim_end_matches(']');
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(unquote)
        .collect()
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').trim_matches('\'').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inline_list_is_split_and_unquoted() {
        assert_eq!(
            inline_list("[\"flow.dial_failed\", datapath.event]"),
            ["flow.dial_failed", "datapath.event"]
        );
    }

    #[test]
    fn a_missing_signal_is_rejected() {
        let mut errors = Vec::new();
        let incident = Incident {
            id: Some("INC-9999".into()),
            title: Some("t".into()),
            status: Some("resolved".into()),
            date: Some("2026-11-11".into()),
            ..Incident::default()
        };
        let codes = BTreeSet::new();
        validate(&incident, "test.md", Path::new("."), &codes, &mut errors);
        assert!(errors.iter().any(|error| error.contains("signal")));
        assert!(errors.iter().any(|error| error.contains("regression")));
    }
}
