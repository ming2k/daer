// SPDX-License-Identifier: AGPL-3.0-only

//! The compiled diagnostic catalog is a public contract: operators grep the codes, alerting
//! keys on the counters, and incident bundles join on the required fields ([INV-EVENT-01]).
//!
//! `cargo xtask events --check` validates the *source* (`events.toml`) and regenerates the
//! Rust module. This test validates the *generated* artifact the daemon actually links: if the
//! generator ever drops a variant, loses a metadata row, or emits a duplicate code, the source
//! check would still be green but every consumer would be wrong.
//!
//! The falsifier is a generated event whose `as_str` has no namespace, whose severity is
//! `warn`/`error` without a counter, rate group and remediation, or whose required fields are
//! empty or duplicated.

use std::collections::BTreeSet;

use daer_observe::{EventCode, Severity};

#[test]
fn the_generated_catalog_is_complete_and_self_consistent() {
    assert!(
        !EventCode::ALL.is_empty(),
        "the catalog must contain at least one event"
    );

    let mut codes = BTreeSet::new();
    for event in EventCode::ALL {
        let code = event.as_str();
        assert!(
            !code.is_empty() && code.contains('.') && !code.ends_with('.'),
            "event code {code:?} must be a dotted lower-case namespace"
        );
        assert!(
            code.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_'),
            "event code {code:?} contains a character the catalog grammar forbids"
        );
        assert!(
            codes.insert(code),
            "event code {code:?} is declared twice in the generated catalog"
        );

        assert!(
            !event.message().trim().is_empty(),
            "event {code:?} has an empty operator-facing message"
        );

        let mut fields = BTreeSet::new();
        for field in event.required_fields() {
            assert!(
                !field.trim().is_empty(),
                "event {code:?} declares an empty required field"
            );
            assert!(
                fields.insert(*field),
                "event {code:?} declares required field {field:?} twice"
            );
        }

        if matches!(event.level(), Severity::Warn | Severity::Error) {
            assert!(
                event.counter().is_some_and(|counter| !counter.is_empty()),
                "client-visible event {code:?} must have a counter"
            );
            assert!(
                event.rate_limit().is_some_and(|rate| !rate.is_empty()),
                "client-visible event {code:?} must have a rate-limit group"
            );
            assert!(
                event
                    .remediation()
                    .is_some_and(|remediation| !remediation.trim().is_empty()),
                "client-visible event {code:?} must name a remediation"
            );
        }
    }

    assert_eq!(
        codes.len(),
        EventCode::ALL.len(),
        "every variant in ALL must have a unique code"
    );
}

#[test]
fn every_severity_has_a_stable_spelling() {
    let expected = [
        (Severity::Error, "error"),
        (Severity::Warn, "warn"),
        (Severity::Info, "info"),
        (Severity::Debug, "debug"),
        (Severity::Trace, "trace"),
    ];
    for (severity, spelling) in expected {
        assert_eq!(
            severity.as_str(),
            spelling,
            "the severity string is part of the catalog's stable surface"
        );
        assert_eq!(severity.to_string(), spelling);
    }
}
