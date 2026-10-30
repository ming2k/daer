// SPDX-License-Identifier: AGPL-3.0-only

//! JSON Schema export.
//!
//! The schema is the configuration's contract in a form other tools can consume:
//! an editor completes keys and values without linking this crate, CI validates a
//! file without building daer, and a generated config document cannot drift from
//! the model. `daer config schema` prints it; a configuration can point at it with
//! the `#:schema` directive that TOML editors understand.
//!
//! Two implementation notes:
//!
//! * The schema is derived from the same types the loader deserializes into, so it
//!   cannot describe a field the loader does not accept.
//! * Values that are *expressions* rather than data (routing rules, filters,
//!   policies) are described as strings with the grammar in the description. That
//!   mirrors the design decision in `ADR-0001`: a boolean combination over
//!   predicates has no faithful tabular encoding, so the schema must not pretend it
//!   has one.

use schemars::JsonSchema;
use schemars::schema_for;
use serde::Serialize;

use crate::model::Config;

/// The JSON Schema of a configuration file, pretty-printed.
///
/// # Panics
///
/// Never in practice: the schema is a plain data structure of owned strings.
#[must_use]
pub fn json_schema() -> String {
    let schema = schema_for!(Config);
    serde_json::to_string_pretty(&schema).expect("the schema is JSON-representable")
}

/// Schema-only mirrors of the shapes the loader accepts but derives by hand.
///
/// They exist so the schema can say "string or table" where the Rust type is a
/// custom `Deserialize`. Keeping them next to the schema (rather than in the model)
/// means the model stays free of schema concerns, and a divergence is a compile
/// error in this module's tests rather than a silently wrong document.
pub mod mirror {
    use std::collections::BTreeMap;

    use schemars::JsonSchema;
    use serde::Serialize;

    /// `subscription = ["url"]` or `[[subscription]] tag/url/persist`.
    #[derive(Debug, Serialize, JsonSchema)]
    #[serde(untagged)]
    #[schemars(untagged)]
    pub enum Subscription {
        /// A bare URL, no tag.
        Url(String),
        /// A tagged subscription.
        Table {
            /// Tag used by `subtag()` filters.
            #[serde(skip_serializing_if = "Option::is_none")]
            tag: Option<String>,
            url: String,
            /// Cache the last successful fetch next to the configuration.
            #[serde(default)]
            persist: bool,
        },
    }

    /// `[[node]] tag/type/...`.
    pub type Node = crate::model::Node;

    /// A `group.filters` entry: an expression, or an expression plus values the
    /// selected node inherits.
    #[derive(Debug, Serialize, JsonSchema)]
    #[serde(untagged)]
    #[schemars(untagged)]
    pub enum Filter {
        /// `subtag(sub) && !name(keyword: 'ExpireAt:')`
        Expr(String),
        Table {
            /// The predicate conjunction.
            #[serde(rename = "match")]
            expr: String,
            /// Values copied into the selected node's properties.
            #[serde(default)]
            annotate: BTreeMap<String, String>,
        },
    }

    /// Every HTTP method a health-check probe may use.
    #[derive(Debug, Serialize, JsonSchema)]
    pub enum HttpMethod {
        /// The two a probe can issue: it reads no body and discards the response, so anything
        /// else would need a body or cannot be framed by this client. Advertising a method that
        /// silently becomes `HEAD` is the "accepted and ignored" failure ADR-0006 removed.
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "HEAD")]
        Head,
    }
}

/// A schema document with the top-level shape asserted at compile time.
///
/// The type exists so `Config` and the mirrors are referenced from one place: if a
/// mirror stops being used, this fails to build instead of silently disappearing
/// from the schema.
#[derive(Serialize)]
struct _SchemaUsesEveryMirror {
    subscription: mirror::Subscription,
    node: mirror::Node,
    filter: mirror::Filter,
    method: mirror::HttpMethod,
}

/// Compile-time assertion that [`Config`] is what the schema is derived from.
const _: fn() = || {
    fn assert_json_schema<T: JsonSchema>() {}
    assert_json_schema::<Config>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> serde_json::Value {
        serde_json::from_str(&json_schema()).expect("schema is valid JSON")
    }

    #[test]
    fn the_schema_describes_every_top_level_table() {
        let schema = schema();
        let properties = schema["properties"].as_object().expect("properties");
        for key in [
            "schema",
            "include",
            "global",
            "subscription",
            "node",
            "group",
            "routing",
            "dns",
        ] {
            assert!(
                properties.contains_key(key),
                "missing `{key}` in {schema:#}"
            );
        }
    }

    #[test]
    fn unknown_keys_are_rejected_by_the_schema() {
        // `deny_unknown_fields` must survive into the document, otherwise an editor
        // would happily complete a typo.
        let schema = schema();
        assert_eq!(
            schema["additionalProperties"],
            serde_json::Value::Bool(false),
            "{schema:#}"
        );
        let global = &schema["$defs"]["Global"];
        assert_eq!(
            global["additionalProperties"],
            serde_json::Value::Bool(false),
            "Global must reject unknown keys: {global:#}"
        );
    }

    #[test]
    fn expressions_are_described_as_strings() {
        let schema = schema();
        let rendered = schema["$defs"]["Routing"]["properties"]["rules"].to_string();
        assert!(
            rendered.contains("\"string\""),
            "rules must be described as strings: {rendered}"
        );
    }

    #[test]
    fn filters_accept_a_string_or_a_table() {
        let schema = schema();
        let filter = schema["$defs"]
            .as_object()
            .and_then(|defs| {
                defs.iter()
                    .find(|(name, _)| name.contains("Filter"))
                    .map(|(_, value)| value)
            })
            .expect("a filter definition");
        let rendered = filter.to_string();
        assert!(
            rendered.contains("string") && rendered.contains("annotate"),
            "a filter must be described as an expression or a table: {rendered}"
        );
    }

    #[test]
    fn enumerated_values_complete_in_an_editor() {
        // Completion is the point of mirroring this as an enum rather than a string:
        // `tcp-method` has a closed set of valid values, and a typo should be a squiggle, not a
        // runtime failure.
        //
        // The set is exactly what the probe can issue. It used to advertise `POST`, `PUT`,
        // `PATCH`, `DELETE`, `COPY`, `CONNECT` and `PROPFIND` while `HttpMethod` could only
        // produce `HEAD` and `GET`, so an editor offered seven values that silently became
        // `HEAD` (ADR-0006).
        let rendered = schema().to_string();
        for value in ["\"HEAD\"", "\"GET\""] {
            assert!(rendered.contains(value), "missing HTTP method {value}");
        }
        for value in ["\"PROPFIND\"", "\"CONNECT\"", "\"PATCH\"", "\"COPY\""] {
            assert!(
                !rendered.contains(value),
                "{value} is advertised but no probe can issue it"
            );
        }
    }
}
