// SPDX-License-Identifier: AGPL-3.0-only

//! Group filters: `filter: name(...) && subtag(...)`.
//!
//! Port of `component/outbound/filter.go`. Each `filter:` line is a conjunction
//! of functions; a node is selected by the first line that hits. Within one
//! function the parameters are a disjunction, and `!` inverts the function.
//!
//! `name` accepts `key: regex`, `key: keyword`, and a bare value (exact match).
//! `subtag` accepts `key: regex` and a bare value; `keyword` is not part of the
//! Go grammar and is rejected here too.
//!
//! Regexes use Rust's `regex` crate. Go's `regexp2` is a backtracking engine, so
//! patterns that rely on backreferences or lookaround cannot be written here;
//! everything in the documented filter examples works unchanged.

use std::fmt;

use daer_config::{Function, Param, TimeSpan, parse_duration};
use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    BadRegex { pattern: String, message: String },
    UnsupportedKey { key: String, function: String },
    UnsupportedInput(String),
    NonLiteralValue { function: String, key: String },
    BadAnnotation(String),
    AnnotationCountMismatch { filters: usize, annotations: usize },
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRegex { pattern, message } => {
                write!(f, "bad regexp in filter {pattern:?}: {message}")
            }
            Self::UnsupportedKey { key, function } => {
                write!(
                    f,
                    "unsupported filter key \"{key}\" in \"filter: {function}()\""
                )
            }
            Self::UnsupportedInput(input) => {
                write!(f, "unsupported filter input type: \"{input}\"")
            }
            Self::NonLiteralValue { function, key } => {
                write!(f, "filter {function}({key}): expected a literal value")
            }
            Self::BadAnnotation(message) => f.write_str(message),
            Self::AnnotationCountMismatch {
                filters,
                annotations,
            } => write!(
                f,
                "unmatched annotations length: {filters} filters and {annotations} annotations"
            ),
        }
    }
}

impl std::error::Error for FilterError {}

/// Per-filter annotation, e.g. `[add_latency: -500ms]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Annotation {
    pub add_latency: TimeSpan,
}

impl Annotation {
    /// Mirrors `dialer.NewAnnotation`: unknown keys are an error, and only the
    /// first non-zero `add_latency` takes effect.
    pub fn parse(params: &[Param]) -> Result<Self, FilterError> {
        let mut annotation = Self::default();
        for param in params {
            match param.key.as_str() {
                "add_latency" => {
                    let value = param.as_literal().ok_or_else(|| {
                        FilterError::BadAnnotation(
                            "add_latency: expected a duration literal".to_owned(),
                        )
                    })?;
                    let latency = parse_duration(value).ok_or_else(|| {
                        FilterError::BadAnnotation(format!("incorrect latency format: {value:?}"))
                    })?;
                    if annotation.add_latency == TimeSpan::ZERO {
                        annotation.add_latency = latency;
                    }
                }
                key => {
                    return Err(FilterError::BadAnnotation(format!(
                        "unknown filter annotation: {key}"
                    )));
                }
            }
        }
        Ok(annotation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterInput {
    Name,
    Subtag,
}

#[derive(Debug)]
enum Matcher {
    Exact(String),
    Keyword(String),
    Regex(Regex),
}

impl Matcher {
    fn matches(&self, subject: &str) -> bool {
        match self {
            Self::Exact(value) => subject == value,
            Self::Keyword(value) => subject.contains(value.as_str()),
            Self::Regex(regex) => regex.is_match(subject),
        }
    }
}

#[derive(Debug)]
struct FilterFunction {
    input: FilterInput,
    negated: bool,
    matchers: Vec<Matcher>,
}

#[derive(Debug)]
struct FilterLine {
    functions: Vec<FilterFunction>,
    annotation: Annotation,
}

/// Compiled filters, ready to be applied to a node list.
#[derive(Debug, Default)]
pub struct FilterSet {
    lines: Vec<FilterLine>,
}

impl FilterSet {
    pub fn compile(
        filters: &[Vec<Function>],
        annotations: &[Vec<Param>],
    ) -> Result<Self, FilterError> {
        if filters.len() != annotations.len() {
            return Err(FilterError::AnnotationCountMismatch {
                filters: filters.len(),
                annotations: annotations.len(),
            });
        }

        let mut lines = Vec::with_capacity(filters.len());
        for (line, annotation) in filters.iter().zip(annotations) {
            let annotation = Annotation::parse(annotation)?;
            let mut functions = Vec::with_capacity(line.len());
            for function in line {
                functions.push(compile_function(function)?);
            }
            lines.push(FilterLine {
                functions,
                annotation,
            });
        }
        Ok(Self { lines })
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Returns the annotation of the first matching line.
    ///
    /// With no filters every node matches with a default annotation, which is
    /// `FilterAndAnnotate`'s early return in Go. `None` means the node is not
    /// selected by the group.
    pub fn matches(&self, name: &str, subscription_tag: &str) -> Option<Annotation> {
        if self.lines.is_empty() {
            return Some(Annotation::default());
        }
        for line in &self.lines {
            let hit = line.functions.iter().all(|function| {
                let subject = match function.input {
                    FilterInput::Name => name,
                    FilterInput::Subtag => subscription_tag,
                };
                let matched = function
                    .matchers
                    .iter()
                    .any(|matcher| matcher.matches(subject));
                matched != function.negated
            });
            if hit {
                return Some(line.annotation);
            }
        }
        None
    }
}

fn compile_function(function: &Function) -> Result<FilterFunction, FilterError> {
    let input = match function.name.as_str() {
        "name" => FilterInput::Name,
        "subtag" => FilterInput::Subtag,
        other => return Err(FilterError::UnsupportedInput(other.to_owned())),
    };

    let mut matchers = Vec::with_capacity(function.params.len());
    for param in &function.params {
        let value = param
            .as_literal()
            .ok_or_else(|| FilterError::NonLiteralValue {
                function: function.name.clone(),
                key: param.key.clone(),
            })?;
        let matcher = match (input, param.key.as_str()) {
            (_, "regex") => {
                Matcher::Regex(Regex::new(value).map_err(|error| FilterError::BadRegex {
                    pattern: value.to_owned(),
                    message: error.to_string(),
                })?)
            }
            (FilterInput::Name, "keyword") => Matcher::Keyword(value.to_owned()),
            (_, "") => Matcher::Exact(value.to_owned()),
            (_, key) => {
                return Err(FilterError::UnsupportedKey {
                    key: key.to_owned(),
                    function: function.name.clone(),
                });
            }
        };
        matchers.push(matcher);
    }

    Ok(FilterFunction {
        input,
        negated: function.negated,
        matchers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One filter per line, each optionally written as `filter: …`.
    fn filters(src: &str) -> Vec<Vec<Function>> {
        src.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| line.strip_prefix("filter:").unwrap_or(line).trim())
            .map(|line| daer_config::parse_filter_expr(line).expect("parses"))
            .collect()
    }

    fn compile_set(src: &str) -> FilterSet {
        let filters = filters(src);
        let annotations = vec![Vec::new(); filters.len()];
        FilterSet::compile(&filters, &annotations).expect("compiles")
    }

    #[test]
    fn no_filters_matches_everything() {
        let set = compile_set("");
        assert!(set.is_empty());
        assert_eq!(set.matches("anything", "any"), Some(Annotation::default()));
    }

    #[test]
    fn name_exact_keyword_and_regex() {
        let set = compile_set("filter: name(HK_node)");
        assert!(set.matches("HK_node", "").is_some());
        assert!(set.matches("hk_node", "").is_none());

        let set = compile_set("filter: name(keyword: HK)");
        assert!(set.matches("my_HK_node", "").is_some());
        assert!(set.matches("US_node", "").is_none());

        let set = compile_set("filter: name(regex: '^HK[0-9]+$')");
        assert!(set.matches("HK12", "").is_some());
        assert!(set.matches("HK", "").is_none());
    }

    #[test]
    fn params_inside_a_function_are_or_ed() {
        let set = compile_set("filter: name(HK_node, US_node)");
        assert!(set.matches("HK_node", "").is_some());
        assert!(set.matches("US_node", "").is_some());
        assert!(set.matches("SG_node", "").is_none());
    }

    #[test]
    fn functions_inside_a_line_are_and_ed() {
        let set = compile_set("filter: name(keyword: HK) && subtag(mysub)");
        assert!(set.matches("my_HK_node", "mysub").is_some());
        assert!(set.matches("my_HK_node", "other").is_none());
    }

    #[test]
    fn negation_inverts_a_function() {
        let set = compile_set("filter: subtag(my_sub) && !name(keyword: 'ExpireAt:')");
        assert!(set.matches("HK_node", "my_sub").is_some());
        assert!(set.matches("ExpireAt: 2026", "my_sub").is_none());
    }

    #[test]
    fn lines_are_or_ed() {
        let set = compile_set("filter: name(HK_node)\n    filter: name(US_node)");
        assert!(set.matches("HK_node", "").is_some());
        assert!(set.matches("US_node", "").is_some());
        assert!(set.matches("SG_node", "").is_none());
    }

    #[test]
    fn annotations_follow_their_line() {
        // Annotations are data in the TOML schema, so they arrive beside the
        // filter rather than inside its text.
        let filters = filters("filter: name(HK_node)\nfilter: name(US_node)");
        let annotations = vec![vec![Param::literal("add_latency", "-500ms")], Vec::new()];
        let set = FilterSet::compile(&filters, &annotations).expect("compiles");
        assert_eq!(
            set.matches("HK_node", "").expect("hit").add_latency,
            TimeSpan::from_millis(-500)
        );
        assert_eq!(
            set.matches("US_node", "").expect("hit").add_latency,
            TimeSpan::ZERO
        );
    }

    #[test]
    fn rejects_unknown_inputs_keys_and_bad_regexes() {
        let error =
            FilterSet::compile(&filters("filter: bogus(x)"), &[Vec::new()]).expect_err("must fail");
        assert!(
            error.to_string().contains("unsupported filter input"),
            "{error}"
        );

        let error = FilterSet::compile(&filters("filter: subtag(keyword: x)"), &[Vec::new()])
            .expect_err("must fail");
        assert!(
            error.to_string().contains("unsupported filter key"),
            "{error}"
        );

        let error = FilterSet::compile(&filters("filter: name(regex: '[')"), &[Vec::new()])
            .expect_err("must fail");
        assert!(error.to_string().contains("bad regexp"), "{error}");
    }

    #[test]
    fn rejects_unknown_annotations() {
        let error = FilterSet::compile(
            &filters("filter: name(x)"),
            &[vec![Param::literal("oops", "1")]],
        )
        .expect_err("must fail");
        assert!(
            error.to_string().contains("unknown filter annotation"),
            "{error}"
        );
    }

    #[test]
    fn requires_one_annotation_vector_per_filter() {
        let error = FilterSet::compile(&filters("filter: name(x)"), &[]).expect_err("must fail");
        assert!(
            error.to_string().contains("unmatched annotations"),
            "{error}"
        );
    }
}
