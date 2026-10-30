// SPDX-License-Identifier: AGPL-3.0-only

//! Rule optimizers, ported from `component/routing/optimizer.go`.
//!
//! They run before lowering and must stay semantically neutral: aliasing is
//! spelling-only, merging relies on De Morgan's law holding for *positive*
//! singleton rules, and deduplication removes identical parameters.

use std::collections::HashSet;

use daer_config::{Function, RoutingRule};

use crate::error::RoutingError;

pub trait RulesOptimizer {
    fn optimize(&self, rules: Vec<RoutingRule>) -> Result<Vec<RoutingRule>, RoutingError>;
}

pub fn apply_optimizers(
    rules: &[RoutingRule],
    optimizers: &[&dyn RulesOptimizer],
) -> Result<Vec<RoutingRule>, RoutingError> {
    let mut current = rules.to_vec();
    for optimizer in optimizers {
        current = optimizer.optimize(current)?;
    }
    Ok(current)
}

/// Rewrites the documented aliases into their authoritative names.
#[derive(Debug, Default, Clone, Copy)]
pub struct AliasOptimizer;

impl RulesOptimizer for AliasOptimizer {
    fn optimize(&self, mut rules: Vec<RoutingRule>) -> Result<Vec<RoutingRule>, RoutingError> {
        for rule in &mut rules {
            for function in &mut rule.and_functions {
                match function.name.as_str() {
                    "dport" => function.name = "port".to_owned(),
                    "dip" => function.name = "ip".to_owned(),
                    _ => {}
                }
                if function.name == "domain" {
                    for param in &mut function.params {
                        match param.key.as_str() {
                            "" | "domain" => param.key = "suffix".to_owned(),
                            "contains" => param.key = "keyword".to_owned(),
                            _ => {}
                        }
                    }
                }
            }
        }
        Ok(rules)
    }
}

/// Sorts functions and parameters so that equivalent rules lower identically,
/// and merges adjacent single-function rules that share an outbound.
#[derive(Debug, Default, Clone, Copy)]
pub struct MergeAndSortOptimizer;

impl RulesOptimizer for MergeAndSortOptimizer {
    fn optimize(&self, mut rules: Vec<RoutingRule>) -> Result<Vec<RoutingRule>, RoutingError> {
        if rules.is_empty() {
            return Ok(rules);
        }

        for rule in &mut rules {
            rule.and_functions.sort_by(|a, b| a.name.cmp(&b.name));
        }

        // Only positive singleton rules may merge: for negated rules De Morgan
        // breaks the equivalence `!f(a) -> X OR !f(b) -> X != !f(a, b) -> X`.
        let mut merged: Vec<RoutingRule> = Vec::with_capacity(rules.len());
        let mut remaining = rules.into_iter();
        let mut current = remaining.next().expect("non-empty");
        for rule in remaining {
            let mergeable = current.and_functions.len() == 1
                && rule.and_functions.len() == 1
                && !current.and_functions[0].negated
                && !rule.and_functions[0].negated
                && current.and_functions[0].name == rule.and_functions[0].name
                && current.outbound.compact_omit_empty() == rule.outbound.compact_omit_empty();
            if mergeable {
                let params = rule
                    .and_functions
                    .into_iter()
                    .next()
                    .expect("one function")
                    .params;
                current.and_functions[0].params.extend(params);
            } else {
                merged.push(std::mem::replace(&mut current, rule));
            }
        }
        merged.push(current);

        for rule in &mut merged {
            for function in &mut rule.and_functions {
                sort_params(function);
            }
        }

        Ok(merged)
    }
}

fn sort_params(function: &mut Function) {
    if function.name == "ip" || function.name == "sip" {
        function.params.sort_by(|a, b| {
            let a_value = a.as_literal().unwrap_or_default();
            let b_value = b.as_literal().unwrap_or_default();
            let a_version = if a_value.contains(':') { 6 } else { 4 };
            let b_version = if b_value.contains(':') { 6 } else { 4 };
            a_version.cmp(&b_version).then_with(|| a_value.cmp(b_value))
        });
    } else {
        function.params.sort_by(|a, b| {
            a.key.cmp(&b.key).then_with(|| {
                a.as_literal()
                    .unwrap_or_default()
                    .cmp(b.as_literal().unwrap_or_default())
            })
        });
    }
}

/// Removes duplicate parameters while preserving order.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeduplicateParamsOptimizer;

impl RulesOptimizer for DeduplicateParamsOptimizer {
    fn optimize(&self, mut rules: Vec<RoutingRule>) -> Result<Vec<RoutingRule>, RoutingError> {
        for rule in &mut rules {
            for function in &mut rule.and_functions {
                let mut seen = HashSet::new();
                function.params.retain(|param| seen.insert(param.compact()));
            }
        }
        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixtures are written as config used to read: a `routing { … }` wrapper
    /// around one rule per line. Only the lines matter.
    fn rules(src: &str) -> Vec<RoutingRule> {
        let body = src.trim();
        let body = body.strip_prefix("routing {").unwrap_or(body);
        let body = body.strip_suffix('}').unwrap_or(body);
        body.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| daer_config::parse_rule_expr(line).expect("parses"))
            .collect()
    }

    #[test]
    fn alias_rewrites_functions_and_domain_keys() {
        let rules = rules(
            "routing {\n    dip(1.1.1.1) -> direct\n    dport(80) -> direct\n    domain(example.com) -> direct\n    domain(contains:ad) -> direct\n}",
        );
        let rules = AliasOptimizer.optimize(rules).unwrap();
        assert_eq!(rules[0].and_functions[0].name, "ip");
        assert_eq!(rules[1].and_functions[0].name, "port");
        assert_eq!(rules[2].and_functions[0].params[0].key, "suffix");
        assert_eq!(rules[3].and_functions[0].params[0].key, "keyword");
    }

    #[test]
    fn merges_adjacent_positive_singleton_rules() {
        let rules = rules(
            "routing {\n    domain(suffix:a.com) -> direct\n    domain(suffix:b.com) -> direct\n    domain(suffix:c.com) -> block\n}",
        );
        let rules = MergeAndSortOptimizer.optimize(rules).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].and_functions.len(), 1);
        assert_eq!(rules[0].and_functions[0].params.len(), 2);
        assert_eq!(&*rules[0].outbound.name, "direct");
        assert_eq!(&*rules[1].outbound.name, "block");
    }

    #[test]
    fn does_not_merge_negated_rules() {
        let rules = rules(
            "routing {\n    !domain(suffix:a.com) -> direct\n    !domain(suffix:b.com) -> direct\n}",
        );
        let rules = MergeAndSortOptimizer.optimize(rules).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn does_not_merge_different_outbounds() {
        let rules = rules(
            "routing {\n    domain(suffix:a.com) -> direct\n    domain(suffix:b.com) -> direct(mark: 1)\n}",
        );
        let rules = MergeAndSortOptimizer.optimize(rules).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn sorts_functions_and_params() {
        let rules = rules("routing { port(443) && domain(suffix:b.com, suffix:a.com) -> direct }");
        let rules = MergeAndSortOptimizer.optimize(rules).unwrap();
        assert_eq!(rules[0].and_functions[0].name, "domain");
        assert_eq!(rules[0].and_functions[1].name, "port");
        let values: Vec<&str> = rules[0].and_functions[0]
            .params
            .iter()
            .filter_map(|param| param.as_literal())
            .collect();
        assert_eq!(values, ["a.com", "b.com"]);
    }

    #[test]
    fn deduplicates_params() {
        let rules = rules("routing { domain(suffix:a.com, suffix:a.com, suffix:b.com) -> direct }");
        let rules = DeduplicateParamsOptimizer.optimize(rules).unwrap();
        assert_eq!(rules[0].and_functions[0].params.len(), 2);
    }
}
