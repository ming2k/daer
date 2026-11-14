// SPDX-License-Identifier: AGPL-3.0-only

//! Rule optimizers.
//!
//! Rules carry stable names, so an optimizer may normalize the inside of a rule
//! but must never merge two rules: merging would delete one identity and make a
//! log line name a rule the operator did not write.

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

/// Sorts predicates and parameters so equivalent matches lower identically.
///
/// This does not reorder rules: array order is priority.
#[derive(Debug, Default, Clone, Copy)]
pub struct SortFunctionsOptimizer;

impl RulesOptimizer for SortFunctionsOptimizer {
    fn optimize(&self, mut rules: Vec<RoutingRule>) -> Result<Vec<RoutingRule>, RoutingError> {
        for rule in &mut rules {
            rule.match_expr
                .and_functions
                .sort_by(|a, b| a.name.cmp(&b.name));
            for function in &mut rule.match_expr.and_functions {
                sort_params(function);
            }
        }
        Ok(rules)
    }
}

fn sort_params(function: &mut Function) {
    if function.name == "dip" || function.name == "sip" {
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
            for function in &mut rule.match_expr.and_functions {
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
    use daer_config::{BuiltinOutbound, OutboundAction};

    fn rule(name: &str, expr: &str, action: OutboundAction) -> RoutingRule {
        RoutingRule {
            name: name.to_owned(),
            match_expr: daer_config::parse_match_expr(expr).expect("parses"),
            action,
        }
    }

    fn direct() -> OutboundAction {
        OutboundAction::Builtin(BuiltinOutbound::Direct)
    }

    #[test]
    fn sorts_predicates_and_params_without_reordering_rules() {
        let rules = vec![
            rule("b", "dport(443) && domain(b.com, a.com)", direct()),
            rule("a", "domain(c.com)", direct()),
        ];
        let rules = SortFunctionsOptimizer.optimize(rules).unwrap();
        assert_eq!(rules[0].name, "b");
        assert_eq!(rules[0].match_expr.and_functions[0].name, "domain");
        assert_eq!(rules[0].match_expr.and_functions[1].name, "dport");
        let values: Vec<&str> = rules[0].match_expr.and_functions[0]
            .params
            .iter()
            .filter_map(|param| param.as_literal())
            .collect();
        assert_eq!(values, ["a.com", "b.com"]);
        assert_eq!(rules[1].name, "a");
    }

    #[test]
    fn never_merges_named_rules_even_with_the_same_action() {
        let rules = vec![
            rule("a", "domain(a.com)", direct()),
            rule("b", "domain(b.com)", direct()),
        ];
        let rules = SortFunctionsOptimizer.optimize(rules).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "a");
        assert_eq!(rules[1].name, "b");
    }

    #[test]
    fn deduplicates_parameters_inside_one_predicate() {
        let rules = vec![rule(
            "a",
            "domain(example.com, example.com, other.com)",
            direct(),
        )];
        let rules = DeduplicateParamsOptimizer.optimize(rules).unwrap();
        assert_eq!(
            rules[0].match_expr.and_functions[0].params.len(),
            2,
            "duplicates are removed, order is preserved"
        );
    }
}
