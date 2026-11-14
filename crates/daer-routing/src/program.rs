// SPDX-License-Identifier: AGPL-3.0-only

//! The normalized routing program shared by every backend.

use std::collections::HashSet;

use daer_config::{OutboundAction, RoutingRule};

use crate::builder::{MatchSink, RulesBuilder};
use crate::error::RoutingError;
use crate::optimizer::{RulesOptimizer, apply_optimizers};

/// An immutable, normalized routing policy.
///
/// Rules are never mutated after construction, so a data-path task can hold an
/// `Arc<NormalizedProgram>` across a reload without synchronizing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedProgram {
    pub rules: Vec<RoutingRule>,
    pub fallback: OutboundAction,
}

impl NormalizedProgram {
    /// Clones `rules`, applies `optimizers`, and keeps `fallback` as written.
    pub fn new(
        rules: &[RoutingRule],
        fallback: OutboundAction,
        optimizers: &[&dyn RulesOptimizer],
    ) -> Result<Self, RoutingError> {
        let mut names = HashSet::with_capacity(rules.len());
        for rule in rules {
            let name = rule.name.trim();
            if name.is_empty() {
                return Err(RoutingError::new("a routing rule has an empty name"));
            }
            if !names.insert(name) {
                return Err(RoutingError::new(format!(
                    "duplicate routing rule name {name:?}"
                )));
            }
        }
        let rules = apply_optimizers(rules, optimizers)?;
        Ok(Self { rules, fallback })
    }

    /// Lowers the rules into `builder`'s sink, then hands the fallback to the
    /// backend.
    pub fn lower<S: MatchSink>(
        &self,
        builder: &mut RulesBuilder<'_, S>,
        add_fallback: impl FnOnce(&OutboundAction) -> Result<(), RoutingError>,
    ) -> Result<(), RoutingError> {
        builder.apply(&self.rules)?;
        add_fallback(&self.fallback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::RecordingSink;
    use daer_config::{BuiltinOutbound, ElectionAction};

    fn rule(name: &str, expr: &str, action: OutboundAction) -> RoutingRule {
        RoutingRule {
            name: name.to_owned(),
            match_expr: daer_config::parse_match_expr(expr).expect("parses"),
            action,
        }
    }

    #[test]
    fn lowers_through_the_program() {
        let rules = [rule(
            "https",
            "dport(443)",
            OutboundAction::Builtin(BuiltinOutbound::Direct),
        )];
        let program = NormalizedProgram::new(
            &rules,
            OutboundAction::Builtin(BuiltinOutbound::Direct),
            &[],
        )
        .expect("normalizes");

        let mut sink = RecordingSink::default();
        let mut builder = RulesBuilder::new(&mut sink);
        let mut fallback_seen = false;
        program
            .lower(&mut builder, |fallback| {
                fallback_seen = *fallback == OutboundAction::Builtin(BuiltinOutbound::Direct);
                Ok(())
            })
            .expect("lowers");

        assert!(fallback_seen);
        assert_eq!(sink.matches.len(), 1);
    }

    #[test]
    fn duplicate_rule_names_are_rejected_even_without_the_config_validator() {
        let rules = [
            rule(
                "same",
                "dport(443)",
                OutboundAction::Builtin(BuiltinOutbound::Direct),
            ),
            rule(
                "same",
                "dport(80)",
                OutboundAction::Builtin(BuiltinOutbound::Block),
            ),
        ];
        let error = NormalizedProgram::new(
            &rules,
            OutboundAction::Builtin(BuiltinOutbound::Direct),
            &[],
        )
        .expect_err("duplicate identities are ambiguous");
        assert!(error.message.contains("duplicate"), "{error}");
    }

    #[test]
    fn keeps_the_typed_fallback() {
        let rules = [rule(
            "https",
            "dport(443)",
            OutboundAction::Builtin(BuiltinOutbound::Direct),
        )];
        let fallback = OutboundAction::Election(ElectionAction {
            election: "proxy".to_owned(),
        });
        let program = NormalizedProgram::new(&rules, fallback.clone(), &[]).expect("normalizes");
        assert_eq!(program.fallback, fallback);
        assert_eq!(program.rules[0].match_expr.and_functions[0].name, "dport");
    }
}
