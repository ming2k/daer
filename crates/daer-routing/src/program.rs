// SPDX-License-Identifier: AGPL-3.0-only

//! The normalized routing program shared by every backend.

use daer_config::{FunctionOrString, RoutingRule};

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
    pub fallback: FunctionOrString,
}

impl NormalizedProgram {
    /// Clones `rules`, applies `optimizers`, and keeps `fallback` as written.
    pub fn new(
        rules: &[RoutingRule],
        fallback: FunctionOrString,
        optimizers: &[&dyn RulesOptimizer],
    ) -> Result<Self, RoutingError> {
        let rules = apply_optimizers(rules, optimizers)?;
        Ok(Self { rules, fallback })
    }

    /// Lowers the rules into `builder`'s sink, then hands the fallback to the
    /// backend.
    pub fn lower<S: MatchSink>(
        &self,
        builder: &mut RulesBuilder<'_, S>,
        add_fallback: impl FnOnce(&FunctionOrString) -> Result<(), RoutingError>,
    ) -> Result<(), RoutingError> {
        builder.apply(&self.rules)?;
        add_fallback(&self.fallback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::RecordingSink;
    use crate::optimizer::AliasOptimizer;

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
    fn lowers_through_the_program() {
        let program = NormalizedProgram::new(
            &rules("routing { dport(443) -> direct }"),
            FunctionOrString::Name("direct".to_owned()),
            &[&AliasOptimizer],
        )
        .expect("normalizes");

        let mut sink = RecordingSink::default();
        let mut builder = RulesBuilder::new(&mut sink);
        let mut fallback_seen = false;
        program
            .lower(&mut builder, |fallback| {
                fallback_seen =
                    matches!(fallback, FunctionOrString::Name(name) if name == "direct");
                Ok(())
            })
            .expect("lowers");

        assert!(fallback_seen);
        assert_eq!(sink.matches.len(), 1);
    }

    #[test]
    fn keeps_the_parsed_fallback() {
        let program = NormalizedProgram::new(
            &rules("routing { dport(443) -> direct }"),
            FunctionOrString::Name("my_group".to_owned()),
            &[],
        )
        .expect("normalizes");
        assert_eq!(
            program.fallback,
            FunctionOrString::Name("my_group".to_owned())
        );
        assert!(matches!(
            program.rules[0].and_functions[0].name.as_str(),
            "dport"
        ));
    }
}
