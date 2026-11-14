// SPDX-License-Identifier: AGPL-3.0-only

//! Immutable policy identity, ported from `component/routing/policy_hash.go`
//! and `policy_identity.go`.
//!
//! A reload compares policies by hash instead of by rule tree, so the previous
//! generation's rules can be dropped as soon as the new program is built.
//!
//! The canonical byte stream follows the Go hasher: a schema string, then
//! length-prefixed little-endian fields. Go distinguishes nil from empty
//! slices; Rust does not, so presence is encoded as "non-empty". The hash is
//! only ever compared within one implementation, so this difference does not
//! affect reload decisions.

use daer_config::{Function, OutboundAction, OutboundKind, Param, ParamValue, RoutingRule};
use sha2::{Digest, Sha256};

use crate::error::RoutingError;
use crate::program::NormalizedProgram;

const NORMALIZED_POLICY_HASH_SCHEMA: &str = "daer.normalized-policy.v1";

/// Identifies one immutable policy generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PolicyEpoch(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyIdentity {
    epoch: PolicyEpoch,
    hash: [u8; 32],
}

impl PolicyIdentity {
    /// Computes the semantic content hash of `program` for generation `epoch`.
    pub fn new(epoch: PolicyEpoch, program: &NormalizedProgram) -> Result<Self, RoutingError> {
        Ok(Self {
            epoch,
            hash: hash_normalized_program(program)?,
        })
    }

    pub fn epoch(&self) -> PolicyEpoch {
        self.epoch
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

/// Computes the semantic content hash, excluding the generation identifier.
pub fn hash_normalized_program(program: &NormalizedProgram) -> Result<[u8; 32], RoutingError> {
    let mut hasher = CanonicalHasher::new();
    hasher.write_rules(&program.rules);
    hasher.write_fallback(&program.fallback);
    Ok(hasher.finish())
}

struct CanonicalHasher {
    digest: Sha256,
}

impl CanonicalHasher {
    fn new() -> Self {
        let mut digest = Sha256::new();
        digest.update(NORMALIZED_POLICY_HASH_SCHEMA.as_bytes());
        Self { digest }
    }

    fn finish(self) -> [u8; 32] {
        let digest = self.digest.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }

    fn write_byte(&mut self, value: u8) {
        self.digest.update([value]);
    }

    fn write_bool(&mut self, value: bool) {
        self.write_byte(u8::from(value));
    }

    fn write_u64(&mut self, value: u64) {
        self.digest.update(value.to_le_bytes());
    }

    fn write_string(&mut self, value: &str) {
        self.write_u64(value.len() as u64);
        self.digest.update(value.as_bytes());
    }

    fn write_strings_presence(&mut self, count: usize) {
        self.write_bool(count != 0);
        self.write_u64(count as u64);
    }

    fn write_functions(&mut self, functions: &[Function]) {
        self.write_strings_presence(functions.len());
        for function in functions {
            self.write_function(function);
        }
    }

    fn write_function(&mut self, function: &Function) {
        self.write_byte(1);
        self.write_function_value(function);
    }

    fn write_function_value(&mut self, function: &Function) {
        self.write_string(&function.name);
        self.write_bool(function.negated);
        self.write_params(&function.params);
    }

    fn write_params(&mut self, params: &[Param]) {
        self.write_strings_presence(params.len());
        for param in params {
            self.write_param(param);
        }
    }

    fn write_param(&mut self, param: &Param) {
        self.write_byte(1);
        self.write_string(&param.key);
        match &param.value {
            ParamValue::Literal(value) => {
                self.write_string(value);
                self.write_functions(&[]);
            }
            ParamValue::Functions(functions) => {
                self.write_string("");
                self.write_functions(functions);
            }
        }
        self.write_params(&param.annotation);
    }

    fn write_rules(&mut self, rules: &[RoutingRule]) {
        self.write_strings_presence(rules.len());
        for rule in rules {
            self.write_byte(1);
            self.write_string(&rule.name);
            self.write_functions(&rule.match_expr.and_functions);
            self.write_action(&rule.action);
        }
    }

    fn write_action(&mut self, action: &OutboundAction) {
        self.write_byte(match action.kind() {
            OutboundKind::Direct => 1,
            OutboundKind::Block => 2,
            OutboundKind::Election => 3,
        });
        if let Some(name) = action.election_name() {
            self.write_string(name);
        }
    }

    fn write_fallback(&mut self, fallback: &OutboundAction) {
        self.write_action(fallback);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daer_config::BuiltinOutbound;

    fn rule(name: &str, expr: &str) -> RoutingRule {
        RoutingRule {
            name: name.to_owned(),
            match_expr: daer_config::parse_match_expr(expr).expect("parses"),
            action: OutboundAction::Builtin(BuiltinOutbound::Direct),
        }
    }

    fn program(name: &str, expr: &str) -> NormalizedProgram {
        NormalizedProgram::new(
            &[rule(name, expr)],
            OutboundAction::Builtin(BuiltinOutbound::Direct),
            &[],
        )
        .expect("normalizes")
    }

    #[test]
    fn identical_policies_hash_identically() {
        let left = program("a", "dport(443) && domain(a.com)");
        let right = program("a", "dport(443) && domain(a.com)");
        assert_eq!(
            hash_normalized_program(&left).unwrap(),
            hash_normalized_program(&right).unwrap()
        );
    }

    #[test]
    fn rule_names_are_part_of_the_identity() {
        let left = program("a", "dport(443)");
        let right = program("b", "dport(443)");
        assert_ne!(
            hash_normalized_program(&left).unwrap(),
            hash_normalized_program(&right).unwrap()
        );
    }

    #[test]
    fn different_policies_hash_differently() {
        let left = program("a", "dport(443)");
        let right = program("a", "dport(80)");
        assert_ne!(
            hash_normalized_program(&left).unwrap(),
            hash_normalized_program(&right).unwrap()
        );
    }

    #[test]
    fn fallback_is_part_of_the_identity() {
        let rules = [rule("a", "dport(443)")];
        let with_direct = NormalizedProgram::new(
            &rules,
            OutboundAction::Builtin(BuiltinOutbound::Direct),
            &[],
        )
        .unwrap();
        let with_block =
            NormalizedProgram::new(&rules, OutboundAction::Builtin(BuiltinOutbound::Block), &[])
                .unwrap();
        assert_ne!(
            hash_normalized_program(&with_direct).unwrap(),
            hash_normalized_program(&with_block).unwrap()
        );
    }

    #[test]
    fn epoch_is_separate_from_the_hash() {
        let program = program("a", "dport(443)");
        let first = PolicyIdentity::new(PolicyEpoch(1), &program).unwrap();
        let second = PolicyIdentity::new(PolicyEpoch(2), &program).unwrap();
        assert_eq!(first.hash(), second.hash());
        assert_ne!(first.epoch(), second.epoch());
        assert_eq!(second.epoch(), PolicyEpoch(2));
    }
}
