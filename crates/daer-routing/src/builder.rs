// SPDX-License-Identifier: AGPL-3.0-only

//! Rule lowering: turns parsed routing rules into match sets.
//!
//! This is `RulesBuilder.Apply` from `component/routing/matcher_builder.go`,
//! with the parser registry replaced by a fixed dispatch over the built-in
//! routing functions. A [`MatchSink`] decides what a lowered match set becomes:
//! match sets for the userspace evaluator, eBPF map entries, or nothing at all
//! during validation.

use daer_config::{Function, Param, RoutingRule};
use daer_primitives::{MacAddr, PortRange};
use ipnet::IpNet;

use crate::domain::DomainTable;
use crate::drb::{DrbSet, RuleProviderPool};
use crate::error::RoutingError;
use crate::ipset::IpIndex;
use crate::matcher::{MatchSet, MatchValue};
use crate::outbound::{MatchTarget, Outbound};
use crate::values::{
    IpVersionMask, L4ProtoMask, ProcessName, parse_dscp, parse_ip_version, parse_l4_proto,
    parse_mac_addresses, parse_port_ranges, parse_prefixes, parse_process_names,
};

/// Receives one call per `(function, parameter key)` group.
pub trait MatchSink {
    /// Adds a domain predicate. `patterns` are complete `kind:value` spellings, so the sink
    /// never has to reassemble a key and a value into one rule.
    fn add_domain(
        &mut self,
        negated: bool,
        patterns: &[String],
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_ip(
        &mut self,
        negated: bool,
        prefixes: &[IpNet],
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_source_ip(
        &mut self,
        negated: bool,
        prefixes: &[IpNet],
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_mac(
        &mut self,
        negated: bool,
        macs: &[MacAddr],
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_port(
        &mut self,
        negated: bool,
        ranges: &[PortRange],
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_source_port(
        &mut self,
        negated: bool,
        ranges: &[PortRange],
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_l4_proto(
        &mut self,
        negated: bool,
        mask: L4ProtoMask,
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_ip_version(
        &mut self,
        negated: bool,
        mask: IpVersionMask,
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_process_name(
        &mut self,
        negated: bool,
        names: &[ProcessName],
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_dscp(
        &mut self,
        negated: bool,
        values: &[u8],
        target: &MatchTarget,
    ) -> Result<(), RoutingError>;

    fn add_provider(
        &mut self,
        negated: bool,
        set: &DrbSet,
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let _ = (negated, set, target);
        Ok(())
    }

    fn add_ip_index(
        &mut self,
        negated: bool,
        index: IpIndex,
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let _ = (negated, index, target);
        Ok(())
    }

    fn add_domain_index(
        &mut self,
        negated: bool,
        index: DomainTable,
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let _ = (negated, index, target);
        Ok(())
    }

    /// Records a non-fatal diagnostic, such as a truncated process name.
    fn warn(&mut self, _message: String) {}
}

#[derive(Debug)]
pub struct RulesBuilder<'a, S: MatchSink> {
    sink: &'a mut S,
    providers: Option<&'a RuleProviderPool>,
}

impl<'a, S: MatchSink> RulesBuilder<'a, S> {
    pub fn new(sink: &'a mut S) -> Self {
        Self {
            sink,
            providers: None,
        }
    }

    pub fn with_providers(sink: &'a mut S, providers: &'a RuleProviderPool) -> Self {
        Self {
            sink,
            providers: Some(providers),
        }
    }

    pub fn sink(&self) -> &S {
        self.sink
    }

    pub fn sink_mut(&mut self) -> &mut S {
        self.sink
    }

    /// Lowers every rule. `rule.match_expr.and_functions` must already be normalized
    /// (parameters sorted), otherwise the canonical predicate names are rejected.
    pub fn apply(&mut self, rules: &[RoutingRule]) -> Result<(), RoutingError> {
        for rule in rules {
            let outbound = Outbound::from_action(&rule.action)?;
            let function_count = rule.match_expr.and_functions.len();

            for (function_index, function) in rule.match_expr.and_functions.iter().enumerate() {
                let groups = group_params_by_key(&function.params);
                let group_count = groups.len();

                for (group_index, (key, values)) in groups.into_iter().enumerate() {
                    let target = if group_index + 1 < group_count {
                        MatchTarget::logical_or(outbound.mark, outbound.must)
                    } else if function_index + 1 < function_count {
                        MatchTarget::logical_and(outbound.mark, outbound.must)
                    } else {
                        MatchTarget::Outbound(outbound.clone())
                    };

                    self.dispatch(function, key, &values, &target)
                        .map_err(|err| err.context(format!("in '{function}'")))?;
                }
            }
        }
        Ok(())
    }

    fn dispatch(
        &mut self,
        function: &Function,
        key: &str,
        values: &[&str],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let negated = function.negated;

        match function.name.as_str() {
            "rule-set" => {
                require_bare(function, key)?;
                for (index, name) in values.iter().enumerate() {
                    let set = self
                        .providers
                        .and_then(|p| p.get(name))
                        .ok_or_else(|| RoutingError::new(format!("unknown rule set: {name}")))?;
                    let t = if index + 1 == values.len() {
                        target.clone()
                    } else {
                        MatchTarget::logical_or(target.mark(), target.must())
                    };
                    self.sink.add_provider(negated, set, &t)?;
                }
                Ok(())
            }
            "domain-set" => {
                require_bare(function, key)?;
                for (index, name) in values.iter().enumerate() {
                    let set = self
                        .providers
                        .and_then(|p| p.get(name))
                        .ok_or_else(|| RoutingError::new(format!("unknown rule set: {name}")))?;
                    let t = if index + 1 == values.len() {
                        target.clone()
                    } else {
                        MatchTarget::logical_or(target.mark(), target.must())
                    };
                    if !set.domains().is_empty() {
                        self.sink
                            .add_domain_index(negated, set.domains().clone(), &t)?;
                    }
                }
                Ok(())
            }
            "domain" => {
                if is_retired_dat_key(key) {
                    Err(retired_dat_key("domain", key))
                } else if matches!(key, "full" | "suffix" | "domain" | "root_domain") {
                    Err(RoutingError::new(format!(
                        "domain({key}: ...): the `{key}:` key is retired (ADR-0036); spell the \
                         pattern directly — a bare name is a suffix, `.name` is subdomains only, \
                         `=name` is an exact match"
                    )))
                } else if matches!(key, "keyword" | "regex" | "contains") {
                    Err(RoutingError::new(format!(
                        "domain({key}: ...): `{key}:` is not a routing predicate (ADR-0031, \
                         ADR-0033); expand it into concrete names upstream"
                    )))
                } else {
                    // Hand the sink complete patterns rather than a key it would have to
                    // reassemble. A bare param (`domain(example.com)`) and an exact prefix
                    // (`domain(=example.com)`) carry their spelling verbatim so
                    // `DomainTable::compile` classifies them under CRS v3 (ADR-0036).
                    let patterns: Vec<String> = values
                        .iter()
                        .map(|value| {
                            let trimmed = value.trim();
                            if key.is_empty() || trimmed.starts_with('=') {
                                trimmed.to_string()
                            } else {
                                format!("{key}:{trimmed}")
                            }
                        })
                        .collect();
                    self.sink.add_domain(negated, &patterns, target)
                }
            }
            "ip-set" => {
                require_bare(function, key)?;
                for (index, name) in values.iter().enumerate() {
                    let set = self
                        .providers
                        .and_then(|p| p.get(name))
                        .ok_or_else(|| RoutingError::new(format!("unknown rule set: {name}")))?;
                    let t = if index + 1 == values.len() {
                        target.clone()
                    } else {
                        MatchTarget::logical_or(target.mark(), target.must())
                    };
                    if let Some(ip) = set.to_ip_index() {
                        self.sink.add_ip_index(negated, ip, &t)?;
                    }
                }
                Ok(())
            }
            "dip" => {
                require_bare(function, key)?;
                let prefixes = parse_prefixes(values)?;
                self.sink.add_ip(negated, &prefixes, target)
            }
            "sip" => {
                require_bare(function, key)?;
                let prefixes = parse_prefixes(values)?;
                self.sink.add_source_ip(negated, &prefixes, target)
            }
            "dport" => {
                require_bare(function, key)?;
                let ranges = parse_port_ranges(values)?;
                self.sink.add_port(negated, &ranges, target)
            }
            "sport" => {
                require_bare(function, key)?;
                let ranges = parse_port_ranges(values)?;
                self.sink.add_source_port(negated, &ranges, target)
            }
            "l4proto" => {
                require_bare(function, key)?;
                let mask = parse_l4_proto(values)?;
                self.sink.add_l4_proto(negated, mask, target)
            }
            "ipversion" => {
                require_bare(function, key)?;
                let mask = parse_ip_version(values)?;
                self.sink.add_ip_version(negated, mask, target)
            }
            "mac" => {
                require_bare(function, key)?;
                let macs = parse_mac_addresses(values)?;
                self.sink.add_mac(negated, &macs, target)
            }
            "pname" => {
                require_bare(function, key)?;
                let mut warnings = Vec::new();
                let names = parse_process_names(values, &mut warnings);
                for warning in warnings {
                    self.sink.warn(warning);
                }
                self.sink.add_process_name(negated, &names, target)
            }
            "dscp" => {
                require_bare(function, key)?;
                let values = parse_dscp(values)?;
                self.sink.add_dscp(negated, &values, target)
            }
            name => Err(RoutingError::new(format!("unknown function: {name}"))),
        }
    }
}

fn require_bare(function: &Function, key: &str) -> Result<(), RoutingError> {
    if key.is_empty() {
        return Ok(());
    }
    let name = &function.name;
    if is_retired_dat_key(key) {
        return Err(retired_dat_key(name, key));
    }
    Err(RoutingError::new(format!(
        "{name}: unsupported parameter key {key:?}; {name} takes bare values only and accepts \
         no named parameter, so write {name}(<value>)"
    )))
}

/// True for the keys that used to reach a Protobuf `.dat` file.
fn is_retired_dat_key(key: &str) -> bool {
    matches!(key, "geosite" | "geoip" | "ext")
}

/// The error for `geosite:` / `geoip:` / `ext:`.
///
/// These named a Protobuf `.dat` file. Both the file and the reader are gone (ADR-0014,
/// ADR-0015), so the honest answer is to name the replacement rather than say "unsupported key":
/// an operator migrating a working configuration needs to know where the category went, and the
/// data is still available — as a compiled `.drb` from `daer-drb`.
fn retired_dat_key(function: &str, key: &str) -> RoutingError {
    RoutingError::new(format!(
        "{function}({key}: ...): the `{key}:` key names a Protobuf .dat file, which this build \
         no longer reads (ADR-0014). Declare the category as a `[[rule-set]]` and write \
         `rule-set(<name>)`, or `ip-set(<name>)` / `domain-set(<name>)` to use only that \
         set's {}. See `daer-drb`.",
        if function == "domain" {
            "domains"
        } else {
            "addresses"
        }
    ))
}

fn group_params_by_key(params: &[Param]) -> Vec<(&str, Vec<&str>)> {
    let mut groups: Vec<(&str, Vec<&str>)> = Vec::with_capacity(params.len());
    for param in params {
        let value = param.as_literal().unwrap_or_default();
        match groups.iter_mut().find(|(key, _)| *key == param.key) {
            Some((_, values)) => values.push(value),
            None => groups.push((param.key.as_str(), vec![value])),
        }
    }
    groups
}

/// A sink that keeps the operands so [`crate::evaluate`] can replay the kernel's
/// decision loop in userspace.
#[derive(Debug, Default)]
pub struct RecordingSink {
    pub matches: Vec<MatchSet>,
    pub warnings: Vec<String>,
}

impl RecordingSink {
    fn push(&mut self, value: MatchValue, target: &MatchTarget, negated: bool) {
        self.matches.push(MatchSet {
            value,
            target: target.clone(),
            negated,
        });
    }
}

impl MatchSink for RecordingSink {
    fn add_domain(
        &mut self,
        negated: bool,
        patterns: &[String],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let borrowed: Vec<&str> = patterns.iter().map(String::as_str).collect();
        let table = DomainTable::compile(&borrowed, &mut self.warnings);
        self.push(MatchValue::Domain(table), target, negated);
        Ok(())
    }

    fn add_ip(
        &mut self,
        negated: bool,
        prefixes: &[IpNet],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push(MatchValue::IpSet(IpIndex::new(prefixes)?), target, negated);
        Ok(())
    }

    fn add_source_ip(
        &mut self,
        negated: bool,
        prefixes: &[IpNet],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push(
            MatchValue::SourceIpSet(IpIndex::new(prefixes)?),
            target,
            negated,
        );
        Ok(())
    }

    fn add_mac(
        &mut self,
        negated: bool,
        macs: &[MacAddr],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let mut macs = macs.to_vec();
        if negated {
            // Negative MAC rules must also catch traffic without a MAC
            // (localhost), matching `addSourceMac`.
            macs.push(MacAddr::UNSPECIFIED);
        }
        self.push(MatchValue::Mac(macs), target, negated);
        Ok(())
    }

    fn add_port(
        &mut self,
        negated: bool,
        ranges: &[PortRange],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push_each(ranges, target, negated, MatchValue::Port);
        Ok(())
    }

    fn add_source_port(
        &mut self,
        negated: bool,
        ranges: &[PortRange],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push_each(ranges, target, negated, MatchValue::SourcePort);
        Ok(())
    }

    fn add_l4_proto(
        &mut self,
        negated: bool,
        mask: L4ProtoMask,
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push(MatchValue::L4Proto(mask), target, negated);
        Ok(())
    }

    fn add_ip_version(
        &mut self,
        negated: bool,
        mask: IpVersionMask,
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push(MatchValue::IpVersion(mask), target, negated);
        Ok(())
    }

    fn add_process_name(
        &mut self,
        negated: bool,
        names: &[ProcessName],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push_each(names, target, negated, MatchValue::ProcessName);
        Ok(())
    }

    fn add_dscp(
        &mut self,
        negated: bool,
        values: &[u8],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push_each(values, target, negated, MatchValue::Dscp);
        Ok(())
    }

    fn add_provider(
        &mut self,
        negated: bool,
        set: &DrbSet,
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let sets = set.to_match_sets(target, negated);
        for s in sets {
            self.matches.push(s);
        }
        Ok(())
    }

    fn add_ip_index(
        &mut self,
        negated: bool,
        index: IpIndex,
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push(MatchValue::IpSet(index), target, negated);
        Ok(())
    }

    fn add_domain_index(
        &mut self,
        negated: bool,
        index: DomainTable,
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        self.push(MatchValue::Domain(index), target, negated);
        Ok(())
    }

    fn warn(&mut self, message: String) {
        self.warnings.push(message);
    }
}

impl RecordingSink {
    /// Some functions take several values (port ranges, process names, DSCP
    /// values). The Go sink emits one match set per value: the last one carries
    /// the target and the others are joined with logical-or.
    fn push_each<T: Copy>(
        &mut self,
        values: &[T],
        target: &MatchTarget,
        negated: bool,
        build: impl Fn(T) -> MatchValue,
    ) {
        for (index, value) in values.iter().enumerate() {
            let target = if index + 1 == values.len() {
                target.clone()
            } else {
                MatchTarget::logical_or(target.mark(), target.must())
            };
            self.push(build(*value), &target, negated);
        }
    }
}

/// A sink that validates operands and discards them.
///
/// This is what makes `daer validate` run the same parsers as `daer run`, so a
/// rule that would fail at startup fails validation instead.
#[derive(Debug, Default)]
pub struct ValidationSink {
    pub warnings: Vec<String>,
}

impl MatchSink for ValidationSink {
    fn add_domain(
        &mut self,
        _negated: bool,
        patterns: &[String],
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let borrowed: Vec<&str> = patterns.iter().map(String::as_str).collect();
        let _ = DomainTable::compile(&borrowed, &mut self.warnings);
        Ok(())
    }

    fn add_ip(
        &mut self,
        _negated: bool,
        _prefixes: &[IpNet],
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn add_source_ip(
        &mut self,
        _negated: bool,
        _prefixes: &[IpNet],
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn add_mac(
        &mut self,
        _negated: bool,
        _macs: &[MacAddr],
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn add_port(
        &mut self,
        _negated: bool,
        _ranges: &[PortRange],
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn add_source_port(
        &mut self,
        _negated: bool,
        _ranges: &[PortRange],
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn add_l4_proto(
        &mut self,
        _negated: bool,
        _mask: L4ProtoMask,
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn add_ip_version(
        &mut self,
        _negated: bool,
        _mask: IpVersionMask,
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn add_process_name(
        &mut self,
        _negated: bool,
        _names: &[ProcessName],
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn add_dscp(
        &mut self,
        _negated: bool,
        _values: &[u8],
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn add_provider(
        &mut self,
        _negated: bool,
        set: &DrbSet,
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        if set.is_empty() {
            self.warnings
                .push(format!("rule provider '{}' is empty", set.name));
        }
        Ok(())
    }

    fn warn(&mut self, message: String) {
        self.warnings.push(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixtures use the compact DNS-rule spelling to separate the match from
    /// its action. Production flow rules are `[[routing.rule]]` tables; the match
    /// language is identical.
    fn rules(src: &str) -> Vec<RoutingRule> {
        let body = src.trim();
        let body = body.strip_prefix("routing {").unwrap_or(body);
        let body = body.strip_suffix('}').unwrap_or(body);
        body.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .enumerate()
            .map(|(index, line)| {
                let parsed = daer_config::parse_dns_rule_expr(line).expect("parses");
                let action = match parsed.upstream.name.as_str() {
                    "direct" => {
                        daer_config::OutboundAction::Builtin(daer_config::BuiltinOutbound::Direct)
                    }
                    "block" => {
                        daer_config::OutboundAction::Builtin(daer_config::BuiltinOutbound::Block)
                    }
                    election => daer_config::OutboundAction::Election(election.to_owned()),
                };
                RoutingRule {
                    name: format!("r{index}"),
                    match_expr: daer_config::MatchExpr::new(parsed.and_functions),
                    action,
                }
            })
            .collect()
    }

    /// The retired `.dat` keys must name their replacement, not say "unsupported key".
    ///
    /// A migrating operator has a configuration that worked, and the only useful answer says
    /// where the category went. "unsupported key: geosite" is indistinguishable from a typo and
    /// leaves them to guess.
    #[test]
    fn retired_dat_keys_name_the_replacement() {
        for (rule, function, data) in [
            ("domain(geosite:cn) -> direct", "domain", "domains"),
            ("dip(geoip:cn) -> direct", "dip", "addresses"),
            ("sip(geoip:private) -> direct", "sip", "addresses"),
        ] {
            let error = RulesBuilder::new(&mut RecordingSink::default())
                .apply(&rules(rule))
                .expect_err("a .dat key must not lower");
            let message = error.to_string();
            assert!(message.contains("ADR-0014"), "{rule}: {message}");
            assert!(message.contains("[[rule-set]]"), "{rule}: {message}");
            assert!(message.contains(data), "{rule}: {message}");
            assert!(
                !message.contains("unsupported parameter key"),
                "{rule} fell back to the generic message: {message}"
            );
            // The context names the function, so a rule with several predicates is identifiable.
            assert!(
                message.contains(&format!("in '{function}(")),
                "{rule}: the error must name the function: {message}"
            );
        }
    }

    #[test]
    fn lowers_canonical_ip_and_port_predicates() {
        let rules = rules("routing { dip(1.0.0.0/8) && dport(80, 443) -> direct }");

        let mut sink = RecordingSink::default();
        RulesBuilder::new(&mut sink).apply(&rules).expect("lowers");

        assert_eq!(sink.matches.len(), 3);
        assert!(matches!(sink.matches[0].value, MatchValue::IpSet(_)));
        assert!(sink.matches[0].target.is_logical_and());
        // Two port ranges become two sets; the first is joined with logical-or.
        assert!(matches!(sink.matches[1].value, MatchValue::Port(_)));
        assert!(sink.matches[1].target.is_logical_or());
        assert!(matches!(sink.matches[2].value, MatchValue::Port(_)));
        assert_eq!(sink.matches[2].target.name(), Some("direct"));
    }

    #[test]
    fn retired_predicate_aliases_are_unknown_functions() {
        for alias in ["ip(1.0.0.0/8)", "port(443)", "provider(cn)"] {
            let rule = format!("routing {{ {alias} -> direct }}");
            let mut sink = RecordingSink::default();
            let error = RulesBuilder::new(&mut sink)
                .apply(&rules(&rule))
                .expect_err("an alias must not lower");
            assert!(
                error.message.contains("unknown function"),
                "{alias}: {error}"
            );
        }
    }

    #[test]
    fn named_parameters_are_rejected_for_bare_functions() {
        let rules = rules("routing { dport(bogus: 443) -> direct }");
        let mut sink = RecordingSink::default();
        let error = RulesBuilder::new(&mut sink)
            .apply(&rules)
            .expect_err("must fail");
        assert!(
            error.message.contains("unsupported parameter key"),
            "{error}"
        );
        assert!(error.message.contains("\"bogus\""), "{error}");
    }

    #[test]
    fn invalid_operands_are_reported_with_the_rule() {
        let rules = rules("routing { dip(not-an-ip) -> direct }");
        let mut sink = RecordingSink::default();
        let error = RulesBuilder::new(&mut sink)
            .apply(&rules)
            .expect_err("must fail");
        assert!(error.message.starts_with("in 'dip("), "{error}");
    }

    /// A bare name is a suffix, exactly as it is in rule text.
    ///
    /// The old matcher refused `domain(example.com)` and demanded `domain(suffix: example.com)`,
    /// which meant the same text had two meanings depending on whether it came from a config
    /// rule or a `.rules` file. One vocabulary (ADR-0033, ADR-0036) makes the bare name mean the
    /// suffix it obviously reads as: bare is a suffix, `.name` is subdomains only, `=name` is
    /// exact.
    #[test]
    fn a_bare_domain_is_a_suffix() {
        let bare = rules("routing { domain(example.com) -> direct }");
        let mut sink = RecordingSink::default();
        RulesBuilder::new(&mut sink)
            .apply(&bare)
            .expect("a bare name is a suffix");
        match &sink.matches[0].value {
            crate::matcher::MatchValue::Domain(table) => {
                assert!(
                    table.matches("example.com"),
                    "suffix includes the bare name"
                );
                assert!(table.matches("www.example.com"));
                assert!(table.patterns().iter().any(|p| p.as_ref() == "example.com"));
            }
            other => panic!("expected a domain table, got {other:?}"),
        }

        let sub_only = rules("routing { domain(.corp.example) -> direct }");
        let mut sink = RecordingSink::default();
        RulesBuilder::new(&mut sink)
            .apply(&sub_only)
            .expect("leading dot is subdomains only");
        match &sink.matches[0].value {
            crate::matcher::MatchValue::Domain(table) => {
                assert!(table.matches("a.corp.example"));
                assert!(
                    !table.matches("corp.example"),
                    "`.corp.example` excludes the bare name"
                );
            }
            other => panic!("expected a domain table, got {other:?}"),
        }

        let exact = rules("routing { domain(=exact.example.com) -> direct }");
        let mut sink = RecordingSink::default();
        RulesBuilder::new(&mut sink)
            .apply(&exact)
            .expect("equals prefix compiles as exact match");
        // The single lowered set must carry an exact-match domain table.
        assert_eq!(sink.matches.len(), 1);
        match &sink.matches[0].value {
            crate::matcher::MatchValue::Domain(table) => {
                assert!(table.matches("exact.example.com"));
                assert!(
                    !table.matches("sub.exact.example.com"),
                    "= must not match a subdomain"
                );
                assert!(
                    table
                        .patterns()
                        .iter()
                        .any(|p| p.as_ref() == "=exact.example.com")
                );
            }
            other => panic!("expected a domain table, got {other:?}"),
        }
    }

    /// A retired key is refused by name and says where it went, rather than matching nothing.
    #[test]
    fn a_removed_domain_key_names_its_replacement() {
        for spelling in ["regex: ^a.*z$", "suffix: example.com", "full: example.com"] {
            let retired = rules(&format!("routing {{ domain({spelling}) -> direct }}"));
            let mut sink = RecordingSink::default();
            let error = RulesBuilder::new(&mut sink)
                .apply(&retired)
                .expect_err("a retired key must be refused");
            assert!(
                error.to_string().contains("ADR-0033") || error.to_string().contains("ADR-0036"),
                "the error must name the fix: {error} ({spelling})"
            );
        }
    }

    #[test]
    fn multi_value_functions_are_or_joined() {
        let rules = rules("routing { pname(a, b) -> direct }");
        let mut sink = RecordingSink::default();
        RulesBuilder::new(&mut sink).apply(&rules).expect("lowers");

        assert_eq!(sink.matches.len(), 2);
        assert!(sink.matches[0].target.is_logical_or());
        assert_eq!(sink.matches[1].target.name(), Some("direct"));

        let facts = crate::matcher::MatchFacts {
            source_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            dest_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            source_port: 1,
            dest_port: 1,
            l4proto: L4ProtoMask::TCP,
            domain: None,
            process_name: ProcessName::from_bytes_truncated(b"b"),
            dscp: 0,
            mac: MacAddr::UNSPECIFIED,
        };
        assert_eq!(
            &*crate::matcher::evaluate(&sink.matches, &facts)
                .expect("hits")
                .outbound
                .name,
            "direct"
        );

        let mut other = facts;
        other.process_name = ProcessName::from_bytes_truncated(b"c");
        assert!(crate::matcher::evaluate(&sink.matches, &other).is_err());
    }

    #[test]
    fn pname_lowers_as_a_first_class_predicate() {
        let rules = rules("routing { pname(curl) -> direct }");
        let mut sink = RecordingSink::default();
        RulesBuilder::new(&mut sink).apply(&rules).expect("lowers");
        assert!(
            sink.warnings.is_empty(),
            "pname is supported by the attached cgroup hooks: {:?}",
            sink.warnings
        );
        assert_eq!(sink.matches.len(), 1);
        assert!(matches!(
            sink.matches[0].value,
            crate::matcher::MatchValue::ProcessName(_)
        ));
    }

    #[test]
    fn validation_sink_accepts_valid_rules() {
        let rules = rules(
            "routing { domain(example.com) && l4proto(tcp, udp) && mac('aa:bb:cc:dd:ee:ff') -> group(mark: 1) }",
        );
        let mut sink = ValidationSink::default();
        RulesBuilder::new(&mut sink)
            .apply(&rules)
            .expect("validates");
    }

    #[test]
    fn negated_mac_includes_the_zero_address() {
        let rules = rules("routing { !mac('aa:bb:cc:dd:ee:ff') -> direct }");
        let mut sink = RecordingSink::default();
        RulesBuilder::new(&mut sink).apply(&rules).expect("lowers");
        let MatchValue::Mac(macs) = &sink.matches[0].value else {
            panic!("expected a mac set");
        };
        assert!(macs.contains(&MacAddr::UNSPECIFIED));
    }
}
