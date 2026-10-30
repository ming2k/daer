// SPDX-License-Identifier: AGPL-3.0-only

//! Rule lowering: turns parsed routing rules into match sets.
//!
//! This is `RulesBuilder.Apply` from `component/routing/matcher_builder.go`,
//! with the parser registry replaced by a fixed dispatch over the built-in
//! routing functions. A [`MatchSink`] decides what a lowered match set becomes:
//! match sets for the userspace evaluator, eBPF map entries, or nothing at all
//! during validation.

use daer_common::{MacAddr, PortRange};
use daer_config::{Function, Param, RoutingRule};
use ipnet::IpNet;

use crate::domain::{DomainIndex, DomainKey};
use crate::error::RoutingError;
use crate::ipset::IpIndex;
use crate::matcher::{MatchSet, MatchValue};
use crate::outbound::{MatchTarget, parse_outbound};
use crate::values::{
    IpVersionMask, L4ProtoMask, ProcessName, parse_dscp, parse_ip_version, parse_l4_proto,
    parse_mac_addresses, parse_port_ranges, parse_prefixes, parse_process_names,
};

/// Receives one call per `(function, parameter key)` group.
pub trait MatchSink {
    fn add_domain(
        &mut self,
        negated: bool,
        key: DomainKey,
        values: &[&str],
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

    /// Records a non-fatal diagnostic, such as a truncated process name.
    fn warn(&mut self, _message: String) {}
}

#[derive(Debug)]
pub struct RulesBuilder<'a, S: MatchSink> {
    sink: &'a mut S,
}

impl<'a, S: MatchSink> RulesBuilder<'a, S> {
    pub fn new(sink: &'a mut S) -> Self {
        Self { sink }
    }

    pub fn sink(&self) -> &S {
        self.sink
    }

    pub fn sink_mut(&mut self) -> &mut S {
        self.sink
    }

    /// Lowers every rule. `rule.and_functions` must already be normalized
    /// (aliases rewritten, parameters sorted), otherwise `dip`/`dport` and the
    /// bare `domain` key are rejected — the same contract as the Go optimizer
    /// pipeline.
    pub fn apply(&mut self, rules: &[RoutingRule]) -> Result<(), RoutingError> {
        for rule in rules {
            let outbound = parse_outbound(&rule.outbound)?;
            let function_count = rule.and_functions.len();

            for (function_index, function) in rule.and_functions.iter().enumerate() {
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
                        .map_err(|err| err.context(format!("failed to parse '{function}'")))?;
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
            "domain" => {
                let key = DomainKey::parse(key)?;
                self.sink.add_domain(negated, key, values, target)
            }
            "ip" => {
                require_bare(function, key)?;
                let prefixes = parse_prefixes(values)?;
                self.sink.add_ip(negated, &prefixes, target)
            }
            "sip" => {
                require_bare(function, key)?;
                let prefixes = parse_prefixes(values)?;
                self.sink.add_source_ip(negated, &prefixes, target)
            }
            "port" => {
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
    Err(RoutingError::new(format!(
        "{name}: unsupported parameter key {key:?}; {name} takes bare values only and accepts \
         no named parameter, so write {name}(<value>)"
    )))
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
        key: DomainKey,
        values: &[&str],
        target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let patterns = DomainIndex::new(key, values, &mut self.warnings);
        self.push(MatchValue::Domain(patterns), target, negated);
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
        key: DomainKey,
        values: &[&str],
        _target: &MatchTarget,
    ) -> Result<(), RoutingError> {
        let _ = DomainIndex::new(key, values, &mut self.warnings);
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

    fn warn(&mut self, message: String) {
        self.warnings.push(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::{AliasOptimizer, RulesOptimizer};

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
    fn lowers_aliases_and_keys_after_optimization() {
        let rules = rules("routing { dip(1.0.0.0/8) && dport(80, 443) -> direct }");
        let rules = AliasOptimizer.optimize(rules).expect("optimizes");

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
    fn unoptimized_aliases_are_unknown_functions() {
        let rules = rules("routing { dip(1.0.0.0/8) -> direct }");
        let mut sink = RecordingSink::default();
        let error = RulesBuilder::new(&mut sink)
            .apply(&rules)
            .expect_err("must fail");
        assert!(error.message.contains("unknown function: dip"), "{error}");
    }

    #[test]
    fn named_parameters_are_rejected_for_bare_functions() {
        let rules = rules("routing { port(bogus: 443) -> direct }");
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
        let rules = rules("routing { ip(not-an-ip) -> direct }");
        let mut sink = RecordingSink::default();
        let error = RulesBuilder::new(&mut sink)
            .apply(&rules)
            .expect_err("must fail");
        assert!(error.message.starts_with("failed to parse 'ip("), "{error}");
    }

    #[test]
    fn domain_requires_an_authoritative_key() {
        let rules = rules("routing { domain(example.com) -> direct }");
        let mut sink = RecordingSink::default();
        let error = RulesBuilder::new(&mut sink)
            .apply(&rules)
            .expect_err("must fail");
        assert!(
            error.message.contains("addDomain: unsupported key"),
            "{error}"
        );
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
    fn validation_sink_accepts_valid_rules() {
        let rules = rules(
            "routing { domain(suffix:example.com) && l4proto(tcp, udp) && mac('aa:bb:cc:dd:ee:ff') -> group(mark: 1) }",
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
