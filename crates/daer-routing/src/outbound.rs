// SPDX-License-Identifier: AGPL-3.0-only

//! Outbound parsing and the "current target" of a lowered match set.
//!
//! Mirrors `component/routing/matcher_builder.go` (`Outbound`, `ParseOutbound`)
//! and the `OutboundLogicalOr` / `OutboundLogicalAnd` markers that encode AND/OR
//! structure inside the flat match-set array.

use daer_config::Function;

use crate::error::RoutingError;

/// Reserved outbound: marks the following rules as "must", without terminating
/// the rule (see `patchMustOutbound` and `tproxy.c`).
pub const MUST_RULES: &str = "must_rules";

/// Reserved outbound used by the implicit sniff-punt projection.
///
/// The Go constant is `OutboundControlPlaneRouting.String()`; the angle brackets
/// are part of the name and cannot collide with a configured group.
pub const CONTROL_PLANE_ROUTING: &str = "<Control Plane Routing>";

/// Name of the logical-or marker (`OutboundLogicalOr.String()`).
pub const LOGICAL_OR: &str = "<OR>";

/// Name of the logical-and marker (`OutboundLogicalAnd.String()`).
pub const LOGICAL_AND: &str = "<AND>";

/// Built-in outbounds that may appear in a rule without being declared in a
/// `group` section.
pub const BUILTIN_OUTBOUNDS: [&str; 6] = [
    "direct",
    "block",
    MUST_RULES,
    CONTROL_PLANE_ROUTING,
    LOGICAL_OR,
    LOGICAL_AND,
];

/// True for the implicit outbounds the control plane always provides.
pub fn is_builtin_outbound(name: &str) -> bool {
    BUILTIN_OUTBOUNDS.contains(&name)
}

/// A resolved outbound: the immutable identity a flow is sent to.
///
/// `name` is an `Arc<str>` rather than a `String` because a decision clones it on
/// every flow. An outbound identity is created once per generation and never
/// mutated, so cloning it must be an atomic increment and not an allocation — this
/// is the difference between a decision path with zero heap traffic and one with a
/// `malloc`/`free` pair per connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    pub name: std::sync::Arc<str>,
    pub mark: u32,
    pub must: bool,
}

impl Outbound {
    pub fn new(name: impl Into<std::sync::Arc<str>>) -> Self {
        Self {
            name: name.into(),
            mark: 0,
            must: false,
        }
    }
}

/// Where a match set points once it is reached.
///
/// `LogicalOr`/`LogicalAnd` are not real outbounds: they are the glue that lets a
/// flat array express `a && b && c -> outbound`, where parameters inside one
/// function are OR-ed and functions are AND-ed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchTarget {
    Outbound(Outbound),
    LogicalOr { mark: u32, must: bool },
    LogicalAnd { mark: u32, must: bool },
}

impl MatchTarget {
    pub fn logical_or(mark: u32, must: bool) -> Self {
        Self::LogicalOr { mark, must }
    }

    pub fn logical_and(mark: u32, must: bool) -> Self {
        Self::LogicalAnd { mark, must }
    }

    pub fn mark(&self) -> u32 {
        match self {
            Self::Outbound(outbound) => outbound.mark,
            Self::LogicalOr { mark, .. } | Self::LogicalAnd { mark, .. } => *mark,
        }
    }

    pub fn must(&self) -> bool {
        match self {
            Self::Outbound(outbound) => outbound.must,
            Self::LogicalOr { must, .. } | Self::LogicalAnd { must, .. } => *must,
        }
    }

    /// True when more parameter groups follow inside the same function.
    pub fn is_logical_or(&self) -> bool {
        matches!(self, Self::LogicalOr { .. })
    }

    pub fn is_logical_and(&self) -> bool {
        matches!(self, Self::LogicalAnd { .. })
    }

    pub fn is_logical(&self) -> bool {
        !matches!(self, Self::Outbound(_))
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Outbound(outbound) => Some(&outbound.name),
            Self::LogicalOr { .. } | Self::LogicalAnd { .. } => None,
        }
    }

    pub fn outbound(&self) -> Option<&Outbound> {
        match self {
            Self::Outbound(outbound) => Some(outbound),
            Self::LogicalOr { .. } | Self::LogicalAnd { .. } => None,
        }
    }
}

/// Parses `direct`, `proxy(mark: 0x10)`, `my_group(must)` and friends.
pub fn parse_outbound(raw: &Function) -> Result<Outbound, RoutingError> {
    let mut outbound = Outbound {
        name: std::sync::Arc::from(raw.name.as_str()),
        mark: 0,
        must: false,
    };

    for param in &raw.params {
        match param.key.as_str() {
            "mark" => {
                let value = param.as_literal().unwrap_or_default();
                let parsed = daer_config::parse_integer(value)
                    .and_then(|number| u32::try_from(number).ok())
                    .ok_or_else(|| {
                        RoutingError::new(format!("failed to parse mark: {value} is not a uint32"))
                    })?;
                outbound.mark = parsed;
            }
            "" => {
                let value = param.as_literal().unwrap_or_default();
                if value == "must" {
                    outbound.must = true;
                } else {
                    return Err(RoutingError::new(format!(
                        "unknown outbound param: {value}"
                    )));
                }
            }
            key => {
                return Err(RoutingError::new(format!(
                    "unknown outbound param key: {key}"
                )));
            }
        }
    }

    Ok(outbound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use daer_config::Param;

    fn outbound_from(outbound: &str) -> Outbound {
        let rule =
            daer_config::parse_rule_expr(&format!("domain(a.com) -> {outbound}")).expect("parses");
        parse_outbound(&rule.outbound).expect("parses outbound")
    }

    #[test]
    fn parses_plain_outbound() {
        let outbound = outbound_from("direct");
        assert_eq!(&*outbound.name, "direct");
        assert_eq!(outbound.mark, 0);
        assert!(!outbound.must);
    }

    #[test]
    fn parses_mark_and_must() {
        assert_eq!(outbound_from("proxy(mark: 0x10)").mark, 16);
        assert_eq!(outbound_from("proxy(mark: 16)").mark, 16);
        assert!(outbound_from("direct(must)").must);
    }

    #[test]
    fn rejects_unknown_params() {
        let rule = daer_config::parse_rule_expr("domain(a.com) -> proxy(nope: 1)").expect("parses");
        let error = parse_outbound(&rule.outbound).expect_err("must fail");
        assert_eq!(error.message, "unknown outbound param key: nope");

        let rule = daer_config::parse_rule_expr("domain(a.com) -> proxy(oops)").expect("parses");
        let error = parse_outbound(&rule.outbound).expect_err("must fail");
        assert_eq!(error.message, "unknown outbound param: oops");
    }

    #[test]
    fn rejects_mark_out_of_range() {
        let rule = daer_config::parse_rule_expr("domain(a.com) -> proxy(mark: 0x100000000)")
            .expect("parses");
        assert!(parse_outbound(&rule.outbound).is_err());
    }

    #[test]
    fn parses_outbound_with_annotation_free_params() {
        let function = Function::with_params("group", vec![Param::bare("must")]);
        let outbound = parse_outbound(&function).expect("parses");
        assert!(outbound.must);
    }
}
