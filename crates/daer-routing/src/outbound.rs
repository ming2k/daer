// SPDX-License-Identifier: AGPL-3.0-only

//! Outbound parsing and the "current target" of a lowered match set.
//!
//! Mirrors `component/routing/matcher_builder.go` (`Outbound`, `ParseOutbound`)
//! and the `OutboundLogicalOr` / `OutboundLogicalAnd` markers that encode AND/OR
//! structure inside the flat match-set array.

use daer_config::OutboundKind;

use crate::error::RoutingError;

/// Reserved outbound: marks the following rules as "must", without terminating
/// the rule (see `patchMustOutbound` and `datapath.bpf.c`).
///
/// Defined in `daer-common` so the rule lowering, the kernel id mapping and the configuration
/// validator cannot disagree about the spelling.
pub use daer_common::consts::outbound_name::MUST_RULES;

/// Reserved outbound used by the implicit sniff-punt projection.
///
/// The Go constant is `OutboundControlPlaneRouting.String()`; the angle brackets
/// are part of the name and cannot collide with a configured group.
pub use daer_common::consts::outbound_name::CONTROL_PLANE_ROUTING;

/// Name of the logical-or marker (`OutboundLogicalOr.String()`).
pub use daer_common::consts::outbound_name::LOGICAL_OR;

/// Name of the logical-and marker (`OutboundLogicalAnd.String()`).
pub use daer_common::consts::outbound_name::LOGICAL_AND;

/// Built-in outbounds that may appear in a rule without being declared in a
/// `group` section.
///
/// Defined once, in `daer-common`: `daer-config` uses the same list to reject a `[[group]]` whose
/// name would shadow a builtin, which is how a configuration and the daemon are kept from
/// disagreeing about what `direct` means.
pub use daer_common::consts::BUILTIN_OUTBOUNDS;

/// True for the implicit outbounds the control plane always provides.
pub use daer_common::consts::is_builtin_outbound;

/// A resolved outbound: the immutable identity a flow is sent to.
///
/// `name` is an `Arc<str>` rather than a `String` because a decision clones it on
/// every flow. An outbound identity is created once per generation and never
/// mutated, so cloning it must be an atomic increment and not an allocation — this
/// is the difference between a decision path with zero heap traffic and one with a
/// `malloc`/`free` pair per connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// What kind of egress this is. `Direct` and `Block` are built-in policies;
    /// `Election` is a dynamic egress whose selected node is the concrete dialer.
    pub kind: OutboundKind,
    pub name: std::sync::Arc<str>,
    /// Reserved datapath modifier. Configuration actions set it to zero.
    pub mark: u32,
    /// Reserved datapath marker. Configuration actions set it to false.
    pub must: bool,
}

impl std::fmt::Display for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            OutboundKind::Direct => f.write_str("direct"),
            OutboundKind::Block => f.write_str("block"),
            OutboundKind::Election => write!(f, "election {:?}", self.name),
        }
    }
}

impl Outbound {
    #[must_use]
    pub fn direct() -> Self {
        Self {
            kind: OutboundKind::Direct,
            name: std::sync::Arc::from(daer_common::consts::outbound_name::DIRECT),
            mark: 0,
            must: false,
        }
    }

    #[must_use]
    pub fn block() -> Self {
        Self {
            kind: OutboundKind::Block,
            name: std::sync::Arc::from(daer_common::consts::outbound_name::BLOCK),
            mark: 0,
            must: false,
        }
    }

    #[must_use]
    pub fn election(name: impl Into<std::sync::Arc<str>>) -> Self {
        Self {
            kind: OutboundKind::Election,
            name: name.into(),
            mark: 0,
            must: false,
        }
    }

    /// Builds the outbound a configured action names.
    ///
    /// # Errors
    ///
    /// An election name must not be empty; the loader has already reserved the
    /// built-in names, so a non-empty election is the only dynamic case.
    pub fn from_action(action: &daer_config::OutboundAction) -> Result<Self, RoutingError> {
        match action {
            daer_config::OutboundAction::Builtin(daer_config::BuiltinOutbound::Direct) => {
                Ok(Self::direct())
            }
            daer_config::OutboundAction::Builtin(daer_config::BuiltinOutbound::Block) => {
                Ok(Self::block())
            }
            daer_config::OutboundAction::Election(election) => {
                if election.election.trim().is_empty() {
                    return Err(RoutingError::new("election action names no election"));
                }
                Ok(Self::election(election.election.as_str()))
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use daer_config::{BuiltinOutbound, ElectionAction, OutboundAction};

    #[test]
    fn builtins_are_distinct_outbounds() {
        let direct = Outbound::from_action(&OutboundAction::Builtin(BuiltinOutbound::Direct))
            .expect("direct");
        assert_eq!(direct.kind, OutboundKind::Direct);
        assert_eq!(&*direct.name, daer_common::consts::outbound_name::DIRECT);

        let block =
            Outbound::from_action(&OutboundAction::Builtin(BuiltinOutbound::Block)).expect("block");
        assert_eq!(block.kind, OutboundKind::Block);
        assert_eq!(&*block.name, daer_common::consts::outbound_name::BLOCK);
    }

    #[test]
    fn an_election_is_a_dynamic_outbound() {
        let outbound = Outbound::from_action(&OutboundAction::Election(ElectionAction {
            election: "proxy".to_owned(),
        }))
        .expect("election");
        assert_eq!(outbound.kind, OutboundKind::Election);
        assert_eq!(&*outbound.name, "proxy");
    }

    #[test]
    fn an_empty_election_name_is_rejected() {
        let error = Outbound::from_action(&OutboundAction::Election(ElectionAction {
            election: "  ".to_owned(),
        }))
        .expect_err("empty election");
        assert!(error.message.contains("no election"), "{error}");
    }
}
