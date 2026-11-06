// SPDX-License-Identifier: AGPL-3.0-only

//! Names of the eBPF maps and programs inside the datapath object.
//!
//! The string values are the **object's** ABI: the C datapath declares them and they
//! must match byte for byte. Rust constant names describe the role instead, so call
//! sites read as daer's vocabulary rather than as the C's. `tests/object.rs` asserts
//! every value against a freshly compiled object, which is what keeps this table
//! honest.
//!
//! The values are daer's own (ADR-0020). There is no prefix left over from another
//! project: `daer_ifindex_map`, `tproxy_daer0_ingress` and the rest are named here and
//! in `ebpf/kern/tproxy.c`, in one commit, because the C source is ours.

/// How a map relates to a configuration generation (ADR-0004).
///
/// The distinction is load-bearing, not descriptive. A reload publishes into the inactive
/// slot and then commits with one switch; a map that holds routing policy but is **not**
/// per-generation would keep serving the old policy after the switch, and a map that holds
/// flow state but *is* per-generation would lose every connection on reload. So every map has
/// to be classified, and `ALL_CLASSIFIED` below is what makes "somebody added a map and forgot"
/// a test failure instead of a production surprise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generationality {
    /// Holds routing policy. Exists per slot; a reload writes the inactive one and switches.
    PerGeneration,
    /// Holds state about flows, not policy. Single, and deliberately survives a reload: a
    /// connection must not be forgotten because the rules changed.
    Shared,
}

/// Map names, generated from `ebpf/abi.toml` (ADR-0021).
///
/// Re-exported rather than re-declared: there is one copy of every name, and
/// `cargo xtask abi --check` fails the build when the generated module and the
/// declaration disagree.
pub use crate::generated::map;
pub use crate::generated::program;

/// The generationality of every map in [`map::ALL`], from `ebpf/abi.toml` (ADR-0004).
///
/// The classification is declared next to each map rather than derived here, so a map
/// cannot be added to the object without saying whether a reload must write it per slot or
/// must preserve it. `tests/object.rs` asserts the table covers every map.
pub fn generationality(name: &str) -> Option<Generationality> {
    use Generationality::{PerGeneration, Shared};
    use map::*;
    Some(match name {
        // Routing policy: written per slot, switched atomically.
        ACTIVE_ROUTING_EPOCH
        | DOMAIN_ROUTING
        | LPM_ARRAY
        | OUTBOUND_CONNECTIVITY
        | ROUTING
        | ROUTING_HANDOFF
        | ROUTING_META
        | UNUSED_LPM_TYPE => PerGeneration,

        // Flow and datapath state: survives a reload by design.
        ALIVE_BLOCK_RATE
        | BPF_STATS
        | CONN_STATE
        | CONNTRACK_ARGS
        | COOKIE_PID
        | DEVICE_IFINDEX
        | EVENT_RINGBUF
        | FAST_SOCK
        | LISTEN_SOCKET
        | PARSE_CTX_SCRATCH
        | PKT_SCRATCH
        | REDIRECT_TRACK
        | ROUTE_CTX_SCRATCH
        | TCP_OFFLOAD_PAUSE
        | TCP_OFFLOAD_SENT
        | WAN_EGRESS_ROUTE_SCRATCH => Shared,

        _ => return None,
    })
}

/// Name of the `const volatile` parameter global rewritten at load time.
///
/// From `ebpf/abi.toml` via the generated module, so the loader's override and the C's
/// declaration cannot disagree.
pub use crate::generated::PARAM_GLOBAL;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_map_is_classified() {
        // ADR-0004: an unclassified map is either a policy table that a reload would leave
        // half-updated, or a state table that a reload would wrongly clear. Both are silent
        // production bugs, so the classification is asserted, not assumed.
        let unclassified: Vec<&str> = map::ALL
            .iter()
            .copied()
            .filter(|name| generationality(name).is_none())
            .collect();
        assert!(
            unclassified.is_empty(),
            "these maps have no generationality in ADR-0004: {unclassified:?}"
        );
    }

    #[test]
    fn the_classification_covers_nothing_that_is_not_a_map() {
        // The reverse direction: a name classified here but absent from `ALL` would be a table
        // the object test never checks, so it would rot silently.
        for name in map::ALL {
            assert!(
                generationality(name).is_some(),
                "{name} is in ALL but not classified"
            );
        }
    }

    #[test]
    fn policy_tables_are_per_generation_and_state_is_shared() {
        for name in [
            map::ROUTING,
            map::DOMAIN_ROUTING,
            map::LPM_ARRAY,
            map::OUTBOUND_CONNECTIVITY,
            map::ACTIVE_ROUTING_EPOCH,
        ] {
            assert_eq!(
                generationality(name),
                Some(Generationality::PerGeneration),
                "{name} holds routing policy"
            );
        }
        for name in [
            map::CONN_STATE,
            map::EVENT_RINGBUF,
            map::LISTEN_SOCKET,
            map::DEVICE_IFINDEX,
        ] {
            assert_eq!(
                generationality(name),
                Some(Generationality::Shared),
                "{name} holds flow or datapath state"
            );
        }
    }

    #[test]
    fn an_unknown_name_is_not_classified() {
        assert_eq!(generationality("not_a_map"), None);
    }
}
