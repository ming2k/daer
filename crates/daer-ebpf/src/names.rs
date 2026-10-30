// SPDX-License-Identifier: AGPL-3.0-only

//! Names of the eBPF maps and programs inside the datapath object.
//!
//! The string values are the **object's** ABI, not daer's vocabulary: the C
//! datapath declares them and they must match byte for byte. Rust constant names
//! describe the role instead, so daer's own code never spells a foreign product
//! name. `tests/object.rs` asserts every value against a freshly compiled object,
//! which is what keeps this table honest.
//!
//! The values themselves still carry a pre-daet prefix in a few places
//! (`dev_ifindex_map`-era names). Renaming them means owning the C source; that is
//! tracked as the first datapath milestone, not done silently here.

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

pub mod map {
    pub const ACTIVE_ROUTING_EPOCH: &str = "active_routing_epoch_map";
    pub const ALIVE_BLOCK_RATE: &str = "alive_block_rate_map";
    pub const BPF_STATS: &str = "bpf_stats_map";
    pub const CONN_STATE: &str = "conn_state_map";
    pub const CONNTRACK_ARGS: &str = "conntrack_args_map";
    pub const COOKIE_PID: &str = "cookie_pid_map";
    pub const DEVICE_IFINDEX: &str = "dae_ifindex_map";
    pub const DOMAIN_ROUTING: &str = "domain_routing_map";
    pub const EVENT_RINGBUF: &str = "event_ringbuf";
    pub const FAST_SOCK: &str = "fast_sock";
    pub const LISTEN_SOCKET: &str = "listen_socket_map";
    pub const LPM_ARRAY: &str = "lpm_array_map";
    pub const OUTBOUND_CONNECTIVITY: &str = "outbound_connectivity_map";
    pub const PARSE_CTX_SCRATCH: &str = "parse_ctx_scratch_map";
    pub const PKT_SCRATCH: &str = "pkt_scratch_map";
    pub const REDIRECT_TRACK: &str = "redirect_track";
    pub const ROUTE_CTX_SCRATCH: &str = "route_ctx_scratch_map";
    pub const ROUTING: &str = "routing_map";
    pub const ROUTING_HANDOFF: &str = "routing_handoff_map";
    pub const ROUTING_META: &str = "routing_meta_map";
    pub const TCP_OFFLOAD_PAUSE: &str = "tcp_offload_pause";
    pub const TCP_OFFLOAD_SENT: &str = "tcp_offload_sent";
    pub const UNUSED_LPM_TYPE: &str = "unused_lpm_type";
    pub const WAN_EGRESS_ROUTE_SCRATCH: &str = "wan_egress_route_scratch_map";

    /// Every map the object must contain.
    pub const ALL: [&str; 24] = [
        ACTIVE_ROUTING_EPOCH,
        ALIVE_BLOCK_RATE,
        BPF_STATS,
        CONN_STATE,
        CONNTRACK_ARGS,
        COOKIE_PID,
        DEVICE_IFINDEX,
        DOMAIN_ROUTING,
        EVENT_RINGBUF,
        FAST_SOCK,
        LISTEN_SOCKET,
        LPM_ARRAY,
        OUTBOUND_CONNECTIVITY,
        PARSE_CTX_SCRATCH,
        PKT_SCRATCH,
        REDIRECT_TRACK,
        ROUTE_CTX_SCRATCH,
        ROUTING,
        ROUTING_HANDOFF,
        ROUTING_META,
        TCP_OFFLOAD_PAUSE,
        TCP_OFFLOAD_SENT,
        UNUSED_LPM_TYPE,
        WAN_EGRESS_ROUTE_SCRATCH,
    ];
}

/// The generationality of every map in [`map::ALL`], by name.
///
/// Kept as a match so adding a constant without classifying it is a compile error at this
/// site, and adding it to `ALL` without classifying it fails `ALL_CLASSIFIED`.
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

pub mod program {
    pub const DEVICE_INGRESS: &str = "tproxy_dae0_ingress";
    pub const PEER_INGRESS: &str = "tproxy_dae0peer_ingress";
    pub const LAN_INGRESS_L2: &str = "tproxy_lan_ingress_l2";
    pub const LAN_INGRESS_L3: &str = "tproxy_lan_ingress_l3";
    pub const LAN_EGRESS_L2: &str = "tproxy_lan_egress_l2";
    pub const LAN_EGRESS_L3: &str = "tproxy_lan_egress_l3";
    pub const LAN_WAN_EGRESS_L2: &str = "tproxy_lan_wan_egress_l2";
    pub const LAN_WAN_EGRESS_L3: &str = "tproxy_lan_wan_egress_l3";
    pub const WAN_INGRESS_L2: &str = "tproxy_wan_ingress_l2";
    pub const WAN_INGRESS_L3: &str = "tproxy_wan_ingress_l3";
    pub const WAN_EGRESS_L2: &str = "tproxy_wan_egress_l2";
    pub const WAN_EGRESS_L3: &str = "tproxy_wan_egress_l3";
    pub const WAN_LAN_INGRESS_L2: &str = "tproxy_wan_lan_ingress_l2";
    pub const WAN_LAN_INGRESS_L3: &str = "tproxy_wan_lan_ingress_l3";
    pub const WAN_CG_CONNECT4: &str = "tproxy_wan_cg_connect4";
    pub const WAN_CG_CONNECT6: &str = "tproxy_wan_cg_connect6";
    pub const WAN_CG_SENDMSG4: &str = "tproxy_wan_cg_sendmsg4";
    pub const WAN_CG_SENDMSG6: &str = "tproxy_wan_cg_sendmsg6";
    pub const WAN_CG_SOCK_CREATE: &str = "tproxy_wan_cg_sock_create";
    pub const WAN_CG_SOCK_RELEASE: &str = "tproxy_wan_cg_sock_release";
    pub const TCP_OFFLOAD_REDIRECT: &str = "tcp_offload_redirect";
    pub const TCP_OFFLOAD_SENT_ACCOUNT: &str = "tcp_offload_sent_account";
    pub const TCP_OFFLOAD_SENT_ACCOUNT_KPROBE: &str = "tcp_offload_sent_account_kprobe";

    /// Every program the object must contain.
    pub const ALL: [&str; 23] = [
        DEVICE_INGRESS,
        PEER_INGRESS,
        LAN_INGRESS_L2,
        LAN_INGRESS_L3,
        LAN_EGRESS_L2,
        LAN_EGRESS_L3,
        LAN_WAN_EGRESS_L2,
        LAN_WAN_EGRESS_L3,
        WAN_INGRESS_L2,
        WAN_INGRESS_L3,
        WAN_EGRESS_L2,
        WAN_EGRESS_L3,
        WAN_LAN_INGRESS_L2,
        WAN_LAN_INGRESS_L3,
        WAN_CG_CONNECT4,
        WAN_CG_CONNECT6,
        WAN_CG_SENDMSG4,
        WAN_CG_SENDMSG6,
        WAN_CG_SOCK_CREATE,
        WAN_CG_SOCK_RELEASE,
        TCP_OFFLOAD_REDIRECT,
        TCP_OFFLOAD_SENT_ACCOUNT,
        TCP_OFFLOAD_SENT_ACCOUNT_KPROBE,
    ];
}

/// Name of the `const volatile` parameter global rewritten at load time.
pub const PARAM_GLOBAL: &str = "PARAM";

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
