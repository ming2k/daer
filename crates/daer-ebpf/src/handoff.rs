// SPDX-License-Identifier: AGPL-3.0-only

//! Reading back what the kernel observed about a flow.
//!
//! # The gap this closes
//!
//! Three facts about a flow are visible only to the datapath:
//!
//! * the client's **source MAC** (the packet has it; the accepted socket does not);
//! * the packet's **DSCP**;
//! * the **process name and pid** that opened the flow, which the cgroup hooks record in
//!   `cookie_pid_map` and `wan_egress` copies into the handoff entry.
//!
//! When the kernel defers a flow to the control plane — which ADR-0011 makes it do for any
//! configuration containing a `domain(...)` rule, and which is the *only* path for a rule the
//! kernel cannot encode — it writes those facts into `routing_handoff_map` before redirecting.
//! Nothing read that map, so `MatchFacts` was built with `mac: [0; 6]`, `dscp: 0`, and an
//! empty `process_name`. Every `mac(...)`, `dscp(...)`, and `pname(...)` rule after the
//! partition boundary was therefore accepted, lowered, and silently inert.
//!
//! # Why the key is derived from the accepted socket
//!
//! `routing_handoff_map` is keyed by `struct tuples_key`, the C's five-tuple. For a redirected
//! TCP flow the accepted socket's peer address is the client and its local address is the
//! original destination, so the key can be rebuilt exactly. The C zero-fills `sip`/`dip` for
//! an IPv4 flow (`union ip6` holding a v4 address in its low bytes), which
//! [`TuplesKey::of`] reproduces.

use aya::Ebpf;
use aya::maps::{HashMap as BpfHashMap, MapData};

use crate::abi::{RoutingHandoff, TuplesKey};
use crate::names::map;

/// A reader over the datapath's per-flow handoff entries.
///
/// # Why this is a separate type
///
/// The map only exists while the datapath is attached, and the reader needs `&mut Ebpf` to
/// look a value up. Bundling the two means the control plane holds one `Option<Handoff>` and
/// the "no datapath" case is a `None` rather than a flag checked per flow.
#[derive(Debug)]
pub struct Handoff<'a> {
    ebpf: &'a mut Ebpf,
}

impl<'a> Handoff<'a> {
    /// Wraps a loaded object.
    pub fn new(ebpf: &'a mut Ebpf) -> Self {
        Self { ebpf }
    }

    /// The kernel's decision for `key`, if it wrote one.
    ///
    /// Returns `None` when the datapath is not attached, when the map is missing, when the
    /// flow was never handed off (the kernel decided it itself, so userspace will not see it),
    /// or when the entry does not decode. Every one of those is a normal outcome: the caller
    /// falls back to the facts it can observe.
    pub fn lookup(&mut self, key: TuplesKey) -> Option<RoutingHandoff> {
        let data = self.ebpf.map_mut(map::ROUTING_HANDOFF)?;
        // The key and value are read as raw bytes rather than through typed `aya` map
        // parameters: `aya::Pod` is an unsafe marker, and implementing it for a struct with
        // layout assertions in this crate would move the proof out of the type. A byte key is
        // what the map actually stores.
        let mut bytes_key = [0u8; std::mem::size_of::<TuplesKey>()];
        // SAFETY: `TuplesKey` is `repr(C, align(8))` over integers and byte arrays with no
        // padding (asserted in `abi`), so every bit pattern is valid and the copy covers
        // exactly one value.
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::from_ref(&key).cast::<u8>(),
                bytes_key.as_mut_ptr(),
                bytes_key.len(),
            );
        }
        let map =
            BpfHashMap::<&mut MapData, [u8; KEY_SIZE], [u8; VALUE_SIZE]>::try_from(data).ok()?;
        let value = map.get(&bytes_key, 0).ok()?;
        RoutingHandoff::from_bytes(&value)
    }
}

/// The `tuples_key` width, asserted in `abi`.
const KEY_SIZE: usize = std::mem::size_of::<TuplesKey>();
/// The `routing_handoff_entry` value width, asserted in `abi`.
const VALUE_SIZE: usize = std::mem::size_of::<RoutingHandoff>();

impl TuplesKey {
    /// The handoff key for an accepted TCP flow.
    ///
    /// `source` is the client (`peer_addr`) and `destination` the original destination
    /// (`local_addr` on a transparent socket). IPv4 addresses are stored the way the C stores
    /// them: zero-filled 16-byte arrays with the four octets in the **last** four bytes, which
    /// is what `union ip6` looks like when the C reads a `struct iphdr`.
    #[must_use]
    pub fn of(
        source: std::net::SocketAddr,
        destination: std::net::SocketAddr,
        l4proto: u8,
    ) -> Self {
        Self {
            sip: ip_bytes(source.ip()),
            dip: ip_bytes(destination.ip()),
            sport: source.port(),
            dport: destination.port(),
            l4proto,
        }
    }
}

/// A v4-mapped or v6 address in the C's `union ip6` layout.
fn ip_bytes(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let mut bytes = [0u8; 16];
            bytes[12..16].copy_from_slice(&v4.octets());
            bytes
        }
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn an_ipv4_key_matches_the_c_union_layout() {
        // The C reads a v4 `iphdr` into `union ip6`, so the address lands in the last four
        // bytes and the first twelve stay zero. A key built any other way never matches, and
        // the lookup would fail silently for every IPv4 flow — which is most of them.
        let key = TuplesKey::of(
            "192.0.2.9:40000".parse::<SocketAddr>().expect("addr"),
            "198.51.100.7:443".parse::<SocketAddr>().expect("addr"),
            6,
        );
        assert_eq!(key.sip, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 9]);
        assert_eq!(
            key.dip,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 7]
        );
        assert_eq!(key.sport, 40000);
        assert_eq!(key.dport, 443);
        assert_eq!(key.l4proto, 6);
    }

    #[test]
    fn an_ipv6_key_is_the_address_verbatim() {
        let key = TuplesKey::of(
            "[2001:db8::1]:1234".parse::<SocketAddr>().expect("addr"),
            "[2001:db8::2]:53".parse::<SocketAddr>().expect("addr"),
            17,
        );
        assert_eq!(
            key.sip,
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .expect("addr")
                .octets()
        );
        assert_eq!(key.l4proto, 17);
    }

    #[test]
    fn a_handoff_entry_round_trips_through_its_bytes() {
        let entry = RoutingHandoff {
            last_seen_ns: 42,
            result: crate::abi::RoutingResult {
                mark: 0x64616572,
                must: 1,
                mac: [2, 0, 0, 0, 0, 1],
                outbound: 3,
                pname: {
                    let mut name = [0u8; crate::abi::TASK_COMM_LEN];
                    name[..7].copy_from_slice(b"firefox");
                    name
                },
                pid: 4242,
                dscp: 46,
                routing_epoch_slot: 2,
                datapath_generation: 7,
            },
        };
        // Round-trip through the same decode the map reader uses: the assertion is that a
        // value written by the C's layout decodes back to itself, which is what the reader
        // depends on.
        let mut bytes = [0u8; VALUE_SIZE];
        // SAFETY: `RoutingHandoff` is `repr(C)` over integers and byte arrays with no padding
        // (asserted in `abi`), so copying its bytes is a valid read of exactly one value.
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::from_ref(&entry).cast::<u8>(),
                bytes.as_mut_ptr(),
                VALUE_SIZE,
            );
        }
        assert_eq!(RoutingHandoff::from_bytes(&bytes), Some(entry));
    }

    #[test]
    fn a_value_of_the_wrong_width_is_refused_rather_than_read() {
        assert_eq!(RoutingHandoff::from_bytes(&[0u8; 8]), None);
        assert_eq!(RoutingHandoff::from_bytes(&[0u8; 47]), None);
    }
}
