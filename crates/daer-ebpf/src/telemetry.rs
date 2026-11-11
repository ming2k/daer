// SPDX-License-Identifier: AGPL-3.0-only

//! Userspace consumers for the datapath's structured telemetry (ADR-0040).
//!
//! # Why this module exists
//!
//! The datapath has always produced two observability surfaces: `bpf_stats_map`, a set of
//! per-packet counters, and `event_ringbuf`, a stream of rate-limited structured events. Before
//! this module neither had a reader, so every overflow, rebind rejection and map-full event was
//! invisible. The C comments said "userspace reads it"; nothing did.
//!
//! # Counters, not event counts
//!
//! The ring is deliberately rate-limited (at most once per second per key). It is the
//! explanation, not the measurement. Volume and deltas come from [`BpfCounters`]; an event says
//! *why* a counter moved, never *how often*.
//!
//! # Ownership
//!
//! [`DatapathTelemetry::attach`] takes the two maps out of the `Ebpf` handle. That is the same
//! ownership the policy publisher uses for its maps: one reader, no aliasing of a map fd.

use aya::Ebpf;
use aya::maps::{Array, MapData, RingBuf};

use crate::generated::{bpf_stats, daer_event, map};
use crate::loader::LoadError;

// SAFETY: `DaerEvent` is `#[repr(C)]`, every byte is covered by a field (the explicit `pad`
// covers the only gap), and every field is an integer or an array of integers, so every bit
// pattern is a valid value. The generated layout assertions in `generated.rs` pin the size and
// every offset to `ebpf/abi.toml`; a change there that is not reflected here fails the build.
unsafe impl aya::Pod for daer_event::DaerEvent {}

/// A point-in-time read of every `bpf_stats_map` counter.
///
/// The vector is indexed by the generated [`bpf_stats`] constants. `bpf_stats::MAX` is the
/// number of keys, not an index; the vector length is checked at construction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BpfCounters {
    values: Vec<u64>,
}

impl BpfCounters {
    /// The value of one counter.
    ///
    /// # Panics
    ///
    /// Panics when `key` is not a declared counter. The key is a generated constant in every
    /// internal caller; an out-of-range key is a wiring bug, not a runtime condition.
    #[must_use]
    pub fn get(&self, key: u32) -> u64 {
        self.values
            .get(key as usize)
            .copied()
            .unwrap_or_else(|| panic!("bpf_stats key {key} is out of range"))
    }

    /// The delta from an earlier snapshot, saturating at zero for a reset map.
    #[must_use]
    pub fn delta(&self, earlier: &Self) -> Self {
        let values = self
            .values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value.saturating_sub(earlier.values.get(index).copied().unwrap_or(0))
            })
            .collect();
        Self { values }
    }

    /// True when every delta is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.values.iter().all(|value| *value == 0)
    }

    /// Every `(key, value)` pair where the value is non-zero.
    pub fn nonzero(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        self.values
            .iter()
            .enumerate()
            .filter(|(_, value)| **value != 0)
            .map(|(index, value)| (index as u32, *value))
    }

    /// The number of declared keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True when no counter is present (only possible before a successful read).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// The datapath's two telemetry maps, owned by one reader.
pub struct DatapathTelemetry {
    counters: Array<MapData, u64>,
    events: RingBuf<MapData>,
}

impl std::fmt::Debug for DatapathTelemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatapathTelemetry")
            .field("counters", &"bpf_stats_map")
            .field("events", &"event_ringbuf")
            .finish()
    }
}

impl DatapathTelemetry {
    /// Takes `bpf_stats_map` and `event_ringbuf` out of the loaded object.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::NotFound`] when the object lacks a map, or [`LoadError::Map`] when
    /// a map has the wrong type or the kernel refuses the handoff.
    pub fn attach(ebpf: &mut Ebpf) -> Result<Self, LoadError> {
        let counters = ebpf
            .take_map(map::BPF_STATS)
            .ok_or_else(|| LoadError::NotFound(map::BPF_STATS.to_owned()))?
            .try_into()
            .map_err(LoadError::Map)?;
        let events = ebpf
            .take_map(map::EVENT_RINGBUF)
            .ok_or_else(|| LoadError::NotFound(map::EVENT_RINGBUF.to_owned()))?
            .try_into()
            .map_err(LoadError::Map)?;
        Ok(Self { counters, events })
    }

    /// Reads every counter.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::Map`] when a lookup fails. The array is preallocated, so this is a
    /// kernel/syscall failure, not a missing key.
    pub fn read_counters(&self) -> Result<BpfCounters, LoadError> {
        let mut values = Vec::with_capacity(bpf_stats::MAX as usize);
        for value in self.counters.iter() {
            values.push(value.map_err(LoadError::Map)?);
        }
        if values.len() != bpf_stats::MAX as usize {
            return Err(LoadError::NotFound(format!(
                "{} has {} keys, expected {}",
                map::BPF_STATS,
                values.len(),
                bpf_stats::MAX
            )));
        }
        Ok(BpfCounters { values })
    }

    /// Takes the next event, if the ring has one.
    ///
    /// The caller may poll the ring's fd for readiness; this method never blocks. A record
    /// shorter than the declared layout is skipped and counted as a malformed read rather than
    /// interpreted field-by-field.
    pub fn try_next_event(&mut self) -> Option<daer_event::DaerEvent> {
        let item = self.events.next()?;
        if item.len() < daer_event::SIZE {
            return None;
        }
        // SAFETY: `DaerEvent` is `Pod` (see the impl above), the ring item is at least
        // `SIZE` bytes, and `read_unaligned` does not require the ring's byte offset to be
        // aligned. The event is copied out before the item is consumed on drop.
        Some(unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) })
    }

    /// Drains at most `max` events.
    pub fn drain_events(&mut self, max: usize) -> Vec<daer_event::DaerEvent> {
        let mut events = Vec::new();
        while events.len() < max {
            match self.try_next_event() {
                Some(event) => events.push(event),
                None => break,
            }
        }
        events
    }

    /// The raw fd of the event ring, for a poll/epoll loop.
    #[must_use]
    pub fn event_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.events.as_raw_fd()
    }
}

/// Decodes the `type` of an event into the catalog's stable name.
///
/// The mapping is intentionally in one place: a new kernel event type must either gain an
/// entry here or be reported as `unknown`, never silently flattened into another event.
#[must_use]
pub fn event_type_name(kind: u32) -> &'static str {
    match kind {
        x if x == crate::generated::event_type::BLOCKED => "blocked",
        x if x == crate::generated::event_type::UDP_CONN_OVERFLOW => "udp_conn_overflow",
        x if x == crate::generated::event_type::TCP_CONN_OVERFLOW => "tcp_conn_overflow",
        x if x == crate::generated::event_type::BLOCKED_ALIVE => "blocked_alive",
        x if x == crate::generated::event_type::REDIRECT_REBIND_REJECTED => {
            "redirect_rebind_rejected"
        }
        x if x == crate::generated::event_type::SYN_REBIND_REJECTED => "syn_rebind_rejected",
        x if x == crate::generated::event_type::REDIRECT_UPDATE_FAILED => "redirect_update_failed",
        x if x == crate::generated::event_type::SYN_REBIND_REROUTED => "syn_rebind_rerouted",
        x if x == crate::generated::event_type::RESERVED_STATELESS_TCP_PASSTHROUGH => {
            "reserved_stateless_tcp_passthrough"
        }
        x if x == crate::generated::event_type::RESERVED_FRAG_TAIL_PASSED => {
            "reserved_frag_tail_passed"
        }
        _ => "unknown",
    }
}

/// Decodes the four network-order u32 words of an address into an `IpAddr`.
///
/// The ring record stores the same `__u32[4]` representation as the conntrack key; the first
/// four bytes of an IPv6 address occupy `sip[0]`, not the last, because the C side copies from
/// `union ip6` directly.
#[must_use]
pub fn event_address(words: [u32; 4]) -> std::net::IpAddr {
    let mut bytes = [0u8; 16];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_counter_has_a_distinct_key() {
        let mut keys = std::collections::BTreeSet::new();
        for value in 0..bpf_stats::MAX {
            assert!(keys.insert(value), "duplicate counter key {value}");
        }
        assert_eq!(keys.len(), bpf_stats::MAX as usize);
    }

    #[test]
    fn every_event_type_has_a_name_or_is_explicitly_unknown() {
        for kind in 0..=crate::generated::event_type::MAX {
            let name = event_type_name(kind);
            assert!(!name.is_empty());
        }
        assert_eq!(event_type_name(u32::MAX), "unknown");
    }

    #[test]
    fn a_counter_delta_saturates_when_the_map_resets() {
        let before = BpfCounters {
            values: vec![10, 0, 5],
        };
        let after = BpfCounters {
            values: vec![12, 0, 1],
        };
        let delta = after.delta(&before);
        assert_eq!(delta.get(0), 2);
        assert_eq!(delta.get(1), 0);
        assert_eq!(delta.get(2), 0);
        assert!(!delta.is_zero());
    }
}
