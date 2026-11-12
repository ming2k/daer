// SPDX-License-Identifier: AGPL-3.0-only

//! Kernel-side ABI shared with `ebpf/kern/datapath.bpf.c`.
//!
//! Both sides are daer's own source (ADR-0020), so these types have to stay
//! byte-compatible with the C declarations that live in the same repository, and the
//! assertions at the bottom of the module fail the build if they ever drift. The C
//! declarations are the ones in `ebpf/kern/datapath.bpf.c`; the doc blocks below quote them
//! so a reader can compare without opening a second file.

/// Key of the connection-tracking maps (`fast_sock`, `tcp_offload_pause`,
/// `conn_state_map`, ...).
///
/// ```c
/// struct tuples_key {
///     union ip6 sip;
///     union ip6 dip;
///     __u16 sport;
///     __u16 dport;
///     __u8 l4proto;
/// };
/// ```
///
/// `union ip6` holds two `__be64`, so the C alignment is 8 and the size is 40.
#[repr(C, align(8))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TuplesKey {
    pub sip: [u8; 16],
    pub dip: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
}

impl std::fmt::Debug for TuplesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuplesKey")
            .field("sip", &std::net::Ipv6Addr::from(self.sip))
            .field("dip", &std::net::Ipv6Addr::from(self.dip))
            .field("sport", &self.sport)
            .field("dport", &self.dport)
            .field("l4proto", &self.l4proto)
            .finish()
    }
}

/// ```c
/// struct port_range {
///     __u16 port_start;
///     __u16 port_end;
/// };
/// ```
///
/// Rust field names differ (`start`/`end`); the two `u16` layout matches.
pub use daer_common::net::PortRange;

/// Runtime parameters written to the `PARAM` global before load.
///
/// The Rust fields are named for what they carry, and only their order and size
/// matter — `repr(C)` makes the layout positional.
///
/// ```c
/// struct daer_param {
///     __u32 control_plane_pid;
///     __u32 daer0_ifindex;
///     __u32 daer_netns_id;
///     __u8 daer0peer_mac[6];
///     __u8 padding_after_mac[2];
///     __u8 use_redirect_peer;
///     __u8 has_bpf_get_current_task;
///     __u16 datapath_generation;
///     __u32 daer_socket_mark;
/// };
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuntimeParam {
    pub control_plane_pid: u32,
    /// ifindex of the local device the datapath redirects through.
    pub device_ifindex: u32,
    /// Kernel netns id of the network namespace, or 0 when unknown.
    pub netns_id: u32,
    /// MAC of the device's peer end.
    pub peer_mac: [u8; 6],
    pub padding_after_mac: [u8; 2],
    pub use_redirect_peer: bool,
    pub has_bpf_get_current_task: bool,
    pub datapath_generation: u16,
    /// Socket mark daer applies to its own outbound traffic.
    pub socket_mark: u32,
}

const _: () = assert!(std::mem::size_of::<RuntimeParam>() == 28);
const _: () = assert!(std::mem::align_of::<RuntimeParam>() == 4);

impl RuntimeParam {
    /// The bytes written over the `PARAM` global.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `RuntimeParam` is `repr(C)` and contains only integers and byte
        // arrays, so every bit pattern is a valid value and the struct has no
        // padding other than the explicit `padding_after_mac` field.
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(self).cast::<u8>(),
                std::mem::size_of::<Self>(),
            )
        }
    }
}

/// The largest number of `match_set` entries one routing slot can hold.
///
/// ```c
/// #ifndef MAX_MATCH_SET_LEN
/// #define MAX_MATCH_SET_LEN (32 * 32) // Should be sync with common/consts/ebpf_sync_spec.json.
/// #endif
/// ```
///
/// The object is compiled with `-DMAX_MATCH_SET_LEN=…` (see `cargo xtask ebpf`, whose
/// default is 1024), so this value is a **build-time agreement**, not a constant of the ABI.
/// `tests/object.rs` reads the real bound out of the compiled object's `routing_map`
/// `max_entries` and fails when the two disagree; that check is what keeps a rebuild with a
/// different `-D` from silently truncating a rule table at load time.
pub const MAX_MATCH_SET_LEN: usize = 1024;

/// How many routing slots the datapath keeps (double-buffering, ADR-0004).
pub const ROUTING_EPOCH_SLOTS: u32 = 2;

/// The width of one `struct match_set` in the kernel's layout.
///
/// Taken from the generated layout table rather than written here, so it cannot disagree
/// with what `ebpf/abi.toml` declares and what the C compiles to (ADR-0021).
pub const MATCH_SET_SIZE: usize = crate::generated::layout::match_set::SIZE;

/// The width of one `struct lpm_key` in the kernel's layout.
pub const LPM_KEY_SIZE: usize = crate::generated::layout::lpm_key::SIZE;

/// The `enum MatchType` discriminants.
///
/// Re-exported from the generated module: the enum is `packed`, so it occupies **one byte**
/// inside `match_set`, not four. Writing it as a `u32` would shift `outbound`, `must` and
/// `mark` and produce a table whose every entry the datapath misreads — which is why the
/// encoder builds bytes explicitly rather than casting a `repr(C)` struct.
pub use crate::generated::match_type;

/// The reserved outbound ids the datapath interprets itself.
///
/// Re-exported from the generated module; `OUTBOUND_LOGICAL_MASK` is the bit mask that
/// isolates the logical markers, which is why `OR` and `AND` share their high bits.
pub use crate::generated::outbound;

/// One `struct match_set`, in the object's byte layout.
///
/// ```c
/// struct match_set {
///     union {
///         __u8 __value[16];
///         __u32 index;                       // IpSet/SourceIpSet: the LPM trie index
///         struct port_range port_range;
///         enum L4ProtoType l4proto_type;
///         enum IpVersionType ip_version;
///         __u32 pname[TASK_COMM_LEN / 4];    // 4 words, 16 bytes
///         __u8 dscp;
///     };                                     // offset 0, 16 bytes
///     __u8 not;                              // offset 16
///     enum MatchType type;                   // offset 17, ONE byte (the enum is packed)
///     __u8 outbound;                         // offset 18
///     __u8 must;                             // offset 19
///     __u32 mark;                            // offset 20
/// };                                         // 24 bytes, align 4
/// ```
///
/// The union means a set carries exactly one operand, which is why this type has one
/// `operand` field and a `kind` that says how to read it — the C's `type` tag and the union
/// member are the same fact, and separating them here would let them disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchSet {
    /// The union: 16 bytes, interpreted according to [`Self::kind`].
    pub operand: [u8; 16],
    /// Negation of the subrule (`not`).
    pub negated: bool,
    /// The `enum MatchType` discriminant.
    pub kind: u8,
    /// The outbound id, or one of [`outbound`]'s reserved values.
    pub outbound: u8,
    /// The `must` flag.
    pub must: bool,
    /// The routing mark.
    pub mark: u32,
}

impl MatchSet {
    /// The object's bytes for this set, in order.
    ///
    /// Written field by field rather than by casting `self`: the struct is `repr(C)` with an
    /// `align(4)` tail, so a cast would depend on Rust's padding matching clang's — and the
    /// explicit form is the only one that cannot be quietly wrong.
    #[must_use]
    pub fn to_bytes(self) -> [u8; MATCH_SET_SIZE] {
        let mut bytes = [0u8; MATCH_SET_SIZE];
        bytes[0..16].copy_from_slice(&self.operand);
        bytes[16] = u8::from(self.negated);
        bytes[17] = self.kind;
        bytes[18] = self.outbound;
        bytes[19] = u8::from(self.must);
        bytes[20..24].copy_from_slice(&self.mark.to_ne_bytes());
        bytes
    }

    /// The `port_range` operand, if this set is a port predicate.
    #[must_use]
    pub fn port_range(&self) -> Option<(u16, u16)> {
        if self.kind != match_type::PORT && self.kind != match_type::SOURCE_PORT {
            return None;
        }
        let start = u16::from_ne_bytes([self.operand[0], self.operand[1]]);
        let end = u16::from_ne_bytes([self.operand[2], self.operand[3]]);
        Some((start, end))
    }

    /// The LPM index operand, if this set names one.
    #[must_use]
    pub fn lpm_index(&self) -> Option<u32> {
        match self.kind {
            match_type::IP_SET | match_type::SOURCE_IP_SET | match_type::MAC => {
                Some(u32::from_ne_bytes([
                    self.operand[0],
                    self.operand[1],
                    self.operand[2],
                    self.operand[3],
                ]))
            }
            _ => None,
        }
    }
}

/// One `struct lpm_key`, the key of every per-match-set LPM trie.
///
/// ```c
/// struct lpm_key {
///     __u32 prefixlen;   // bits, and it must come first: the map ABI requires it
///     __be32 data[4];    // 16 bytes, IPv6-shaped even for IPv4
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpmKey {
    /// How many leading bits of [`Self::data`] are significant.
    pub prefix_len: u32,
    /// The 16 address bytes, in the datapath's own convention.
    ///
    /// The datapath builds these keys from `tuples.five.{s,d}ip.u6_addr32` (16 bytes for both
    /// families) and searches with `prefixlen = 128`. So the convention is *not* "IPv4
    /// addresses are 32 bits": an IPv4 address occupies the **last four bytes** with the first
    /// twelve zero, and to represent a *prefix* the entry's `prefix_len` must be
    /// `96 + prefix_len`, which is the only form an in-kernel longest-prefix match answers
    /// correctly for a fixed-width lookup key.
    pub data: [u8; 16],
}

impl LpmKey {
    /// The object's bytes for this key.
    #[must_use]
    pub fn to_bytes(self) -> [u8; LPM_KEY_SIZE] {
        let mut bytes = [0u8; LPM_KEY_SIZE];
        bytes[0..4].copy_from_slice(&self.prefix_len.to_ne_bytes());
        bytes[4..20].copy_from_slice(&self.data);
        bytes
    }

    /// The key that **matches** an IPv4 address: full width, no prefix.
    #[must_use]
    pub fn lookup_ipv4(addr: std::net::Ipv4Addr) -> Self {
        let mut data = [0u8; 16];
        data[12..16].copy_from_slice(&addr.octets());
        // The lookup is always a full-width key: a shorter one would match entries that are
        // *less* specific than intended, because the trie compares the shorter prefix.
        Self {
            prefix_len: 128,
            data,
        }
    }

    /// The key that **matches** an IPv6 address.
    #[must_use]
    pub fn lookup_ipv6(addr: std::net::Ipv6Addr) -> Self {
        Self {
            prefix_len: 128,
            data: addr.octets(),
        }
    }

    /// The key that **matches** a source MAC.
    ///
    /// The C builds `mac_be` as
    /// `{0, 0, htonl(m0 << 8 | m1), htonl(m2 << 24 | m3 << 16 | m4 << 8 | m5)}` and searches
    /// with `prefixlen = 128`, so in memory the MAC occupies bytes 10..16 of the 16-byte word:
    /// `data[8..10] == 0` and then the six address bytes, big-endian throughout.
    #[must_use]
    pub fn lookup_mac(addr: daer_common::MacAddr) -> Self {
        let mut data = [0u8; 16];
        data[10..16].copy_from_slice(&addr.0);
        Self {
            prefix_len: 128,
            data,
        }
    }

    /// The entry that covers an IPv4 **prefix**.
    ///
    /// `prefix + 96` because the address sits in the last four bytes: an entry inserted as
    /// `1.2.3.0/24` must match any `…1.2.3.x`, and the trie compares only the first
    /// `prefix_len` bits.
    #[must_use]
    pub fn prefix_ipv4(net: ipnet::Ipv4Net) -> Self {
        let mut data = [0u8; 16];
        data[12..16].copy_from_slice(&net.network().octets());
        Self {
            prefix_len: 96 + u32::from(net.prefix_len()),
            data,
        }
    }

    /// The entry that covers an IPv6 **prefix**.
    #[must_use]
    pub fn prefix_ipv6(net: ipnet::Ipv6Net) -> Self {
        Self {
            prefix_len: u32::from(net.prefix_len()),
            data: net.network().octets(),
        }
    }
}

const _: () = assert!(std::mem::size_of::<TuplesKey>() == 40);
const _: () = assert!(std::mem::align_of::<TuplesKey>() == 8);
const _: () = assert!(std::mem::size_of::<PortRange>() == 4);
const _: () = assert!(MATCH_SET_SIZE == 24);
const _: () = assert!(LPM_KEY_SIZE == 20);

/// The kernel's routing decision for one flow, as `routing_handoff_map` carries it.
///
/// ```c
/// struct routing_result {
///     __u32 mark;
///     __u8 must;
///     __u8 mac[6];
///     __u8 outbound;
///     __u8 pname[TASK_COMM_LEN];
///     __u32 pid;
///     __u8 dscp;
///     __u8 routing_epoch_slot;
///     __u16 datapath_generation;
/// };
/// struct routing_handoff_entry {
///     __u64 last_seen_ns;
///     struct routing_result result;
/// };
/// ```
///
/// # Why userspace reads this
///
/// The datapath observes three things userspace cannot recover from the accepted socket: the
/// client's **source MAC**, the packet's **DSCP**, and — through the cgroup hooks — the
/// **process name** and pid that opened the flow. When the kernel defers a flow to the
/// control plane (any configuration with a `domain(...)` rule, see ADR-0011), it publishes
/// this entry first. A userspace evaluation that did not read it had those three fields
/// zeroed, so every `mac(...)`, `dscp(...)`, and `pname(...)` rule after the partition
/// boundary silently matched nothing — the rule was accepted, lowered, and inert.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoutingResult {
    /// `mark` the rule attached to the outbound.
    pub mark: u32,
    /// Whether the outbound is `must`.
    pub must: u8,
    /// The client's source MAC, as the packet carried it.
    pub mac: [u8; 6],
    /// The selected outbound id.
    pub outbound: u8,
    /// `TASK_COMM_LEN` bytes, NUL-padded.
    pub pname: [u8; TASK_COMM_LEN],
    /// The pid that opened the flow, or `0` when the cgroup hooks are not attached.
    pub pid: u32,
    /// The packet's DSCP.
    pub dscp: u8,
    /// The routing epoch slot, encoded so `0` means unknown (see `datapath.bpf.c`).
    pub routing_epoch_slot: u8,
    /// Which datapath generation wrote this entry.
    pub datapath_generation: u16,
}

/// `TASK_COMM_LEN`, the size of the kernel's `pname` field.
///
/// Derived from the generated `routing_result` layout: `pname` is 16 bytes there, and the
/// kernel's `TASK_COMM_LEN` is what that field is sized from.
pub const TASK_COMM_LEN: usize = 16;

const _: () = assert!(
    TASK_COMM_LEN == crate::generated::layout::routing_result::SIZE - 20,
    "TASK_COMM_LEN must match the pname field width the datapath declares"
);

/// One `routing_handoff_map` value.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoutingHandoff {
    /// `bpf_ktime_get_ns()` at the write, used to expire a stale entry.
    pub last_seen_ns: u64,
    /// The decision the kernel reached.
    pub result: RoutingResult,
}

// Verified against the C with `cc -c` and `offsetof`: `mark` is 4 bytes at 0, `must` at 4,
// `mac` at 5, `outbound` at 11, `pname` at 12, `pid` at 28, `dscp` at 32, the slot at 33,
// and the generation at 34, giving 36 with 4-byte alignment. The handoff entry pads the
// result to offset 8, so the whole value is 48.
const _: () = assert!(std::mem::size_of::<RoutingResult>() == 36);
const _: () = assert!(std::mem::align_of::<RoutingResult>() == 4);
const _: () = assert!(std::mem::size_of::<RoutingHandoff>() == 48);
const _: () = assert!(std::mem::align_of::<RoutingHandoff>() == 8);

impl RoutingHandoff {
    /// Decodes a map value, or `None` when the width is not this struct's.
    ///
    /// A wrong width is not a panic: it means the object and this crate disagree, which the
    /// caller reports once at startup rather than aborting a flow.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != std::mem::size_of::<Self>() {
            return None;
        }
        // SAFETY: the length is exactly `size_of::<Self>()` and every field is an integer or
        // a byte array, so any bit pattern is a valid value.
        Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_param_layout_matches_the_c_struct() {
        let param = RuntimeParam {
            control_plane_pid: 12345,
            datapath_generation: 7,
            peer_mac: [1, 2, 3, 4, 5, 6],
            ..RuntimeParam::default()
        };
        let bytes = param.as_bytes();
        assert_eq!(bytes.len(), 28);
        // Field offsets, asserted as little-endian byte ranges.
        assert_eq!(&bytes[0..4], &12345u32.to_le_bytes());
        assert_eq!(&bytes[12..18], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&bytes[22..24], &7u16.to_le_bytes());
        assert_eq!(&bytes[24..28], &0u32.to_le_bytes());
    }

    #[test]
    fn tuples_key_round_trips_ipv4_as_ipv6() {
        let mut key = TuplesKey {
            sip: [0; 16],
            dip: [0; 16],
            sport: 1024,
            dport: 443,
            l4proto: 6,
        };
        key.sip[10] = 0xff;
        key.sip[11] = 0xff;
        key.sip[12..].copy_from_slice(&[192, 168, 1, 2]);
        assert_eq!(
            std::net::Ipv6Addr::from(key.sip).to_string(),
            "::ffff:192.168.1.2"
        );
    }
}
