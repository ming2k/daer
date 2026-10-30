// SPDX-License-Identifier: AGPL-3.0-only

//! Compiling the lowered match sets into the datapath's own table (ADR-0005).
//!
//! # Why this is not "serialisation"
//!
//! `MatchSet` is a predicate list for [`crate::matcher::first_hit`]; the kernel's
//! `struct match_set` is an operand with a type tag plus a per-entry LPM trie and a
//! per-destination-IP domain bitmap. Translating one into the other is a *compilation*, and
//! its correctness is a statement about two implementations agreeing — not about bytes being
//! laid out in the order the doc comment claims.
//!
//! # The contract this module upholds
//!
//! **The kernel either reproduces userspace's answer exactly, or it defers the flow to
//! userspace. It never invents a third answer.** Every function here is shaped by that:
//!
//! * [`compile`] returns a [`Policy`] whose [`Policy::equivalent`] is computed from the sets
//!   themselves, never assumed;
//! * when a construct cannot be represented, the policy is not "the part of the table that
//!   fit" — it is a [`Policy::defer`], a one-entry table whose `MatchType_Fallback` sends every
//!   flow to the control plane;
//! * a partially encoded table is not a representable value of this module at all, which is
//!   what makes "half a policy silently published" impossible rather than merely unlikely.
//!
//! # What cannot be represented, and why
//!
//! | Construct | Kernel mechanism | Why it is absent here |
//! | --- | --- | --- |
//! | `domain(...)` | `domain_routing_map`, a bitmap keyed by **destination IP** | the bitmap is derived from DNS answers, which daer does not feed the kernel yet |
//! | `pname(...)` | `cookie_pid_map`, keyed by socket cookie | daer does not populate that map |
//! | > `MAX_MATCH_SET_LEN` sets | `routing_map` is a fixed `ARRAY` | the bound is the object's |
//!
//! The first two are not limitations of the encoding; they are tables the *control plane* has
//! to maintain. Deferring is therefore the honest answer, and it costs a userspace relay hop
//! only on the configurations that need it.

use std::net::IpAddr;

use daer_common::{MacAddr, PortRange};
use daer_ebpf::abi::{
    LpmKey, MAX_MATCH_SET_LEN, MatchSet as KernelMatchSet, match_type, outbound as kernel_outbound,
};
use ipnet::IpNet;

use crate::matcher::{MatchSet, MatchValue};
use crate::outbound::{MatchTarget, Outbound};
use crate::values::TASK_COMM_LEN;

/// One entry of `domain_routing_map`'s value: a bitmap of match-set indices.
///
/// Not encoded today (see the module docs), but named here because the deferral reason cites
/// it and because the follow-up lands in this module.
pub const DOMAIN_BITMAP_WORDS: usize = MAX_MATCH_SET_LEN / 32;

/// The kernel-side routing table for one slot.
///
/// Invariant, asserted at construction: `entries.len()` is either `1` (the defer entry) or the
/// full number of lowered match sets. There is no value of this type that holds a prefix of the
/// policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The `struct match_set` entries, in lowered order, keyed from `slot * MAX + index`.
    pub entries: Vec<KernelMatchSet>,
    /// The LPM tries, one per entry that needs one, as `(index, keys)`.
    ///
    /// The datapath addresses a trie by the match-set index, so a set that names an LPM
    /// predicate must have exactly one entry here.
    pub lpms: Vec<(u32, Vec<LpmKey>)>,
    /// The id → group mapping, so a kernel verdict can be named in a diagnostic.
    pub outbounds: OutboundIds,
    /// True when the kernel reproduces userspace's verdict for every flow.
    pub equivalent: bool,
    /// Why not, when [`Self::equivalent`] is false.
    pub reasons: Vec<DeferReason>,
}

/// Why the table cannot reproduce userspace's answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferReason {
    /// A `domain(...)` predicate exists: it needs `domain_routing_map`, which is IP-keyed and
    /// derived from DNS answers daer does not yet maintain.
    Domain { rule: usize },
    /// A `pname(...)` predicate exists: it needs `cookie_pid_map`, which daer does not populate.
    ProcessName { rule: usize },
    /// The program lowers to more sets than one slot can hold.
    TooManySets { sets: usize, bound: usize },
    /// An outbound id exhausted the datapath's user-defined range (`2..=251`).
    TooManyOutbounds { count: usize },
    /// A predicate the kernel has no `MatchType` for.
    Unsupported { rule: usize, what: String },
}

impl std::fmt::Display for DeferReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain { rule } => write!(
                f,
                "rule {rule} uses domain(...) and domain_routing_map is not maintained by this \
                 build, so the kernel cannot evaluate it"
            ),
            Self::ProcessName { rule } => write!(
                f,
                "rule {rule} uses pname(...) and cookie_pid_map is not populated by this build, \
                 so the kernel cannot evaluate it"
            ),
            Self::TooManySets { sets, bound } => write!(
                f,
                "the program lowers to {sets} match sets and one routing slot holds {bound}"
            ),
            Self::TooManyOutbounds { count } => write!(
                f,
                "{count} distinct outbounds exceed the datapath's {} user-defined ids",
                usize::from(kernel_outbound::LAST_GROUP - kernel_outbound::FIRST_GROUP) + 1
            ),
            Self::Unsupported { rule, what } => {
                write!(
                    f,
                    "rule {rule} uses {what}, which the datapath cannot match"
                )
            }
        }
    }
}

impl Policy {
    /// A table whose single entry hands every flow to the control plane.
    ///
    /// This is the only value returned when the compilation is not faithful, and it is what
    /// turns "the kernel cannot represent this rule" into a performance choice instead of a
    /// leak or an outage.
    #[must_use]
    pub fn defer(reasons: Vec<DeferReason>) -> Self {
        debug_assert!(!reasons.is_empty(), "a defer policy always has a reason");
        let entries = vec![KernelMatchSet {
            operand: [0; 16],
            negated: false,
            kind: match_type::FALLBACK,
            // `Fallback` matches unconditionally, and the reserved id is what makes the
            // datapath hand the flow to userspace instead of proxying it itself.
            outbound: kernel_outbound::CONTROL_PLANE_ROUTING,
            must: false,
            mark: 0,
        }];
        Self {
            entries,
            lpms: Vec::new(),
            outbounds: OutboundIds::default(),
            equivalent: false,
            reasons,
        }
    }

    /// True when the datapath decides the whole program in the kernel.
    #[must_use]
    pub fn is_split(&self) -> bool {
        self.equivalent
    }

    /// The rule count the datapath bounds-checks against.
    #[must_use]
    pub fn rules_len(&self) -> u32 {
        u32::try_from(self.entries.len()).unwrap_or(u32::MAX)
    }

    /// The key of entry `index` in slot `slot`, as the datapath computes it.
    #[must_use]
    pub fn key(slot: u32, index: u32) -> u32 {
        slot * MAX_MATCH_SET_LEN as u32 + index
    }

    /// The LPM index of entry `index` in slot `slot`, as the datapath computes it.
    ///
    /// The same arithmetic as [`Self::key`]: `lpm_array_map` and `routing_map` index their
    /// slots identically, which is what lets the datapath look a trie up from a match-set index
    /// without a second field. The C's `MAX_LPM_NUM` is
    /// `ROUTING_EPOCH_SLOT_NUM * MAX_MATCH_SET_LEN + 8`, so the two bounds differ by a constant
    /// and the shared index is in range for both.
    #[must_use]
    pub fn lpm_key(slot: u32, index: u32) -> u32 {
        Self::key(slot, index)
    }
}

/// Assigns the outbound ids the kernel table uses.
///
/// The datapath's user-defined range is `2..=251` (`OUTBOUND_DIRECT = 0`,
/// `OUTBOUND_BLOCK = 1`, `0xFC..` reserved for its own markers), so the mapping is not the
/// userspace name — it is a dense index into that window. The reverse map is kept so a
/// diagnostic can name the group a kernel verdict selected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundIds {
    names: Vec<String>,
}

impl OutboundIds {
    /// The id for `outbound`, allocating one on first use.
    ///
    /// `direct` and `block` are the datapath's own constants and consume no id.
    fn id_for(&mut self, outbound: &Outbound) -> Option<u8> {
        if let Some(id) = Self::reserved(&outbound.name) {
            return Some(id);
        }
        let name = &*outbound.name;
        if let Some(position) = self.names.iter().position(|known| known == name) {
            let id = kernel_outbound::FIRST_GROUP as usize + position;
            return u8::try_from(id).ok();
        }
        let id = kernel_outbound::FIRST_GROUP as usize + self.names.len();
        if id > usize::from(kernel_outbound::LAST_GROUP) {
            return None;
        }
        self.names.push(name.to_owned());
        u8::try_from(id).ok()
    }

    /// The datapath's own id for a reserved outbound name, or `None` for a group.
    fn reserved(name: &str) -> Option<u8> {
        match name {
            "direct" => Some(kernel_outbound::DIRECT),
            "block" => Some(kernel_outbound::BLOCK),
            _ => None,
        }
    }

    /// Allocates an id for `outbound`, for tests that assert the window's edges.
    ///
    /// Production code reaches the same path through [`compile`]; exposing it is what lets a
    /// test prove the window does not wrap instead of assuming it.
    #[doc(hidden)]
    #[must_use]
    pub fn id_for_test(&mut self, outbound: &Outbound) -> Option<u8> {
        self.id_for(outbound)
    }

    /// Builds a table from outbound names in assignment order.
    ///
    /// The test that cross-checks the kernel table against the userspace evaluator has to
    /// reproduce the id assignment independently; if it used [`compile`]'s own map, an
    /// off-by-one in the assignment would cancel out on both sides and prove nothing.
    #[must_use]
    pub fn from_names(names: Vec<String>) -> Self {
        Self { names }
    }

    /// The name an id stands for, for diagnostics.
    ///
    /// Returns `None` for the reserved ids, which name a datapath behaviour rather than a
    /// configured group.
    #[must_use]
    pub fn name(&self, id: u8) -> Option<&str> {
        if !(kernel_outbound::FIRST_GROUP..=kernel_outbound::LAST_GROUP).contains(&id) {
            return None;
        }
        self.names
            .get(usize::from(id - kernel_outbound::FIRST_GROUP))
            .map(String::as_str)
    }

    /// Every outbound this table assigned an id to, in id order.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }
}

/// Compiles `sets` into a kernel table.
///
/// `sets` is the output of [`crate::builder::RecordingSink`] for the same program the userspace
/// evaluator uses, so a divergence between this function and
/// [`crate::matcher::first_hit`] is a real defect rather than a configuration choice.
///
/// `fallback` is the outbound the program applies when no rule fires. It is emitted as a
/// trailing `MatchType_Fallback` entry, because the C has no "no rule hit" path that is not an
/// error: without an explicit fallback set the last thing `route()` can do is `-EPERM`, which
/// every caller converts into `TC_ACT_SHOT`.
#[must_use]
pub fn compile(sets: &[MatchSet], fallback: &Outbound, rule_of: impl Fn(usize) -> usize) -> Policy {
    let mut reasons = Vec::new();

    // The fallback is one extra entry, so the bound applies to `sets.len() + 1`.
    let total = sets.len() + 1;
    if total > MAX_MATCH_SET_LEN {
        reasons.push(DeferReason::TooManySets {
            sets: total,
            bound: MAX_MATCH_SET_LEN,
        });
    }
    for (index, set) in sets.iter().enumerate() {
        match &set.value {
            MatchValue::Domain(_) => reasons.push(DeferReason::Domain {
                rule: rule_of(index),
            }),
            MatchValue::ProcessName(_) => reasons.push(DeferReason::ProcessName {
                rule: rule_of(index),
            }),
            // Every other predicate has a `MatchType`, so it is representable. Listed
            // explicitly rather than with `_ => {}` so adding a `MatchValue` variant is a
            // compile error here instead of a silently deferred rule.
            MatchValue::IpSet(_)
            | MatchValue::SourceIpSet(_)
            | MatchValue::Mac(_)
            | MatchValue::Port(_)
            | MatchValue::SourcePort(_)
            | MatchValue::L4Proto(_)
            | MatchValue::IpVersion(_)
            | MatchValue::Dscp(_) => {}
        }
    }

    if !reasons.is_empty() {
        return Policy::defer(reasons);
    }

    let mut ids = OutboundIds::default();
    let mut entries = Vec::with_capacity(total);
    let mut lpms: Vec<(u32, Vec<LpmKey>)> = Vec::new();

    for (index, set) in sets.iter().enumerate() {
        let index = u32::try_from(index).expect("bounded by MAX_MATCH_SET_LEN above");
        match encode_set(set, index, &mut ids, &mut lpms) {
            Some(entry) => entries.push(entry),
            None => {
                reasons.push(DeferReason::Unsupported {
                    rule: rule_of(index as usize),
                    what: format!("{:?}", set.value),
                });
                return Policy::defer(reasons);
            }
        }
    }

    // The fallback entry: `MatchType_Fallback` matches unconditionally.
    let Some(fallback_id) = ids.id_for(fallback) else {
        return Policy::defer(vec![DeferReason::TooManyOutbounds {
            count: ids.names().len() + 1,
        }]);
    };
    entries.push(KernelMatchSet {
        operand: [0; 16],
        negated: false,
        kind: match_type::FALLBACK,
        outbound: fallback_id,
        must: fallback.must,
        mark: fallback.mark,
    });

    Policy {
        entries,
        lpms,
        outbounds: ids,
        equivalent: true,
        reasons: Vec::new(),
    }
}

/// Encodes one match set, appending its LPM keys when it needs a trie.
///
/// Returns `None` for a value with no `MatchType`, which [`compile`] turns into a deferral
/// rather than a skip. A skipped set would make a rule match *more* than it says.
fn encode_set(
    set: &MatchSet,
    index: u32,
    ids: &mut OutboundIds,
    lpms: &mut Vec<(u32, Vec<LpmKey>)>,
) -> Option<KernelMatchSet> {
    let (outbound, must, mark) = target_of(&set.target, ids)?;

    // The `LogicalAnd` marker means "this set ends a function's operand list inside a rule",
    // which the C expresses with `OUTBOUND_LOGICAL_OR` on the subrule and no terminator. Only
    // `LogicalOr` needs its own encoding, and it must not carry the outbound id.
    let (kind, operand) = match &set.value {
        MatchValue::IpSet(prefixes) => {
            push_lpm(index, prefixes.prefixes(), lpms);
            (match_type::IP_SET, index.to_ne_bytes_16())
        }
        MatchValue::SourceIpSet(prefixes) => {
            push_lpm(index, prefixes.prefixes(), lpms);
            (match_type::SOURCE_IP_SET, index.to_ne_bytes_16())
        }
        MatchValue::Mac(macs) => {
            let keys = macs.iter().copied().map(LpmKey::lookup_mac).collect();
            lpms.push((index, keys));
            (match_type::MAC, index.to_ne_bytes_16())
        }
        MatchValue::Port(range) => (match_type::PORT, port_operand(*range)),
        MatchValue::SourcePort(range) => (match_type::SOURCE_PORT, port_operand(*range)),
        MatchValue::L4Proto(mask) => {
            // The C compares `value & mask`, and its `L4ProtoType` uses the same bit values
            // (`TCP = 1`, `UDP = 2`), so the userspace mask travels unchanged.
            let mut operand = [0u8; 16];
            operand[0] = mask.0;
            (match_type::L4_PROTO, operand)
        }
        MatchValue::IpVersion(mask) => {
            let mut operand = [0u8; 16];
            operand[0] = mask.0;
            (match_type::IP_VERSION, operand)
        }
        MatchValue::Dscp(value) => {
            let mut operand = [0u8; 16];
            operand[0] = *value;
            (match_type::DSCP, operand)
        }
        MatchValue::ProcessName(_) | MatchValue::Domain(_) => return None,
    };

    Some(KernelMatchSet {
        operand,
        negated: set.negated,
        kind,
        outbound,
        must,
        mark,
    })
}

/// The outbound id, `must` flag and mark a target encodes to.
///
/// A logical marker carries no outbound: the C reads `OUTBOUND_LOGICAL_OR`/`_AND` from the same
/// byte, so the id field *is* the marker.
fn target_of(target: &MatchTarget, ids: &mut OutboundIds) -> Option<(u8, bool, u32)> {
    match target {
        MatchTarget::LogicalOr { mark, must } => Some((kernel_outbound::LOGICAL_OR, *must, *mark)),
        MatchTarget::LogicalAnd { mark, must } => {
            Some((kernel_outbound::LOGICAL_AND, *must, *mark))
        }
        MatchTarget::Outbound(outbound) => ids
            .id_for(outbound)
            .map(|id| (id, outbound.must, outbound.mark)),
    }
}

/// The `port_range` operand: two `__u16`s, native order, at offset 0.
fn port_operand(range: PortRange) -> [u8; 16] {
    let mut operand = [0u8; 16];
    operand[0..2].copy_from_slice(&range.start.to_ne_bytes());
    operand[2..4].copy_from_slice(&range.end.to_ne_bytes());
    operand
}

/// Replaces the entry's trie with the one for `prefixes`.
///
/// One key per prefix, never per *merged interval*: a trie holds prefixes, and expanding a
/// merged range back into prefixes would need a walk over up to 2^32 addresses.
fn push_lpm(index: u32, prefixes: &[IpNet], lpms: &mut Vec<(u32, Vec<LpmKey>)>) {
    let keys = prefixes
        .iter()
        .map(|prefix| match prefix {
            IpNet::V4(net) => LpmKey::prefix_ipv4(*net),
            IpNet::V6(net) => LpmKey::prefix_ipv6(*net),
        })
        .collect();
    lpms.push((index, keys));
}

/// A 16-byte operand holding `index` in its first four bytes.
trait ToNeBytes16 {
    fn to_ne_bytes_16(self) -> [u8; 16];
}

impl ToNeBytes16 for u32 {
    fn to_ne_bytes_16(self) -> [u8; 16] {
        let mut operand = [0u8; 16];
        operand[0..4].copy_from_slice(&self.to_ne_bytes());
        operand
    }
}

/// The 16-byte datapath key of an address, for the interpreter in `tests/`.
///
/// Exported because the test has to ask the same question the kernel asks, and duplicating the
/// IPv4-in-the-last-four-bytes convention there would defeat the purpose of the test.
#[must_use]
pub fn lookup_key(addr: IpAddr) -> LpmKey {
    match addr {
        IpAddr::V4(addr) => LpmKey::lookup_ipv4(addr),
        IpAddr::V6(addr) => LpmKey::lookup_ipv6(addr),
    }
}

/// The `TASK_COMM_LEN` the datapath uses, re-exported so callers do not reach into
/// `daer-routing::values` for an ABI constant.
pub const KERNEL_TASK_COMM_LEN: usize = TASK_COMM_LEN;

/// True when `macs` holds the value the datapath would see for a flow with no MAC.
///
/// The lowering already appends [`MacAddr::UNSPECIFIED`] to a negated set so that a negated
/// MAC rule catches localhost traffic; this exists so the test corpus can generate that case
/// explicitly instead of relying on it to be exercised by accident.
#[must_use]
pub fn is_unspecified_mac(mac: MacAddr) -> bool {
    mac.is_unspecified()
}
