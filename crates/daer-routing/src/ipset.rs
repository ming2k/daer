// SPDX-License-Identifier: AGPL-3.0-only

//! IP prefix sets, compiled into merged intervals.
//!
//! A `geoip:cn` expansion is ~10,000 prefixes and a `geoip:!cn` expansion is larger
//! still. Evaluating that as a linear `prefix.contains(&addr)` scan costs
//! microseconds per flow, and it sits on the hot path twice (destination and
//! source).
//!
//! # Why intervals and not a longest-prefix trie
//!
//! Routing asks exactly one question about a `dip(...)` / `sip(...)` set: *is this
//! address inside it?* It never asks **which** prefix matched, because a prefix set
//! is a predicate, not a lookup table. Longest-prefix matching would therefore be
//! answering a question nobody asks, and answering it expensively: an LPM walk is
//! one hash or comparison per distinct prefix length, which for `geoip.dat` is
//! ~30 hashes per miss.
//!
//! Membership in a union of prefixes is membership in a union of **intervals**, so
//! the set is compiled by sorting the intervals, merging the ones that touch, and
//! answering with one binary search. That is:
//!
//! * **deterministic** — no hasher, no per-process seed, no iteration order;
//! * **compact** — 8 bytes per IPv4 interval, versus a hash bucket per prefix;
//! * **cache-friendly** — a `miss` touches ~13 u32s in a contiguous array, so the
//!   whole working set for `geoip:cn` fits in a few cache lines per probe.
//!
//! Merging also *shrinks* real data: `geoip.dat` files routinely list one /24 per
//! CDN edge, and consecutive edges collapse into a single /16.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// The largest number of prefixes a single match set may carry.
///
/// This is a correctness guard, not a performance knob: a rule that expands past
/// this is almost certainly a mistake (a whole continent pasted into one predicate),
/// and accepting it silently would turn a typo into a multi-megabyte generation.
pub const MAX_PREFIXES: usize = 1 << 22;

/// A compiled set of IP prefixes, as merged intervals.
#[derive(Debug, Clone, Default)]
pub struct IpIndex {
    /// Sorted, non-overlapping, non-adjacent inclusive `[start, end]` ranges.
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    /// The prefixes as written, for diagnostics.
    prefixes: Vec<IpNet>,
    /// Distinct prefixes before merging, for the limit check and for reports.
    len: usize,
}

impl IpIndex {
    /// Compiles `prefixes`.
    ///
    /// # Errors
    ///
    /// Returns an error when the set holds more than [`MAX_PREFIXES`] distinct
    /// prefixes. Duplicates are removed first, so a rule that names the same prefix
    /// through two geodata codes is not rejected for it.
    pub fn new(prefixes: &[IpNet]) -> Result<Self, crate::error::RoutingError> {
        let mut v4: Vec<(u32, u32)> = Vec::new();
        let mut v6: Vec<(u128, u128)> = Vec::new();

        for prefix in prefixes {
            match prefix {
                IpNet::V4(net) => {
                    let length = net.prefix_len();
                    if length > 32 {
                        continue;
                    }
                    v4.push(range_v4(net.addr(), length));
                }
                IpNet::V6(net) => {
                    let length = net.prefix_len();
                    if length > 128 {
                        continue;
                    }
                    v6.push(range_v6(net.addr(), length));
                }
            }
        }

        let total = v4.len() + v6.len();
        if total > MAX_PREFIXES {
            return Err(crate::error::RoutingError::new(format!(
                "a match set with {total} IP prefixes exceeds the limit of {MAX_PREFIXES}; \
                 narrow the rule"
            )));
        }

        Ok(Self {
            v4: merge(v4),
            v6: merge(v6),
            prefixes: prefixes.to_vec(),
            len: total,
        })
    }

    /// True when `addr` falls inside any prefix in the set.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(addr) => self.contains_v4(addr),
            IpAddr::V6(addr) => {
                // An IPv4-mapped address is an IPv4 address in an IPv6 envelope. A
                // `dip(geoip:cn)` rule must still match it, or every dual-stacked
                // flow silently escapes the rule.
                if let Some(mapped) = addr.to_ipv4_mapped() {
                    return self.contains_v4(mapped);
                }
                in_ranges(&self.v6, u128::from(addr))
            }
        }
    }

    fn contains_v4(&self, addr: Ipv4Addr) -> bool {
        if !self.v4.is_empty() && in_ranges(&self.v4, u32::from(addr)) {
            return true;
        }
        // A v4 address can also be named by a v6 set (`::ffff:0:0/96` and friends).
        if !self.v6.is_empty() {
            return in_ranges(&self.v6, u128::from(addr.to_ipv6_mapped()));
        }
        false
    }

    /// The prefixes as written, for diagnostics.
    #[must_use]
    pub fn prefixes(&self) -> &[IpNet] {
        &self.prefixes
    }

    /// How many prefixes the set holds (before interval merging).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many intervals the set compiles to. Exposed for tests that assert the
    /// merge actually merges; not part of the matching contract.
    #[must_use]
    pub fn interval_count(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

/// Sorts and coalesces intervals that overlap or touch.
///
/// Merging adjacent ranges is what makes `a.b.c.0/25` + `a.b.c.128/25` one probe
/// instead of two.
fn merge<T: Ord + Copy + Step>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    if ranges.len() < 2 {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    let mut current = ranges[0];
    for (start, end) in ranges.into_iter().skip(1) {
        // `start <= current.end + 1` means the ranges touch, so they can be one.
        if start <= current.1 || current.1.successor().is_some_and(|next| start <= next) {
            if end > current.1 {
                current.1 = end;
            }
        } else {
            merged.push(current);
            current = (start, end);
        }
    }
    merged.push(current);
    merged
}

/// The one operation `merge` needs beyond `Ord`: the next value, if any.
///
/// Spelled as a trait so IPv4 and IPv6 share one merge without a macro.
trait Step: Sized {
    fn successor(self) -> Option<Self>;
}

impl Step for u32 {
    fn successor(self) -> Option<Self> {
        self.checked_add(1)
    }
}

impl Step for u128 {
    fn successor(self) -> Option<Self> {
        self.checked_add(1)
    }
}

/// One binary search: the last range starting at or before `value`, then a bounds
/// check. Sorted order makes this `O(log n)` with no hashing and no allocation.
fn in_ranges<T: Ord + Copy>(ranges: &[(T, T)], value: T) -> bool {
    // `partition_point` returns the count of ranges whose start is `<= value`, so
    // the candidate is the one just before it.
    let index = ranges.partition_point(|&(start, _)| start <= value);
    index > 0 && value <= ranges[index - 1].1
}

fn range_v4(addr: Ipv4Addr, length: u8) -> (u32, u32) {
    let host_bits = 32u32.saturating_sub(u32::from(length));
    let base = u32::from(addr) & mask_u32(host_bits);
    let end = base | low_mask_u32(host_bits);
    (base, end)
}

fn range_v6(addr: Ipv6Addr, length: u8) -> (u128, u128) {
    let host_bits = 128u32.saturating_sub(u32::from(length));
    let base = u128::from(addr) & mask_u128(host_bits);
    let end = base | low_mask_u128(host_bits);
    (base, end)
}

fn mask_u32(host_bits: u32) -> u32 {
    if host_bits >= 32 {
        0
    } else {
        !0u32 << host_bits
    }
}

fn low_mask_u32(host_bits: u32) -> u32 {
    if host_bits >= 32 {
        !0u32
    } else {
        (1u32 << host_bits) - 1
    }
}

fn mask_u128(host_bits: u32) -> u128 {
    if host_bits >= 128 {
        0
    } else {
        !0u128 << host_bits
    }
}

fn low_mask_u128(host_bits: u32) -> u128 {
    if host_bits >= 128 {
        !0u128
    } else {
        (1u128 << host_bits) - 1
    }
}

impl PartialEq for IpIndex {
    /// Two indexes are equal when they name the same prefixes. The interval layout
    /// is a construction detail; the identity is the set that was compiled.
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.prefixes == other.prefixes
    }
}

impl Eq for IpIndex {}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(prefixes: &[&str]) -> IpIndex {
        let parsed: Vec<IpNet> = prefixes
            .iter()
            .map(|p| p.parse().expect("prefix"))
            .collect();
        IpIndex::new(&parsed).expect("index")
    }

    fn contains(index: &IpIndex, addr: &str) -> bool {
        index.contains(addr.parse().expect("addr"))
    }

    #[test]
    fn matches_a_single_host_prefix() {
        let index = index(&["1.2.3.4/32"]);
        assert!(contains(&index, "1.2.3.4"));
        assert!(!contains(&index, "1.2.3.5"));
    }

    #[test]
    fn matches_a_network_and_its_children() {
        let index = index(&["10.0.0.0/8"]);
        assert!(contains(&index, "10.0.0.1"));
        assert!(contains(&index, "10.255.255.255"));
        assert!(!contains(&index, "11.0.0.0"));
    }

    #[test]
    fn a_default_route_matches_everything_of_that_family() {
        let index = index(&["0.0.0.0/0"]);
        assert!(contains(&index, "1.1.1.1"));
        assert!(contains(&index, "255.255.255.255"));
        assert!(!contains(&index, "::1"));
    }

    #[test]
    fn ipv6_prefixes_match() {
        let index = index(&["2001:db8::/32"]);
        assert!(contains(&index, "2001:db8::1"));
        assert!(contains(&index, "2001:db8:ffff::1"));
        assert!(!contains(&index, "2001:db9::1"));
    }

    #[test]
    fn an_ipv4_mapped_address_matches_the_v4_set() {
        let index = index(&["127.0.0.0/8"]);
        assert!(contains(&index, "127.0.0.1"));
        assert!(
            contains(&index, "::ffff:127.0.0.1"),
            "a dual-stacked flow must not slip past an IPv4 rule"
        );
    }

    #[test]
    fn an_empty_set_matches_nothing() {
        let index = index(&[]);
        assert!(!contains(&index, "1.1.1.1"));
        assert!(index.is_empty());
    }

    #[test]
    fn adjacent_halves_collapse_into_one_interval() {
        let index = index(&["10.0.0.0/25", "10.0.0.128/25"]);
        assert_eq!(
            index.interval_count(),
            1,
            "two touching halves are one range"
        );
        assert!(contains(&index, "10.0.0.1"));
        assert!(contains(&index, "10.0.0.200"));
    }

    #[test]
    fn an_overlapping_more_specific_prefix_stays_correct() {
        let index = index(&["10.0.0.0/8", "10.1.2.3/32"]);
        assert!(contains(&index, "10.1.2.3"));
        assert!(contains(&index, "10.9.9.9"));
        assert_eq!(index.interval_count(), 1, "/32 is inside /8");
    }

    #[test]
    fn distinct_ranges_stay_distinct() {
        let index = index(&["8.8.8.8/32", "10.0.0.0/8", "192.168.1.0/24"]);
        assert_eq!(index.interval_count(), 3);
        assert!(contains(&index, "8.8.8.8"));
        assert!(!contains(&index, "8.8.8.9"));
        assert!(contains(&index, "10.1.1.1"));
        assert!(contains(&index, "192.168.1.7"));
    }

    #[test]
    fn masking_ignores_host_bits_in_the_input() {
        // `10.1.2.3/8` means `10.0.0.0/8`; compilation must mask, not trust.
        let index = index(&["10.1.2.3/8"]);
        assert!(contains(&index, "10.200.1.1"));
    }

    #[test]
    fn deduplication_keeps_the_count_stable() {
        let index = index(&["10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/8"]);
        assert_eq!(index.len(), 3);
        assert_eq!(index.interval_count(), 1);
    }

    #[test]
    fn all_zero_and_all_ones_boundaries_are_exact() {
        let last = index(&["255.255.255.255/32"]);
        assert!(contains(&last, "255.255.255.255"));
        assert!(!contains(&last, "255.255.255.254"));

        let first = index(&["0.0.0.0/32"]);
        assert!(contains(&first, "0.0.0.0"));
        assert!(!contains(&first, "0.0.0.1"));
    }

    #[test]
    fn a_full_ipv6_range_covers_everything() {
        let index = index(&["::/0"]);
        assert!(contains(&index, "::1"));
        assert!(contains(&index, "2001:db8::1"));
        assert!(contains(&index, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    }
}
