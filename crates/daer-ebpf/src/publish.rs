// SPDX-License-Identifier: AGPL-3.0-only

//! The `aya` side of [`MapWriter`](crate::epoch::MapWriter): the syscalls behind a publish.
//!
//! `epoch` owns the *sequence* and is tested without a kernel; this module is the thin layer
//! that turns each step into a map update. It exists because the sequence was complete and
//! tested while **nothing called it** — the routing tables the datapath reads were never
//! written, so an attached datapath had no policy to match on.
//!
//! # Why the widths are checked here
//!
//! `active_routing_epoch_map` and `routing_meta_map` are both `ARRAY<u32, u32>`, as the C
//! declares them. An earlier version of `epoch` wrote a 16-byte `{generation, timestamp}`
//! stamp into `routing_meta_map` and spelled both map names differently from the object, so
//! the first real publish would have failed with "map not found" or a rejected value size.
//! The names now come from [`crate::names`], and the value width is rejected at the call.
//!
//! # Why `RefCell`
//!
//! `aya`'s `Array::set` takes `&mut self`, while [`MapWriter`] hands out `&self`: the
//! sequence is a pure ordering of writes and must be callable from a `&Daemon`. A `RefCell`
//! bridges the two. Publishing happens on one thread, so a borrow conflict would be a bug in
//! the sequence rather than contention — and a panic there is the right report.

use std::cell::RefCell;

use aya::Ebpf;
use aya::maps::{Array, MapData};

use crate::epoch::{ACTIVE_SLOT_MAP, MapWriter, STAMP_MAP, Slot};

/// A [`MapWriter`] over a loaded object.
pub struct AyaWriter<'a> {
    ebpf: RefCell<&'a mut Ebpf>,
}

impl std::fmt::Debug for AyaWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The handle is not printable and has nothing to say; only the fact that a writer
        // exists is useful in a log.
        f.write_str("AyaWriter(..)")
    }
}

impl<'a> AyaWriter<'a> {
    /// Wraps a loaded object.
    pub fn new(ebpf: &'a mut Ebpf) -> Self {
        Self {
            ebpf: RefCell::new(ebpf),
        }
    }

    /// Runs `f` with the `u32` array named `map`.
    ///
    /// A closure rather than a returned handle: the handle borrows the `RefCell`'s guard,
    /// which cannot outlive the call without keeping the whole `Ebpf` borrowed.
    fn with_array<T>(
        &self,
        map: &str,
        f: impl FnOnce(&mut Array<&mut MapData, u32>) -> Result<T, aya::maps::MapError>,
    ) -> std::io::Result<T> {
        let mut ebpf = self.ebpf.borrow_mut();
        let data = ebpf.map_mut(map).ok_or_else(|| {
            // The names come from `crate::names`, so this can only happen when the object and
            // the crate disagree — which is what `tests/object.rs` guards.
            std::io::Error::other(format!("the object has no map named {map}"))
        })?;
        let mut array = Array::<&mut MapData, u32>::try_from(data).map_err(|error| {
            std::io::Error::other(format!("{map} is not an array of u32: {error}"))
        })?;
        f(&mut array).map_err(|error| std::io::Error::other(format!("{map}: {error}")))
    }
    /// Runs `f` with the `routing_map`, typed as its real 24-byte value.
    fn with_match_sets<T>(
        &self,
        f: impl FnOnce(
            &mut Array<&mut MapData, [u8; crate::abi::MATCH_SET_SIZE]>,
        ) -> Result<T, aya::maps::MapError>,
    ) -> std::io::Result<T> {
        let mut ebpf = self.ebpf.borrow_mut();
        let name = crate::names::map::ROUTING;
        let data = ebpf
            .map_mut(name)
            .ok_or_else(|| std::io::Error::other(format!("the object has no map named {name}")))?;
        let mut array = Array::<&mut MapData, [u8; crate::abi::MATCH_SET_SIZE]>::try_from(data)
            .map_err(|error| {
                std::io::Error::other(format!(
                    "{name} is not an array of {}-byte match sets: {error}",
                    crate::abi::MATCH_SET_SIZE
                ))
            })?;
        f(&mut array).map_err(|error| std::io::Error::other(format!("{name}: {error}")))
    }
}

impl MapWriter for AyaWriter<'_> {
    fn write(&self, map: &str, key: &[u8], value: &[u8]) -> std::io::Result<()> {
        let index = read_index(map, key)?;
        match map {
            ACTIVE_SLOT_MAP | STAMP_MAP => {
                let word = read_word(map, value)?;
                self.with_array(map, |array| array.set(index, word, 0))
            }
            crate::names::map::ROUTING => {
                let entry: [u8; crate::abi::MATCH_SET_SIZE] = value.try_into().map_err(|_| {
                    std::io::Error::other(format!(
                        "{}: value is {} bytes, a match_set is {}",
                        map,
                        value.len(),
                        crate::abi::MATCH_SET_SIZE
                    ))
                })?;
                self.with_match_sets(|array| array.set(index, entry, 0))
            }
            other => Err(std::io::Error::other(format!(
                "no word writer for {other}: the routing tables go through `publish_policy`"
            ))),
        }
    }

    fn read(&self, map: &str, key: &[u8]) -> std::io::Result<Vec<u8>> {
        let index = read_index(map, key)?;
        match map {
            ACTIVE_SLOT_MAP | STAMP_MAP => {
                let word = self.with_array(map, |array| array.get(&index, 0))?;
                Ok(word.to_ne_bytes().to_vec())
            }
            other => Err(std::io::Error::other(format!("no reader for {other}"))),
        }
    }

    fn set_active_slot(&self, slot: Slot) -> std::io::Result<()> {
        // Key 0, per the C comment: "key=0: active routing epoch slot".
        self.with_array(ACTIVE_SLOT_MAP, |array| array.set(0, slot.index(), 0))
    }

    fn active_slot(&self) -> std::io::Result<Slot> {
        let word = self.with_array(ACTIVE_SLOT_MAP, |array| array.get(&0, 0))?;
        Slot::from_index(word).ok_or_else(|| {
            std::io::Error::other(format!(
                "{ACTIVE_SLOT_MAP} holds {word}, which is not a slot (0 or 1)"
            ))
        })
    }
}

/// Publishes the routing trie for one match-set entry into the inactive slot.
///
/// # Why an inner map per entry
///
/// `lpm_array_map` is `ARRAY_OF_MAPS` over `unused_lpm_type`, and the datapath looks a trie up
/// by **the same index the match set has** (`ctx->routing_epoch_slot * MAX_MATCH_SET_LEN +
/// match_set->index`). So the trie for entry `n` must live at `lpm_array_map[slot * MAX + n]`,
/// and there is no way to express that with a single shared trie.
///
/// # Errors
///
/// Returns the OS error when a map is missing, is not the expected type, or the kernel refuses
/// the update. A failure here is not recoverable by retrying: the caller must abandon the
/// publish, which is what leaves the active slot serving (ADR-0004).
pub fn publish_lpm(
    ebpf: &mut Ebpf,
    slot: crate::epoch::Slot,
    index: u32,
    keys: &[crate::abi::LpmKey],
) -> std::io::Result<()> {
    use aya::maps::lpm_trie::Key;
    use aya::maps::{ArrayOfMaps, IterableMap as _, LpmTrie, MapData};

    let outer_name = crate::names::map::LPM_ARRAY;
    let data = ebpf.map_mut(outer_name).ok_or_else(|| {
        std::io::Error::other(format!("the object has no map named {outer_name}"))
    })?;
    let mut outer = ArrayOfMaps::<&mut MapData, MapData>::try_from(data)
        .map_err(|error| std::io::Error::other(format!("{outer_name}: {error}")))?;

    // The inner map must be created with the same type, key size and value size the object's
    // `unused_lpm_type` template declares, or the kernel refuses to store it.
    let mut trie =
        LpmTrie::<MapData, [u8; 16], u32>::create(LPM_MAX_ENTRIES, LPM_FLAGS).map_err(|error| {
            std::io::Error::other(format!("cannot create the trie for entry {index}: {error}"))
        })?;
    for key in keys {
        // `Key::new` takes the data first and the prefix length second; the datapath's key
        // struct has `prefixlen` first, which is the map's business, not the API's.
        let raw = key.to_bytes();
        let prefix_len = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let mut data = [0u8; 16];
        data.copy_from_slice(&raw[4..20]);
        if prefix_len == 0 {
            // A zero-length prefix matches everything; `IpIndex` never emits one because an
            // empty set emits no trie at all, so reaching here is a bug in the encoder.
            return Err(std::io::Error::other(format!(
                "entry {index}: a zero-length LPM prefix would match every flow"
            )));
        }
        trie.insert(&Key::new(prefix_len, data), 1u32, 0)
            .map_err(|error| std::io::Error::other(format!("entry {index}: {error}")))?;
    }

    // The slot key, computed exactly as the datapath does.
    let key = slot.index() * crate::abi::MAX_MATCH_SET_LEN as u32 + index;
    // `0` is `BPF_ANY`: create or replace, which is what publishing into the inactive slot
    // wants (the slot may hold the previous-but-one generation's trie).
    outer.set(key, trie.map(), 0).map_err(|error| {
        std::io::Error::other(format!("{outer_name}[{key}] for entry {index}: {error}"))
    })
}

/// How many prefixes one match set's trie may hold.
///
/// The object's `unused_lpm_type` template declares `MAX_LPM_SIZE = 2_048_000`; a *smaller*
/// bound here would silently drop prefixes, so this matches the template.
const LPM_MAX_ENTRIES: u32 = 2_048_000;

/// `BPF_F_NO_PREALLOC`, which the object's template sets.
const LPM_FLAGS: u32 = u32::from_le_bytes(*b"\x01\0\0\0");

/// Publishes which outbounds the datapath may send traffic to.
///
/// # Why this is load-bearing
///
/// `wan_outbound_is_alive` reads
/// `outbound_connectivity_map[outbound * 6 + domain * 2 + ipversion]` and **drops the flow** when
/// the value is `0`. The map is a zero-initialised `ARRAY`, so an id that is never written is an
/// id the datapath considers dead: a proxied rule whose group has a perfectly healthy node would
/// have every SYN shot. Writing the group ids that the generation actually selected is therefore
/// part of publishing a policy, not a health-check nicety.
///
/// # Errors
///
/// Returns the OS error when the map is missing or the kernel refuses an update.
pub fn publish_outbound_connectivity(
    ebpf: &mut Ebpf,
    ids: &[u8],
    alive: bool,
) -> std::io::Result<()> {
    use aya::maps::{Array, MapData};

    let name = crate::names::map::OUTBOUND_CONNECTIVITY;
    let data = ebpf
        .map_mut(name)
        .ok_or_else(|| std::io::Error::other(format!("the object has no map named {name}")))?;
    let mut array = Array::<&mut MapData, u32>::try_from(data)
        .map_err(|error| std::io::Error::other(format!("{name}: {error}")))?;

    let value = u32::from(alive);
    for id in ids {
        // domain: 0 = TCP, 1 = DNS UDP, 2 = data UDP; ipversion: 0 = IPv4, 1 = IPv6.
        for domain in 0..3u32 {
            for ipversion in 0..2u32 {
                let key = u32::from(*id) * 6 + domain * 2 + ipversion;
                array.set(key, value, 0).map_err(|error| {
                    std::io::Error::other(format!("{name}[{key}] for outbound {id}: {error}"))
                })?;
            }
        }
    }
    Ok(())
}

/// Hands the transparent listener's sockets to the datapath.
///
/// # Why this is not optional
///
/// The datapath redirects a matching flow with `bpf_sk_assign` into the socket held in
/// `listen_socket_map` — a `SOCKMAP` keyed by family (`0` = tcp4, `1` = udp, `2` = tcp6, per
/// the C). If the map is empty, `assign_listener` returns -1 and **nothing reaches the
/// listener**: the datapath decides "proxy", then has nowhere to put the packet, and the
/// flow dies without a diagnostic on either side. Publishing the fd is what closes that gap,
/// and it is separate from attaching the programs.
///
/// # Errors
///
/// Returns the OS error when the map is missing or is not a `SOCKMAP`.
pub fn publish_listeners(
    ebpf: &mut Ebpf,
    tcp4: std::os::fd::RawFd,
    tcp6: std::os::fd::RawFd,
) -> std::io::Result<()> {
    use aya::maps::SockMap;

    let data = ebpf
        .map_mut(crate::names::map::LISTEN_SOCKET)
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "the object has no map named {}",
                crate::names::map::LISTEN_SOCKET
            ))
        })?;
    let mut map = SockMap::try_from(data).map_err(|error| {
        std::io::Error::other(format!(
            "{} is not a SOCKMAP: {error}",
            crate::names::map::LISTEN_SOCKET
        ))
    })?;
    // The keys are the C's own: 0 is tcp4, 1 is udp, 2 is tcp6. UDP has no listener yet —
    // datagram relay is a known gap — so its slot stays empty rather than pointing at a TCP
    // socket that would corrupt the flow.
    // `SockMap::set` wants references: the fd is borrowed for the duration of the call and
    // the kernel takes its own reference, so the fd stays owned by the caller.
    map.set(0, &tcp4, 0).map_err(|error| {
        std::io::Error::other(format!("cannot publish the tcp4 listener: {error}"))
    })?;
    map.set(2, &tcp6, 0).map_err(|error| {
        std::io::Error::other(format!("cannot publish the tcp6 listener: {error}"))
    })?;
    Ok(())
}

/// The map index from its four big-endian bytes.
fn read_index(map: &str, key: &[u8]) -> std::io::Result<u32> {
    let bytes: [u8; 4] = key.try_into().map_err(|_| {
        std::io::Error::other(format!(
            "{map}: key is {} bytes, an ARRAY key is 4",
            key.len()
        ))
    })?;
    Ok(u32::from_be_bytes(bytes))
}

/// The `u32` value from its four native-endian bytes.
fn read_word(map: &str, value: &[u8]) -> std::io::Result<u32> {
    let bytes: [u8; 4] = value.try_into().map_err(|_| {
        std::io::Error::other(format!(
            "{map}: value is {} bytes, an ARRAY<u32> value is 4",
            value.len()
        ))
    })?;
    Ok(u32::from_ne_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_of_the_wrong_width_is_refused_by_name() {
        let error = read_index(ACTIVE_SLOT_MAP, &[0, 0]).expect_err("must refuse");
        assert!(error.to_string().contains(ACTIVE_SLOT_MAP), "{error}");
        assert!(error.to_string().contains("4"), "{error}");
    }

    #[test]
    fn a_value_of_the_wrong_width_is_refused() {
        // The bug this guards: a 16-byte stamp written into a four-byte slot. The width check
        // turns that into an error at the call instead of a truncated map.
        let error = read_word(STAMP_MAP, &[0u8; 16]).expect_err("must refuse");
        assert!(error.to_string().contains(STAMP_MAP), "{error}");
        assert!(error.to_string().contains("4"), "{error}");
    }

    #[test]
    fn a_four_byte_value_round_trips() {
        assert_eq!(read_word(STAMP_MAP, &7u32.to_ne_bytes()).expect("ok"), 7);
        assert_eq!(read_index(STAMP_MAP, &2u32.to_be_bytes()).expect("ok"), 2);
    }

    #[test]
    fn the_published_map_names_are_the_objects() {
        // Pinned here as well as in `names.rs`, because these two strings were wrong in an
        // earlier version of `epoch` and nothing caught it: the module was never called.
        assert_eq!(ACTIVE_SLOT_MAP, "active_routing_epoch_map");
        assert_eq!(STAMP_MAP, "routing_meta_map");
    }
}
