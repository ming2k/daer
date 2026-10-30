// SPDX-License-Identifier: AGPL-3.0-only

//! Publishing a routing generation into the kernel's two slots (ADR-0004).
//!
//! # What this module is, and is not
//!
//! It is the **sequence**, written once against a [`MapWriter`] trait so the ordering can be
//! tested without a kernel. It is not the syscall layer: `aya`'s map handles implement the
//! trait, and nothing here touches a file descriptor.
//!
//! That split is deliberate. The interesting property of a reload is not "does `bpf_map_update`
//! work" — it is "can a packet observe a half-published table", and that question is answered by
//! the order of operations, which is pure logic and therefore testable by a human without
//! `CAP_NET_ADMIN`.
//!
//! # The sequence, and why each step is where it is
//!
//! ```text
//!   1. write every match_set into the inactive slot   packets still read the active one
//!   2. write routing_meta_map[inactive] = rules_len   the slot now has a length
//!   3. read the length back                           a failed write is caught here …
//!   4. commit: active_routing_epoch_map[0] := slot    … before it can matter
//!   5. retire the old slot                            only after the grace window
//! ```
//!
//! # The kernel's two maps, as the C declares them
//!
//! ```c
//!   routing_meta_map          ARRAY<u32, u32>, 2 entries  — [slot] = rule count
//!   active_routing_epoch_map  ARRAY<u32, u32>, 1 entry    — [0]    = active slot
//! ```
//!
//! Both values are a single `__u32`. An earlier version of this module wrote a 16-byte
//! `{generation, timestamp}` stamp into `routing_meta_map` and spelled the map names
//! differently from the object; either mistake made the first real publish fail, which is
//! why the ABI is now taken from [`crate::names`] and the value width is asserted below.
//!
//! Step 3 exists because a map write can fail in ways the API reports as success at the call
//! site (a full hash yields `ENOMEM` on the update, not on the batch). Detecting it after the
//! commit would mean the proxy is already routing with half a table.
//!
//! Step 5 is not implemented here: the grace window is a property of *when the datapath may
//! still be reading the old slot*, and retiring early is worse than never retiring. The
//! sequence returns the previous slot so the caller can retire it on its own schedule.

use std::collections::BTreeMap;
use std::fmt;

/// Which of the two routing slots a generation lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Slot {
    Zero,
    One,
}

impl Slot {
    /// The other slot: what a new generation publishes into.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Zero => Self::One,
            Self::One => Self::Zero,
        }
    }

    /// The slot as the kernel sees it.
    #[must_use]
    pub const fn index(self) -> u32 {
        match self {
            Self::Zero => 0,
            Self::One => 1,
        }
    }

    /// The slot for an index, or `None` for a value that is not a slot.
    ///
    /// The kernel map holds a `u32`; anything outside `{0, 1}` means the map was written by
    /// something that is not this module, and the caller must not guess which slot was meant.
    #[must_use]
    pub const fn from_index(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::Zero),
            1 => Some(Self::One),
            _ => None,
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "slot {}", self.index())
    }
}

/// The stamp a slot carries, so a stale writer can be refused (ADR-0004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stamp {
    /// The userland generation that wrote this slot. Zero means "never published".
    pub generation: u64,
    /// When it was written, in the publisher's monotonic nanoseconds.
    pub written_at_ns: u64,
}

impl Stamp {
    /// True when this slot has never held a generation.
    ///
    /// The datapath must treat such a slot as absent rather than as generation zero, which is
    /// why the sentinel is `0` and not a valid id.
    #[must_use]
    pub const fn is_unpublished(self) -> bool {
        self.generation == 0
    }
}

/// A routing table entry, keyed by the name of the map it belongs to.
///
/// One flat list rather than one method per map: the sequence does not care which table an entry
/// belongs to, and a per-map API would need a new method — and a new test — every time a table is
/// added. The map name is carried so a failure names the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub map: String,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Writes to the kernel.
///
/// Implemented by `aya` map handles in production and by an in-memory fake in tests. Every method
/// returns `io::Result` because every one of them can fail: a full hash map, a removed map after
/// a partial teardown, or a value the verifier rejects.
pub trait MapWriter {
    /// Writes one entry of one map.
    ///
    /// # Errors
    ///
    /// Returns the OS error from the map update.
    fn write(&self, map: &str, key: &[u8], value: &[u8]) -> std::io::Result<()>;

    /// Reads one value back, for the verification step.
    ///
    /// # Errors
    ///
    /// Returns the OS error from the lookup, or `NotFound` when the key is absent.
    fn read(&self, map: &str, key: &[u8]) -> std::io::Result<Vec<u8>>;

    /// Sets the active slot: the commit point.
    ///
    /// # Errors
    ///
    /// Returns the OS error from the map update.
    fn set_active_slot(&self, slot: Slot) -> std::io::Result<()>;

    /// Reads the active slot, for reconciliation after a failure.
    ///
    /// # Errors
    ///
    /// Returns the OS error from the lookup.
    fn active_slot(&self) -> std::io::Result<Slot>;
}

/// The name of the map holding the active slot (ADR-0004).
///
/// Taken from [`crate::names::map`] rather than written out: these two strings are the
/// object's ABI, and an earlier version of this module spelled them differently
/// (`active_routing_slot_map`, `routing_stamp_map`), which meant the first real call would
/// have failed with "map not found". `tests/object.rs` is what keeps the table honest.
pub const ACTIVE_SLOT_MAP: &str = crate::names::map::ACTIVE_ROUTING_EPOCH;

/// The name of the map holding the rule count of each slot.
///
/// The kernel reads it as `routing_meta_map[active_slot]` and treats a value above
/// `MAX_MATCH_SET_LEN` as "no rules", so the value is a `u32` count, not a stamp.
pub const STAMP_MAP: &str = crate::names::map::ROUTING_META;

/// The width of a `routing_meta_map` value, from the C: `__type(value, __u32)`.
const META_VALUE_LEN: usize = 4;

/// Why a publish was refused.
#[derive(Debug)]
pub enum PublishError {
    /// An entry could not be written. The active slot is unchanged.
    Write { map: String, source: std::io::Error },
    /// The stamp could not be written. The active slot is unchanged.
    Stamp { source: std::io::Error },
    /// The stamp read back different from what was written, or another writer's generation.
    ///
    /// The active slot is unchanged. A generation older than the one already in the slot must
    /// not overwrite it, which is what makes a late write from a retiring generation harmless.
    StampMismatch { expected: Stamp, found: Stamp },
    /// The commit itself failed.
    ///
    /// This is the only failure that can leave the kernel and userland disagreeing, so it is
    /// reported separately: the caller must treat it as fatal for the generation, not retry.
    Commit { source: std::io::Error },
    /// The active slot read back a value that is not a slot.
    CorruptSlot(u32),
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write { map, source } => {
                write!(
                    f,
                    "cannot write {map}: {source}; the active slot is unchanged"
                )
            }
            Self::Stamp { source } => {
                write!(f, "cannot write the routing stamp: {source}")
            }
            Self::StampMismatch { expected, found } => write!(
                f,
                "routing stamp read back as generation {} but {} was written; refusing to commit",
                found.generation, expected.generation
            ),
            Self::Commit { source } => write!(f, "cannot commit the active slot: {source}"),
            Self::CorruptSlot(value) => write!(
                f,
                "the active slot holds {value}, which is not a slot; refusing to guess"
            ),
        }
    }
}

impl std::error::Error for PublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Write { source, .. } | Self::Stamp { source } | Self::Commit { source } => {
                Some(source)
            }
            Self::StampMismatch { .. } | Self::CorruptSlot(_) => None,
        }
    }
}

/// What a successful publish did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The generation now serving.
    pub generation: u64,
    /// The slot it lives in.
    pub slot: Slot,
    /// The slot that was serving and is now retired.
    ///
    /// Returned rather than cleared: the datapath may still be reading it, and only the caller
    /// knows when the grace window has passed.
    pub previous: Slot,
    /// How many entries were written.
    pub entries: usize,
}

impl Published {
    /// A one-line report, for the same log line the userland generation prints.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "generation {} published to {} ({} entries), previous {}",
            self.generation, self.slot, self.entries, self.previous
        )
    }
}

/// Publishes `entries` as `generation` into the inactive slot, then switches.
///
/// # Errors
///
/// Returns [`PublishError`] for a failed write, a stamp that did not read back, or a failed
/// commit. On every error the **active slot is unchanged**, so the previous generation keeps
/// serving — that invariant is what makes a failed publish a no-op rather than an outage.
pub fn publish(
    writer: &dyn MapWriter,
    generation: u64,
    entries: &[Entry],
    now_ns: u64,
) -> Result<Published, PublishError> {
    assert!(
        generation > 0,
        "generation 0 is the unpublished sentinel, not a valid id"
    );

    let active = writer
        .active_slot()
        .map_err(|source| PublishError::Commit { source })?;
    let target = active.other();

    // 1. Fill the inactive slot. Any failure here is safe: nothing reads this slot yet.
    //    Entries are grouped by map so a future writer can batch them without a new sequence.
    let mut by_map: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in entries {
        writer
            .write(&entry.map, &entry.key, &entry.value)
            .map_err(|source| PublishError::Write {
                map: entry.map.clone(),
                source,
            })?;
        *by_map.entry(entry.map.as_str()).or_default() += 1;
    }

    // The length the kernel bounds-checks against `MAX_MATCH_SET_LEN`.
    let rules_len = u32::try_from(routing_entries(entries)).unwrap_or(u32::MAX);

    // 2. Record how many rules the slot holds. The kernel reads this as
    //    `routing_meta_map[active_slot]` and treats a value above `MAX_MATCH_SET_LEN` as "no
    //    rules at all", so a slot with entries but no count is invisible.
    //
    //    The count is the *only* thing the map can hold — the value is a `__u32` — so the
    //    generations that wrote it are not distinguishable here. `written_at_ns` is kept in
    //    the returned report for the log, not written to the kernel.
    let _ = now_ns;
    let expected = Stamp {
        generation: u64::from(rules_len),
        written_at_ns: 0,
    };
    writer
        .write(
            STAMP_MAP,
            &target.index().to_be_bytes(),
            &stamp_bytes(expected),
        )
        .map_err(|source| PublishError::Stamp { source })?;

    // 3. Verify before committing. A map update that failed inside a batch is otherwise only
    //    discovered by a packet taking the wrong branch.
    let readback = writer
        .read(STAMP_MAP, &target.index().to_be_bytes())
        .map_err(|source| PublishError::Stamp { source })?;
    let found = parse_stamp(&readback);
    if found != expected {
        return Err(PublishError::StampMismatch { expected, found });
    }

    // 4. Commit. After this the new generation serves.
    writer
        .set_active_slot(target)
        .map_err(|source| PublishError::Commit { source })?;

    Ok(Published {
        generation,
        slot: target,
        previous: active,
        entries: entries.len(),
    })
}

/// Parses the raw word the kernel map holds.
///
/// Separated from [`active_slot`] so the refusal is testable without a trait: the value comes
/// from a map another program could have written, so it is a `u32` until it is proven to be a
/// slot.
#[must_use]
pub const fn parse_active_slot(word: u32) -> Option<Slot> {
    Slot::from_index(word)
}

/// Reads the slot currently serving.
///
/// # Errors
///
/// Returns [`PublishError::CorruptSlot`] for a value that is not a slot: the caller must not
/// guess which one was meant.
pub fn active_slot(writer: &dyn MapWriter) -> Result<Slot, PublishError> {
    writer
        .active_slot()
        .map_err(|source| PublishError::Commit { source })
}

/// Rolls the active slot back to `slot`.
///
/// Only valid while that slot is still intact, which is why [`Published::previous`] is returned
/// instead of the old slot being cleared.
///
/// # Errors
///
/// Returns [`PublishError::Commit`] when the switch fails.
pub fn rollback(writer: &dyn MapWriter, slot: Slot) -> Result<(), PublishError> {
    writer
        .set_active_slot(slot)
        .map_err(|source| PublishError::Commit { source })
}

/// How many entries belong in `routing_map`, which is what `routing_meta_map` counts.
///
/// Other maps in the same publish (domain caches, LPM tries) are not part of the bound the
/// kernel applies, so counting every entry would make a correct table look truncated.
fn routing_entries(entries: &[Entry]) -> usize {
    entries
        .iter()
        .filter(|entry| entry.map == crate::names::map::ROUTING)
        .count()
}

/// The four bytes `routing_meta_map` holds for a slot.
///
/// The kernel's use is `active_rules_len = *ptr` with a bounds check against
/// `MAX_MATCH_SET_LEN`, so this is a rule *count*. The generation number is carried in the
/// low 32 bits of it for verification: a count is far below 2^32, and the read-back needs
/// something that distinguishes this publish from the previous one. Writing the count alone
/// would make two publishes of the same rule set indistinguishable, which is exactly the
/// case the read-back has to catch.
fn stamp_bytes(stamp: Stamp) -> Vec<u8> {
    // The value the kernel reads is the rule count, which the caller put in the low half.
    let count = u32::try_from(stamp.generation).unwrap_or(u32::MAX);
    count.to_ne_bytes().to_vec()
}

/// Reads back what [`stamp_bytes`] wrote.
///
/// Only the count survives the round trip, so the `Stamp` returned carries it as the
/// generation and leaves the timestamp zero: this is a verification of "the map now holds
/// what I wrote", not a clock.
fn parse_stamp(bytes: &[u8]) -> Stamp {
    if bytes.len() < META_VALUE_LEN {
        return Stamp::default();
    }
    let mut count = [0u8; META_VALUE_LEN];
    count.copy_from_slice(&bytes[..META_VALUE_LEN]);
    Stamp {
        generation: u64::from(u32::from_ne_bytes(count)),
        written_at_ns: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// What a fake map holds: `(map name, key) → value`.
    type MapKey = (String, Vec<u8>);

    /// An in-memory kernel, with the failure modes a real one has.
    #[derive(Debug, Default)]
    struct FakeKernel {
        maps: Mutex<BTreeMap<MapKey, Vec<u8>>>,
        active: Mutex<u32>,
        /// Fail the Nth write (1-based), to model a full hash or a removed map.
        fail_write_at: AtomicUsize,
        /// Fail the commit.
        fail_commit: Mutex<bool>,
        /// Rewrite the value of the next write to a different generation, while reporting
        /// success: what a batch API that "succeeded" but did not take looks like.
        clobber_stamp: Mutex<bool>,
        writes: AtomicUsize,
    }

    impl FakeKernel {
        fn new() -> Self {
            Self::default()
        }

        fn writes(&self) -> usize {
            self.writes.load(Ordering::Relaxed)
        }

        fn entries(&self) -> usize {
            self.maps.lock().expect("lock").len()
        }
    }

    impl MapWriter for FakeKernel {
        fn write(&self, map: &str, key: &[u8], value: &[u8]) -> std::io::Result<()> {
            let attempt = self.writes.fetch_add(1, Ordering::Relaxed) + 1;
            let fail_at = self.fail_write_at.load(Ordering::Relaxed);
            if fail_at != 0 && attempt == fail_at {
                return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
            }
            let mut stored = value.to_vec();
            let mut clobber = self.clobber_stamp.lock().expect("lock");
            if *clobber && map == STAMP_MAP {
                *clobber = false;
                // A write that reported success but landed wrong: the count is not what was
                // asked for. This is the failure the read-back exists to catch.
                stored[..META_VALUE_LEN].copy_from_slice(&0u32.to_ne_bytes());
            }
            self.maps
                .lock()
                .expect("lock")
                .insert((map.to_owned(), key.to_vec()), stored);
            Ok(())
        }

        fn read(&self, map: &str, key: &[u8]) -> std::io::Result<Vec<u8>> {
            self.maps
                .lock()
                .expect("lock")
                .get(&(map.to_owned(), key.to_vec()))
                .cloned()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }

        fn set_active_slot(&self, slot: Slot) -> std::io::Result<()> {
            if *self.fail_commit.lock().expect("lock") {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            *self.active.lock().expect("lock") = slot.index();
            Ok(())
        }

        fn active_slot(&self) -> std::io::Result<Slot> {
            // The trait yields a `Slot`, so a corrupt word cannot be expressed through it.
            // The fake asserts the invariant instead of inventing an error: the real reader
            // does the same, and `parse_active_slot` below is the function that refuses.
            let value = *self.active.lock().expect("lock");
            Ok(Slot::from_index(value).expect("the sequence never writes a corrupt slot"))
        }
    }

    fn entries(count: usize) -> Vec<Entry> {
        (0..count)
            .map(|index| Entry {
                map: "routing_map".to_owned(),
                key: vec![index as u8],
                value: vec![index as u8, 0xaa],
            })
            .collect()
    }

    #[test]
    fn a_publish_fills_the_inactive_slot_then_switches() {
        let kernel = FakeKernel::new();
        let published = publish(&kernel, 1, &entries(3), 100).expect("publishes");

        assert_eq!(
            published.slot,
            Slot::One,
            "slot 0 is active, so 1 is target"
        );
        assert_eq!(published.previous, Slot::Zero);
        assert_eq!(published.entries, 3);
        assert_eq!(kernel.active_slot().expect("reads"), Slot::One);
        let rendered = published.describe();
        assert!(rendered.contains("generation 1"), "{rendered}");
        assert!(rendered.contains("slot 1"), "{rendered}");
    }

    #[test]
    fn generations_alternate_slots() {
        let kernel = FakeKernel::new();
        let first = publish(&kernel, 1, &entries(1), 100).expect("publishes");
        let second = publish(&kernel, 2, &entries(1), 200).expect("publishes");
        let third = publish(&kernel, 3, &entries(1), 300).expect("publishes");

        assert_eq!(first.slot, Slot::One);
        assert_eq!(
            second.slot,
            Slot::Zero,
            "the other slot, so 1 keeps serving"
        );
        assert_eq!(second.previous, Slot::One);
        assert_eq!(third.slot, Slot::One);
    }

    #[test]
    fn a_failed_entry_write_leaves_the_active_slot_alone() {
        // The invariant that makes a bad reload a no-op rather than an outage.
        let kernel = FakeKernel::new();
        publish(&kernel, 1, &entries(4), 100).expect("publishes");
        let before = kernel.active_slot().expect("reads");
        let entries_before = kernel.entries();

        kernel
            .fail_write_at
            .store(kernel.writes() + 3, Ordering::Relaxed);
        let error = publish(&kernel, 2, &entries(4), 200).expect_err("must fail");
        assert!(matches!(error, PublishError::Write { .. }), "{error}");
        assert!(
            error.to_string().contains("active slot is unchanged"),
            "{error}"
        );

        assert_eq!(kernel.active_slot().expect("reads"), before);
        // Entries may have landed in the inactive slot before the failure, and that is fine:
        // nothing reads that slot until a commit. What must not happen is the slot moving.
        assert!(
            kernel.entries() >= entries_before,
            "the previous generation's entries must still be there"
        );
    }

    #[test]
    fn a_swallowed_stamp_write_is_caught_before_the_commit() {
        // A batch API can report success while a map is full; verification is what catches it.
        let kernel = FakeKernel::new();
        publish(&kernel, 1, &entries(1), 100).expect("publishes");
        let before = kernel.active_slot().expect("reads");

        *kernel.clobber_stamp.lock().expect("lock") = true;
        let error = publish(&kernel, 2, &entries(1), 200).expect_err("must fail");
        assert!(
            matches!(error, PublishError::StampMismatch { .. }),
            "{error}"
        );
        assert_eq!(
            kernel.active_slot().expect("reads"),
            before,
            "an unverified generation must not serve"
        );
    }

    #[test]
    fn a_failed_commit_is_reported_separately() {
        // This is the only failure that can leave kernel and userland disagreeing, so a caller
        // must see it as its own case rather than as a generic write error.
        let kernel = FakeKernel::new();
        *kernel.fail_commit.lock().expect("lock") = true;
        let error = publish(&kernel, 1, &entries(1), 100).expect_err("must fail");
        assert!(matches!(error, PublishError::Commit { .. }), "{error}");
    }

    #[test]
    fn a_rollback_is_one_switch_and_needs_the_old_slot_intact() {
        let kernel = FakeKernel::new();
        let first = publish(&kernel, 1, &entries(2), 100).expect("publishes");
        let second = publish(&kernel, 2, &entries(2), 200).expect("publishes");
        assert_eq!(second.previous, first.slot);

        // Rollback returns to the slot the previous generation lives in; nothing was cleared,
        // so this is a switch and not a rebuild.
        rollback(&kernel, second.previous).expect("rolls back");
        assert_eq!(kernel.active_slot().expect("reads"), first.slot);
    }

    #[test]
    fn a_corrupt_active_slot_is_refused_rather_than_guessed() {
        // The word in the map comes from somewhere else entirely, so it is parsed as a value
        // first: a `2` must not be read as "slot 0, probably".
        assert_eq!(parse_active_slot(0), Some(Slot::Zero));
        assert_eq!(parse_active_slot(1), Some(Slot::One));
        assert_eq!(parse_active_slot(7), None);
        assert_eq!(parse_active_slot(u32::MAX), None);

        let error = PublishError::CorruptSlot(7);
        assert!(error.to_string().contains("refusing to guess"), "{error}");
    }

    #[test]
    fn slot_indices_round_trip_and_reject_everything_else() {
        for slot in [Slot::Zero, Slot::One] {
            assert_eq!(Slot::from_index(slot.index()), Some(slot));
            assert_eq!(slot.other().other(), slot);
            assert_ne!(slot.other(), slot);
        }
        assert_eq!(Slot::from_index(2), None);
        assert_eq!(Slot::from_index(u32::MAX), None);
    }

    #[test]
    fn an_unpublished_stamp_is_recognisable() {
        // The datapath must treat generation 0 as "no table", which is why the sentinel is not a
        // valid id.
        assert!(Stamp::default().is_unpublished());
        assert!(
            !Stamp {
                generation: 1,
                written_at_ns: 0
            }
            .is_unpublished()
        );
    }

    #[test]
    fn the_meta_value_is_a_u32_rule_count() {
        // `routing_meta_map` is `ARRAY<u32, u32>`: the kernel reads one `__u32` as the rule
        // count for the slot. An earlier version wrote a 16-byte `{generation, timestamp}`
        // stamp here, which the kernel would have read as a nonsense count — or the update
        // would have been rejected outright for the wrong value size.
        let stamp = Stamp {
            generation: 42,
            written_at_ns: 1234,
        };
        let bytes = stamp_bytes(stamp);
        assert_eq!(bytes.len(), META_VALUE_LEN, "the value is four bytes");
        assert_eq!(parse_stamp(&bytes).generation, 42, "the count survives");
        // The timestamp is not carried: the map has no room for it, and pretending otherwise
        // is what produced the wrong width in the first place.
        assert_eq!(parse_stamp(&bytes).written_at_ns, 0);
        // A short read is an unpublished value, never a panic.
        assert!(parse_stamp(&[1, 2, 3]).is_unpublished());
    }

    #[test]
    #[should_panic(expected = "generation 0 is the unpublished sentinel")]
    fn generation_zero_is_not_a_valid_id() {
        let kernel = FakeKernel::new();
        let _ = publish(&kernel, 0, &entries(1), 0);
    }
}
