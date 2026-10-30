// SPDX-License-Identifier: AGPL-3.0-only

//! The alive set of one dialer group for one network type.
//!
//! Port of `alive_dialer_set.go`. The Go type is per (group, network type) and
//! is mutated by health-check notifications; this port keeps the same state
//! machine and the same tolerance rule, without the logging and callbacks.
//!
//! Invariants carried over:
//!
//! * a dialer's index in `entries` never changes except by swap-remove;
//! * a new sample replaces the best dialer only when it is better by at least
//!   `tolerance` (or when the current best is itself below `tolerance`);
//! * `best` is cached so the hot path does not scan.

use std::collections::HashMap;

use daer_common::SelectionPolicy;
use daer_config::TimeSpan;

/// A stable identifier for a dialer inside one set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DialerId(pub u64);

// Go stores negative sentinels: `-Init` and `-NotAlive`.
const INIT: isize = 1;
const NOT_ALIVE: isize = 2;

/// The latency a set uses before any dialer has been measured.
const STARTING_SORTING_LATENCY: TimeSpan = TimeSpan::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AliveEntry {
    dialer: DialerId,
    sorting_latency: TimeSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NotifyOutcome {
    /// The selected best dialer changed (including becoming/ceasing to exist).
    pub best_changed: bool,
    /// Whether any dialer is alive after this notification.
    pub has_alive: bool,
}

#[derive(Debug)]
pub struct AliveDialerSet {
    policy: SelectionPolicy,
    tolerance: TimeSpan,
    /// `>= 0` is the index in `entries`; `-1` never seen; `-2` not alive.
    index: HashMap<DialerId, isize>,
    offsets: HashMap<DialerId, TimeSpan>,
    latencies: HashMap<DialerId, TimeSpan>,
    entries: Vec<AliveEntry>,
    best: Option<AliveEntry>,
}

impl AliveDialerSet {
    /// `dialers` fixes membership for the lifetime of the set; `add_latency`
    /// annotations are passed as the second element.
    pub fn new(
        policy: SelectionPolicy,
        tolerance: TimeSpan,
        dialers: Vec<(DialerId, TimeSpan)>,
    ) -> Self {
        let mut index = HashMap::with_capacity(dialers.len());
        let mut offsets = HashMap::with_capacity(dialers.len());
        for (dialer, offset) in dialers {
            index.insert(dialer, -INIT);
            offsets.insert(dialer, offset);
        }
        Self {
            policy,
            tolerance,
            index,
            offsets,
            latencies: HashMap::new(),
            entries: Vec::new(),
            best: None,
        }
    }

    pub fn policy(&self) -> SelectionPolicy {
        self.policy
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The cached best dialer and its sorting latency (raw latency + offset).
    pub fn best(&self) -> Option<(DialerId, TimeSpan)> {
        self.best.map(|entry| (entry.dialer, entry.sorting_latency))
    }

    /// Builds a set whose members are all **presumed alive until measured**.
    ///
    /// # Why the set starts populated
    ///
    /// A group whose policy ranks by latency had an empty alive set until the first probe
    /// completed, so `select()` returned `None` and `daer route explain` answered "undeliverable,
    /// group has no selectable node" for the first probe interval — which is the *default*
    /// configuration (`min-moving-avg`, `interval = 30s`), so a freshly started daemon refused
    /// every flow for thirty seconds and an operator reading the diagnostic reasonably concluded
    /// the node was broken.
    ///
    /// The alternative reading of the Go implementation is that membership starts empty and only
    /// a probe admits a node. That is defensible for a *cluster* where a dead node is worse than
    /// no node; it is wrong here, for two reasons a deployment makes obvious:
    ///
    /// * daer is usually the only path to the network. Refusing traffic because a probe has not
    ///   run yet is an outage the operator did not ask for, and the probe cannot even run before
    ///   the network is up.
    /// * "unmeasured" is not "dead". A node is excluded when a probe **proves** it dead; until
    ///   then it is a candidate at the starting latency, which is exactly what
    ///   `STARTING_SORTING_LATENCY` already models for ranking.
    ///
    /// The policies that do not rank by latency (`fixed`, `random`) are unaffected: they never
    /// consulted the alive set's measurement state to begin with.
    pub fn presuming_alive(
        policy: SelectionPolicy,
        tolerance: TimeSpan,
        dialers: Vec<(DialerId, TimeSpan)>,
    ) -> Self {
        let mut set = Self::new(policy, tolerance, dialers.clone());
        for (dialer, offset) in dialers {
            set.index.insert(dialer, set.entries.len() as isize);
            set.entries.push(AliveEntry {
                dialer,
                sorting_latency: STARTING_SORTING_LATENCY + offset,
            });
        }
        set.recalculate_best();
        set
    }

    /// Records a health-check result.
    ///
    /// `latency` is the raw sample for the policy in use; `None` means the
    /// caller has no sample (for example a data-UDP domain that only flips the
    /// alive flag).
    pub fn notify(
        &mut self,
        dialer: DialerId,
        alive: bool,
        latency: Option<TimeSpan>,
    ) -> NotifyOutcome {
        let Some(current_index) = self.index.get(&dialer).copied() else {
            // Membership is fixed at construction; an unknown dialer is a
            // caller bug. Ignoring it keeps the other entries intact.
            return NotifyOutcome {
                best_changed: false,
                has_alive: !self.entries.is_empty(),
            };
        };
        let offset = self.offsets.get(&dialer).copied().unwrap_or_default();
        let old_best = self.best;

        if alive {
            if current_index < 0 {
                self.index.insert(dialer, self.entries.len() as isize);
                self.entries.push(AliveEntry {
                    dialer,
                    sorting_latency: offset,
                });
            }
        } else if current_index >= 0 {
            let removed_without_latency = self.policy.is_latency_based()
                && latency.is_none()
                && old_best.map(|e| e.dialer) == Some(dialer);

            let index = current_index as usize;
            let last = self.entries.len() - 1;
            if index != last {
                let swapped = self.entries[last];
                self.index.insert(swapped.dialer, index as isize);
                self.entries[index] = swapped;
            }
            self.entries.pop();
            self.index.insert(dialer, -NOT_ALIVE);

            if removed_without_latency {
                self.best = None;
                self.recalculate_best();
            }
        }

        let Some(raw_latency) = latency else {
            // A death may still change the best dialer even without a sample.
            return NotifyOutcome {
                best_changed: self.best.map(|entry| entry.dialer)
                    != old_best.map(|entry| entry.dialer),
                has_alive: !self.entries.is_empty(),
            };
        };

        let sorting_latency = raw_latency + offset;
        self.latencies.insert(dialer, raw_latency);
        if let Some(index) = self.index.get(&dialer).copied().filter(|index| *index >= 0) {
            self.entries[index as usize].sorting_latency = sorting_latency;
        }

        let best_latency = self
            .best
            .map_or(STARTING_SORTING_LATENCY, |e| e.sorting_latency);
        if alive
            && sorting_latency <= best_latency
            && (best_latency < self.tolerance || sorting_latency <= best_latency - self.tolerance)
        {
            self.best = Some(AliveEntry {
                dialer,
                sorting_latency,
            });
        } else if self.best.map(|e| e.dialer) == Some(dialer) {
            self.best = Some(AliveEntry {
                dialer,
                sorting_latency,
            });
            if !alive || sorting_latency > best_latency {
                if !alive {
                    self.best = None;
                }
                self.recalculate_best();
            }
        }

        NotifyOutcome {
            best_changed: self.best.map(|e| e.dialer) != old_best.map(|e| e.dialer),
            has_alive: !self.entries.is_empty(),
        }
    }

    /// Picks a dialer for a new connection.
    ///
    /// `fixed` and the latency policies never use randomness; `random` does a
    /// reservoir sample so excluding a dialer stays uniform.
    pub fn select(&self, excluded: Option<DialerId>) -> Option<DialerId> {
        match self.policy {
            SelectionPolicy::Fixed => self
                .entries
                .iter()
                .find(|entry| Some(entry.dialer) != excluded)
                .map(|entry| entry.dialer),
            SelectionPolicy::Random => self.select_random(excluded),
            _ => self.select_min(excluded),
        }
    }

    fn select_min(&self, excluded: Option<DialerId>) -> Option<DialerId> {
        if let Some(best) = self.best
            && Some(best.dialer) != excluded
        {
            return Some(best.dialer);
        }

        self.entries
            .iter()
            .filter(|entry| Some(entry.dialer) != excluded)
            .min_by_key(|entry| entry.sorting_latency)
            .map(|entry| entry.dialer)
    }

    fn select_random(&self, excluded: Option<DialerId>) -> Option<DialerId> {
        let mut chosen = None;
        let mut candidates = 0usize;
        for entry in &self.entries {
            if Some(entry.dialer) == excluded {
                continue;
            }
            candidates += 1;
            if fastrand::usize(..candidates) == 0 {
                chosen = Some(entry.dialer);
            }
        }
        chosen
    }

    fn recalculate_best(&mut self) {
        self.best = self
            .entries
            .iter()
            .copied()
            .min_by_key(|entry| entry.sorting_latency);
    }

    /// Raw latency of the last sample, for diagnostics.
    pub fn latency(&self, dialer: DialerId) -> Option<TimeSpan> {
        self.latencies.get(&dialer).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: i64) -> TimeSpan {
        TimeSpan::from_millis(value)
    }

    fn set(policy: SelectionPolicy, tolerance: TimeSpan) -> AliveDialerSet {
        AliveDialerSet::new(
            policy,
            tolerance,
            vec![
                (DialerId(1), TimeSpan::ZERO),
                (DialerId(2), TimeSpan::ZERO),
                (DialerId(3), TimeSpan::ZERO),
            ],
        )
    }

    #[test]
    fn a_new_set_admits_every_member_until_a_probe_proves_one_dead() {
        // The default configuration is `min-moving-avg`, and its group used to be empty until the
        // first probe finished: `daer route explain` answered "undeliverable, group has no
        // selectable node" for thirty seconds after every start. Membership is now presumed.
        let set = AliveDialerSet::presuming_alive(
            SelectionPolicy::MinMovingAverage,
            TimeSpan::ZERO,
            vec![(DialerId(1), TimeSpan::ZERO), (DialerId(2), TimeSpan::ZERO)],
        );
        assert_eq!(set.len(), 2, "both members are candidates before any probe");
        assert!(
            set.select(None).is_some(),
            "an unmeasured node must be selectable, or a fresh daemon proxies nothing"
        );
    }

    #[test]
    fn a_probe_that_proves_a_node_dead_removes_it() {
        // The other half of the rule: "unmeasured" is not "dead", but a failed probe is.
        let mut set = AliveDialerSet::presuming_alive(
            SelectionPolicy::MinLastLatency,
            TimeSpan::ZERO,
            vec![(DialerId(1), TimeSpan::ZERO), (DialerId(2), TimeSpan::ZERO)],
        );
        set.notify(DialerId(1), false, None);
        set.notify(DialerId(2), true, Some(ms(40)));
        assert_eq!(set.len(), 1);
        assert_eq!(set.select(None), Some(DialerId(2)));

        set.notify(DialerId(2), false, None);
        assert_eq!(
            set.select(None),
            None,
            "with every node proven dead, selection must fail rather than invent one"
        );
    }

    #[test]
    fn picks_the_lowest_latency() {
        let mut set = set(SelectionPolicy::MinLastLatency, TimeSpan::ZERO);
        assert_eq!(set.best(), None);

        set.notify(DialerId(1), true, Some(ms(80)));
        set.notify(DialerId(2), true, Some(ms(40)));
        set.notify(DialerId(3), true, Some(ms(60)));

        assert_eq!(set.best(), Some((DialerId(2), ms(40))));
        assert_eq!(set.select(None), Some(DialerId(2)));
    }

    #[test]
    fn excludes_the_best_dialer_on_request() {
        let mut set = set(SelectionPolicy::MinLastLatency, TimeSpan::ZERO);
        set.notify(DialerId(1), true, Some(ms(80)));
        set.notify(DialerId(2), true, Some(ms(40)));

        assert_eq!(set.select(Some(DialerId(2))), Some(DialerId(1)));
    }

    #[test]
    fn tolerance_keeps_the_incumbent() {
        let mut set = set(SelectionPolicy::MinLastLatency, ms(10));
        set.notify(DialerId(1), true, Some(ms(50)));
        // 45 is better, but not by the 10 ms tolerance.
        set.notify(DialerId(2), true, Some(ms(45)));
        assert_eq!(set.best(), Some((DialerId(1), ms(50))));

        // 39 is better by more than the tolerance.
        set.notify(DialerId(3), true, Some(ms(39)));
        assert_eq!(set.best(), Some((DialerId(3), ms(39))));
    }

    #[test]
    fn dead_dialer_leaves_the_alive_set() {
        let mut set = set(SelectionPolicy::MinLastLatency, TimeSpan::ZERO);
        set.notify(DialerId(1), true, Some(ms(40)));
        set.notify(DialerId(2), true, Some(ms(80)));

        let outcome = set.notify(DialerId(1), false, None);
        assert!(outcome.best_changed);
        assert_eq!(set.len(), 1);
        assert_eq!(set.best(), Some((DialerId(2), ms(80))));
        assert_eq!(set.select(None), Some(DialerId(2)));
    }

    #[test]
    fn reports_when_no_dialer_is_alive() {
        let mut set = set(SelectionPolicy::MinLastLatency, TimeSpan::ZERO);
        set.notify(DialerId(1), true, Some(ms(40)));
        let outcome = set.notify(DialerId(1), false, None);
        assert!(!outcome.has_alive);
        assert_eq!(set.best(), None);
        assert_eq!(set.select(None), None);
    }

    #[test]
    fn offset_shifts_the_sorting_latency() {
        let mut set = AliveDialerSet::new(
            SelectionPolicy::MinLastLatency,
            TimeSpan::ZERO,
            vec![(DialerId(1), ms(100)), (DialerId(2), ms(-50))],
        );
        set.notify(DialerId(1), true, Some(ms(80)));
        // 80 + 100 = 180 vs 90 - 50 = 40.
        set.notify(DialerId(2), true, Some(ms(90)));
        assert_eq!(set.best(), Some((DialerId(2), ms(40))));
    }

    #[test]
    fn random_selection_only_returns_alive_dialers() {
        let mut set = set(SelectionPolicy::Random, TimeSpan::ZERO);
        set.notify(DialerId(2), true, Some(ms(10)));
        for _ in 0..50 {
            assert_eq!(set.select(None), Some(DialerId(2)));
        }
        assert_eq!(set.select(Some(DialerId(2))), None);
    }

    #[test]
    fn fixed_selection_uses_the_first_alive_dialer() {
        let mut set = set(SelectionPolicy::Fixed, TimeSpan::ZERO);
        set.notify(DialerId(3), true, None);
        assert_eq!(set.select(None), Some(DialerId(3)));
    }

    #[test]
    fn unknown_dialers_are_ignored() {
        let mut set = set(SelectionPolicy::MinLastLatency, TimeSpan::ZERO);
        let outcome = set.notify(DialerId(99), true, Some(ms(1)));
        assert!(!outcome.has_alive);
        assert_eq!(set.best(), None);
    }
}
