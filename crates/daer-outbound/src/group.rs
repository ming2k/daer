// SPDX-License-Identifier: AGPL-3.0-only

//! A dialer group: the alive set plus the per-node measured state.
//!
//! Replaces the selection half of `dialer_group.go`. Filtering happens when the
//! group is built (`from_properties`), and the resulting dialer list is what
//! `fixed(<index>)` indexes into — the same order the Go implementation uses.

use std::collections::HashMap;

use daer_common::SelectionPolicy;
use daer_config::TimeSpan;

use crate::alive::{AliveDialerSet, DialerId, NotifyOutcome};
use crate::dialer::Dialer;
use crate::error::OutboundError;
use crate::filter::FilterSet;
use crate::property::{GroupPolicy, Property};

#[derive(Debug)]
pub struct DialerGroup {
    name: String,
    group_policy: GroupPolicy,
    dialers: Vec<Dialer>,
    index: HashMap<DialerId, usize>,
    alive: AliveDialerSet,
}

impl DialerGroup {
    /// Builds a group from an already-filtered dialer list.
    pub fn new(
        name: impl Into<String>,
        group_policy: GroupPolicy,
        tolerance: TimeSpan,
        dialers: Vec<Dialer>,
    ) -> Self {
        let index = dialers
            .iter()
            .enumerate()
            .map(|(position, dialer)| (dialer.id(), position))
            .collect();
        let alive = AliveDialerSet::presuming_alive(
            group_policy.selection_policy(),
            tolerance,
            dialers
                .iter()
                .map(|dialer| (dialer.id(), dialer.offset()))
                .collect(),
        );
        Self {
            name: name.into(),
            group_policy,
            dialers,
            index,
            alive,
        }
    }

    /// Applies `filters` to `properties` and builds the group.
    ///
    /// # Errors
    ///
    /// A `fixed` policy whose index falls outside the filtered list is rejected
    /// here, where the Go implementation only fails on the first selection.
    pub fn from_properties(
        name: impl Into<String>,
        group_policy: GroupPolicy,
        tolerance: TimeSpan,
        properties: Vec<Property>,
        filters: &FilterSet,
    ) -> Result<Self, OutboundError> {
        let mut dialers = Vec::with_capacity(properties.len());
        for property in properties {
            let Some(annotation) = filters.matches(&property.name, &property.subscription_tag)
            else {
                continue;
            };
            let id = DialerId(dialers.len() as u64);
            dialers.push(Dialer::new(id, property, annotation.add_latency));
        }

        if let GroupPolicy::Fixed { index } = group_policy
            && index >= dialers.len()
        {
            return Err(OutboundError::FixedIndexOutOfRange {
                index,
                count: dialers.len(),
            });
        }

        Ok(Self::new(name, group_policy, tolerance, dialers))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn group_policy(&self) -> GroupPolicy {
        self.group_policy
    }

    pub fn policy(&self) -> SelectionPolicy {
        self.group_policy.selection_policy()
    }

    pub fn len(&self) -> usize {
        self.dialers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dialers.is_empty()
    }

    pub fn dialer(&self, id: DialerId) -> Option<&Dialer> {
        self.index.get(&id).map(|position| &self.dialers[*position])
    }

    /// Every dialer in the group, in filter order.
    ///
    /// Filter order is what `fixed(n)` indexes by, so a diagnostic that listed them in another
    /// order would describe a different group.
    pub fn dialers(&self) -> impl Iterator<Item = &Dialer> {
        self.dialers.iter()
    }

    pub fn alive_len(&self) -> usize {
        self.alive.len()
    }

    pub fn best(&self) -> Option<(DialerId, TimeSpan)> {
        self.alive.best()
    }

    /// Applies one health-check result: updates the node's history, then the
    /// alive set with the number the policy ranks on.
    pub fn record(
        &mut self,
        id: DialerId,
        alive: bool,
        latency: Option<TimeSpan>,
    ) -> Result<NotifyOutcome, OutboundError> {
        let policy = self.policy();
        let Some(position) = self.index.get(&id).copied() else {
            return Err(OutboundError::UnknownDialer(id));
        };

        let dialer = &mut self.dialers[position];
        dialer.record(alive, latency);
        let sample = dialer.sorting_sample(policy);
        Ok(self.alive.notify(id, alive, sample))
    }

    /// Picks a node for a new connection.
    ///
    /// `fixed` ignores `excluded`, because the configured index is explicit user
    /// intent (Go documents the same behaviour).
    pub fn select(&self, excluded: Option<DialerId>) -> Option<&Dialer> {
        match self.group_policy {
            GroupPolicy::Fixed { index } => self.dialers.get(index),
            _ => self.alive.select(excluded).and_then(|id| self.dialer(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::FilterSet;
    use crate::property::Property;
    use daer_config::{Function, Param};

    fn ms(value: i64) -> TimeSpan {
        TimeSpan::from_millis(value)
    }

    fn group(policy: GroupPolicy, offsets: &[i64]) -> DialerGroup {
        let dialers = offsets
            .iter()
            .enumerate()
            .map(|(position, offset)| {
                let mut property = Property::direct();
                property.name = format!("node{position}");
                Dialer::new(DialerId(position as u64), property, ms(*offset))
            })
            .collect();
        DialerGroup::new("g", policy, TimeSpan::ZERO, dialers)
    }

    fn property(name: &str, tag: &str) -> Property {
        Property {
            name: name.to_owned(),
            address: String::new(),
            protocol: crate::property::Protocol::Direct,
            udp: false,
            subscription_tag: tag.to_owned(),
            security: crate::property::Security::Plaintext,
        }
    }

    #[test]
    fn records_checks_and_picks_the_best_node() {
        let mut group = group(GroupPolicy::MinLastLatency, &[0, 0, 0]);
        group
            .record(DialerId(0), true, Some(ms(50)))
            .expect("records");
        group
            .record(DialerId(1), true, Some(ms(20)))
            .expect("records");
        group
            .record(DialerId(2), true, Some(ms(80)))
            .expect("records");

        assert_eq!(group.alive_len(), 3);
        assert_eq!(
            group.select(None).map(|dialer| dialer.id()),
            Some(DialerId(1))
        );
        // Excluding the best falls back to the next lowest.
        assert_eq!(
            group.select(Some(DialerId(1))).map(|dialer| dialer.id()),
            Some(DialerId(0))
        );
    }

    #[test]
    fn a_dead_node_is_skipped() {
        let mut group = group(GroupPolicy::MinLastLatency, &[0, 0]);
        group
            .record(DialerId(0), true, Some(ms(10)))
            .expect("records");
        group
            .record(DialerId(1), true, Some(ms(90)))
            .expect("records");
        group.record(DialerId(0), false, None).expect("records");

        assert_eq!(group.alive_len(), 1);
        assert_eq!(
            group.select(None).map(|dialer| dialer.id()),
            Some(DialerId(1))
        );

        group.record(DialerId(1), false, None).expect("records");
        assert!(group.select(None).is_none());
    }

    #[test]
    fn min_avg10_uses_the_average_not_the_last_sample() {
        let mut group = group(GroupPolicy::MinAverage10, &[0, 0]);
        group
            .record(DialerId(0), true, Some(ms(40)))
            .expect("records");
        group
            .record(DialerId(0), true, Some(ms(40)))
            .expect("records");
        group
            .record(DialerId(1), true, Some(ms(10)))
            .expect("records");

        assert_eq!(
            group.dialer(DialerId(0)).unwrap().average_latency(),
            Some(ms(40))
        );
        assert_eq!(
            group.dialer(DialerId(1)).unwrap().average_latency(),
            Some(ms(10))
        );

        group
            .record(DialerId(1), true, Some(ms(90)))
            .expect("records");
        // Node 1's average is now 50, worse than node 0's 40.
        assert_eq!(
            group.select(None).map(|dialer| dialer.id()),
            Some(DialerId(0))
        );
    }

    #[test]
    fn add_latency_offsets_are_applied() {
        let mut group = group(GroupPolicy::MinLastLatency, &[100, -30]);
        group
            .record(DialerId(0), true, Some(ms(10)))
            .expect("records");
        group
            .record(DialerId(1), true, Some(ms(80)))
            .expect("records");
        assert_eq!(
            group.select(None).map(|dialer| dialer.id()),
            Some(DialerId(1))
        );
    }

    #[test]
    fn records_reject_unknown_dialers() {
        let mut group = group(GroupPolicy::MinLastLatency, &[0]);
        let error = group
            .record(DialerId(9), true, Some(ms(1)))
            .expect_err("must fail");
        assert!(matches!(error, OutboundError::UnknownDialer(DialerId(9))));
    }

    #[test]
    fn filters_select_the_dialers_of_a_group() {
        let filters = FilterSet::compile(
            &[vec![Function::with_params(
                "name",
                vec![Param::literal("keyword", "HK")],
            )]],
            &[vec![Param::literal("add_latency", "-500ms")]],
        )
        .expect("compiles");

        let properties = vec![
            property("HK_node", "sub"),
            property("US_node", "sub"),
            property("HK_backup", "sub"),
        ];
        let group = DialerGroup::from_properties(
            "g",
            GroupPolicy::MinLastLatency,
            TimeSpan::ZERO,
            properties,
            &filters,
        )
        .expect("builds");

        assert_eq!(group.len(), 2);
        assert_eq!(
            group
                .dialers()
                .map(|dialer| dialer.property().name.as_str())
                .collect::<Vec<_>>(),
            ["HK_node", "HK_backup"]
        );
        // The filter's annotation became the latency offset.
        assert_eq!(group.dialers().next().unwrap().offset(), ms(-500));
    }

    #[test]
    fn fixed_selects_the_configured_index_of_the_filtered_list() {
        let filters = FilterSet::compile(&[], &[]).expect("compiles");
        let properties = vec![property("a", ""), property("b", ""), property("c", "")];
        let group = DialerGroup::from_properties(
            "g",
            GroupPolicy::Fixed { index: 1 },
            TimeSpan::ZERO,
            properties,
            &filters,
        )
        .expect("builds");

        assert_eq!(
            group
                .select(None)
                .map(|dialer| dialer.property().name.as_str()),
            Some("b")
        );
        // Fixed ignores the exclusion parameter.
        assert_eq!(
            group
                .select(Some(DialerId(1)))
                .map(|dialer| dialer.property().name.as_str()),
            Some("b")
        );
    }

    #[test]
    fn fixed_rejects_an_out_of_range_index() {
        let filters = FilterSet::compile(&[], &[]).expect("compiles");
        let error = DialerGroup::from_properties(
            "g",
            GroupPolicy::Fixed { index: 3 },
            TimeSpan::ZERO,
            vec![property("a", "")],
            &filters,
        )
        .expect_err("must fail");
        assert!(matches!(
            error,
            OutboundError::FixedIndexOutOfRange { index: 3, count: 1 }
        ));
    }

    #[test]
    fn a_filter_that_matches_nothing_yields_an_empty_group() {
        let filters = FilterSet::compile(
            &[vec![Function::with_params(
                "name",
                vec![Param::bare("nope")],
            )]],
            &[Vec::new()],
        )
        .expect("compiles");
        let group = DialerGroup::from_properties(
            "g",
            GroupPolicy::Random,
            TimeSpan::ZERO,
            vec![property("a", "")],
            &filters,
        )
        .expect("builds");
        assert!(group.is_empty());
        assert!(group.select(None).is_none());
    }
}
