// SPDX-License-Identifier: AGPL-3.0-only

//! The runtime half of an election: its candidate dialers and measured state.
//!
//! A group is only a resource pool. This type is built from the pool's survivors
//! plus the election's selection rule; it owns the alive set and the per-node
//! latency history that rule ranks. It never decides *which* group to use and it
//! never owns a routing target: that is the election's name in the routing
//! program.

use std::collections::HashMap;

use daer_common::SelectionPolicy;
use daer_config::TimeSpan;

use crate::alive::{AliveDialerSet, DialerId, NotifyOutcome};
use crate::dialer::Dialer;
use crate::error::OutboundError;
use crate::filter::FilterSet;
use crate::property::Property;

#[derive(Debug)]
pub struct ElectionRuntime {
    name: String,
    policy: SelectionPolicy,
    dialers: Vec<Dialer>,
    index: HashMap<DialerId, usize>,
    alive: AliveDialerSet,
}

impl ElectionRuntime {
    /// Builds an election runtime from an already-filtered dialer list.
    pub fn new(
        name: impl Into<String>,
        policy: SelectionPolicy,
        tolerance: TimeSpan,
        dialers: Vec<Dialer>,
    ) -> Self {
        let index = dialers
            .iter()
            .enumerate()
            .map(|(position, dialer)| (dialer.id(), position))
            .collect();
        let alive = AliveDialerSet::presuming_alive(
            policy,
            tolerance,
            dialers
                .iter()
                .map(|dialer| (dialer.id(), dialer.offset()))
                .collect(),
        );
        Self {
            name: name.into(),
            policy,
            dialers,
            index,
            alive,
        }
    }

    /// Applies `filters` to `properties` and builds the election runtime.
    pub fn from_properties(
        name: impl Into<String>,
        policy: SelectionPolicy,
        tolerance: TimeSpan,
        properties: Vec<Property>,
        filters: &FilterSet,
    ) -> Self {
        let mut dialers = Vec::with_capacity(properties.len());
        for property in properties {
            let Some(annotation) = filters.matches(&property.name, &property.subscription_name)
            else {
                continue;
            };
            let id = DialerId(dialers.len() as u64);
            dialers.push(Dialer::new(id, property, annotation.add_latency));
        }
        Self::new(name, policy, tolerance, dialers)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn policy(&self) -> SelectionPolicy {
        self.policy
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

    /// Resolves a node name to its dialer, for runtime `elect`.
    pub fn dialer_by_name(&self, name: &str) -> Option<&Dialer> {
        self.dialers
            .iter()
            .find(|dialer| dialer.property().name == name)
    }

    /// Every dialer in the election's candidate order.
    pub fn dialers(&self) -> impl Iterator<Item = &Dialer> {
        self.dialers.iter()
    }

    pub fn alive_len(&self) -> usize {
        self.alive.len()
    }

    pub fn best(&self) -> Option<(DialerId, TimeSpan)> {
        self.alive.best()
    }

    /// Whether a candidate is currently alive.
    #[must_use]
    pub fn is_alive(&self, id: DialerId) -> Option<bool> {
        self.alive.is_alive(id)
    }

    /// Applies one probe result: updates the node's history, then the alive set
    /// with the number the election's rule ranks on.
    pub fn record(
        &mut self,
        id: DialerId,
        alive: bool,
        latency: Option<TimeSpan>,
    ) -> Result<NotifyOutcome, OutboundError> {
        let Some(position) = self.index.get(&id).copied() else {
            return Err(OutboundError::UnknownDialer(id));
        };

        let dialer = &mut self.dialers[position];
        dialer.record(alive, latency);
        let sample = dialer.sorting_sample(self.policy);
        Ok(self.alive.notify(id, alive, sample))
    }

    /// Picks a node for a new connection.
    pub fn select(&self, excluded: Option<DialerId>) -> Option<&Dialer> {
        self.alive.select(excluded).and_then(|id| self.dialer(id))
    }

    /// Picks a specific candidate by name, bypassing the policy.
    ///
    /// This is the runtime `daer elect <election> <node>` path. It is deliberately
    /// separate from [`Self::select`]: the override is an operator decision and must
    /// not be silently replaced by a health rule.
    pub fn select_named(&self, name: &str) -> Option<&Dialer> {
        self.dialer_by_name(name)
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

    fn group(policy: SelectionPolicy, offsets: &[i64]) -> ElectionRuntime {
        let dialers = offsets
            .iter()
            .enumerate()
            .map(|(position, offset)| {
                let mut property = Property::direct();
                property.name = format!("node{position}");
                Dialer::new(DialerId(position as u64), property, ms(*offset))
            })
            .collect();
        ElectionRuntime::new("g", policy, TimeSpan::ZERO, dialers)
    }

    fn property(name: &str, subscription_name: &str) -> Property {
        Property {
            name: name.to_owned(),
            address: String::new(),
            protocol: crate::property::Protocol::Direct,
            udp: false,
            subscription_name: subscription_name.to_owned(),
            security: crate::property::Security::Plaintext,
        }
    }

    #[test]
    fn records_checks_and_picks_the_best_node() {
        let mut group = group(SelectionPolicy::MinLastLatency, &[0, 0, 0]);
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
        assert_eq!(
            group.select(Some(DialerId(1))).map(|dialer| dialer.id()),
            Some(DialerId(0))
        );
    }

    #[test]
    fn a_dead_node_is_skipped() {
        let mut group = group(SelectionPolicy::MinLastLatency, &[0, 0]);
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
        let mut group = group(SelectionPolicy::MinAverage10, &[0, 0]);
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
        assert_eq!(
            group.select(None).map(|dialer| dialer.id()),
            Some(DialerId(0))
        );
    }

    #[test]
    fn add_latency_offsets_are_applied() {
        let mut group = group(SelectionPolicy::MinLastLatency, &[100, -30]);
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
        let mut group = group(SelectionPolicy::MinLastLatency, &[0]);
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
        let group = ElectionRuntime::from_properties(
            "g",
            SelectionPolicy::MinLastLatency,
            TimeSpan::ZERO,
            properties,
            &filters,
        );

        assert_eq!(group.len(), 2);
        assert_eq!(
            group
                .dialers()
                .map(|dialer| dialer.property().name.as_str())
                .collect::<Vec<_>>(),
            ["HK_node", "HK_backup"]
        );
        assert_eq!(group.dialers().next().unwrap().offset(), ms(-500));
    }

    #[test]
    fn manual_selects_the_single_candidate() {
        let group = group(SelectionPolicy::Manual, &[0]);
        assert_eq!(
            group
                .select(None)
                .map(|dialer| dialer.property().name.as_str()),
            Some("node0")
        );
        assert_eq!(
            group
                .select_named("node0")
                .map(|dialer| dialer.property().name.as_str()),
            Some("node0")
        );
        assert!(group.select_named("missing").is_none());
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
        let group = ElectionRuntime::from_properties(
            "g",
            SelectionPolicy::Random,
            TimeSpan::ZERO,
            vec![property("a", "")],
            &filters,
        );
        assert!(group.is_empty());
        assert!(group.select(None).is_none());
    }
}
