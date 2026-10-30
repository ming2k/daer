// SPDX-License-Identifier: AGPL-3.0-only

//! A single outbound node and its measured state.

use daer_common::SelectionPolicy;
use daer_config::TimeSpan;

use crate::alive::DialerId;
use crate::latency::{LatenciesN, MovingAverage};
use crate::property::Property;

/// How many samples `min_avg10` averages over.
const LATENCY_WINDOW: usize = 10;

#[derive(Debug)]
pub struct Dialer {
    id: DialerId,
    property: Property,
    /// `add_latency` annotation: shifts this node's sorting latency.
    offset: TimeSpan,
    latencies: LatenciesN,
    moving_average: MovingAverage,
    alive: bool,
}

impl Dialer {
    pub fn new(id: DialerId, property: Property, offset: TimeSpan) -> Self {
        Self {
            id,
            property,
            offset,
            latencies: LatenciesN::new(LATENCY_WINDOW),
            moving_average: MovingAverage::default(),
            alive: false,
        }
    }

    pub fn id(&self) -> DialerId {
        self.id
    }

    pub fn property(&self) -> &Property {
        &self.property
    }

    pub fn offset(&self) -> TimeSpan {
        self.offset
    }

    pub fn is_alive(&self) -> bool {
        self.alive
    }

    /// Records one health-check result. Failures flip the alive flag and leave
    /// the latency history untouched, matching `markAvailable` /
    /// `markUnavailable` in the Go implementation.
    pub fn record(&mut self, alive: bool, latency: Option<TimeSpan>) {
        if alive && let Some(latency) = latency {
            self.latencies.append(latency);
            self.moving_average.update(latency);
        }
        self.alive = alive;
    }

    /// The number the selection policy ranks on (`snapshotLatencyForPolicy`).
    ///
    /// `random` and `fixed` do not rank on latency, so they report no sample.
    pub fn sorting_sample(&self, policy: SelectionPolicy) -> Option<TimeSpan> {
        match policy {
            SelectionPolicy::MinLastLatency => self.latencies.last(),
            SelectionPolicy::MinAverage10 => self.latencies.average(),
            SelectionPolicy::MinMovingAverage => {
                let average = self.moving_average.get();
                (average.as_nanos() > 0).then_some(average)
            }
            SelectionPolicy::Random | SelectionPolicy::Fixed => None,
        }
    }

    pub fn last_latency(&self) -> Option<TimeSpan> {
        self.latencies.last()
    }

    pub fn average_latency(&self) -> Option<TimeSpan> {
        self.latencies.average()
    }

    pub fn moving_average(&self) -> TimeSpan {
        self.moving_average.get()
    }

    pub fn samples(&self) -> usize {
        self.latencies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: i64) -> TimeSpan {
        TimeSpan::from_millis(value)
    }

    fn dialer() -> Dialer {
        Dialer::new(DialerId(1), Property::direct(), TimeSpan::ZERO)
    }

    #[test]
    fn records_successful_samples_only() {
        let mut dialer = dialer();
        dialer.record(true, Some(ms(40)));
        dialer.record(false, None);
        assert!(!dialer.is_alive());
        assert_eq!(dialer.samples(), 1);
        assert_eq!(dialer.last_latency(), Some(ms(40)));

        dialer.record(true, Some(ms(60)));
        assert!(dialer.is_alive());
        assert_eq!(dialer.samples(), 2);
        assert_eq!(dialer.average_latency(), Some(ms(50)));
    }

    #[test]
    fn sorting_sample_follows_the_policy() {
        let mut dialer = dialer();
        dialer.record(true, Some(ms(40)));
        dialer.record(true, Some(ms(80)));

        assert_eq!(
            dialer.sorting_sample(SelectionPolicy::MinLastLatency),
            Some(ms(80))
        );
        assert_eq!(
            dialer.sorting_sample(SelectionPolicy::MinAverage10),
            Some(ms(60))
        );
        // (0 + 40) / 2 = 20, then (20 + 80) / 2 = 50
        assert_eq!(
            dialer.sorting_sample(SelectionPolicy::MinMovingAverage),
            Some(ms(50))
        );
        assert_eq!(dialer.sorting_sample(SelectionPolicy::Random), None);
        assert_eq!(dialer.sorting_sample(SelectionPolicy::Fixed), None);
    }

    #[test]
    fn moving_average_has_no_sample_before_the_first_check() {
        let dialer = dialer();
        assert_eq!(
            dialer.sorting_sample(SelectionPolicy::MinMovingAverage),
            None
        );
    }
}
