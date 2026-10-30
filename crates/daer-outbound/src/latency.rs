// SPDX-License-Identifier: AGPL-3.0-only

//! Latency bookkeeping, ported from `latencies_n.go` and the moving average in
//! `connectivity_check.go`.

use daer_config::TimeSpan;

/// The last `n` measured latencies, as a ring buffer.
///
/// Appending a fixed duration for failures/timeouts is the caller's job, exactly
/// as in the Go implementation.
#[derive(Debug, Clone)]
pub struct LatenciesN {
    n: usize,
    latencies: Vec<TimeSpan>,
    head: usize,
    sum: TimeSpan,
}

impl LatenciesN {
    pub fn new(n: usize) -> Self {
        Self {
            n,
            latencies: Vec::with_capacity(n),
            head: 0,
            sum: TimeSpan::ZERO,
        }
    }

    /// Appends a latency, dropping the oldest sample once full.
    pub fn append(&mut self, latency: TimeSpan) {
        if self.n == 0 {
            return;
        }
        if self.latencies.len() >= self.n {
            self.sum = self.sum - self.latencies[self.head];
            self.latencies[self.head] = latency;
            self.head = (self.head + 1) % self.n;
        } else {
            self.latencies.push(latency);
        }
        self.sum += latency;
    }

    pub fn last(&self) -> Option<TimeSpan> {
        match self.latencies.len() {
            0 => None,
            count if count < self.n => self.latencies.last().copied(),
            _ => {
                let last = (self.head + self.n - 1) % self.n;
                Some(self.latencies[last])
            }
        }
    }

    /// Truncating average, like Go's integer duration division.
    pub fn average(&self) -> Option<TimeSpan> {
        let count = self.latencies.len();
        if count == 0 {
            return None;
        }
        Some(TimeSpan::from_nanos(self.sum.as_nanos() / count as i64))
    }

    pub fn len(&self) -> usize {
        self.latencies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.latencies.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.n
    }
}

/// Exponentially weighted moving average with Go's exact update rule:
/// `moving = (moving + sample) / 2`.
///
/// It starts at zero, so the first successful sample halves the reported value
/// — this matches the Go implementation, where `min_moving_avg` treats zero as
/// "no sample yet".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MovingAverage {
    value: TimeSpan,
}

impl MovingAverage {
    pub fn update(&mut self, latency: TimeSpan) {
        self.value = TimeSpan::from_nanos((self.value.as_nanos() + latency.as_nanos()) / 2);
    }

    pub fn get(&self) -> TimeSpan {
        self.value
    }

    /// Whether at least one sample has been applied (Go checks `> 0`).
    pub fn has_sample(&self) -> bool {
        self.value.as_nanos() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: i64) -> TimeSpan {
        TimeSpan::from_millis(value)
    }

    #[test]
    fn ring_keeps_the_last_n_samples() {
        let mut latencies = LatenciesN::new(3);
        assert_eq!(latencies.last(), None);
        assert_eq!(latencies.average(), None);

        latencies.append(ms(10));
        latencies.append(ms(20));
        assert_eq!(latencies.last(), Some(ms(20)));
        assert_eq!(latencies.average(), Some(ms(15)));

        latencies.append(ms(30));
        latencies.append(ms(40));
        assert_eq!(latencies.len(), 3);
        assert_eq!(latencies.last(), Some(ms(40)));
        // 20 + 30 + 40
        assert_eq!(latencies.average(), Some(ms(30)));
    }

    #[test]
    fn average_truncates_like_go() {
        let mut latencies = LatenciesN::new(4);
        latencies.append(TimeSpan::from_nanos(1));
        latencies.append(TimeSpan::from_nanos(2));
        assert_eq!(latencies.average(), Some(TimeSpan::from_nanos(1)));
    }

    #[test]
    fn zero_capacity_is_inert() {
        let mut latencies = LatenciesN::new(0);
        latencies.append(ms(10));
        assert!(latencies.is_empty());
        assert_eq!(latencies.last(), None);
    }

    #[test]
    fn moving_average_halves_towards_new_samples() {
        let mut average = MovingAverage::default();
        assert!(!average.has_sample());

        average.update(ms(100));
        assert_eq!(average.get(), ms(50));
        assert!(average.has_sample());

        average.update(ms(100));
        assert_eq!(average.get(), ms(75));
    }
}
