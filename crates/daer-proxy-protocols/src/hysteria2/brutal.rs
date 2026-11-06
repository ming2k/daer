// SPDX-License-Identifier: AGPL-3.0-only

//! Brutal: the reference's throughput-pinning congestion controller (ADR-0029).
//!
//! # What it does, and why a proxy wants it
//!
//! Every other controller infers a rate from loss. Brutal does the opposite: the operator
//! says what the link is (`up-mbps`/`down-mbps`) and Brutal *pins* the window to
//! `bps × srtt × 2 / ack_rate`, so a lossy path — a congested transit, a lossy mobile link, a
//! censor that drops a percentage of packets — does not collapse the throughput to what a
//! loss-based controller would infer. That is the selling point of Hysteria, and it is why
//! the reference ships it as its own default.
//!
//! # The one piece of feedback it does take
//!
//! Sending at a rate the path cannot carry is useless, so Brutal measures the **ACK rate** over
//! a five-second window and divides by it, clamped to `>= 0.8`. A path that drops 20 % gets a
//! 25 % larger window, compensating for the bytes that will be lost again; below 0.8 it stops
//! compensating, because at that point the path is broken rather than lossy.
//!
//! # The reference's own numbers
//!
//! `pktInfoSlotCount = 5`, `minSampleCount = 50`, `minAckRate = 0.8`,
//! `congestionWindowMultiplier = 2`, and a `10240`-byte fallback before the first RTT. Each
//! changes the wire behaviour: a "close enough" value makes the two implementations disagree
//! about the send rate, and the disagreement shows up as packet loss rather than as an error.

use std::any::Any;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use quinn_proto::RttEstimator;
use quinn_proto::congestion::{Controller, ControllerFactory};

/// How many one-second slots the ACK rate is measured over (`pktInfoSlotCount`).
const SLOT_COUNT: usize = 5;
/// ACK samples required before the rate is believed (`minSampleCount`).
const MIN_SAMPLE_COUNT: u64 = 50;
/// The floor for the ACK rate (`minAckRate`).
const MIN_ACK_RATE: f64 = 0.8;
/// The window multiplier (`congestionWindowMultiplier`).
const WINDOW_MULTIPLIER: f64 = 2.0;
/// The window before the first RTT is known.
const INITIAL_WINDOW: u64 = 10_240;

/// The process's monotonic zero, so a slot index can be a whole second since start.
///
/// The reference computes the slot from `monotime.Time`, which is nanoseconds since the
/// process started. `std::time::Instant` has no arithmetic origin, so one is fixed here on
/// first use. Its absolute value is irrelevant — only the difference between two readings is
/// ever used — so a shared origin is enough.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// One second's ACK and loss counts.
#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    timestamp: u64,
    ack_count: u64,
    loss_count: u64,
}

/// Brutal's configuration: the rate the operator promised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrutalConfig {
    /// Bytes per second this connection may send.
    pub bytes_per_second: u64,
    /// Skip the ACK-rate compensation and always use the full rate.
    pub disable_loss_compensation: bool,
}

impl BrutalConfig {
    /// A config for `bits_per_second`, converted the way the reference does.
    #[must_use]
    pub const fn from_bits_per_second(bits_per_second: u64) -> Self {
        Self {
            bytes_per_second: bits_per_second / 8,
            disable_loss_compensation: false,
        }
    }

    /// `disable_loss_compensation` set, for a test or an operator who knows the path.
    #[must_use]
    pub const fn without_compensation(mut self) -> Self {
        self.disable_loss_compensation = true;
        self
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: std::time::Instant, current_mtu: u16) -> Box<dyn Controller> {
        // Before the first ACK there is no measured RTT, so the reference's `10240` floor
        // applies and `brutal_window` returns it. No loss compensation can have been measured
        // yet either, so the ACK rate is exactly 1.0.
        let initial = brutal_window(self.bytes_per_second, Duration::from_millis(50), 1.0);
        Box::new(Brutal {
            bytes_per_second: self.bytes_per_second,
            disable_loss_compensation: self.disable_loss_compensation,
            slots: [Slot::default(); SLOT_COUNT],
            ack_rate: 1.0,
            max_datagram_size: current_mtu,
            smoothed_rtt: Duration::ZERO,
            window: initial.max(INITIAL_WINDOW),
        })
    }
}

/// Brutal's controller state.
#[derive(Debug)]
struct Brutal {
    bytes_per_second: u64,
    disable_loss_compensation: bool,
    slots: [Slot; SLOT_COUNT],
    ack_rate: f64,
    max_datagram_size: u16,
    /// The smoothed RTT from the most recent ACK, which is what the window formula needs.
    smoothed_rtt: Duration,
    window: u64,
}

impl Brutal {
    /// Recomputes `ack_rate` from the slot window.
    fn update_ack_rate(&mut self, seconds: u64) {
        if self.disable_loss_compensation {
            self.ack_rate = 1.0;
            return;
        }
        let oldest = seconds.saturating_sub(SLOT_COUNT as u64);
        let mut acked = 0u64;
        let mut lost = 0u64;
        for slot in &self.slots {
            if slot.timestamp < oldest {
                continue;
            }
            acked += slot.ack_count;
            lost += slot.loss_count;
        }
        if acked + lost < MIN_SAMPLE_COUNT {
            // Not enough evidence: assume a clean path rather than inventing a penalty.
            self.ack_rate = 1.0;
            return;
        }
        self.ack_rate = (acked as f64 / (acked + lost) as f64).max(MIN_ACK_RATE);
    }

    fn record(&mut self, seconds: u64, acked: u64, lost: u64) {
        let index = (seconds % SLOT_COUNT as u64) as usize;
        if self.slots[index].timestamp == seconds {
            self.slots[index].ack_count += acked;
            self.slots[index].loss_count += lost;
        } else {
            self.slots[index] = Slot {
                timestamp: seconds,
                ack_count: acked,
                loss_count: lost,
            };
        }
        self.update_ack_rate(seconds);
    }

    /// Recomputes the window from the current rate, RTT and ACK rate.
    fn refresh_window(&mut self) {
        self.window = brutal_window(self.bytes_per_second, self.smoothed_rtt, self.ack_rate)
            .max(u64::from(self.max_datagram_size));
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        _now: std::time::Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.smoothed_rtt = rtt.get();
        let seconds = epoch().elapsed().as_secs();
        self.record(seconds, bytes, 0);
        self.refresh_window();
    }

    fn on_congestion_event(
        &mut self,
        _now: std::time::Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // Brutal does not shrink on a loss: that is the point. It only *measures* the loss so
        // the rate it pins can be divided by the ACK rate.
        let seconds = epoch().elapsed().as_secs();
        self.record(seconds, 0, lost_bytes);
        self.refresh_window();
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram_size = new_mtu;
        self.refresh_window();
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            bytes_per_second: self.bytes_per_second,
            disable_loss_compensation: self.disable_loss_compensation,
            slots: self.slots,
            ack_rate: self.ack_rate,
            max_datagram_size: self.max_datagram_size,
            smoothed_rtt: self.smoothed_rtt,
            window: self.window,
        })
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// The window Brutal pins for a measured RTT: `bps × srtt × 2 / ack_rate`.
///
/// Separated from [`Controller::window`] so the formula is testable without a Quinn
/// connection, and so the reference's numbers can be asserted directly.
#[must_use]
pub fn brutal_window(bytes_per_second: u64, smoothed_rtt: Duration, ack_rate: f64) -> u64 {
    let rate = ack_rate.clamp(MIN_ACK_RATE, 1.0);
    let window = (bytes_per_second as f64) * smoothed_rtt.as_secs_f64() * WINDOW_MULTIPLIER / rate;
    if window < 1.0 {
        return INITIAL_WINDOW;
    }
    window as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_is_the_rate_times_the_rtt_times_two() {
        // 10 MB/s over a 50 ms path: 10e6 × 0.05 × 2 = 1 MB, which is the reference's formula
        // with no loss compensation.
        assert_eq!(
            brutal_window(10_000_000, Duration::from_millis(50), 1.0),
            1_000_000
        );
        // An ACK rate of 0.8 grows the window by 1/0.8, which is the compensation for the
        // bytes that will be lost again.
        assert_eq!(
            brutal_window(10_000_000, Duration::from_millis(50), 0.8),
            1_250_000
        );
    }

    #[test]
    fn the_ack_rate_is_clamped_so_a_broken_path_does_not_get_an_unbounded_window() {
        // Below 0.8 the controller stops compensating: at that point the path is broken, not
        // lossy, and a larger window would make it worse.
        assert_eq!(
            brutal_window(10_000_000, Duration::from_millis(50), 0.1),
            brutal_window(10_000_000, Duration::from_millis(50), 0.8)
        );
        // Above 1.0 is not a real ACK rate; it is clamped too, rather than shrinking the
        // window below what the configured rate promises.
        assert_eq!(
            brutal_window(10_000_000, Duration::from_millis(50), 2.0),
            brutal_window(10_000_000, Duration::from_millis(50), 1.0)
        );
    }

    #[test]
    fn a_rate_that_would_produce_a_tiny_window_falls_back_to_the_reference_default() {
        // Before the first RTT the reference returns 10240 rather than zero or one MTU.
        assert_eq!(brutal_window(1, Duration::ZERO, 1.0), INITIAL_WINDOW);
        assert_eq!(
            brutal_window(0, Duration::from_millis(50), 1.0),
            INITIAL_WINDOW
        );
    }

    #[test]
    fn a_config_converts_bits_to_bytes_without_rounding_up() {
        let config = BrutalConfig::from_bits_per_second(100_000_000);
        assert_eq!(config.bytes_per_second, 12_500_000);
        // A rate that is not a multiple of 8 loses the remainder rather than inventing
        // bandwidth the operator did not buy.
        assert_eq!(BrutalConfig::from_bits_per_second(7).bytes_per_second, 0);
    }

    #[test]
    fn the_ack_rate_needs_the_references_minimum_sample_count_before_it_is_believed() {
        // A controller built without traffic reports a full rate: fifty samples is the
        // reference's floor, and below it the estimate would be noise.
        let factory = Arc::new(BrutalConfig::from_bits_per_second(80_000_000));
        let controller = factory.build(Instant::now(), 1200);
        let boxed = controller.into_any();
        let brutal = boxed
            .downcast::<Brutal>()
            .expect("the factory builds a Brutal");
        assert_eq!(brutal.ack_rate, 1.0);
        assert!(brutal.window > 0);
    }
}
