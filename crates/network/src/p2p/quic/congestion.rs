//! CUBIC that tolerates a share of loss in a flight, and past it cuts the
//! window by the share lost, not by a fixed factor.
//!
//! Growth is quinn-proto's `Cubic` (RFC 9438) as it stands. The loss side
//! differs: quinn declares a packet lost on reordering and has no way to tell
//! it later that the packet arrived, and a path may lose packets at random.
//! A fixed cut for each such loss leaves a bursty sender, which CUBIC does not
//! grow while it has nothing to send, at a window of a few packets.
//!
//! A loss counts against the flight that was out when the first loss of it
//! was seen. Up to `LOSS_TOLERANCE` of the window at that time, or
//! `LOSS_FLOOR_PACKETS` if that is more, nothing is cut. Past it the window is
//! what it was less the share lost, never below CUBIC's own cut, and is
//! lowered again as the flight loses more. ECN and persistent congestion are
//! taken as CUBIC takes them.
//!
//! The data of a packet declared lost is sent again whatever is done here.

use std::{
    any::Any,
    sync::Arc,
    time::{Duration, Instant},
};

use quinn_proto::{
    RttEstimator,
    congestion::{Controller, ControllerFactory, ControllerMetrics},
};

/// RFC 9438's multiplicative decrease and scaling constant.
const BETA_CUBIC: f64 = 0.7;
const C: f64 = 0.4;
/// The share of the window a flight may lose with no cut.
const LOSS_TOLERANCE: f64 = 0.02;
/// The packets a flight may lose with no cut, where that share is fewer.
const LOSS_FLOOR_PACKETS: u64 = 3;
/// quinn-proto's initial window.
const INITIAL_WINDOW: u64 = 12_000;

/// The flight a loss is counted against.
#[derive(Debug, Clone, Copy)]
struct Flight {
    /// When its first loss was seen: a packet sent later is of the next.
    opened: Instant,
    /// The window then, which the share lost and the cut are taken of.
    window: u64,
    lost: u64,
    /// The window has been cut for it.
    cut: bool,
}

#[derive(Debug, Clone)]
pub(super) struct TolerantCubic {
    window: u64,
    /// Below it the window grows by the bytes acknowledged.
    ssthresh: u64,
    /// The start of the congestion avoidance epoch. A packet sent before it
    /// grows nothing.
    recovery_start_time: Option<Instant>,
    k: f64,
    w_max: f64,
    cwnd_inc: u64,
    flight: Option<Flight>,
    mtu: u64,
}

impl TolerantCubic {
    fn new(mtu: u16) -> Self {
        Self {
            window: INITIAL_WINDOW,
            ssthresh: u64::MAX,
            recovery_start_time: None,
            k: 0.0,
            w_max: 0.0,
            cwnd_inc: 0,
            flight: None,
            mtu: mtu as u64,
        }
    }

    fn minimum_window(&self) -> u64 {
        2 * self.mtu
    }

    // W_cubic(t) = C * (t - K)^3 + W_max, in bytes.
    fn w_cubic(&self, t: Duration) -> f64 {
        (C * (t.as_secs_f64() - self.k).powi(3) + self.w_max / self.mtu as f64) * self.mtu as f64
    }

    // W_est(t) = W_max * beta + 3 * (1 - beta) / (1 + beta) * t / RTT, in bytes.
    fn w_est(&self, t: Duration, rtt: Duration) -> f64 {
        let reno = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);
        (self.w_max / self.mtu as f64 * BETA_CUBIC + reno * t.as_secs_f64() / rtt.as_secs_f64()) *
            self.mtu as f64
    }

    /// quinn-proto's `Cubic::on_ack`.
    fn grow(&mut self, now: Instant, sent: Instant, bytes: u64, app_limited: bool, rtt: Duration) {
        if app_limited || self.recovery_start_time.is_some_and(|start| sent <= start) {
            return;
        }
        if self.window < self.ssthresh {
            self.window += bytes;
            return;
        }
        let epoch = *self.recovery_start_time.get_or_insert_with(|| {
            self.w_max = self.window as f64;
            self.k = 0.0;
            now
        });
        let t = now - epoch;
        let (w_cubic, w_est) = (self.w_cubic(t + rtt), self.w_est(t, rtt));
        let mut target = self.window;
        if w_cubic < w_est {
            target = target.max(w_est as u64);
        } else if target < w_cubic as u64 {
            let inc = (w_cubic - target as f64) / target as f64 * self.mtu as f64;
            target = target.saturating_add(inc as u64);
        }
        self.cwnd_inc += target - self.window;
        // RFC 9002 §7.3.3: at most a datagram a window acknowledged.
        if self.cwnd_inc >= self.mtu {
            self.window += self.mtu;
            self.cwnd_inc = 0;
        }
    }

    /// The window as `factor` of `from`, the start of a congestion avoidance
    /// epoch at `now`. K is RFC 9438's general form, for a cut that is not
    /// beta.
    fn cut(&mut self, now: Instant, from: u64, factor: f64) {
        let from = from as f64;
        // Fast convergence (RFC 9438 §4.7).
        self.w_max = if from < self.w_max { from * (1.0 + BETA_CUBIC) / 2.0 } else { from };
        self.ssthresh = ((from * factor) as u64).max(self.minimum_window());
        self.window = self.ssthresh;
        self.k = ((self.w_max - self.window as f64).max(0.0) / self.mtu as f64 / C).cbrt();
        self.cwnd_inc = (self.cwnd_inc as f64 * factor) as u64;
        self.recovery_start_time = Some(now);
    }
}

impl Controller for TolerantCubic {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.grow(now, sent, bytes, app_limited, rtt.get());
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if is_persistent_congestion {
            let from = self.window;
            self.cut(now, from, BETA_CUBIC);
            self.w_max = self.window as f64;
            self.ssthresh = ((self.window as f64 * BETA_CUBIC) as u64).max(self.minimum_window());
            self.window = self.minimum_window();
            (self.cwnd_inc, self.recovery_start_time, self.flight) = (0, None, None);
            return;
        }
        // A mark is the path's word, not a guess of ours: CUBIC's cut, once a
        // flight.
        if lost_bytes == 0 {
            if self.recovery_start_time.is_none_or(|start| sent > start) {
                let from = self.window;
                self.cut(now, from, BETA_CUBIC);
            }
            return;
        }
        let window = self.window;
        let flight = match &mut self.flight {
            Some(flight) if sent <= flight.opened => flight,
            flight => flight.insert(Flight { opened: now, window, lost: 0, cut: false }),
        };
        flight.lost += lost_bytes;
        let tolerated =
            ((flight.window as f64 * LOSS_TOLERANCE) as u64).max(LOSS_FLOOR_PACKETS * self.mtu);
        if flight.lost <= tolerated {
            return;
        }
        let share = flight.lost as f64 / flight.window as f64;
        let factor = (1.0 - share).max(BETA_CUBIC);
        let (from, opened, first) = (flight.window, flight.opened, !flight.cut);
        flight.cut = true;
        if first {
            self.cut(opened.max(now), from, factor);
        } else if ((from as f64 * factor) as u64).max(self.minimum_window()) < self.window {
            // The same flight has lost more: the epoch stands, the window and
            // its K follow.
            self.window = ((from as f64 * factor) as u64).max(self.minimum_window());
            self.ssthresh = self.window;
            self.k = ((self.w_max - self.window as f64).max(0.0) / self.mtu as f64 / C).cbrt();
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu as u64;
        self.window = self.window.max(self.minimum_window());
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window;
        metrics.ssthresh = Some(self.ssthresh);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

pub(super) struct TolerantCubicConfig;

impl ControllerFactory for TolerantCubicConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(TolerantCubic::new(current_mtu))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: u64 = 1200;
    const RTT: Duration = Duration::from_millis(100);

    /// A controller in congestion avoidance at `window`, and the time.
    fn at(window: u64) -> (TolerantCubic, Instant) {
        let now = Instant::now();
        let mut cubic = TolerantCubic::new(MTU as u16);
        (cubic.window, cubic.ssthresh) = (window, window);
        (cubic, now)
    }

    #[test]
    fn a_few_lost_packets_cut_nothing() {
        let (mut cubic, now) = at(1000 * MTU);
        // Under the share, one packet at a time.
        for _ in 0..20 {
            cubic.on_congestion_event(now, now - RTT, false, MTU);
        }
        assert_eq!(cubic.window, 1000 * MTU);

        // A small window: the floor, where the share is less than a packet.
        let (mut cubic, now) = at(10 * MTU);
        for _ in 0..LOSS_FLOOR_PACKETS {
            cubic.on_congestion_event(now, now - RTT, false, MTU);
        }
        assert_eq!(cubic.window, 10 * MTU);
        cubic.on_congestion_event(now, now - RTT, false, MTU);
        assert!(cubic.window < 10 * MTU);
    }

    #[test]
    fn the_cut_is_the_share_lost_down_to_cubics() {
        let (mut cubic, now) = at(1000 * MTU);
        cubic.on_congestion_event(now, now - RTT, false, 50 * MTU);
        assert_eq!(cubic.window, 950 * MTU);
        // More of the same flight lowers it again, from the window it had.
        cubic.on_congestion_event(now + RTT / 4, now - RTT / 2, false, 50 * MTU);
        assert_eq!(cubic.window, 900 * MTU);
        cubic.on_congestion_event(now + RTT / 2, now - RTT / 4, false, 900 * MTU);
        assert_eq!(cubic.window, 700 * MTU);
        assert_eq!(cubic.w_max, (1000 * MTU) as f64);
    }

    #[test]
    fn a_later_flight_is_counted_afresh() {
        let (mut cubic, now) = at(1000 * MTU);
        cubic.on_congestion_event(now, now - RTT, false, 15 * MTU);
        // Sent after the first loss was seen: not added to the 15.
        let later = now + RTT;
        cubic.on_congestion_event(later + RTT, later, false, 15 * MTU);
        assert_eq!(cubic.window, 1000 * MTU);
    }

    #[test]
    fn a_mark_and_persistent_congestion_are_cubics() {
        let (mut cubic, now) = at(1000 * MTU);
        cubic.on_congestion_event(now, now - RTT, false, 0);
        assert_eq!(cubic.window, 700 * MTU);
        // One cut a flight.
        cubic.on_congestion_event(now, now - RTT, false, 0);
        assert_eq!(cubic.window, 700 * MTU);
        cubic.on_congestion_event(now + RTT, now + RTT / 2, true, MTU);
        assert_eq!(cubic.window, 2 * MTU);
    }

    #[test]
    fn the_window_grows_back_after_a_cut() {
        let (mut cubic, now) = at(100 * MTU);
        cubic.on_congestion_event(now, now - RTT, false, 10 * MTU);
        assert_eq!(cubic.window, 90 * MTU);
        // Acknowledgements of the flight that lost grow nothing.
        cubic.grow(now, now - RTT, MTU, false, RTT);
        assert_eq!(cubic.window, 90 * MTU);
        let mut t = now;
        for _ in 0..20_000 {
            t += Duration::from_millis(1);
            cubic.grow(t, t - RTT / 2, MTU, false, RTT);
        }
        assert!(cubic.window > 100 * MTU, "{}", cubic.window / MTU);
        // With nothing to send it stays.
        let window = cubic.window;
        cubic.grow(t + RTT, t + RTT / 2, MTU, true, RTT);
        assert_eq!(cubic.window, window);
    }
}
