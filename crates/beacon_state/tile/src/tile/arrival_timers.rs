use flux::Timer;
use silver_beacon_state_data::Slot;
use silver_common::ticker::SlotTicker;

/// When signature-verified PQ votes reach this node, as time into the slot
/// they vote in: each sample is a latency that starts at the slot's start.
pub(super) struct ArrivalTimers {
    attestation: Timer,
    aggregate: Timer,
}

impl ArrivalTimers {
    pub(super) fn new() -> Self {
        Self {
            attestation: Timer::new("silver", "pq_attestation_arrival"),
            aggregate: Timer::new("silver", "pq_aggregate_arrival"),
        }
    }

    pub(super) fn attestation(&mut self, slot: Slot, ticker: &SlotTicker) {
        self.attestation.emit_latency_from_nanos(ticker.slot_start(slot), ticker.since_genesis());
    }

    pub(super) fn aggregate(&mut self, slot: Slot, ticker: &SlotTicker) {
        self.aggregate.emit_latency_from_nanos(ticker.slot_start(slot), ticker.since_genesis());
    }
}
