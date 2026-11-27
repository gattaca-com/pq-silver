use silver_beacon_state_data::{AGGREGATORS_PER_COMMITTEE, Slot};
use silver_common::{Nanos, ticker::SlotTicker};

use super::{
    cost_model::{CostModel, MergeShape},
    deadline_tracker::DeadlineTracker,
};

/// What the aggregator learns from its own traffic: what a prover request
/// costs, and how long before its due time each proof is read.
#[derive(Default)]
pub(super) struct Stats {
    cost: CostModel,
    /// Indexed by the aggregate proof's last local aggregator position.
    /// A reader can pull all positions at once, even when their due times
    /// differ.
    aggregate_proof_deadlines: [DeadlineTracker; AGGREGATORS_PER_COMMITTEE],
    block_proof_deadline: DeadlineTracker,
}

impl Stats {
    pub(super) fn cost(&self) -> &CostModel {
        &self.cost
    }

    pub(super) fn aggregate_proof_deadline(&self, due: Nanos, last_position: u64) -> Nanos {
        self.aggregate_proof_deadlines[deadline_index(last_position)].deadline(due)
    }

    pub(super) fn block_proof_deadline(&self, due: Nanos) -> Nanos {
        self.block_proof_deadline.deadline(due)
    }

    pub(super) fn aggregate_proof_read(
        &mut self,
        slot: Slot,
        due: Nanos,
        last_position: u64,
        ticker: &SlotTicker,
    ) {
        let tracker = &mut self.aggregate_proof_deadlines[deadline_index(last_position)];
        tracker.record_read(due, ticker.since_genesis(), ticker.slot_start(slot));
        let early_read_ms = tracker.early_read().as_millis();
        silver_log::debug!(slot, last_position, early_read_ms, "aggregate proof read");
    }

    /// A read before the previous slot opens is a stray call.
    pub(super) fn block_proof_read(&mut self, block_slot: Slot, ticker: &SlotTicker) {
        let spec = ticker.slot_start(block_slot);
        let opens = ticker.slot_start(block_slot.saturating_sub(1));
        self.block_proof_deadline.record_read(spec, ticker.since_genesis(), opens);
    }

    /// Raises the margin for a request in flight for `elapsed` once it is
    /// past its plan. Returns whether the request is overdue.
    pub(super) fn overdue(&mut self, predicted: Nanos, elapsed: Nanos) -> bool {
        self.cost.overdue(predicted, elapsed)
    }

    /// Returns the round trip over the prediction.
    /// An answer feeds the cost model only when it produced a proof.
    pub(super) fn record_answer(
        &mut self,
        shape: &MergeShape,
        predicted: Nanos,
        round_trip: Nanos,
        proved: bool,
    ) -> f64 {
        let predicted_secs = predicted.as_secs();
        let ratio = if predicted_secs > 0.0 { round_trip.as_secs() / predicted_secs } else { 0.0 };
        if proved {
            self.cost.record(shape, predicted, round_trip);
        }
        ratio
    }
}

/// A position past the last uses the last tracker.
fn deadline_index(last_position: u64) -> usize {
    last_position.min(AGGREGATORS_PER_COMMITTEE as u64 - 1) as usize
}

#[cfg(test)]
mod tests;
