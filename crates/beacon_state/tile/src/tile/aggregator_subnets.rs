use rustc_hash::FxHashMap;
use silver_beacon_state_data::{AGGREGATORS_PER_COMMITTEE, Slot};
use silver_common::SlotSubnets;

const _: () = assert!(SlotSubnets::POSITIONS_PER_SUBNET == AGGREGATORS_PER_COMMITTEE as u64);

#[derive(Default)]
struct Aggregating {
    subnets: u64,
    positions: u64,
}

/// The attestation subnets a local validator aggregates on, per slot.
#[derive(Default)]
pub(super) struct AggregatorSubnets {
    by_slot: FxHashMap<Slot, Aggregating>,
}

impl AggregatorSubnets {
    pub(super) fn record(&mut self, encoded: &[u8]) {
        for SlotSubnets { slot, aggregating, aggregator_positions, .. } in
            SlotSubnets::decode_all(encoded)
        {
            if aggregating != 0 {
                let held = self.by_slot.entry(slot).or_default();
                held.subnets |= aggregating;
                held.positions |= aggregator_positions;
            }
        }
    }

    pub(super) fn aggregates(&self, slot: Slot, subnet: u64) -> bool {
        subnet < u64::BITS as u64 &&
            self.by_slot.get(&slot).is_some_and(|held| held.subnets & (1 << subnet) != 0)
    }

    /// The last place a local aggregator of `subnet` holds in its aggregation
    /// committee; the last place of all when the subscription named none.
    pub(super) fn last_position(&self, slot: Slot, subnet: u64) -> Option<u64> {
        let held = self.by_slot.get(&slot).filter(|_| self.aggregates(slot, subnet))?;
        let last = SlotSubnets::last_aggregator_position(held.positions, subnet);
        Some(last.unwrap_or(SlotSubnets::POSITIONS_PER_SUBNET - 1))
    }

    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.by_slot.retain(|&slot, _| slot >= floor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aggregating(slot: Slot, subnet: u64, aggregator_positions: u64) -> SlotSubnets {
        SlotSubnets { slot, attesting: 1 << subnet, aggregating: 1 << subnet, aggregator_positions }
    }

    fn encoded(subnets: &[SlotSubnets]) -> Vec<u8> {
        let mut out = vec![0; subnets.len() * SlotSubnets::SIZE];
        for (subnet, chunk) in subnets.iter().zip(out.chunks_exact_mut(SlotSubnets::SIZE)) {
            subnet.encode(chunk);
        }
        out
    }

    #[test]
    fn subscriptions_add_up_per_slot_and_only_aggregating_ones_count() {
        let mut subnets = AggregatorSubnets::default();
        subnets.record(&encoded(&[
            aggregating(7, 2, SlotSubnets::position_bit(2, 1)),
            SlotSubnets { slot: 7, attesting: 1 << 3, ..SlotSubnets::default() },
            aggregating(8, 5, 0),
        ]));
        subnets.record(&encoded(&[aggregating(7, 0, SlotSubnets::position_bit(0, 0))]));
        subnets.record(&encoded(&[aggregating(7, 0, SlotSubnets::position_bit(0, 2))]));

        assert!(subnets.aggregates(7, 0) && subnets.aggregates(7, 2));
        assert!(!subnets.aggregates(7, 3), "attesting only");
        assert!(!subnets.aggregates(7, 64), "past the mask");
        assert_eq!(subnets.last_position(7, 0), Some(2), "the later of two aggregators");
        assert_eq!(subnets.last_position(7, 2), Some(1));
        assert_eq!(subnets.last_position(7, 3), None, "attesting only");
        assert_eq!(subnets.last_position(8, 5), Some(3), "no place named: the last");

        subnets.prune_before(8);
        assert!(!subnets.aggregates(7, 2));
        assert!(subnets.aggregates(8, 5));
    }
}
