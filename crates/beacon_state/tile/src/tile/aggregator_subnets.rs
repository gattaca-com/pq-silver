use rustc_hash::FxHashMap;
use silver_beacon_state_data::Slot;
use silver_common::SlotSubnets;

/// The attestation subnets a local validator aggregates on, per slot, as the
/// VC's committee subscriptions name them.
#[derive(Default)]
pub(super) struct AggregatorSubnets {
    by_slot: FxHashMap<Slot, u64>,
}

impl AggregatorSubnets {
    pub(super) fn record(&mut self, encoded: &[u8]) {
        for SlotSubnets { slot, aggregating, .. } in SlotSubnets::decode_all(encoded) {
            if aggregating != 0 {
                *self.by_slot.entry(slot).or_default() |= aggregating;
            }
        }
    }

    pub(super) fn aggregates(&self, slot: Slot, subnet: u64) -> bool {
        subnet < u64::BITS as u64 &&
            self.by_slot.get(&slot).is_some_and(|subnets| subnets & (1 << subnet) != 0)
    }

    pub(super) fn prune_before(&mut self, floor: Slot) {
        self.by_slot.retain(|&slot, _| slot >= floor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            SlotSubnets { slot: 7, attesting: 1 << 2, aggregating: 1 << 2 },
            SlotSubnets { slot: 7, attesting: 1 << 3, aggregating: 0 },
            SlotSubnets { slot: 8, attesting: 1 << 5, aggregating: 1 << 5 },
        ]));
        subnets.record(&encoded(&[SlotSubnets { slot: 7, attesting: 1, aggregating: 1 }]));

        assert!(subnets.aggregates(7, 0) && subnets.aggregates(7, 2));
        assert!(!subnets.aggregates(7, 3), "attesting only");
        assert!(!subnets.aggregates(7, 64), "past the mask");

        subnets.prune_before(8);
        assert!(!subnets.aggregates(7, 2));
        assert!(subnets.aggregates(8, 5));
    }
}
