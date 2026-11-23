use blst::min_pk::PublicKey;
use silver_beacon_state_data::{
    Epoch, MIN_SEED_LOOKAHEAD, RandaoMixesView, SLOTS_PER_EPOCH, Slot, StateReadView,
    StateWriterView, ValidatorsView, committee_range, committees_per_slot,
};

use crate::shuffling::{DOMAIN_BEACON_ATTESTER, Seed};

/// One epoch's attester shuffling and the committee split it implies.
pub struct EpochShuffling<'a> {
    shuffled: &'a [u32],
    pub committees_per_slot: usize,
    /// One past the largest shuffled validator index, or zero for an empty set.
    pub required_validator_count: usize,
    /// One aggregate pubkey per beacon committee, indexed
    /// `slot_in_epoch * committees_per_slot + committee_index`; `None` until
    /// the aggregates have been precomputed for this epoch.
    pub committee_aggs: Option<&'a [PublicKey]>,
}

impl<'a> EpochShuffling<'a> {
    /// Attester shuffling for `epoch`, seeded from the state's randao ring.
    pub fn from_state(rv: &StateReadView, epoch: Epoch, buf: &'a mut Vec<u32>) -> Self {
        Self::from_views(
            &rv.validators,
            &rv.randao_mixes,
            epoch,
            rv.imm.max_committees_per_slot(epoch),
            buf,
        )
    }

    pub fn lookahead(view: &StateWriterView, current_epoch: Epoch, buf: &'a mut Vec<u32>) -> Self {
        let target_epoch = current_epoch + MIN_SEED_LOOKAHEAD + 1;
        Self::from_views(
            &view.validators.reader(),
            &view.randao_mixes.reader(),
            target_epoch,
            view.imm.max_committees_per_slot(target_epoch),
            buf,
        )
    }

    pub(super) fn from_views(
        validators: &ValidatorsView,
        randao: &RandaoMixesView,
        epoch: Epoch,
        max_committees_per_slot: usize,
        buf: &'a mut Vec<u32>,
    ) -> Self {
        let seed = Seed::from_randao(randao, epoch, DOMAIN_BEACON_ATTESTER);
        validators.active_indices_into(epoch, buf);
        let required_validator_count = buf.last().map_or(0, |&i| i as usize + 1);
        seed.shuffle(buf);
        Self::new(buf, required_validator_count, max_committees_per_slot)
    }

    pub(crate) fn new(
        shuffled: &'a [u32],
        required_validator_count: usize,
        max_committees_per_slot: usize,
    ) -> Self {
        Self {
            shuffled,
            committees_per_slot: committees_per_slot(shuffled.len(), max_committees_per_slot),
            required_validator_count,
            committee_aggs: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_committees_per_slot(
        shuffled: &'a [u32],
        committees_per_slot: usize,
    ) -> Self {
        Self {
            shuffled,
            committees_per_slot,
            required_validator_count: shuffled.iter().max().map_or(0, |&i| i as usize + 1),
            committee_aggs: None,
        }
    }

    pub fn indices_in_range(&self, validators_count: usize) -> bool {
        self.required_validator_count <= validators_count
    }

    pub(crate) fn with_committee_aggs(self, committee_aggs: Option<&'a [PublicKey]>) -> Self {
        Self { committee_aggs, ..self }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.shuffled.is_empty() || self.committees_per_slot == 0
    }

    pub fn largest_committee_len(&self) -> usize {
        self.shuffled.len().div_ceil(SLOTS_PER_EPOCH as usize * self.committees_per_slot)
    }

    /// Proportional split, so sizes differ by at most one and the committees
    /// partition `shuffled` exactly — every active validator lands in one.
    pub fn committee(&self, slot: Slot, committee_index: usize) -> &'a [u32] {
        &self.shuffled
            [committee_range(self.shuffled.len(), self.committees_per_slot, slot, committee_index)]
    }
}

/// The two shufflings an attestation's target epoch may name.
pub struct ShufflingRef<'a> {
    pub curr: EpochShuffling<'a>,
    pub prev: EpochShuffling<'a>,
}

impl<'a> ShufflingRef<'a> {
    pub fn build(
        rv: &StateReadView,
        current_epoch: Epoch,
        curr_buf: &'a mut Vec<u32>,
        prev_buf: &'a mut Vec<u32>,
    ) -> Self {
        let previous_epoch = current_epoch.saturating_sub(1);
        Self {
            curr: EpochShuffling::from_state(rv, current_epoch, curr_buf),
            prev: EpochShuffling::from_state(rv, previous_epoch, prev_buf),
        }
    }

    pub(crate) fn for_target(&self, is_current: bool) -> &EpochShuffling<'a> {
        if is_current { &self.curr } else { &self.prev }
    }
}

#[cfg(test)]
mod tests {
    use super::EpochShuffling;

    #[test]
    fn committee_slicing() {
        let shuffled: Vec<u32> = (0..640).collect();
        let shuffling = EpochShuffling::with_committees_per_slot(&shuffled, 2);

        let c = shuffling.committee(0, 0);
        assert_eq!(c.len(), 10);

        let c1 = shuffling.committee(0, 1);
        assert_eq!(c1.len(), 10);
        assert_ne!(c[0], c1[0]);

        let c_last = shuffling.committee(31, 1);
        assert_eq!(c_last.len(), 10);
    }

    #[test]
    fn largest_committee_len_bounds_every_committee() {
        for (active, per_slot) in [(640, 2), (641, 2), (65_536, 1), (65_537, 1)] {
            let shuffled: Vec<u32> = (0..active).collect();
            let shuffling = &EpochShuffling::with_committees_per_slot(&shuffled, per_slot);
            let lengths = (0..32).flat_map(|slot| {
                (0..per_slot).map(move |index| shuffling.committee(slot, index).len())
            });
            assert_eq!(lengths.max(), Some(shuffling.largest_committee_len()), "{active}");
        }
    }
}
