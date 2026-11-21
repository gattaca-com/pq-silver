use std::ops::Range;

use flux::type_hash_derive::TypeHash;

use crate::{
    StateReadView,
    types::{B256, Epoch, SLOTS_PER_EPOCH, Slot},
};

/// Identifies an attester shuffling by its epoch and attester-duty decision
/// root. Blocks after that decision can share the same shuffling across
/// branches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, TypeHash)]
pub struct ShufflingId {
    pub epoch: Epoch,
    pub dependent_root: B256,
    pub is_pq: bool,
    pub max_committees_per_slot: u64,
}

impl ShufflingId {
    pub fn from_state(view: &StateReadView<'_>, epoch: Epoch) -> Option<Self> {
        if epoch > view.slot.current_epoch().saturating_add(1) {
            return None;
        }
        let slot = view.slot.state();
        let dependent_root = view.block_roots.duty_dependent_root(
            epoch.saturating_sub(1),
            slot.latest_block_root,
            slot.slot,
        )?;
        Some(Self {
            epoch,
            dependent_root,
            is_pq: epoch >= view.imm.pq_fork_epoch,
            max_committees_per_slot: view.imm.max_committees_per_slot(epoch) as u64,
        })
    }

    pub fn decision_slot(&self) -> Slot {
        (self.epoch.saturating_sub(1) * SLOTS_PER_EPOCH).saturating_sub(1)
    }
}

pub const TARGET_COMMITTEE_SIZE: usize = 128;

/// Spec `compute_committee` over an epoch's shuffled active set: committee
/// `committee_index` of `slot` is a proportional slice, so sizes differ by at
/// most one and the committees of the epoch partition the set exactly.
pub fn committee_range(
    shuffled_len: usize,
    committees_per_slot: usize,
    slot: Slot,
    committee_index: usize,
) -> Range<usize> {
    let epoch_committee_count = committees_per_slot * SLOTS_PER_EPOCH as usize;
    let slot_in_epoch = (slot % SLOTS_PER_EPOCH) as usize;
    let index_in_epoch = slot_in_epoch * committees_per_slot + committee_index;

    let start = shuffled_len * index_in_epoch / epoch_committee_count;
    let end = shuffled_len * (index_in_epoch + 1) / epoch_committee_count;
    start..end
}

/// Spec `get_committee_count_per_slot`.
pub fn committees_per_slot(active_validator_count: usize, max_committees_per_slot: usize) -> usize {
    let per_slot = active_validator_count / SLOTS_PER_EPOCH as usize / TARGET_COMMITTEE_SIZE;
    per_slot.min(max_committees_per_slot).max(1)
}

/// Where one position of the shuffled active set attests.
pub struct CommitteeSlot {
    pub slot_in_epoch: Slot,
    pub committee_index: usize,
    pub members: Range<usize>,
}

/// Inverse of [`committee_range`]: the committee whose range holds `position`.
pub fn committee_at_position(
    shuffled_len: usize,
    committees_per_slot: usize,
    position: usize,
) -> CommitteeSlot {
    debug_assert!(position < shuffled_len);
    let epoch_committee_count = committees_per_slot * SLOTS_PER_EPOCH as usize;
    let index_in_epoch = ((position + 1) * epoch_committee_count).div_ceil(shuffled_len) - 1;
    let slot_in_epoch = (index_in_epoch / committees_per_slot) as Slot;
    let committee_index = index_in_epoch % committees_per_slot;
    CommitteeSlot {
        slot_in_epoch,
        committee_index,
        members: committee_range(shuffled_len, committees_per_slot, slot_in_epoch, committee_index),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table under the spec's `X_MAX_COMMITTEE_COUNT_PER_SLOT`.
    #[test]
    fn a_lower_cap_gives_fewer_larger_committees() {
        for (active, cap, per_slot, committee_len) in [
            (4_096, 16, 1, 128),
            (16_384, 16, 4, 128),
            (16_384, 1, 1, 512),
            (65_536, 16, 16, 128),
            (65_536, 4, 4, 512),
            (65_536, 1, 1, 2_048),
        ] {
            assert_eq!(committees_per_slot(active, cap), per_slot, "{active} under {cap}");
            assert_eq!(committee_range(active, per_slot, 0, 0).len(), committee_len);
        }
        assert_eq!(committees_per_slot(0, 16), 1, "never none");
    }
}
