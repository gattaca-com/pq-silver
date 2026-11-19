use std::ops::Deref;

use super::{
    EpochGroup, EpochId,
    aggregation_committee_window::{AggregationCommittee, AggregationCommitteeWindow},
    effective_increments::EffectiveIncrements,
    finalized::EpochStateFinalized,
    ptc_window::PtcWindow,
};
use crate::{
    gloas::{PTC_WINDOW_LEN, PtcCommittee},
    pq::MIN_ATTESTATION_INCLUSION_DELAY_PQ,
    ring::{Reset, Slot as RingSlot},
    types::{Epoch, EpochState, Fork, Immutable, MIN_ATTESTATION_INCLUSION_DELAY, Slot, Version},
};

#[derive(Clone, Default)]
pub(crate) struct EpochStateDelta {
    pub(super) state: EpochState,
    // [New in Gloas]
    pub(super) ptc_window: PtcWindow,
    pub(super) increments: EffectiveIncrements,
    // [New in PQ]
    pub(super) aggregation_committee_window: AggregationCommitteeWindow,
}

impl Reset for EpochStateDelta {
    fn reset(&mut self) {
        self.state = Default::default();
        // The windows and `increments` are left as-is: every roll overwrites
        // them (`fresh` copies the base's, `reset_from` the parent's), so
        // zeroing their buffers here would be redundant work.
    }

    fn reset_from(&mut self, other: &Self) {
        self.state = other.state;
        self.ptc_window.clone_from(&other.ptc_window);
        self.increments.clone_from(&other.increments);
        self.aggregation_committee_window.clone_from(&other.aggregation_committee_window);
    }
}

/// Value-layer read over the epoch tier (base + optional per-fork delta). The
/// delta is `Some` for a fork that crossed an epoch boundary, else `None` and
/// reads fall through to the base.
#[derive(Clone, Copy)]
pub struct EpochView<'a> {
    pub(crate) read: EpochReadView<'a>,
}

#[derive(Clone, Copy)]
pub struct EpochReadView<'a> {
    base: &'a EpochStateFinalized,
    delta: Option<&'a EpochStateDelta>,
}

impl<'a> EpochView<'a> {
    #[inline]
    pub(crate) fn new(base: &'a EpochStateFinalized, delta: Option<&'a EpochStateDelta>) -> Self {
        Self { read: EpochReadView { base, delta } }
    }

    #[inline]
    pub fn increments(&self) -> &'a EffectiveIncrements {
        self.read.delta.map_or(&self.read.base.increments, |d| &d.increments)
    }
}

impl<'a> Deref for EpochView<'a> {
    type Target = EpochReadView<'a>;

    fn deref(&self) -> &Self::Target {
        &self.read
    }
}

impl<'a> EpochReadView<'a> {
    #[inline]
    pub fn state(&self) -> &'a EpochState {
        self.delta.map_or(&self.base.state, |d| &d.state)
    }

    #[inline]
    pub fn ptc_window(&self) -> &'a PtcWindow {
        self.delta.map_or(&self.base.ptc_window, |d| &d.ptc_window)
    }

    #[inline]
    pub fn aggregation_committee_window(&self) -> &'a AggregationCommitteeWindow {
        self.delta
            .map_or(&self.base.aggregation_committee_window, |d| &d.aggregation_committee_window)
    }

    /// Expected proposer at `lookahead_idx` (slots since the lookahead's
    /// anchor epoch start; the window covers current + next epoch), `None`
    /// outside the window.
    #[inline]
    pub fn proposer_at(&self, lookahead_idx: usize) -> Option<u64> {
        self.state().proposer_lookahead.get(lookahead_idx).copied()
    }

    #[inline]
    pub fn fork(&self) -> &'a Fork {
        &self.state().fork
    }

    #[inline]
    pub fn post_gloas_fork(&self, imm: &Immutable) -> bool {
        imm.is_post_gloas_fork(self.state().fork.current_version)
    }

    #[inline]
    pub fn is_pq(&self, imm: &Immutable) -> bool {
        imm.is_pq(self.state().fork.current_version)
    }

    #[inline]
    pub fn min_attestation_inclusion_delay(&self, imm: &Immutable) -> Slot {
        if self.is_pq(imm) {
            MIN_ATTESTATION_INCLUSION_DELAY_PQ
        } else {
            MIN_ATTESTATION_INCLUSION_DELAY
        }
    }

    #[inline]
    pub fn fork_version_at(&self, block_epoch: Epoch) -> Version {
        let f = &self.state().fork;
        if block_epoch >= f.epoch { f.current_version } else { f.previous_version }
    }

    #[inline]
    pub fn fork_descriptor(&self) -> (Epoch, Version, Version) {
        let f = &self.state().fork;
        (f.epoch, f.previous_version, f.current_version)
    }
}

pub struct EpochWriteView<'a> {
    base: &'a EpochStateFinalized,
    fork: RingSlot<'a, EpochGroup>,
}

impl<'a> EpochWriteView<'a> {
    /// Fresh fork: a full working copy of the base's scalars and PTC window.
    #[inline]
    pub(super) fn fresh(base: &'a EpochStateFinalized, mut fork: RingSlot<'a, EpochGroup>) -> Self {
        fork.state = base.state;
        fork.ptc_window.clone_from(&base.ptc_window);
        fork.increments.clone_from(&base.increments);
        fork.aggregation_committee_window.clone_from(&base.aggregation_committee_window);
        Self { base, fork }
    }

    /// Fork whose delta already carries its state (roll_from).
    #[inline]
    pub(super) fn derived(base: &'a EpochStateFinalized, fork: RingSlot<'a, EpochGroup>) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> EpochId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> EpochView<'_> {
        EpochView::new(self.base, Some(&self.fork))
    }

    #[inline]
    pub fn state_mut(&mut self) -> &mut EpochState {
        &mut self.fork.state
    }

    #[inline]
    pub fn set_ptc_window(&mut self, committees: Box<[PtcCommittee; PTC_WINDOW_LEN]>) {
        self.fork.ptc_window.copy_committees(&committees);
    }

    pub fn set_increments(&mut self, effective_balances: impl Iterator<Item = u64>) {
        self.fork.increments.refill(effective_balances);
    }

    #[inline]
    pub fn rotate_ptc_window(&mut self, new_last_epoch: &[PtcCommittee]) {
        self.fork.ptc_window.rotate(new_last_epoch);
    }

    pub fn rotate_aggregation_committee_window(
        &mut self,
        committees_per_slot: usize,
        committee: impl FnMut(usize, usize) -> AggregationCommittee,
    ) {
        self.fork.aggregation_committee_window.rotate(committees_per_slot, committee);
    }
}
