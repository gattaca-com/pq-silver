mod list;
mod records;
#[cfg(test)]
mod tests;

use flux_profiler::timed;
use list::ListDelta;
pub use list::{FinalizedList, ListView, ListWriter, PREREGISTRATIONS_LIMIT, Record};
pub use records::{BuilderPreregistration, ValidatorPreregistration};

use crate::{
    DecomposeError,
    reanchor::reanchor_survivors,
    ring::{Id, Reset, Ring, RingGroup, Slot},
    types::SLOTS_RING_N,
};

pub type PreregistrationsId = Id<PreregistrationsGroup>;

/// The two finalized PQ preregistration lists. Deposit requests append or
/// overwrite records; deposits and the epoch sweep remove them.
#[derive(Default)]
pub struct Preregistrations {
    pub validators: FinalizedList<ValidatorPreregistration>,
    pub builders: FinalizedList<BuilderPreregistration>,
}

impl Preregistrations {
    pub(crate) fn from_ssz(validators: &[u8], builders: &[u8]) -> Result<Self, DecomposeError> {
        Ok(Self {
            validators: FinalizedList::from_ssz(validators, "validator_preregistrations")?,
            builders: FinalizedList::from_ssz(builders, "builder_preregistrations")?,
        })
    }
}

#[derive(Clone, Default)]
pub(crate) struct PreregistrationsDelta {
    validators: ListDelta<ValidatorPreregistration>,
    builders: ListDelta<BuilderPreregistration>,
}

impl Reset for PreregistrationsDelta {
    fn reset(&mut self) {
        // Every roll overwrites both lists: `fresh` from the base, `reset_from`
        // from the parent.
    }

    fn reset_from(&mut self, other: &Self) {
        self.validators.reset_from(&other.validators);
        self.builders.reset_from(&other.builders);
    }
}

pub struct PreregistrationsGroup {
    finalized: Preregistrations,
    deltas: Ring<Self>,
}

impl RingGroup for PreregistrationsGroup {
    type Entry = PreregistrationsDelta;
}

impl PreregistrationsGroup {
    pub fn new(finalized: Preregistrations) -> Self {
        Self { finalized, deltas: Ring::new(SLOTS_RING_N) }
    }

    #[inline]
    pub fn finalized(&self) -> &Preregistrations {
        &self.finalized
    }

    #[inline]
    pub fn view(&self, id: PreregistrationsId) -> PreregistrationsView<'_> {
        PreregistrationsView::new(&self.finalized, self.deltas.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> PreregistrationsWriteView<'_> {
        let Self { finalized, deltas } = self;
        let mut fork = deltas.roll_fresh();
        fork.validators.reset_onto(&finalized.validators);
        fork.builders.reset_onto(&finalized.builders);
        PreregistrationsWriteView { base: finalized, fork }
    }

    #[inline]
    pub fn roll_from(&mut self, parent: PreregistrationsId) -> PreregistrationsWriteView<'_> {
        let Self { finalized, deltas } = self;
        PreregistrationsWriteView { base: finalized, fork: deltas.roll_from(parent) }
    }

    /// Copy a survivor into a fresh slot and rebase it against the
    /// pre-promotion `winner`.
    fn reanchor(
        &mut self,
        survivor: PreregistrationsId,
        winner: PreregistrationsId,
    ) -> PreregistrationsId {
        let (mut fork, old, winner_delta) = self.deltas.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.validators.rebase(&winner_delta.validators);
        fork.builders.rebase(&winner_delta.builders);
        fork.commit()
    }

    #[timed]
    pub fn finalize(
        &mut self,
        winner: PreregistrationsId,
        survivors: &[PreregistrationsId],
    ) -> Vec<PreregistrationsId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner));

        let Self { finalized, deltas } = self;
        let winner_delta = deltas.get(winner);
        finalized.validators.promote(&winner_delta.validators);
        finalized.builders.promote(&winner_delta.builders);

        deltas.free_outdated(&fresh);
        fresh
    }
}

#[derive(Clone, Copy)]
pub struct PreregistrationsView<'a> {
    pub validators: ListView<'a, ValidatorPreregistration>,
    pub builders: ListView<'a, BuilderPreregistration>,
}

impl<'a> PreregistrationsView<'a> {
    fn new(base: &'a Preregistrations, delta: &'a PreregistrationsDelta) -> Self {
        Self {
            validators: ListView::new(&base.validators, &delta.validators),
            builders: ListView::new(&base.builders, &delta.builders),
        }
    }
}

pub struct PreregistrationsWriteView<'a> {
    base: &'a Preregistrations,
    fork: Slot<'a, PreregistrationsGroup>,
}

impl PreregistrationsWriteView<'_> {
    #[inline]
    pub fn commit(self) -> PreregistrationsId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> PreregistrationsView<'_> {
        PreregistrationsView::new(self.base, &self.fork)
    }

    #[inline]
    pub fn validators(&mut self) -> ListWriter<'_, ValidatorPreregistration> {
        ListWriter::new(&self.base.validators, &mut self.fork.validators)
    }

    #[inline]
    pub fn builders(&mut self) -> ListWriter<'_, BuilderPreregistration> {
        ListWriter::new(&self.base.builders, &mut self.fork.builders)
    }
}
