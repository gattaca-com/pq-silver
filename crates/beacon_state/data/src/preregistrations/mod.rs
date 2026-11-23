mod list;
mod records;
#[cfg(test)]
mod tests;

use flux_profiler::timed;
use list::ListDelta;
pub use list::{FinalizedList, ListView, ListWriter};
pub use records::{BuilderPreregistration, Preregistration, ValidatorPreregistration};

use crate::{
    DecomposeError,
    reanchor::reanchor_survivors,
    ring::{Id, Reset, Ring, RingGroup, Slot},
    tree::{TreeGroup, TreeSpec, TreeWriteView},
    types::{B256, HashFormat, SLOTS_RING_N},
};

pub struct PreregistrationRoots;
impl TreeSpec for PreregistrationRoots {
    type Val = B256;
    type Page = [B256; 32];
}

type RootsGroup = TreeGroup<PreregistrationRoots>;

/// The data ring reanchors survivors at finalize while the paged roots keep
/// their ids, so a fork's id is the triple.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PreregistrationsId {
    data: Id<PreregistrationsGroup>,
    validator_roots: Id<RootsGroup>,
    builder_roots: Id<RootsGroup>,
}

/// The two finalized PQ preregistration lists. Requests append or overwrite
/// records; deposits and the epoch sweep remove them.
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
        self.validators.clear();
        self.builders.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.validators.reset_from(&other.validators);
        self.builders.reset_from(&other.builders);
    }
}

pub struct PreregistrationsGroup {
    finalized: Preregistrations,
    deltas: Ring<Self>,
    validator_roots: RootsGroup,
    builder_roots: RootsGroup,
}

impl RingGroup for PreregistrationsGroup {
    type Entry = PreregistrationsDelta;
}

impl PreregistrationsGroup {
    pub fn new(finalized: Preregistrations) -> Self {
        Self {
            validator_roots: roots_of(&finalized.validators),
            builder_roots: roots_of(&finalized.builders),
            finalized,
            deltas: Ring::new(SLOTS_RING_N),
        }
    }

    #[inline]
    pub fn finalized(&self) -> &Preregistrations {
        &self.finalized
    }

    #[inline]
    pub fn view(&self, id: PreregistrationsId) -> PreregistrationsView<'_> {
        let delta = self.deltas.get(id.data);
        PreregistrationsView {
            validators: ListView::new(
                &self.finalized.validators,
                &delta.validators,
                self.validator_roots.view(id.validator_roots),
            ),
            builders: ListView::new(
                &self.finalized.builders,
                &delta.builders,
                self.builder_roots.view(id.builder_roots),
            ),
        }
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> PreregistrationsWriteView<'_> {
        let Self { finalized, deltas, validator_roots, builder_roots } = self;
        PreregistrationsWriteView {
            base: finalized,
            fork: deltas.roll_fresh(),
            validator_roots: validator_roots.roll_fresh(),
            builder_roots: builder_roots.roll_fresh(),
        }
    }

    #[inline]
    pub fn roll_from(&mut self, parent: PreregistrationsId) -> PreregistrationsWriteView<'_> {
        let Self { finalized, deltas, validator_roots, builder_roots } = self;
        PreregistrationsWriteView {
            base: finalized,
            fork: deltas.roll_from(parent.data),
            validator_roots: validator_roots.roll_from(parent.validator_roots),
            builder_roots: builder_roots.roll_from(parent.builder_roots),
        }
    }

    /// Copy a survivor into a fresh slot and rebase it against the
    /// pre-promotion `winner`.
    fn reanchor(&mut self, survivor: Id<Self>, winner: Id<Self>) -> Id<Self> {
        let Self { finalized, deltas, .. } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.validators.rebase(&winner_delta.validators, &finalized.validators);
        fork.builders.rebase(&winner_delta.builders, &finalized.builders);
        fork.commit()
    }

    #[timed]
    pub fn finalize(
        &mut self,
        winner: PreregistrationsId,
        survivors: &[PreregistrationsId],
    ) -> Vec<PreregistrationsId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        let data_ids: Vec<_> = survivors.iter().map(|s| s.data).collect();
        self.deltas.free_outdated(&data_ids);

        let fresh = reanchor_survivors(survivors, |s| PreregistrationsId {
            data: self.reanchor(s.data, winner.data),
            ..s
        });

        let Self { finalized, deltas, validator_roots, builder_roots } = self;
        let winner_delta = deltas.get(winner.data);
        finalized.validators.promote(&winner_delta.validators);
        finalized.builders.promote(&winner_delta.builders);
        validator_roots.finalize(winner.validator_roots, survivors, |s| s.validator_roots);
        builder_roots.finalize(winner.builder_roots, survivors, |s| s.builder_roots);

        let fresh_data: Vec<_> = fresh.iter().map(|f| f.data).collect();
        deltas.free_outdated(&fresh_data);
        fresh
    }
}

fn roots_of<T: Preregistration>(list: &FinalizedList<T>) -> RootsGroup {
    let count = list.as_slice().len();
    TreeGroup::from_leaves(count, count, list.leaf_roots(), HashFormat::Progressive)
}

pub struct PreregistrationsView<'a> {
    pub validators: ListView<'a, ValidatorPreregistration>,
    pub builders: ListView<'a, BuilderPreregistration>,
}

pub struct PreregistrationsWriteView<'a> {
    base: &'a Preregistrations,
    fork: Slot<'a, PreregistrationsGroup>,
    validator_roots: TreeWriteView<'a, PreregistrationRoots>,
    builder_roots: TreeWriteView<'a, PreregistrationRoots>,
}

impl<'a> PreregistrationsWriteView<'a> {
    #[inline]
    pub fn commit(self) -> PreregistrationsId {
        PreregistrationsId {
            data: self.fork.commit(),
            validator_roots: self.validator_roots.commit(),
            builder_roots: self.builder_roots.commit(),
        }
    }

    pub fn hashed_reader(&mut self) -> PreregistrationsView<'_> {
        let Self { base, fork, validator_roots, builder_roots } = self;
        PreregistrationsView {
            validators: ListView::new(
                &base.validators,
                &fork.validators,
                validator_roots.hashed_reader(),
            ),
            builders: ListView::new(&base.builders, &fork.builders, builder_roots.hashed_reader()),
        }
    }

    #[inline]
    pub fn validators(&mut self) -> ListWriter<'_, 'a, ValidatorPreregistration> {
        ListWriter::new(&self.base.validators, &mut self.fork.validators, &mut self.validator_roots)
    }

    #[inline]
    pub fn builders(&mut self) -> ListWriter<'_, 'a, BuilderPreregistration> {
        ListWriter::new(&self.base.builders, &mut self.fork.builders, &mut self.builder_roots)
    }
}
