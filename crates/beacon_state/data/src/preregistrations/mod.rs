mod lists;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use flux_profiler::timed;
pub use lists::{
    BuilderPreregistration, PREREGISTRATIONS_LIMIT, Preregistrations, ValidatorPreregistration,
};
use parking_lot::Mutex;

use crate::{
    reanchor::finalize_full_copies,
    ring::{Id, Reset, Ring, RingGroup, Slot},
    types::SLOTS_RING_N,
};

pub type PreregistrationsId = Id<PreregistrationsGroup>;

/// Each fork holds the whole lists behind an `Arc`, so a roll is a refcount
/// bump and a fork copies the lists only on its first write. Owner-only: a
/// slot's reuse can drop the last reference, so lock-free readers must never
/// see these lists.
pub struct PreregistrationsGroup {
    finalized: Arc<Preregistrations>,
    deltas: Ring<Self>,
    persist_lock: Mutex<()>,
}

impl RingGroup for PreregistrationsGroup {
    type Entry = Arc<Preregistrations>;
}

impl Reset for Arc<Preregistrations> {
    fn reset(&mut self) {
        *self = Arc::default();
    }

    fn reset_from(&mut self, other: &Self) {
        self.clone_from(other);
    }
}

impl PreregistrationsGroup {
    pub fn new(finalized: Preregistrations) -> Self {
        Self {
            finalized: Arc::new(finalized),
            deltas: Ring::new(SLOTS_RING_N),
            persist_lock: Mutex::new(()),
        }
    }

    /// The checkpoint encoder's only way in. Keep `f` to a bounded memcpy.
    #[inline]
    pub(crate) fn with_finalized_locked<R>(&self, f: impl FnOnce(&Preregistrations) -> R) -> R {
        let _g = self.persist_lock.lock();
        f(&self.finalized)
    }

    #[inline]
    pub fn view(&self, id: PreregistrationsId) -> &Preregistrations {
        self.deltas.get(id)
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> PreregistrationsWriteView<'_> {
        let Self { finalized, deltas, .. } = self;
        let mut fork = deltas.roll_fresh();
        fork.clone_from(finalized);
        PreregistrationsWriteView { fork }
    }

    #[inline]
    pub fn roll_from(&mut self, parent: PreregistrationsId) -> PreregistrationsWriteView<'_> {
        PreregistrationsWriteView { fork: self.deltas.roll_from(parent) }
    }

    #[timed]
    pub fn finalize(
        &mut self,
        winner: PreregistrationsId,
        survivors: &[PreregistrationsId],
    ) -> Vec<PreregistrationsId> {
        let Self { finalized, deltas, persist_lock } = self;
        finalize_full_copies(deltas, winner, survivors, |w| {
            let _g = persist_lock.lock();
            finalized.clone_from(w);
        })
    }
}

pub struct PreregistrationsWriteView<'a> {
    fork: Slot<'a, PreregistrationsGroup>,
}

impl PreregistrationsWriteView<'_> {
    #[inline]
    pub fn commit(self) -> PreregistrationsId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> &Preregistrations {
        &self.fork
    }

    /// The first call in a fork copies the lists it shares with its parent.
    #[inline]
    pub fn lists_mut(&mut self) -> &mut Preregistrations {
        Arc::make_mut(&mut self.fork)
    }
}
