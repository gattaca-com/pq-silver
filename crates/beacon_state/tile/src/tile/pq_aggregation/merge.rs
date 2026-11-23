use silver_common::{Nanos, TCacheRead, TProducer};

use super::{
    aggregation::Aggregation,
    claims::{Aggregate, Group},
    rolling::{OnChainAttestations, Proved},
    strategy::{Batch, MarginalGain},
    wire::MAX_PROOFS,
};

/// The aggregates of one attestation slot, proved as one proof. It ends when
/// the next slot starts; the rolling proof then takes it in.
pub(super) struct MergeAggregation {
    /// The votes of each aggregate.
    groups: Vec<Group>,
    pub(super) core: Aggregation<MarginalGain>,
}

impl MergeAggregation {
    pub(super) fn new(deadline: Nanos) -> Self {
        Self { groups: Vec::new(), core: Aggregation::new(deadline) }
    }

    /// `false` once the merge holds too many committees for another.
    pub(super) fn add(&mut self, aggregate: Aggregate) -> bool {
        let positions = aggregate.group.positions();
        let fits = self.core.add_proof(positions, aggregate.claims, aggregate.proof);
        if fits {
            self.groups.push(aggregate.group);
        }
        fits
    }

    /// The best proof counts as one of `MAX_PROOFS`.
    pub(super) fn next_batch(&self, now: Nanos) -> Option<Batch> {
        let limit = MAX_PROOFS - usize::from(self.core.best_proof().is_some());
        self.core.next_batch(now, limit)
    }

    pub(super) fn next_request(
        &mut self,
        now: Nanos,
        tcache: &mut TProducer,
    ) -> Option<(Batch, TCacheRead)> {
        self.next_batch(now).and_then(|batch| self.core.write_request(batch, tcache))
    }

    /// The best proof and the votes it covers. `None` without a best proof.
    pub(super) fn into_proved(self) -> Option<Proved> {
        let (claims, proof, covered) = self.core.into_best()?;
        let groups = (self.groups.into_iter().enumerate())
            .filter(|(index, _)| covered.binary_search(index).is_ok())
            .map(|(_, group)| group);
        Some(Proved::new(groups, claims, proof))
    }

    /// The attestations the best proof covers, with it, for a block body.
    pub(super) fn block_proof(&self) -> Option<(OnChainAttestations<'_>, &[u8])> {
        let (_, proof) = self.core.best_proof()?;
        let covered = Some(self.core.covered_indices());
        Some((OnChainAttestations { groups: &self.groups, covered }, proof))
    }
}
