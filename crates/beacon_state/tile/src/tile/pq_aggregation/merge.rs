use silver_common::{Nanos, TCacheRead, TProducer};

use super::{
    aggregation::{Aggregation, Priority, VerifiedClaims},
    claims::Aggregate,
    strategy::{Batch, MarginalGain, Strategy},
    wire::MAX_PROOFS,
};

/// The aggregates for the block of one slot, proved as the proof of its body.
/// It ends at the block request, when the proposer reads the best proof.
pub(super) struct MergeAggregation {
    /// The `AttestationPq` SSZ of each aggregate, for the block body.
    attestations: Vec<Vec<u8>>,
    strategy: MarginalGain,
    pub(super) core: Aggregation,
}

impl MergeAggregation {
    pub(super) fn new(deadline: Nanos) -> Self {
        let (attestations, strategy) = (Vec::new(), MarginalGain::default());
        Self { attestations, strategy, core: Aggregation::new(deadline) }
    }

    /// `false` once the merge holds too many committees for another.
    pub(super) fn add(&mut self, aggregate: Aggregate) -> bool {
        let fits = self.strategy.arrived(self.attestations.len(), aggregate.positions);
        if fits {
            self.attestations.push(aggregate.attestation);
            self.core.add(VerifiedClaims::Proof(aggregate.claims, aggregate.proof));
        }
        fits
    }

    /// `None` when it has nothing to send: past its deadline, stopped, or no
    /// waiting aggregate adds a position.
    pub(super) fn priority(&self, now: Nanos) -> Option<Priority> {
        self.core.priority(now, self.strategy.waiting())
    }

    /// `None` exactly when `priority` is, unless the strategy has a bug. The
    /// best proof counts as one of `MAX_PROOFS`.
    pub(super) fn next_batch(&mut self, now: Nanos) -> Option<Batch> {
        self.priority(now)?;
        let limit = MAX_PROOFS - usize::from(self.core.best_proof().is_some());
        self.core.check_batch(self.strategy.next_batch(limit), limit)
    }

    pub(super) fn next_request(
        &mut self,
        now: Nanos,
        tcache: &mut TProducer,
    ) -> Option<(Batch, TCacheRead)> {
        self.next_batch(now).and_then(|batch| self.core.write_request(batch, tcache))
    }

    pub(super) fn finish(&mut self, batch: Batch, body: Option<&[u8]>) -> Result<(), &'static str> {
        self.core.finish(&batch, body).map(|()| self.strategy.adopted(&batch))
    }

    /// The `AttestationPq` SSZ of each aggregate the best proof covers, and
    /// the proof, for a block body. `None` without a best proof.
    pub(super) fn block_proof(&self) -> Option<(impl Iterator<Item = &[u8]> + Clone, &[u8])> {
        let (_, proof) = self.core.best_proof()?;
        let attestations =
            self.core.covered_indices().iter().map(|&index| self.attestations[index].as_slice());
        Some((attestations, proof))
    }
}
