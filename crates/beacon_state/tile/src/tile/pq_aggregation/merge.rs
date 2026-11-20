use silver_common::Nanos;

use super::{aggregation::Aggregation, claims::Aggregate};

/// The aggregates of one slot, proved as the proof of the block body. It has
/// no deadline: the proposer reads the best proof when it asks.
pub(super) struct MergeAggregation {
    pub(super) core: Aggregation<Aggregate>,
}

impl MergeAggregation {
    pub(super) fn new() -> Self {
        Self { core: Aggregation::new(Nanos::MAX) }
    }

    /// `false` once the merge holds too many committees for another.
    pub(super) fn add(&mut self, aggregate: Aggregate) -> bool {
        self.core.add(aggregate)
    }

    /// The `AttestationPq` SSZ of each aggregate the best proof covers, and
    /// the proof, for a block body. `None` without a best proof.
    pub(super) fn block_proof(&self) -> Option<(Vec<&[u8]>, &[u8])> {
        let (_, proof) = self.core.proof()?;
        let attestations = self.core.covered().map(|aggregate| aggregate.attestation.as_slice());
        Some((attestations.collect(), proof))
    }
}
