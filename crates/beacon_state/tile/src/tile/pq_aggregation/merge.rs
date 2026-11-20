use silver_common::Nanos;

use super::{
    aggregation::Aggregation,
    claims::{Aggregate, VerifiedClaims},
    strategy::{BatchLimits, Strategy},
};

/// The aggregates of one slot, proved as the proof of the block body. It has
/// no deadline: the proposer reads the best proof when it asks.
pub(super) struct MergeAggregation {
    pub(super) core: Aggregation,
}

impl MergeAggregation {
    pub(super) fn new() -> Self {
        Self { core: Aggregation::new(BatchLimits::MERGE, Strategy::MaxCoverage, Nanos::MAX) }
    }

    pub(super) fn add(&mut self, aggregate: Aggregate) {
        self.core.add(VerifiedClaims::Aggregate(aggregate));
    }

    /// The `AttestationPq` SSZ of each aggregate the best proof covers, and
    /// the proof, for a block body. `None` without a best proof.
    pub(super) fn block_proof(&self) -> Option<(Vec<&[u8]>, &[u8])> {
        let (_, proof) = self.core.proof()?;
        let attestations = self
            .core
            .covered()
            .filter_map(|verified| match verified {
                VerifiedClaims::Aggregate(aggregate) => Some(aggregate.attestation.as_slice()),
                VerifiedClaims::Vote(_) => None,
            })
            .collect();
        Some((attestations, proof))
    }
}
