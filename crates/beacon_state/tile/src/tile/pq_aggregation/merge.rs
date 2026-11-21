use std::collections::{BTreeMap, btree_map::Entry};

use silver_common::{
    Nanos, TCacheRead, TProducer,
    ssz_view::{ATTESTATION_DATA_SIZE, AttestationPqView},
};

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

    /// The block body's attestations for the aggregates the best proof
    /// covers, and the proof. `None` without a best proof.
    pub(super) fn block_proof(&self) -> Option<(Vec<Vec<u8>>, &[u8])> {
        let (_, proof) = self.core.best_proof()?;
        let covered =
            self.core.covered_indices().iter().map(|&index| self.attestations[index].as_slice());
        Some((on_chain_aggregates(covered), proof))
    }
}

/// The block body's attestation for one attestation data.
struct OnChainAggregate<'a> {
    data: &'a [u8; ATTESTATION_DATA_SIZE],
    /// Each committee's votes as a `Bitlist`, by committee index.
    committees: BTreeMap<usize, Vec<u8>>,
}

impl OnChainAggregate<'_> {
    fn encode(&self) -> Vec<u8> {
        let committees = self.committees.iter().map(|(&index, votes)| (index, votes.as_slice()));
        AttestationPqView::encode_committees(self.data, committees)
            .expect("committees ascend in range")
    }
}

/// Spec `compute_on_chain_aggregate`, per attestation data in arrival order.
/// The proof covers the union of a committee's aggregates, so they are united
/// into one. Each of `aggregates` is an `AttestationPq` of one committee.
fn on_chain_aggregates<'a>(aggregates: impl Iterator<Item = &'a [u8]>) -> Vec<Vec<u8>> {
    let mut on_chain: Vec<OnChainAggregate> = Vec::new();
    for aggregate in aggregates {
        let data = AttestationPqView::data(aggregate).as_bytes();
        let committee_bits = u16::from_le_bytes(*AttestationPqView::committee_bits(aggregate));
        let votes = AttestationPqView::aggregation_bits(aggregate);
        let at = on_chain.iter().position(|held| held.data == data).unwrap_or_else(|| {
            on_chain.push(OnChainAggregate { data, committees: BTreeMap::new() });
            on_chain.len() - 1
        });
        match on_chain[at].committees.entry(committee_bits.trailing_zeros() as usize) {
            Entry::Vacant(committee) => {
                committee.insert(votes.to_vec());
            }
            Entry::Occupied(mut committee) => {
                debug_assert_eq!(committee.get().len(), votes.len(), "one committee, one length");
                committee.get_mut().iter_mut().zip(votes).for_each(|(held, votes)| *held |= votes);
            }
        }
    }
    on_chain.iter().map(OnChainAggregate::encode).collect()
}

#[cfg(test)]
mod tests;
