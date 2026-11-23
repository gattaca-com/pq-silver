use silver_common::{
    Nanos, TCacheRead, TProducer,
    ssz_view::{ATTESTATION_DATA_SIZE, AttestationPqView, MAX_COMMITTEES_PER_SLOT_PQ},
};

use super::{
    aggregation::{Aggregation, Priority},
    arena::Arena,
    claims::Aggregate,
    strategy::{Batch, MarginalGain, Strategy},
    wire::MAX_PROOFS,
};

/// The aggregates for the block of one slot, proved as the proof of its body.
/// It ends at the block request, when the proposer reads the best proof.
pub(super) struct MergeAggregation {
    /// The `AttestationPq` SSZ of each aggregate, for the block body.
    attestations: Arena<u8>,
    strategy: MarginalGain,
    pub(super) core: Aggregation,
}

impl MergeAggregation {
    pub(super) fn new(deadline: Nanos) -> Self {
        let (attestations, strategy) = (Arena::default(), MarginalGain::default());
        Self { attestations, strategy, core: Aggregation::new(deadline) }
    }

    /// Empty again for another slot, keeping its buffers.
    pub(super) fn reset(&mut self, deadline: Nanos) {
        self.attestations.clear();
        self.strategy.clear();
        self.core.reset(deadline);
    }

    /// `false` once the merge holds too many committees for another.
    pub(super) fn add(&mut self, aggregate: Aggregate<'_>) -> bool {
        let fits = self.strategy.arrived(self.attestations.len(), aggregate.positions);
        if fits {
            self.attestations.push(aggregate.attestation);
            self.core.add_proof(aggregate.claims, aggregate.proof);
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

    /// `None` without a best proof.
    pub(super) fn block_proof(&self) -> Option<(OnChainAggregates<'_>, &[u8])> {
        let (_, proof) = self.core.best_proof()?;
        let covered = self.core.covered_indices();
        Some((OnChainAggregates { attestations: &self.attestations, covered }, proof))
    }
}

/// The block body's attestations for the aggregates the best proof covers:
/// spec `compute_on_chain_aggregate`, one per attestation data in arrival
/// order. The proof covers the union of a committee's aggregates, so they are
/// united into one.
pub struct OnChainAggregates<'a> {
    /// Each an `AttestationPq` of one committee.
    attestations: &'a Arena<u8>,
    covered: &'a [usize],
}

impl<'a> OnChainAggregates<'a> {
    pub fn len(&self) -> usize {
        self.first_of_each_data().count()
    }

    /// Appends them to `out` as an SSZ `List[AttestationPq]`. `None`, with
    /// `out` partly written, when aggregates of one committee disagree on its
    /// size.
    pub fn write_list(&self, out: &mut Vec<u8>) -> Option<()> {
        let start = out.len();
        out.resize(start + 4 * self.len(), 0);
        for (i, first) in self.first_of_each_data().enumerate() {
            let offset = (out.len() - start) as u32;
            out[start + 4 * i..start + 4 * (i + 1)].copy_from_slice(&offset.to_le_bytes());
            let data = data_of(first);
            let of_data = self.aggregates().filter(move |other| data_of(other) == data);
            let committees = (0..MAX_COMMITTEES_PER_SLOT_PQ).flat_map(|index| {
                of_data
                    .clone()
                    .filter(move |aggregate| committee_of(aggregate) == index)
                    .map(move |aggregate| (index, AttestationPqView::aggregation_bits(aggregate)))
            });
            AttestationPqView::write_committees(out, data, committees)?;
        }
        Some(())
    }

    fn aggregates(&self) -> impl Iterator<Item = &'a [u8]> + Clone {
        let attestations = self.attestations;
        self.covered.iter().map(move |&index| attestations.get(index))
    }

    fn first_of_each_data(&self) -> impl Iterator<Item = &'a [u8]> {
        let aggregates = self.aggregates();
        aggregates.clone().enumerate().filter_map(move |(at, aggregate)| {
            let data = data_of(aggregate);
            let seen = aggregates.clone().take(at).any(|earlier| data_of(earlier) == data);
            (!seen).then_some(aggregate)
        })
    }
}

fn data_of(aggregate: &[u8]) -> &[u8; ATTESTATION_DATA_SIZE] {
    AttestationPqView::data(aggregate).as_bytes()
}

fn committee_of(aggregate: &[u8]) -> usize {
    u16::from_le_bytes(*AttestationPqView::committee_bits(aggregate)).trailing_zeros() as usize
}

#[cfg(test)]
mod tests;
