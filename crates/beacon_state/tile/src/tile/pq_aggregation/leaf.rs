use silver_beacon_state_data::{B256, Slot};
use silver_common::{
    Nanos, TCacheRead, TProducer,
    ssz_view::{
        ATTESTATION_DATA_SIZE, AttestationPqView, ProvedAttestationView, SingleAttestationPqView,
    },
};

use super::{
    aggregation::{Aggregation, Priority},
    claims::{VerifiedVote, Vote},
    strategy::{ArrivalOrder, Batch, Strategy},
    wire::MAX_SIGNATURES,
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LeafKey {
    pub slot: Slot,
    pub committee_index: u64,
    pub data_root: B256,
}

impl LeafKey {
    pub(super) fn new(vote: &VerifiedVote) -> Self {
        Self {
            slot: SingleAttestationPqView::data(vote.single).slot(),
            committee_index: SingleAttestationPqView::committee_index(vote.single),
            data_root: vote.data_root,
        }
    }
}

/// The votes of one committee for one attestation data, proved as a leaf.
/// The best proof is the only proof, so a batch takes up to `MAX_SIGNATURES`.
pub(super) struct LeafAggregation {
    committee_len: usize,
    data: [u8; ATTESTATION_DATA_SIZE],
    /// The committee position of each vote.
    positions: Vec<usize>,
    strategy: ArrivalOrder,
    pub(super) core: Aggregation,
}

impl LeafAggregation {
    pub(super) fn new(
        data: [u8; ATTESTATION_DATA_SIZE],
        committee_len: usize,
        deadline: Nanos,
    ) -> Self {
        let (positions, strategy) = (Vec::new(), ArrivalOrder::default());
        Self { committee_len, data, positions, strategy, core: Aggregation::new(deadline) }
    }

    /// `false` for a position beyond the largest committee.
    pub(super) fn add(&mut self, vote: Vote) -> bool {
        let fits = self.strategy.arrived(self.positions.len(), vote.committee_position);
        if fits {
            self.positions.push(vote.committee_position);
            self.core.add_signature(vote.claim, vote.signature);
        }
        fits
    }

    /// `None` when it has nothing to send: past its deadline, stopped, or no
    /// waiting vote adds a position.
    pub(super) fn priority(&self, now: Nanos) -> Option<Priority> {
        self.core.priority(now, self.strategy.waiting())
    }

    /// `None` exactly when `priority` is, unless the strategy has a bug.
    pub(super) fn next_batch(&mut self, now: Nanos) -> Option<Batch> {
        self.priority(now)?;
        self.core.check_batch(self.strategy.next_batch(MAX_SIGNATURES), MAX_SIGNATURES)
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
    pub(super) fn proved(&self, committee_index: u64) -> Option<ProvedAggregate<'_>> {
        let (_, proof) = self.core.best_proof()?;
        let committee_index = committee_index as usize;
        let attestation_len =
            AttestationPqView::one_committee_len(committee_index, self.committee_len)?;
        Some(ProvedAggregate { leaf: self, committee_index, attestation_len, proof })
    }
}

/// The best proof and the votes it covers, as a `ProvedAttestationView`.
pub struct ProvedAggregate<'a> {
    leaf: &'a LeafAggregation,
    committee_index: usize,
    attestation_len: usize,
    proof: &'a [u8],
}

impl ProvedAggregate<'_> {
    pub fn ssz_len(&self) -> usize {
        ProvedAttestationView::FIXED + self.attestation_len + self.proof.len()
    }

    pub fn write_ssz(&self, out: &mut [u8]) {
        let leaf = self.leaf;
        ProvedAttestationView::write_offsets(out, self.attestation_len);
        let (attestation, proof) =
            out[ProvedAttestationView::FIXED..].split_at_mut(self.attestation_len);
        let positions = leaf.core.covered_indices().iter().map(|&index| leaf.positions[index]);
        let written = AttestationPqView::write_one_committee(
            attestation,
            &leaf.data,
            self.committee_index,
            leaf.committee_len,
            positions,
        );
        debug_assert!(written, "votes are checked against their committee on arrival");
        proof.copy_from_slice(self.proof);
    }
}
