use silver_beacon_state_data::{B256, Slot};
use silver_common::{
    Nanos, TCacheRead, TProducer,
    ssz_view::{ATTESTATION_DATA_SIZE, AttestationPqView, SingleAttestationPqView},
};

use super::{
    aggregation::{Aggregation, Priority, VerifiedClaims},
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
            self.core.add(VerifiedClaims::Signature(vote.claim, vote.signature));
        }
        fits
    }

    /// `None` when it has nothing to send: past its deadline, stopped, or no
    /// waiting vote adds a position.
    pub(super) fn priority(&self, now: Nanos) -> Option<Priority> {
        let (deadline, waiting) = (self.core.open_deadline(now)?, self.strategy.waiting());
        (waiting > 0).then_some(Priority { merge: false, deadline, waiting })
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

    /// The `AttestationPq` of the votes the best proof covers. `None` without
    /// a best proof.
    pub(super) fn attestation(&self, committee_index: u64) -> Option<Vec<u8>> {
        self.core.best_proof()?;
        let positions = self.core.covered_indices().iter().map(|&index| self.positions[index]);
        AttestationPqView::encode_one_committee(
            &self.data,
            committee_index as usize,
            self.committee_len,
            positions,
        )
    }
}
