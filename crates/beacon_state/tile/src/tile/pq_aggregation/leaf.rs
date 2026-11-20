use silver_beacon_state_data::{B256, Slot};
use silver_common::{
    Nanos,
    ssz_view::{ATTESTATION_DATA_SIZE, AttestationPqView, SingleAttestationPqView},
};

use super::{
    aggregation::Aggregation,
    claims::{VerifiedVote, Vote},
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
pub(super) struct LeafAggregation {
    committee_len: usize,
    data: [u8; ATTESTATION_DATA_SIZE],
    pub(super) core: Aggregation<Vote>,
}

impl LeafAggregation {
    pub(super) fn new(vote: &VerifiedVote, deadline: Nanos) -> Self {
        Self {
            committee_len: vote.committee_len,
            data: *SingleAttestationPqView::data(vote.single).as_bytes(),
            core: Aggregation::new(deadline),
        }
    }

    /// `false` for a position beyond the largest committee.
    pub(super) fn add(&mut self, vote: &VerifiedVote) -> bool {
        debug_assert_eq!(SingleAttestationPqView::data(vote.single).as_bytes(), &self.data);
        debug_assert_eq!(vote.committee_len, self.committee_len);
        let signature = SingleAttestationPqView::signature(vote.single);
        let vote = Vote::new(vote.committee_position, vote.pubkey, vote.message, signature);
        self.core.add(vote)
    }

    /// The `AttestationPq` of the votes the best proof covers. `None` without
    /// a best proof.
    pub(super) fn attestation(&self, committee_index: u64) -> Option<Vec<u8>> {
        self.core.proof()?;
        let positions = self.core.covered().map(|vote| vote.committee_position);
        AttestationPqView::encode_one_committee(
            &self.data,
            committee_index as usize,
            self.committee_len,
            positions,
        )
    }
}
