use std::mem;

use silver_beacon_state_data::{B256, ShufflingId, Slot};
use silver_common::ssz_view::{AttestationDataView, MAX_ATTESTING_INDICES_PQ};

use super::{
    unknown_root_votes::BUFFERED_SLOTS,
    vote_candidates::{MAX_SLOT_CANDIDATES, VoteCandidates},
};
use crate::{counters::BeaconStateCounters, tile::gossip::PreparedPqAttestation};

const MAX_BUFFERED_CANDIDATES: usize = BUFFERED_SLOTS * MAX_SLOT_CANDIDATES;
/// Every vote of the slots kept.
const MAX_BUFFERED_VOTES: usize = BUFFERED_SLOTS * MAX_ATTESTING_INDICES_PQ;

/// Signature-verified PQ votes waiting for their block or its payload. The
/// checks that need the block run when it arrives.
pub(crate) struct UnknownRootPqVotes {
    candidates: VoteCandidates<BUFFERED_SLOTS>,
    votes: Box<[CandidateVotes]>,
    vote_count: usize,
}

#[derive(Default)]
pub(crate) struct CandidateVotes {
    /// The head shuffling the committee positions were read from.
    shuffling: ShufflingId,
    pub(crate) attesters: Vec<u32>,
    /// The votes a local aggregator or a local block proof proves.
    pub(crate) aggregated: Vec<PreparedPqAttestation>,
}

impl CandidateVotes {
    /// Empties the votes, keeping their buffers; returns how many there were.
    fn clear(&mut self) -> usize {
        let count = self.attesters.len();
        self.attesters.clear();
        self.aggregated.clear();
        count
    }
}

impl UnknownRootPqVotes {
    pub(crate) fn new() -> Self {
        Self {
            candidates: VoteCandidates::new(),
            votes: (0..MAX_BUFFERED_CANDIDATES).map(|_| CandidateVotes::default()).collect(),
            vote_count: 0,
        }
    }

    /// Returns whether no candidate held the vote's data before.
    pub(crate) fn insert(
        &mut self,
        data: AttestationDataView,
        data_root: B256,
        shuffling: ShufflingId,
        attester: u32,
        aggregated: Option<PreparedPqAttestation>,
    ) -> bool {
        let existing = self.candidates.find(data.slot(), data_root);
        let id = match existing {
            _ if self.vote_count == MAX_BUFFERED_VOTES => None,
            Some(id) if self.votes[id].shuffling != shuffling => None,
            Some(id) => Some(id),
            None => self.candidates.find_or_add(data, data_root).ok(),
        };
        let Some(id) = id else {
            BeaconStateCounters::UnknownRootVotesDropped.inc();
            return false;
        };
        let votes = &mut self.votes[id];
        if existing.is_none() {
            debug_assert!(votes.attesters.is_empty() && votes.aggregated.is_empty());
            votes.shuffling = shuffling;
        }
        votes.attesters.push(attester);
        votes.aggregated.extend(aggregated);
        self.vote_count += 1;
        existing.is_none()
    }

    /// The first candidate from id `from` that holds votes for a block
    /// `is_known` accepts.
    pub(crate) fn next_with_known_block(
        &self,
        from: usize,
        is_known: impl Fn(&B256) -> bool,
    ) -> Option<usize> {
        (from..MAX_BUFFERED_CANDIDATES).find(|&id| {
            !self.votes[id].attesters.is_empty() &&
                is_known(self.candidates[id].data().beacon_block_root())
        })
    }

    pub(crate) fn data(&self, id: usize) -> AttestationDataView<'_> {
        self.candidates[id].data()
    }

    pub(crate) fn shuffling(&self, id: usize) -> ShufflingId {
        self.votes[id].shuffling
    }

    /// Candidate `id`'s votes, leaving it empty until its slot is pruned.
    /// Hand them back with [`Self::recycle`] to keep their buffers.
    pub(crate) fn take(&mut self, id: usize) -> CandidateVotes {
        let votes = mem::take(&mut self.votes[id]);
        self.vote_count -= votes.attesters.len();
        votes
    }

    pub(crate) fn recycle(&mut self, id: usize, mut votes: CandidateVotes) {
        debug_assert!(self.votes[id].attesters.is_empty());
        votes.clear();
        self.votes[id] = votes;
    }

    pub(crate) fn on_slot(&mut self, slot: Slot) {
        let floor = slot.saturating_sub(1);
        let Self { candidates, votes, vote_count } = self;
        let mut expired = 0;
        for id in candidates.retained_ids().filter(|&id| candidates[id].data().slot() < floor) {
            expired += votes[id].clear();
        }
        *vote_count -= expired;
        BeaconStateCounters::UnknownRootVotesDropped.add(expired as u64);
        candidates.prune_before(floor, |_| {});
    }
}

#[cfg(test)]
mod tests {
    use silver_common::ssz_view::ATTESTATION_DATA_SIZE;

    use super::*;

    fn insert(votes: &mut UnknownRootPqVotes, slot: Slot, shuffling: u8, attester: u32) -> bool {
        let mut data = [0; ATTESTATION_DATA_SIZE];
        let root = [slot as u8; 32];
        data[..8].copy_from_slice(&slot.to_le_bytes());
        data[16..48].copy_from_slice(&root);
        let shuffling = ShufflingId { dependent_root: [shuffling; 32], ..Default::default() };
        votes.insert(AttestationDataView::new(&data), root, shuffling, attester, None)
    }

    fn attesters(votes: &UnknownRootPqVotes, slot: Slot) -> Vec<u32> {
        let id = votes.candidates.find(slot, [slot as u8; 32]);
        id.map_or_else(Vec::new, |id| votes.votes[id].attesters.clone())
    }

    #[test]
    fn votes_group_by_data_and_only_the_first_is_new() {
        let mut votes = UnknownRootPqVotes::new();
        votes.on_slot(10);
        assert!(insert(&mut votes, 10, 0, 1));
        assert!(!insert(&mut votes, 10, 0, 2));
        assert!(!insert(&mut votes, 10, 1, 3), "another shuffling is dropped");
        assert!(insert(&mut votes, 11, 0, 4));
        assert_eq!(attesters(&votes, 10), [1, 2]);

        let id = votes.next_with_known_block(0, |root| *root == [10; 32]).unwrap();
        assert_eq!(votes.take(id).attesters, [1, 2]);
        assert_eq!(votes.next_with_known_block(0, |root| *root == [10; 32]), None, "taken once");
        assert_eq!(votes.vote_count, 1);
    }

    #[test]
    fn votes_expire_once_their_slot_is_two_behind() {
        let mut votes = UnknownRootPqVotes::new();
        votes.on_slot(10);
        insert(&mut votes, 10, 0, 1);
        insert(&mut votes, 11, 0, 2);
        votes.on_slot(12);
        assert!(attesters(&votes, 10).is_empty());
        assert_eq!(attesters(&votes, 11), [2]);
        assert_eq!(votes.vote_count, 1);
    }
}
