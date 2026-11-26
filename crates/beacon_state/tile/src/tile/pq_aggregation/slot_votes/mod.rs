use std::cmp::Reverse;

use flux::utils::ArrayVec;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::Slot;
use silver_common::{
    leanvm::{SIGNED_CLAIM_SIZE, SignedClaim},
    ssz_view::{
        ATTESTATION_DATA_SIZE, MAX_COMMITTEES_PER_SLOT_PQ, MAX_VALIDATORS_PER_COMMITTEE,
        SingleAttestationPqView,
    },
};

use super::{
    bits::Bits,
    claims::{Claim, Committee, VerifiedVote},
    proof_sources::OnChain,
    proved::DATA_PER_SLOT,
    segments::Segments,
};

const MAX_VOTES: usize = MAX_COMMITTEES_PER_SLOT_PQ * MAX_VALIDATORS_PER_COMMITTEE;
const VOTE_BLOCKS: usize = Segments::<(), 0>::blocks(MAX_VOTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VoteRefused {
    OutsideCommittee,
    UnknownCommittee,
    BeforeFloor,
    PositionHeld,
}

pub(super) struct StoredVote {
    record: SignedClaim,
    pub arrival: u64,
    pub validator: u32,
    position: u16,
    next: u16,
}

impl StoredVote {
    pub(super) fn position(&self) -> usize {
        usize::from(self.position)
    }

    pub(super) fn claim(&self) -> &Claim {
        self.record.first_chunk().unwrap()
    }

    pub(super) fn record(&self) -> &SignedClaim {
        &self.record
    }
}

#[derive(Clone, Copy, Default)]
struct GroupRow {
    committee_len: usize,
    first: u16,
    last: u16,
    len: u16,
}

struct HeadVotes {
    data: [u8; ATTESTATION_DATA_SIZE],
    groups: [GroupRow; MAX_COMMITTEES_PER_SLOT_PQ],
    arrival: u64,
    votes: usize,
}

#[derive(Clone, Copy)]
pub(super) struct VoteGroup<'a> {
    votes: &'a SlotVotes,
    head: &'a HeadVotes,
    pub index: usize,
}

impl<'a> VoteGroup<'a> {
    fn row(&self) -> &'a GroupRow {
        &self.head.groups[self.index % MAX_COMMITTEES_PER_SLOT_PQ]
    }

    pub(super) fn slot(&self) -> Slot {
        Slot::from_le_bytes(*self.head.data.first_chunk().unwrap())
    }

    pub(super) fn committee(&self) -> Committee {
        Committee { data: self.head.data, index: self.index % MAX_COMMITTEES_PER_SLOT_PQ }
    }

    pub(super) fn len(&self) -> usize {
        usize::from(self.row().len)
    }

    pub(super) fn head_votes(&self) -> usize {
        self.head.votes
    }

    pub(super) fn votes(self) -> impl Iterator<Item = &'a StoredVote> {
        let mut next = self.row().first;
        (0..self.len()).map(move |_| {
            let vote = self.votes.log.get(usize::from(next));
            next = vote.next;
            vote
        })
    }

    pub(super) fn waiting<'b>(
        self,
        covered: &'b Bits,
        on_chain: &'b OnChain,
    ) -> impl Iterator<Item = &'a StoredVote> + use<'a, 'b> {
        self.votes().filter(move |vote| {
            !covered.contains(vote.position()) && !on_chain.contains(vote.validator)
        })
    }

    pub(super) fn committee_len(&self) -> usize {
        self.row().committee_len
    }
}

#[derive(Default)]
pub(super) struct SlotVotes {
    log: Segments<StoredVote, VOTE_BLOCKS>,
    heads: Segments<HeadVotes, VOTE_BLOCKS>,
    head_index: FxHashMap<[u8; ATTESTATION_DATA_SIZE], u16>,
    held: [Bits; MAX_COMMITTEES_PER_SLOT_PQ],
    leading: ArrayVec<usize, DATA_PER_SLOT>,
}

impl SlotVotes {
    pub(super) fn check(vote: &VerifiedVote) -> Result<Committee, VoteRefused> {
        if vote.committee_position >= vote.committee_len.min(MAX_VALIDATORS_PER_COMMITTEE) {
            return Err(VoteRefused::OutsideCommittee);
        }
        let committee = vote.committee();
        if committee.index >= MAX_COMMITTEES_PER_SLOT_PQ {
            return Err(VoteRefused::UnknownCommittee);
        }
        Ok(committee)
    }

    fn find_head(&self, data: &[u8; ATTESTATION_DATA_SIZE]) -> Option<usize> {
        self.head_index.get(data).map(|&row| usize::from(row))
    }

    pub(super) fn add(
        &mut self,
        committee: Committee,
        vote: &VerifiedVote,
        arrival: u64,
    ) -> Result<(), VoteRefused> {
        let position = vote.committee_position;
        // A position can name different validators on different shufflings.
        if !self.held[committee.index].insert(position) {
            return Err(VoteRefused::PositionHeld);
        }
        let head = self.find_head(&committee.data).unwrap_or_else(|| {
            let head = self.heads.push(HeadVotes {
                data: committee.data,
                groups: [GroupRow::default(); MAX_COMMITTEES_PER_SLOT_PQ],
                arrival,
                votes: 0,
            });
            let row = u16::try_from(head).expect("index row fits in u16");
            self.head_index.insert(committee.data, row);
            head
        });
        let new = self.log.push(StoredVote {
            record: [0; SIGNED_CLAIM_SIZE],
            arrival,
            validator: vote.validator,
            position: position as u16,
            next: 0,
        }) as u16;
        let record = &mut self.log.get_mut(usize::from(new)).record;
        record[..32].copy_from_slice(&vote.pubkey);
        record[32..64].copy_from_slice(&vote.message);
        record[64..].copy_from_slice(SingleAttestationPqView::signature(vote.single));
        let derived = self.heads.get_mut(head);
        let group = &mut derived.groups[committee.index];
        if group.len == 0 {
            *group = GroupRow { committee_len: vote.committee_len, first: new, last: new, len: 1 };
        } else {
            self.log.get_mut(usize::from(group.last)).next = new;
            group.last = new;
            group.len += 1;
        }
        derived.votes += 1;
        self.lead(head);
        Ok(())
    }

    fn lead(&mut self, head: usize) {
        let order = |index| {
            let head = self.heads.get(index);
            (Reverse(head.votes), head.arrival)
        };
        let mut at = match self.leading.iter().position(|&held| held == head) {
            Some(at) => at,
            None if !self.leading.is_full() => {
                self.leading.push(head);
                self.leading.len() - 1
            }
            None if order(head) < order(self.leading[DATA_PER_SLOT - 1]) => DATA_PER_SLOT - 1,
            None => return,
        };
        while at > 0 && order(head) < order(self.leading[at - 1]) {
            self.leading[at] = self.leading[at - 1];
            at -= 1;
        }
        self.leading[at] = head;
    }

    pub(super) fn is_empty(&self) -> bool {
        self.log.len() == 0
    }

    pub(super) fn at(&self, index: usize) -> VoteGroup<'_> {
        let head = self.heads.get(index / MAX_COMMITTEES_PER_SLOT_PQ);
        let group = VoteGroup { index, head, votes: self };
        assert!(group.len() != 0);
        group
    }

    pub(super) fn group(&self, committee: &Committee) -> Option<VoteGroup<'_>> {
        let row = self.find_head(&committee.data)?;
        let head = self.heads.get(row);
        let index = row * MAX_COMMITTEES_PER_SLOT_PQ + committee.index;
        (head.groups[committee.index].len != 0).then_some(VoteGroup { index, head, votes: self })
    }

    pub(super) fn head_votes(&self, data: &[u8; ATTESTATION_DATA_SIZE]) -> usize {
        self.find_head(data).map_or(0, |head| self.heads.get(head).votes)
    }

    pub(super) fn leading(&self) -> impl Iterator<Item = &[u8; ATTESTATION_DATA_SIZE]> {
        self.leading.iter().map(|&head| &self.heads.get(head).data)
    }

    pub(super) fn head_groups(
        &self,
        data: &[u8; ATTESTATION_DATA_SIZE],
    ) -> impl Iterator<Item = VoteGroup<'_>> + use<'_> {
        self.find_head(data).into_iter().flat_map(move |row| {
            let head = self.heads.get(row);
            (0..MAX_COMMITTEES_PER_SLOT_PQ).filter_map(move |committee| {
                let group = VoteGroup {
                    index: row * MAX_COMMITTEES_PER_SLOT_PQ + committee,
                    head,
                    votes: self,
                };
                (group.len() != 0).then_some(group)
            })
        })
    }

    pub(super) fn clear(&mut self) {
        self.log.clear();
        self.heads.clear();
        self.head_index.clear();
        self.held.fill(Bits::default());
        self.leading.clear();
    }
}

#[cfg(test)]
mod tests;
