use std::cmp::{Ordering, Reverse};

use flux::utils::ArrayVec;
use silver_beacon_state_data::{AGGREGATORS_PER_COMMITTEE, Slot};
use silver_common::ssz_view::{MAX_ATTESTATIONS_PQ, MAX_COMMITTEES_PER_SLOT_PQ};

use super::super::{
    bits::Bits,
    claims::{Committee, MAX_GROUPS},
    cost_model::CostModel,
    proof_sources::{OnChain, ProofSources},
    proved::POOL_SLOTS,
    running_proof::RunningProof,
    slot_aggregates::StoredAggregate,
    slot_votes::VoteGroup,
};

const MAX_CANDIDATES: usize =
    POOL_SLOTS as usize * MAX_COMMITTEES_PER_SLOT_PQ * AGGREGATORS_PER_COMMITTEE +
        MAX_ATTESTATIONS_PQ * MAX_COMMITTEES_PER_SLOT_PQ;

#[derive(Clone, Copy)]
pub(super) struct Touched {
    pub committee: Committee,
    pub covered: Bits,
}

#[derive(Clone, Copy)]
pub(super) enum Source {
    Aggregate(usize),
    Votes(usize),
}

#[derive(Clone, Copy)]
pub(super) struct Candidate {
    pub source: Source,
    pub touched: usize,
    pub slot: Slot,
    arrival: u64,
    head_votes: usize,
    pub useful: Bits,
    seconds: f64,
    rank: f64,
    gain: usize,
}

impl Candidate {
    fn order(&self, other: &Self) -> Ordering {
        other
            .rank
            .total_cmp(&self.rank)
            .then(other.head_votes.cmp(&self.head_votes))
            .then(self.slot.cmp(&other.slot))
            .then(other.gain.cmp(&self.gain))
            .then(self.arrival.cmp(&other.arrival))
    }

    fn rank(&mut self, covered: &Bits) {
        self.gain = self.useful.count_outside(covered);
        self.rank = match self.source {
            Source::Aggregate(_) => self.gain as f64 / self.seconds,
            Source::Votes(_) => 1.0 / self.seconds,
        };
    }
}

#[derive(Default)]
pub(super) struct PickQueue {
    touched: ArrayVec<Touched, MAX_CANDIDATES>,
    candidates: ArrayVec<Candidate, MAX_CANDIDATES>,
}

impl PickQueue {
    pub(super) fn clear(&mut self) {
        self.touched.clear();
        self.candidates.clear();
    }

    fn touch(&mut self, committee: Committee, running: &RunningProof) -> usize {
        if let Some(at) = self.touched.iter().position(|touched| touched.committee == committee) {
            return at;
        }
        let covered = running.covered(&committee);
        let at = self.touched.len();
        self.touched.push(Touched { committee, covered });
        at
    }

    pub(super) fn queue_aggregate(
        &mut self,
        index: usize,
        stored: &StoredAggregate,
        head_votes: usize,
        running: &RunningProof,
        model: &CostModel,
    ) {
        let touched = self.touch(stored.group.committee, running);
        self.push(Candidate {
            source: Source::Aggregate(index),
            touched,
            slot: stored.group.committee.slot(),
            arrival: stored.arrival,
            head_votes,
            useful: stored.useful,
            seconds: stored.seconds(model),
            rank: 0.0,
            gain: 0,
        });
    }

    pub(super) fn queue_votes(
        &mut self,
        group: VoteGroup<'_>,
        on_chain: &OnChain,
        running: &RunningProof,
        model: &CostModel,
    ) {
        let touched = self.touch(group.committee(), running);
        let mut waiting = group.waiting(&self.touched[touched].covered, on_chain).peekable();
        let Some(arrival) = waiting.peek().map(|vote| vote.arrival) else { return };
        self.push(Candidate {
            source: Source::Votes(group.index),
            touched,
            slot: group.slot(),
            arrival,
            head_votes: group.head_votes(),
            useful: waiting.map(|vote| vote.position()).collect(),
            seconds: model.signature_seconds(),
            rank: 0.0,
            gain: 0,
        });
    }

    pub(super) fn queue_block_votes<'a>(
        &mut self,
        groups: impl IntoIterator<Item = VoteGroup<'a>>,
        sources: &ProofSources,
        running: &RunningProof,
        model: &CostModel,
    ) {
        let first = self.candidates.len();
        for group in groups {
            let entry = sources.slot(group.slot()).unwrap();
            self.queue_votes(group, &entry.on_chain, running, model);
        }

        let votes = &mut self.candidates.as_mut_slice()[first..];
        if votes.len() > MAX_GROUPS {
            votes.select_nth_unstable_by_key(MAX_GROUPS - 1, |row| {
                let Source::Votes(index) = row.source else { unreachable!() };
                let group = sources.slot(row.slot).unwrap().votes.at(index);
                let first_arrival = group.votes().next().unwrap().arrival;
                (Reverse(row.head_votes), row.slot, Reverse(row.gain), first_arrival)
            });
            self.candidates.truncate(first + MAX_GROUPS);
        }
    }

    fn push(&mut self, mut candidate: Candidate) {
        candidate.rank(&self.touched[candidate.touched].covered);
        self.candidates.push(candidate);
    }

    pub(super) fn touched_mut(&mut self, row: usize) -> &mut Touched {
        &mut self.touched[row]
    }

    pub(super) fn new_votes<'a>(
        &mut self,
        aggregates: impl IntoIterator<Item = &'a StoredAggregate>,
        votes: impl IntoIterator<Item = VoteGroup<'a>>,
        proof: &RunningProof,
        sources: &ProofSources,
    ) -> usize {
        self.touched.clear();
        let mut new = 0;
        for stored in aggregates {
            let group = &stored.group;
            let row = self.touch(group.committee, proof);
            let covered = &mut self.touched[row].covered;
            new += stored.useful.count_outside(covered);
            covered.union_with(&stored.useful);
        }
        for group in votes {
            let committee = group.committee();
            let covered = self
                .touched
                .iter()
                .find(|row| row.committee == committee)
                .map_or_else(|| proof.covered(&committee), |row| row.covered);
            let on_chain = &sources.slot(group.slot()).unwrap().on_chain;
            new += group.waiting(&covered, on_chain).count();
        }
        new
    }

    pub(super) fn pop(&mut self) -> Option<Candidate> {
        let (best, _) = self
            .candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| candidate.gain > 0)
            .min_by(|(_, left), (_, right)| left.order(right))?;
        let last = self.candidates.len() - 1;
        self.candidates.swap(best, last);
        self.candidates.pop()
    }

    pub(super) fn rerank(&mut self, row: usize) {
        let covered = &self.touched[row].covered;
        for candidate in self.candidates.iter_mut().filter(|candidate| candidate.touched == row) {
            candidate.rank(covered);
        }
    }
}
