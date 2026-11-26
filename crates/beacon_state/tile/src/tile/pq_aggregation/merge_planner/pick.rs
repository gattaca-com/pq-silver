use flux::utils::ArrayVec;
use silver_beacon_state_data::Slot;
use silver_common::{
    LeanVmReq, Nanos, TCacheRead,
    leanvm::{
        MAX_PROOF_CLAIMS, MAX_PROOFS, MAX_REQUEST_LEN, MAX_SIGNATURES, ProofLen, RequestBody,
        SIGNED_CLAIM_SIZE,
    },
    ssz_view::{ATTESTATION_DATA_SIZE, AttestationDataView, MAX_ATTESTATIONS_PQ},
};

use super::{
    super::{
        bits::Bits,
        claims::MAX_GROUPS,
        cost_model::MergeShape,
        proof_sources::ProofSources,
        proof_store::{ProofId, ProofStore},
        proved::DATA_PER_SLOT,
        running_proof::{ProvedGroup, RunningProof, VisitMember},
        slot_aggregates::StoredAggregate,
        slot_votes::{StoredVote, VoteGroup},
    },
    MergePlanner, TargetKey,
    queue::{PickQueue, Source, Touched},
};

/// The attestation data a proof names. A
/// block packs no proof that names more than `MAX_ATTESTATIONS_PQ`. A
/// running proof never drops one, so the first data in stay.
#[derive(Default)]
pub(super) struct NamedData(ArrayVec<[u8; ATTESTATION_DATA_SIZE], MAX_ATTESTATIONS_PQ>);

impl NamedData {
    pub(super) fn of(running: &RunningProof) -> Self {
        let mut named = Self::default();
        for group in running.groups() {
            named.add(&group.committee.data);
        }
        named
    }

    /// Data already named always fits.
    pub(super) fn admits(&self, data: &[u8; ATTESTATION_DATA_SIZE]) -> bool {
        let slot = AttestationDataView::new(data).slot();
        self.0.contains(data) ||
            (self.0.len() < MAX_ATTESTATIONS_PQ &&
                self.0
                    .iter()
                    .filter(|named| AttestationDataView::new(named).slot() == slot)
                    .count() <
                    DATA_PER_SLOT)
    }

    pub(super) fn add(&mut self, data: &[u8; ATTESTATION_DATA_SIZE]) {
        if !self.0.contains(data) {
            self.0.push(*data);
        }
    }

    pub(super) fn into_heads(self) -> impl Iterator<Item = (Slot, [u8; ATTESTATION_DATA_SIZE])> {
        self.0.into_iter().map(|data| (AttestationDataView::new(&data).slot(), data))
    }
}

#[derive(Clone, Copy)]
struct ProofPick {
    id: ProofId,
    aggregate: ProvedGroup,
    new_positions: Bits,
}

#[derive(Clone, Copy)]
struct VotePick {
    slot: Slot,
    index: usize,
    positions: Bits,
}

impl VotePick {
    fn votes<'a>(
        &self,
        group: VoteGroup<'a>,
    ) -> impl Iterator<Item = &'a StoredVote> + use<'a, '_> {
        group.votes().filter(|vote| self.positions.contains(vote.position()))
    }
}

#[derive(Default)]
pub(in crate::tile::pq_aggregation) struct Merge {
    running: Option<ProofId>,
    proofs: ArrayVec<ProofPick, MAX_PROOFS>,
    votes: ArrayVec<VotePick, MAX_GROUPS>,
    shape: MergeShape,
    new_votes: usize,
    /// Of the proof the answer must hold.
    groups: usize,
    claims: usize,
    data: NamedData,
}

impl MergePlanner<'_> {
    /// Takes inputs by new votes per marginal predicted second, the best
    /// first, while every cap, the fit and the growth guard allow. A pick
    /// changes only the gains of its own committee, so only those are ranked
    /// again.
    pub(super) fn pick(
        &self,
        key: &TargetKey,
        time_left: Nanos,
        idle: bool,
        scratch: &mut PickQueue,
        merge: &mut Merge,
    ) {
        let (running, _) = self.target(key);
        let model = self.stats.cost();
        let refused_in_time = |shape: &MergeShape, inputs| {
            let planned = model.planned(shape);
            if (running.id.is_some() || inputs > 1) && planned > time_left {
                return true;
            }
            let longest = model.longest_round_trip();
            let grows = longest.is_none_or(|longest| planned > Nanos(longest.0.saturating_mul(2)));
            inputs > 1 && grows
        };
        let running_len = running.id.map_or_else(ProofLen::default, |id| self.proofs.len(id));
        merge.start(running, running_len, idle);
        scratch.clear();
        match key {
            TargetKey::AggregateProof(key) => {
                if let Some(entry) = self.sources.slot(key.slot) &&
                    let Some(group) = entry.votes.group(&self.aggregate_proof(key).committee)
                {
                    scratch.queue_votes(group, &entry.on_chain, running, model);
                }
            }
            TargetKey::BlockProof(slot) => {
                for (index, stored) in self.block_aggregates(*slot) {
                    let entry = self.sources.slot(stored.group.committee.slot()).unwrap();
                    let head_votes = entry.votes.head_votes(&stored.group.committee.data);
                    scratch.queue_aggregate(index, stored, head_votes, running, model);
                }
                scratch.queue_block_votes(
                    self.block_vote_groups(*slot),
                    self.sources,
                    running,
                    model,
                );
            }
        }
        while let Some(candidate) = scratch.pop() {
            let entry = self.sources.slot(candidate.slot).unwrap();
            let covered = scratch.touched_mut(candidate.touched);
            let taken = merge.taken();
            match candidate.source {
                Source::Aggregate(index) => {
                    merge.add_aggregate(
                        entry.aggregates.at(index),
                        covered,
                        self.proofs,
                        refused_in_time,
                    );
                }
                Source::Votes(index) => {
                    let group = entry.votes.at(index);
                    merge.add_votes(group, covered, &candidate.useful, refused_in_time);
                }
            }
            if merge.taken() > taken {
                scratch.rerank(candidate.touched);
            }
        }
    }
}

impl Merge {
    fn start(&mut self, running: &RunningProof, running_len: ProofLen, idle: bool) {
        let claims = running_len.claims as usize;
        self.running = running.id;
        self.proofs.clear();
        self.votes.clear();
        self.shape = MergeShape {
            idle,
            proofs: usize::from(self.running.is_some()),
            signatures: 0,
            claims_in: claims,
            request_bytes: running_len.bytes(),
        };
        self.groups = running.groups().len();
        self.claims = claims;
        self.data = NamedData::of(running);
        self.new_votes = 0;
    }

    pub(super) fn is_empty(&self) -> bool {
        self.taken() == 0
    }

    fn taken(&self) -> usize {
        self.proofs.len() + self.shape.signatures
    }

    pub(in crate::tile::pq_aggregation) fn shape(&self) -> &MergeShape {
        &self.shape
    }

    pub(super) fn new_votes(&self) -> usize {
        self.new_votes
    }

    pub(super) fn groups_len(&self) -> usize {
        self.groups
    }

    /// Of the proof the answer must hold.
    pub(super) fn claims(&self) -> usize {
        self.claims
    }

    pub(in crate::tile::pq_aggregation) fn running_id(&self) -> Option<ProofId> {
        self.running
    }

    pub(in crate::tile::pq_aggregation) fn visit_members(
        &self,
        proofs: &ProofStore,
        sources: &ProofSources,
        visit: &mut VisitMember<'_>,
    ) -> bool {
        for picked in self.proofs.iter() {
            let group = &picked.aggregate;
            let mut records = group
                .records(proofs, picked.id)
                .filter(|&(position, _, _)| picked.new_positions.contains(position));
            if !records.all(|(position, _, claim)| {
                visit(&group.committee, group.committee_len, position, claim)
            }) {
                return false;
            }
        }
        for picked in self.votes.iter() {
            let Some(entry) = sources.slot(picked.slot) else { return false };
            let group = entry.votes.at(picked.index);
            let committee = group.committee();
            let mut votes = picked.votes(group);
            if !votes
                .all(|vote| visit(&committee, group.committee_len(), vote.position(), vote.claim()))
            {
                return false;
            }
        }
        true
    }

    pub(in crate::tile::pq_aggregation) fn proof_ids(
        &self,
    ) -> impl Iterator<Item = ProofId> + use<'_> {
        self.running.into_iter().chain(self.proofs.iter().map(|picked| picked.id))
    }

    pub(in crate::tile::pq_aggregation) fn write(
        &self,
        out: &mut [u8],
        proofs: &ProofStore,
        sources: &ProofSources,
    ) {
        let proofs = self.proof_ids().map(|id| proofs.bytes(id));
        let votes = self.votes.iter().flat_map(|picked| {
            let group = sources.slot(picked.slot).unwrap().votes.at(picked.index);
            picked.votes(group).map(StoredVote::record)
        });
        RequestBody::write(out, votes, proofs);
    }

    pub(in crate::tile::pq_aggregation) fn request(
        &self,
        request_id: u64,
        body: TCacheRead,
        proofs: &ProofStore,
    ) -> LeanVmReq {
        let mut children = [ProofLen::default(); MAX_PROOFS];
        for (child, id) in children.iter_mut().zip(self.proof_ids()) {
            *child = proofs.len(id);
        }
        LeanVmReq {
            request_id,
            signatures: self.shape.signatures as u16,
            proofs: self.shape.proofs as u8,
            children,
            body,
        }
    }

    fn add_aggregate(
        &mut self,
        stored: &StoredAggregate,
        touched: &mut Touched,
        proofs: &ProofStore,
        refused_in_time: impl Fn(&MergeShape, usize) -> bool,
    ) {
        let len = proofs.len(stored.proof);
        let claims_in = len.claims as usize;
        let covered = &touched.covered;
        let (claims, gain) =
            (stored.group.positions.count_outside(covered), stored.useful.count_outside(covered));
        let opens = usize::from(touched.covered == Bits::default());
        let shape = MergeShape {
            proofs: self.shape.proofs + 1,
            claims_in: self.shape.claims_in + claims_in,
            request_bytes: self.shape.request_bytes + len.bytes(),
            ..self.shape
        };
        if shape.proofs > MAX_PROOFS ||
            self.groups + opens > MAX_GROUPS ||
            !self.data.admits(&stored.group.committee.data)
        {
            return;
        }
        // Each claim needs a member, so with valid input `MAX_GROUPS`
        // binds before this cap does.
        if self.claims + claims > MAX_PROOF_CLAIMS {
            return;
        }
        // Proofs of `MAX_STARK_PROOF_SIZE` at most never reach this cap.
        if shape.request_bytes > MAX_REQUEST_LEN || refused_in_time(&shape, self.taken() + 1) {
            return;
        }
        let new_positions = stored.group.positions.outside(covered);
        self.commit(shape, touched, &new_positions, claims, gain);
        self.proofs.push(ProofPick { id: stored.proof, aggregate: stored.group, new_positions });
    }

    /// Takes the longest prefix of the waiting votes that every check allows.
    /// A picked aggregate may have covered some of them since they waited.
    fn add_votes(
        &mut self,
        group: VoteGroup<'_>,
        touched: &mut Touched,
        useful: &Bits,
        refused_in_time: impl Fn(&MergeShape, usize) -> bool,
    ) {
        let covered = &touched.covered;
        let opens = usize::from(touched.covered == Bits::default());
        if self.groups + opens > MAX_GROUPS || !self.data.admits(&group.committee().data) {
            return;
        }
        // Each claim needs a member, so with valid input `MAX_GROUPS` binds
        // before this cap does.
        let claims = MAX_PROOF_CLAIMS.saturating_sub(self.claims);
        let room = MAX_REQUEST_LEN.saturating_sub(self.shape.request_bytes) / SIGNED_CLAIM_SIZE;
        let signatures = MAX_SIGNATURES.saturating_sub(self.shape.signatures);
        let limit = claims.min(room).min(signatures).min(useful.count_outside(covered));
        let refused = |count| refused_in_time(&self.with_signatures(count), self.taken() + count);
        if limit == 0 || refused(1) {
            return;
        }

        let (mut taken, mut over) = (1, limit + 1);
        while over - taken > 1 {
            let middle = taken + (over - taken) / 2;
            if refused(middle) {
                over = middle;
            } else {
                taken = middle;
            }
        }

        let positions = group
            .votes()
            .map(|vote| vote.position())
            .filter(|&position| useful.contains(position) && !covered.contains(position))
            .take(taken)
            .collect();
        self.commit(self.with_signatures(taken), touched, &positions, taken, taken);
        self.votes.push(VotePick { slot: group.slot(), index: group.index, positions });
    }

    fn with_signatures(&self, count: usize) -> MergeShape {
        MergeShape {
            signatures: self.shape.signatures + count,
            request_bytes: self.shape.request_bytes + count * SIGNED_CLAIM_SIZE,
            ..self.shape
        }
    }

    /// Adds `claims` new claims at `positions` of a committee.
    /// Of those, `gain` are votes not on chain.
    fn commit(
        &mut self,
        shape: MergeShape,
        touched: &mut Touched,
        positions: &Bits,
        claims: usize,
        gain: usize,
    ) {
        debug_assert!(*positions != Bits::default());
        self.shape = shape;
        self.data.add(&touched.committee.data);
        self.groups += usize::from(touched.covered == Bits::default());
        touched.covered.union_with(positions);
        self.claims += claims;
        self.new_votes += gain;
    }
}
