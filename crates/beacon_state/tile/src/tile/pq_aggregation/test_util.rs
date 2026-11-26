use std::{ops::Range, sync::OnceLock, time::Duration};

use silver_beacon_state_data::{Slot, SpecConfig};
use silver_common::{
    LeanVmReq, Nanos, TCache, TCacheId, TCacheProducer, TCacheRead,
    leanvm::{MAX_SIGNATURES, ProofBody, ProofLen},
    ssz_view::{
        ATTESTATION_DATA_SIZE, AttestationPqView, MAX_VALIDATORS_PER_COMMITTEE, SINGLE_ATT_PQ_SIZE,
    },
    ticker::SlotTicker,
};

use super::{
    claims::{Claim, ClaimCheck, Committee, VerifiedVote},
    cost_model::{CostModel, MergeShape},
    merge_planner::{Merge, MergePlanner, Scratch, Sent as Plan},
    proof_sources::ProofSources,
    proof_store::ProofStore,
    proof_targets::{LeafKey, ProofTargets, TargetKey},
    running_proof::{RunningProof, VisitMember},
    slot_aggregates::AggregateRefused,
    stats::Stats,
};

pub(super) const SLOT: Slot = 40;
pub(super) const SLOT_MS: u64 = SLOT * 12_000;

pub(super) const DATA_MARKER_AT: usize = 100;

pub(in crate::tile) fn attestation_in(
    slot: u64,
    index: usize,
    positions: impl IntoIterator<Item = usize>,
) -> Vec<u8> {
    let mut data = [3; ATTESTATION_DATA_SIZE];
    data[..8].copy_from_slice(&slot.to_le_bytes());
    AttestationPqView::encode_one_committee(&data, index, MAX_VALIDATORS_PER_COMMITTEE, positions)
        .unwrap()
}

/// One voter of a committee: its place in the committee and its claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub(super) position: usize,
    pub(super) claim: Claim,
}

/// One committee's votes for one attestation data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub(super) committee: Committee,
    pub(super) slot: Slot,
    pub(super) committee_len: usize,
    /// Ascending by position, without repeats.
    pub(super) members: Vec<Member>,
}

pub(super) const COMMITTEE_LEN: usize = 9;

/// Committee `index` voting `data` in `slot`. Position `p` is validator
/// `100 * index + p`.
pub(super) fn group_of(data: u8, slot: Slot, index: usize, positions: &[usize]) -> Group {
    let mut bytes = [data; ATTESTATION_DATA_SIZE];
    bytes[..8].copy_from_slice(&slot.to_le_bytes());
    let member = |&position: &usize| {
        let validator = (100 * index + position) as u32;
        let mut claim = [slot as u8; 64];
        claim[0] = validator as u8;
        Member { position, claim }
    };
    Group {
        committee: Committee { data: bytes, index },
        slot,
        committee_len: COMMITTEE_LEN,
        members: positions.iter().map(member).collect(),
    }
}

pub(super) fn group(slot: Slot, index: usize, positions: &[usize]) -> Group {
    group_of(1, slot, index, positions)
}

pub(super) fn claims_of(groups: &[Group]) -> Vec<Claim> {
    let mut claims: Vec<Claim> =
        groups.iter().flat_map(|group| &group.members).map(|member| member.claim).collect();
    claims.sort_unstable();
    claims.dedup();
    claims
}

pub(super) fn answer(groups: &[Group], proof: &[u8]) -> FakeProof {
    FakeProof::new(&claims_of(groups), proof)
}

pub(in crate::tile) struct FakeProof {
    pub len: ProofLen,
    pub bytes: Vec<u8>,
}

impl FakeProof {
    pub(in crate::tile) fn new(claims: &[Claim], proof: &[u8]) -> Self {
        let len = ProofLen { claims: claims.len() as u32, proof: proof.len() as u32 };
        let mut bytes = vec![0; len.bytes()];
        ProofBody::write(&mut bytes, claims.iter(), proof);
        Self { len, bytes }
    }

    pub(super) fn parse(&self) -> Result<ProofBody<'_>, &'static str> {
        self.len.split(&self.bytes).map_err(|_| "malformed response")
    }
}

pub(super) fn running_of(groups: &[Group], proof: &[u8]) -> (RunningProof, ProofStore) {
    let mut proofs = ProofStore::default();
    let mut running = RunningProof::default();
    let body = answer(groups, proof);
    running
        .settle(body.parse(), None, &mut proofs, true, &mut ClaimCheck::default(), |_, visit| {
            visit_groups(groups, visit)
        })
        .unwrap();
    (running, proofs)
}

pub(super) fn visit_groups(groups: &[Group], visit: &mut VisitMember<'_>) -> bool {
    groups.iter().all(|group| {
        group.members.iter().all(|member| {
            visit(&group.committee, group.committee_len, member.position, &member.claim)
        })
    })
}

pub(super) fn signature_batch(signatures: usize) -> MergeShape {
    MergeShape { idle: false, proofs: 0, signatures, claims_in: 0, request_bytes: 0 }
}

/// The claim of position `position` of committee `index` voting `data`, the
/// same for a vote and for an aggregate.
pub(super) fn claim_of(index: usize, data: u8, position: usize) -> Claim {
    let mut claim = [data; 64];
    claim[..8].copy_from_slice(&(position as u64).to_le_bytes());
    claim[8] = index as u8;
    claim
}

pub(super) struct AggregateFixture {
    pub attestation: Vec<u8>,
    pub attesters: Vec<u32>,
    pub claims: Vec<Claim>,
    pub proof: Vec<u8>,
}

impl AggregateFixture {
    pub(super) fn store(
        &self,
        sources: &mut ProofSources,
        proofs: &mut ProofStore,
    ) -> Result<(), AggregateRefused> {
        sources.add_aggregate(&self.attestation, &self.attesters, &self.claims, &self.proof, proofs)
    }

    pub(super) fn group(&self) -> Group {
        let (index, positions) =
            AttestationPqView::one_committee_positions(&self.attestation).unwrap();
        let data = AttestationPqView::data(&self.attestation);
        let members = positions
            .zip(&self.claims)
            .map(|(position, &claim)| Member { position, claim })
            .collect();
        Group {
            committee: Committee { data: *data.as_bytes(), index },
            slot: data.slot(),
            committee_len: MAX_VALIDATORS_PER_COMMITTEE,
            members,
        }
    }
}

/// Position `p` is validator `p`.
pub(super) fn aggregate_of(
    slot: Slot,
    index: usize,
    data: u8,
    voters: Range<usize>,
) -> AggregateFixture {
    let mut attestation = attestation_in(slot, index, voters.clone());
    attestation[4 + DATA_MARKER_AT] = data;
    let attesters = voters.clone().map(|position| position as u32).collect();
    let claims = voters.map(|position| claim_of(index, data, position)).collect();
    AggregateFixture { attestation, attesters, claims, proof: b"proof".to_vec() }
}

/// A single vote at `position` of committee `index` voting `data` in `slot`.
/// Position `p` is validator `p`. Data below 256 are those of `aggregate_of`.
pub(super) struct Single {
    pub slot: Slot,
    pub index: u64,
    pub data: u16,
    pub position: usize,
    pub committee_len: usize,
}

impl Single {
    /// Hands the vote to `use_vote`. Its signature repeats `arrival`, so a
    /// test can tell two votes apart.
    pub(super) fn with<R>(&self, arrival: u64, use_vote: impl FnOnce(&VerifiedVote) -> R) -> R {
        let mut single = [arrival as u8; SINGLE_ATT_PQ_SIZE];
        single[..8].copy_from_slice(&self.index.to_le_bytes());
        single[16..16 + ATTESTATION_DATA_SIZE].fill(3);
        single[16..24].copy_from_slice(&self.slot.to_le_bytes());
        let [low, high] = self.data.to_le_bytes();
        single[16 + DATA_MARKER_AT] = low;
        single[16 + DATA_MARKER_AT + 1] = 3 + high;
        let claim = claim_of(self.index as usize, low, self.position);
        let vote = VerifiedVote {
            single: &single,
            data_root: [low; 32],
            message: claim[32..].try_into().unwrap(),
            pubkey: claim[..32].try_into().unwrap(),
            validator: self.position as u32,
            committee_position: self.position,
            committee_len: self.committee_len,
        };
        use_vote(&vote)
    }
}

pub(super) enum Answer {
    Proof,
    Refusal,
    OtherClaims,
    Lost,
}

pub(super) struct Sent {
    pub(super) merge: Plan,
    pub(super) shape: MergeShape,
    pub(super) expected: Vec<Group>,
    picked: Merge,
    pub(super) body: Vec<u8>,
    pub(super) request: LeanVmReq,
}

impl Sent {
    fn claims(&self) -> Vec<Claim> {
        let request = self.request.split(&self.body).unwrap();
        let signatures = request.signatures.iter().map(|signed| *signed.first_chunk().unwrap());
        let children = request.children().iter().flat_map(|child| child.claims().iter().copied());
        let mut claims: Vec<_> = signatures.chain(children).collect();
        claims.sort_unstable();
        claims.dedup();
        claims
    }

    pub(super) fn aggregate_key(&self) -> LeafKey {
        let TargetKey::AggregateProof(target) = self.merge.key else {
            panic!("a block proof merge")
        };
        target
    }
}

/// Runs a planner pass and scripts the prover's response on a frozen clock.
pub(super) struct Lane {
    pub(super) sources: ProofSources,
    pub(super) proofs: ProofStore,
    pub(super) targets: ProofTargets,
    pub(super) stats: Stats,
    scratch: Box<Scratch>,
    imported: Slot,
    pub(super) ticker: SlotTicker,
    speed: u64,
    pub(super) slowdown: u64,
    pub(super) wake: Option<Nanos>,
}

impl Lane {
    pub(super) fn new(speed: u64) -> Self {
        let mut stats = Stats::default();
        let sample = signature_batch(MAX_SIGNATURES);
        let predicted = stats.cost().predict(&sample);
        stats.record_answer(&sample, predicted, predicted / speed, true);
        Self::with_stats(stats, speed)
    }

    pub(super) fn with_stats(stats: Stats, speed: u64) -> Self {
        let mut ticker = SlotTicker::new(0, &SpecConfig::mainnet(), Duration::from_secs(4));
        ticker.set_since_genesis_ms(SLOT_MS + 1_000);
        Self {
            sources: ProofSources::default(),
            proofs: ProofStore::default(),
            targets: ProofTargets::default(),
            stats,
            scratch: Box::default(),
            imported: 0,
            ticker,
            speed,
            slowdown: 1,
            wake: None,
        }
    }

    pub(super) fn now(&self) -> Nanos {
        self.ticker.since_genesis()
    }

    pub(super) fn planner(&self) -> MergePlanner<'_> {
        MergePlanner {
            sources: &self.sources,
            proofs: &self.proofs,
            targets: &self.targets,
            stats: &self.stats,
            imported: self.imported,
            now: self.now(),
        }
    }

    pub(super) fn import(&mut self, slot: Slot) {
        self.imported = slot;
    }

    /// The first millisecond of the slot clock at or after `time`.
    pub(super) fn at(&mut self, time: Nanos) {
        self.ticker.set_since_genesis_ms(time.0.div_ceil(1_000_000));
    }

    /// A vote of committee `index` whose last local aggregator holds
    /// `last_position`.
    pub(super) fn vote_of(&mut self, index: u64, last_position: u64, position: usize) {
        let committee_len = MAX_VALIDATORS_PER_COMMITTEE;
        let single = Single { slot: SLOT, index, data: 1, position, committee_len };
        self.add_vote(single, Some(last_position));
    }

    pub(super) fn add_vote(&mut self, single: Single, last_position: Option<u64>) {
        single.with(0, |vote| {
            self.sources.add_vote(vote, &mut self.proofs).unwrap();
            if let Some(position) = last_position {
                let due = self.ticker.pq_aggregate_due(single.slot, position);
                self.targets.open_aggregate_proof(
                    LeafKey::new(vote),
                    vote.committee(),
                    due,
                    position,
                );
            }
        });
    }

    pub(super) fn votes(&mut self, positions: std::ops::Range<usize>) {
        positions.for_each(|position| self.vote_of(0, 0, position));
    }

    pub(super) fn send(&mut self, idle: bool) -> Option<Sent> {
        let planner = MergePlanner {
            sources: &self.sources,
            proofs: &self.proofs,
            targets: &self.targets,
            stats: &self.stats,
            imported: self.imported,
            now: self.now(),
        };
        let mut merge = Merge::default();
        let pass = planner.plan_next_merge(idle, &mut self.scratch, &mut merge);
        self.wake = pass.wake;
        let plan = pass.sent?;
        let mut written = vec![0xAA; merge.shape().request_bytes];
        merge.write(&mut written, planner.proofs, planner.sources);

        let running = match plan.key {
            TargetKey::BlockProof(slot) => &self.targets.block_proofs()[&slot].proof,
            TargetKey::AggregateProof(key) => &self.targets.aggregate_proofs()[&key].proof,
        };
        let mut expected: Vec<_> = running
            .groups()
            .map(|held| Group {
                committee: held.committee,
                slot: held.committee.slot(),
                committee_len: held.committee_len,
                members: held
                    .positions
                    .iter()
                    .map(|position| Member { position, claim: [0; 64] })
                    .collect(),
            })
            .collect();
        assert!(merge.visit_members(
            &self.proofs,
            &self.sources,
            &mut |committee, len, position, claim| {
                let group = expected
                    .iter()
                    .position(|group| group.committee == *committee)
                    .unwrap_or_else(|| {
                        expected.push(Group {
                            committee: *committee,
                            slot: committee.slot(),
                            committee_len: len,
                            members: Vec::new(),
                        });
                        expected.len() - 1
                    });
                expected[group].members.push(Member { position, claim: *claim });
                true
            }
        ));
        for id in merge.proof_ids() {
            self.proofs.share(id);
        }
        static READ: OnceLock<TCacheRead> = OnceLock::new();
        let read = *READ.get_or_init(|| {
            TCache::producer(TCacheId::BeaconStateHandoff, 4096)
                .write_with(1, |out| out[0] = 0)
                .unwrap()
        });
        let request = merge.request(0, read, &self.proofs);
        Some(Sent {
            merge: plan,
            shape: *merge.shape(),
            picked: merge,
            expected,
            body: written,
            request,
        })
    }

    pub(super) fn send_when_due(&mut self) -> Sent {
        loop {
            if let Some(sent) = self.send(true) {
                return sent;
            }
            let wake_at = self.wake.expect("a merge is held back");
            assert!(wake_at > self.now(), "a hold ends later");
            self.at(wake_at);
        }
    }

    pub(super) fn answer(&mut self, sent: Sent, answer: Answer) -> Result<usize, &'static str> {
        let shape = sent.shape;
        let round_trip = CostModel::default().predict(&shape) * self.slowdown / self.speed;
        let predicted = self.stats.cost().predict(&shape);
        self.at(self.now() + round_trip);
        let claims = sent.claims();
        let body = match answer {
            Answer::Proof => Ok(FakeProof::new(&claims, b"proof")),
            Answer::Refusal => Err("rejected by the leanvm prover"),
            Answer::OtherClaims => Ok(FakeProof::new(&claims[1..], b"proof")),
            Answer::Lost => Err("no answer"),
        };
        let response = body.as_ref().map_err(|&reason| reason).and_then(FakeProof::parse);
        let settled = self.targets.settle(
            &sent.merge.key,
            response,
            sent.picked.running_id(),
            &mut self.proofs,
            &mut ClaimCheck::default(),
            |proofs, visit| sent.picked.visit_members(proofs, &self.sources, visit),
        );
        for id in sent.picked.proof_ids() {
            self.proofs.release(id);
        }
        self.stats.record_answer(&shape, predicted, round_trip, settled.is_ok());
        settled
    }

    /// The votes in the proof a read of committee `index` gets.
    pub(super) fn propose(&mut self, slots: &[Slot]) {
        self.targets.set_local_proposals(slots, false, &self.ticker);
    }

    pub(super) fn aggregate(&mut self, slot: Slot, index: usize, positions: Range<usize>) {
        self.add_aggregate(aggregate_of(slot, index, slot as u8, positions));
    }

    pub(super) fn add_aggregate(&mut self, aggregate: AggregateFixture) {
        let _ = aggregate.store(&mut self.sources, &mut self.proofs);
    }

    pub(super) fn take_best_aggregates(&mut self) {
        let mut after = None;
        while let Some(slot) = self.targets.next_bare_block_proof(after) {
            after = Some(slot);
            let planner = self.planner();
            let Some(best) = planner.best_aggregate(slot) else { continue };
            let id = best.proof;
            let group = best.group;
            self.targets.take_best_aggregate(slot, id, group, &mut self.proofs);
        }
    }
}
