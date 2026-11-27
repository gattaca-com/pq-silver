use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    ops::Index,
};

use flux::timing::Nanos;
use silver_beacon_state_data::AGGREGATORS_PER_COMMITTEE;
use silver_common::{
    PqEvent, PqMergeVotes, PqTarget,
    ticker::{AGGREGATE_DUE_BPS_PQ, AGGREGATOR_DELAY_BPS, BASIS_POINTS, attestation_due_bps},
};
use silver_stages::SlotClock;

/// Slots kept for browsing; older ones are dropped.
const KEPT_SLOTS: u64 = 64;
/// A block proof reaches back a few slots, so its inputs outlive its slot.
const INPUT_MARGIN_SLOTS: u64 = 8;
/// The attestation slot a block proof's newest votes come from.
const INCLUSION_DELAY: u64 = 2;

/// Times are milliseconds since genesis; slot `s` starts at `s * slot_ms`.
pub struct TimeBase {
    genesis: Nanos,
    pub slot_ms: f64,
    pub attestation_due_ms: f64,
    pub aggregate_due_ms: f64,
    pub aggregator_delay_ms: f64,
}

impl TimeBase {
    fn new(clock: &SlotClock, gloas: bool) -> Self {
        let slot_ms = clock.slot_duration().0 as f64 / 1e6;
        let share = |bps: u64| slot_ms * bps as f64 / BASIS_POINTS as f64;
        Self {
            genesis: clock.slot_start(0),
            slot_ms,
            attestation_due_ms: share(attestation_due_bps(gloas)),
            aggregate_due_ms: share(AGGREGATE_DUE_BPS_PQ),
            aggregator_delay_ms: share(AGGREGATOR_DELAY_BPS),
        }
    }

    pub fn ms(&self, t: Nanos) -> f64 {
        t.0.saturating_sub(self.genesis.0) as f64 / 1e6
    }

    pub fn slot_start(&self, slot: u64) -> f64 {
        slot as f64 * self.slot_ms
    }

    pub fn slot_at(&self, ms: f64) -> u64 {
        (ms / self.slot_ms).max(0.0) as u64
    }

    pub fn aggregate_due(&self, slot: u64, position: u8) -> f64 {
        self.slot_start(slot) +
            self.aggregate_due_ms +
            f64::from(position) * self.aggregator_delay_ms
    }

    pub fn aggregators(&self) -> u8 {
        AGGREGATORS_PER_COMMITTEE as u8
    }
}

/// Ids stay valid while the front is pruned: an item's id is its position
/// counted from the first ever pushed.
pub struct Arena<T> {
    base: usize,
    items: VecDeque<T>,
}

impl<T> Arena<T> {
    fn new() -> Self {
        Self { base: 0, items: VecDeque::new() }
    }

    fn push(&mut self, item: T) -> usize {
        self.items.push_back(item);
        self.base + self.items.len() - 1
    }

    pub fn get(&self, id: usize) -> Option<&T> {
        id.checked_sub(self.base).and_then(|at| self.items.get(at))
    }

    fn get_mut(&mut self, id: usize) -> Option<&mut T> {
        id.checked_sub(self.base).and_then(|at| self.items.get_mut(at))
    }

    pub fn ids(&self) -> std::ops::Range<usize> {
        self.base..self.base + self.items.len()
    }

    fn prune_front(&mut self, mut keep: impl FnMut(&T) -> bool) {
        while self.items.front().is_some_and(|item| !keep(item)) {
            self.items.pop_front();
            self.base += 1;
        }
    }
}

impl<T> Index<usize> for Arena<T> {
    type Output = T;

    fn index(&self, id: usize) -> &T {
        self.get(id).expect("an id kept by a live slot")
    }
}

#[derive(Default)]
pub struct SlotInfo {
    /// Size by committee index; 0 until a vote or aggregate names it.
    pub committees: Vec<u16>,
    /// Committee and aggregator position of each local aggregation duty.
    pub duties: Vec<(u8, u8)>,
    pub votes: Vec<usize>,
    pub aggregates: Vec<usize>,
}

impl SlotInfo {
    pub fn members(&self) -> usize {
        self.committees.iter().map(|&size| usize::from(size)).sum()
    }

    fn note_committee(&mut self, committee: u8, size: u16) {
        let index = usize::from(committee);
        if self.committees.len() <= index {
            self.committees.resize(index + 1, 0);
        }
        self.committees[index] = size;
    }
}

pub struct Vote {
    pub slot: u64,
    pub committee: u8,
    pub validator: u32,
    pub received: f64,
    pub proved_by: Option<usize>,
    pub block_job: Option<usize>,
}

pub struct Aggregate {
    pub slot: u64,
    pub committee: u8,
    pub position: u8,
    pub aggregator: u32,
    pub local: bool,
    pub received: f64,
    pub attesters: u16,
    pub committee_len: u16,
    pub used_in: Option<(usize, usize)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKey {
    Aggregate { committee: u8, position: u8 },
    Block { block_slot: u64 },
}

pub struct Target {
    /// The attestation slot it is listed under: its votes', or a block's
    /// newest.
    pub slot: u64,
    pub key: TargetKey,
    /// `f64::INFINITY` until the proof is requested.
    pub read: f64,
    pub read_claims: Option<u32>,
    pub jobs: Vec<usize>,
}

pub enum Member {
    Running { job: usize, claims: usize },
    Vote(usize),
    Aggregate { index: usize, gain: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    Ok,
    Late,
    Refused(&'static str),
}

pub struct Job {
    pub id: u64,
    pub target: usize,
    pub sent: f64,
    /// `f64::INFINITY` until answered.
    pub answered: f64,
    pub claims_in: usize,
    pub new_claims: usize,
    pub claims_out: usize,
    pub outcome: JobOutcome,
    pub members: Vec<Member>,
}

impl Job {
    pub fn new_votes(&self) -> usize {
        self.members.iter().filter(|member| matches!(member, Member::Vote(_))).count()
    }

    pub fn new_aggregates(&self) -> usize {
        self.members.iter().filter(|member| matches!(member, Member::Aggregate { .. })).count()
    }
}

/// What the PQ aggregator reported, shaped for the Attestations tab.
pub struct PqData {
    pub time: TimeBase,
    pub slots: BTreeMap<u64, SlotInfo>,
    pub votes: Arena<Vote>,
    pub aggregates: Arena<Aggregate>,
    pub targets: Arena<Target>,
    pub jobs: Arena<Job>,
    target_ids: HashMap<PqTarget, usize>,
    job_ids: HashMap<u64, usize>,
    vote_ids: HashMap<(u64, u8, u16), usize>,
    arrivals: HashMap<u64, usize>,
}

impl PqData {
    pub fn new(clock: &SlotClock, gloas: bool) -> Self {
        Self {
            time: TimeBase::new(clock, gloas),
            slots: BTreeMap::new(),
            votes: Arena::new(),
            aggregates: Arena::new(),
            targets: Arena::new(),
            jobs: Arena::new(),
            target_ids: HashMap::new(),
            job_ids: HashMap::new(),
            vote_ids: HashMap::new(),
            arrivals: HashMap::new(),
        }
    }

    pub fn slot(&self, slot: u64) -> &SlotInfo {
        static EMPTY: SlotInfo = SlotInfo {
            committees: Vec::new(),
            duties: Vec::new(),
            votes: Vec::new(),
            aggregates: Vec::new(),
        };
        self.slots.get(&slot).unwrap_or(&EMPTY)
    }

    pub fn aggregates_of(&self, slot: u64) -> &[usize] {
        &self.slot(slot).aggregates
    }

    pub fn targets_of(&self, slot: u64) -> impl Iterator<Item = usize> + '_ {
        self.targets.ids().filter(move |&id| self.targets[id].slot == slot)
    }

    pub fn apply(&mut self, at: Nanos, event: PqEvent) {
        let now = self.time.ms(at);
        match event {
            PqEvent::Vote { slot, committee, position, committee_len, validator } => {
                let committee = committee as u8;
                let id = self.votes.push(Vote {
                    slot,
                    committee,
                    validator,
                    received: now,
                    proved_by: None,
                    block_job: None,
                });
                let info = self.slots.entry(slot).or_default();
                info.note_committee(committee, committee_len);
                info.votes.push(id);
                self.vote_ids.insert((slot, committee, position), id);
            }
            PqEvent::Aggregate {
                slot,
                committee,
                aggregator,
                position,
                attesters,
                committee_len,
                arrival,
            } => {
                let committee = committee as u8;
                let id = self.aggregates.push(Aggregate {
                    slot,
                    committee,
                    position,
                    aggregator,
                    local: false,
                    received: now,
                    attesters,
                    committee_len,
                    used_in: None,
                });
                let info = self.slots.entry(slot).or_default();
                info.note_committee(committee, committee_len);
                info.aggregates.push(id);
                if let Some(arrival) = arrival {
                    self.arrivals.insert(arrival, id);
                }
            }
            PqEvent::AggregateDuty { slot, committee, position, .. } => {
                let committee_u8 = committee as u8;
                self.slots.entry(slot).or_default().duties.push((committee_u8, position));
                let key = TargetKey::Aggregate { committee: committee_u8, position };
                self.target(PqTarget::Aggregate { slot, committee }, Some(key));
            }
            PqEvent::BlockDuty { block_slot } => {
                self.target(PqTarget::Block { slot: block_slot }, None);
            }
            PqEvent::MergeSent { request_id, target, claims_in, .. } => {
                let target = self.target(target, None);
                // The proof a merge builds on is the target's last good one.
                let running = (self.targets[target].jobs.iter().rev().copied()).find(|&job| {
                    self.jobs[job].outcome == JobOutcome::Ok && self.jobs[job].answered <= now
                });
                let members = running
                    .map(|job| vec![Member::Running { job, claims: claims_in as usize }])
                    .unwrap_or_default();
                let job = self.jobs.push(Job {
                    id: request_id,
                    target,
                    sent: now,
                    answered: f64::INFINITY,
                    claims_in: claims_in as usize,
                    new_claims: 0,
                    claims_out: claims_in as usize,
                    outcome: JobOutcome::Ok,
                    members,
                });
                self.targets.get_mut(target).expect("just made").jobs.push(job);
                self.job_ids.insert(request_id, job);
            }
            PqEvent::MergeProof { request_id, arrival, new_votes } => {
                let Some(&job) = self.job_ids.get(&request_id) else { return };
                let Some(&index) = self.arrivals.get(&arrival) else { return };
                let gain = usize::from(new_votes);
                if let Some(job) = self.jobs.get_mut(job) {
                    job.members.push(Member::Aggregate { index, gain });
                    job.new_claims += gain;
                }
            }
            PqEvent::MergeSettled { request_id, claims, failure } => {
                self.settle(request_id, now, claims, failure)
            }
            PqEvent::ProofRead { target, claims } => self.read(target, now, claims),
        }
    }

    pub fn apply_votes(&mut self, votes: &PqMergeVotes) {
        let Some(&job) = self.job_ids.get(&votes.request_id) else { return };
        let committee = votes.committee as u8;
        let members: Vec<Member> = (votes.positions.iter().enumerate())
            .flat_map(|(word, &bits)| {
                (0..64).filter(move |bit| bits >> bit & 1 == 1).map(move |bit| word * 64 + bit)
            })
            .filter_map(|position| {
                self.vote_ids.get(&(votes.slot, committee, position as u16)).copied()
            })
            .map(Member::Vote)
            .collect();
        if let Some(job) = self.jobs.get_mut(job) {
            job.new_claims += members.len();
            job.members.extend(members);
        }
    }

    fn target(&mut self, target: PqTarget, key: Option<TargetKey>) -> usize {
        if let Some(&id) = self.target_ids.get(&target) {
            if let (Some(key), Some(held)) = (key, self.targets.get_mut(id)) {
                held.key = key;
            }
            return id;
        }
        let (slot, key) = match target {
            PqTarget::Aggregate { slot, committee } => (
                slot,
                key.unwrap_or(TargetKey::Aggregate { committee: committee as u8, position: 0 }),
            ),
            PqTarget::Block { slot } => {
                (slot.saturating_sub(INCLUSION_DELAY), TargetKey::Block { block_slot: slot })
            }
        };
        let id = self.targets.push(Target {
            slot,
            key,
            read: f64::INFINITY,
            read_claims: None,
            jobs: Vec::new(),
        });
        self.target_ids.insert(target, id);
        id
    }

    fn settle(
        &mut self,
        request_id: u64,
        now: f64,
        claims: u32,
        failure: Option<silver_common::PqMergeFailure>,
    ) {
        let Some(&id) = self.job_ids.get(&request_id) else { return };
        let Some(job) = self.jobs.get_mut(id) else { return };
        job.answered = now;
        let read = self.targets[job.target].read;
        job.outcome = match failure {
            Some(failure) => JobOutcome::Refused(failure.reason()),
            None if now > read => JobOutcome::Late,
            None => JobOutcome::Ok,
        };
        if job.outcome != JobOutcome::Ok {
            job.new_claims = 0;
            return;
        }
        job.claims_out = claims as usize;
        self.mark_inputs(id, Some(id));
    }

    /// Points the job's votes and aggregates at it, or clears them.
    fn mark_inputs(&mut self, job: usize, by: Option<usize>) {
        let block = matches!(self.targets[self.jobs[job].target].key, TargetKey::Block { .. });
        let marks: Vec<(bool, usize, usize)> = (self.jobs[job].members.iter())
            .filter_map(|member| match *member {
                Member::Vote(index) => Some((true, index, 0)),
                Member::Aggregate { index, gain } => Some((false, index, gain)),
                Member::Running { .. } => None,
            })
            .collect();
        for (vote, index, gain) in marks {
            if vote {
                let Some(held) = self.votes.get_mut(index) else { continue };
                let slot = if block { &mut held.block_job } else { &mut held.proved_by };
                if by.is_some() && slot.is_none() || by.is_none() && *slot == Some(job) {
                    *slot = by;
                }
            } else if let Some(held) = self.aggregates.get_mut(index) &&
                (held.used_in.is_none() || by.is_none())
            {
                held.used_in = by.map(|job| (job, gain));
            }
        }
    }

    /// A proof requested: what it held was given. An aggregate proof is also
    /// published as this node's aggregate.
    fn read(&mut self, target: PqTarget, now: f64, claims: u32) {
        let id = self.target(target, None);
        let Some(held) = self.targets.get_mut(id) else { return };
        held.read = now;
        held.read_claims = Some(claims);
        let (slot, key) = (held.slot, held.key);
        let late: Vec<usize> = (held.jobs.iter().copied())
            .filter(|&job| {
                self.jobs[job].outcome == JobOutcome::Ok && self.jobs[job].answered > now
            })
            .collect();
        for job in late {
            self.mark_inputs(job, None);
            if let Some(job) = self.jobs.get_mut(job) {
                job.outcome = JobOutcome::Late;
                job.claims_out = job.claims_in;
            }
        }
        if let TargetKey::Aggregate { committee, position } = key {
            let committee_len =
                self.slot(slot).committees.get(usize::from(committee)).copied().unwrap_or(0);
            let index = self.aggregates.push(Aggregate {
                slot,
                committee,
                position,
                aggregator: 0,
                local: true,
                received: now,
                attesters: claims as u16,
                committee_len,
                used_in: None,
            });
            self.slots.entry(slot).or_default().aggregates.push(index);
        }
    }

    /// Claims of the target's proof answered by `end`; at its request, what
    /// the node said it gave.
    pub fn proven(&self, target: usize, end: f64) -> usize {
        let held = &self.targets[target];
        if end >= held.read &&
            let Some(claims) = held.read_claims
        {
            return claims as usize;
        }
        (held.jobs.iter().rev())
            .map(|&job| &self.jobs[job])
            .find(|job| job.outcome == JobOutcome::Ok && job.answered <= end)
            .map_or(0, |job| job.claims_out)
    }

    /// Votes the target could hold by `cutoff`. For a block proof, by
    /// committee of each slot it took from, the larger of the votes received
    /// and its best aggregate: a lower bound on their union.
    pub fn available(&self, target: usize, cutoff: f64) -> usize {
        let held = &self.targets[target];
        match held.key {
            TargetKey::Aggregate { committee, .. } => (self.slot(held.slot).votes.iter())
                .filter(|&&id| {
                    self.votes[id].committee == committee && self.votes[id].received <= cutoff
                })
                .count(),
            TargetKey::Block { .. } => {
                let mut slots: Vec<u64> = vec![held.slot];
                for &job in &held.jobs {
                    for member in &self.jobs[job].members {
                        let slot = match *member {
                            Member::Vote(index) => self.votes[index].slot,
                            Member::Aggregate { index, .. } => self.aggregates[index].slot,
                            Member::Running { .. } => continue,
                        };
                        if !slots.contains(&slot) {
                            slots.push(slot);
                        }
                    }
                }
                slots.into_iter().map(|slot| self.slot_votes(slot, cutoff)).sum()
            }
        }
    }

    fn slot_votes(&self, slot: u64, cutoff: f64) -> usize {
        let info = self.slot(slot);
        (0..info.committees.len() as u8)
            .map(|committee| {
                let votes = (info.votes.iter())
                    .filter(|&&id| {
                        self.votes[id].committee == committee && self.votes[id].received <= cutoff
                    })
                    .count();
                let best = (info.aggregates.iter())
                    .map(|&id| &self.aggregates[id])
                    .filter(|aggregate| {
                        aggregate.committee == committee && aggregate.received <= cutoff
                    })
                    .map(|aggregate| usize::from(aggregate.attesters))
                    .max()
                    .unwrap_or(0);
                votes.max(best)
            })
            .sum()
    }

    /// Drops slots older than the kept window, and what only they used.
    pub fn prune(&mut self, current_slot: u64) {
        let floor = current_slot.saturating_sub(KEPT_SLOTS);
        let input_floor = floor.saturating_sub(INPUT_MARGIN_SLOTS);
        self.slots.retain(|&slot, _| slot >= input_floor);
        let targets = &self.targets;
        self.jobs
            .prune_front(|job| targets.get(job.target).is_some_and(|target| target.slot >= floor));
        self.targets.prune_front(|target| target.slot >= floor);
        self.votes.prune_front(|vote| vote.slot >= input_floor);
        self.aggregates.prune_front(|aggregate| aggregate.slot >= input_floor);
        self.target_ids.retain(|_, id| *id >= self.targets.base);
        self.job_ids.retain(|_, id| *id >= self.jobs.base);
        self.vote_ids.retain(|&(slot, ..), _| slot >= input_floor);
        self.arrivals.retain(|_, id| *id >= self.aggregates.base);
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{PqMergeFailure, RefusalCode};

    use super::*;

    const GENESIS_SECS: u64 = 1_000;
    const SLOT_MS: u64 = 12_000;
    const SLOT: u64 = 10;

    fn data() -> PqData {
        PqData::new(&SlotClock::new(GENESIS_SECS, SLOT_MS), true)
    }

    fn at(slot: u64, ms: u64) -> Nanos {
        Nanos::from_millis(GENESIS_SECS * 1_000 + slot * SLOT_MS + ms)
    }

    fn vote(position: u16) -> PqEvent {
        PqEvent::Vote {
            slot: SLOT,
            committee: 0,
            position,
            committee_len: 8,
            validator: 100 + u32::from(position),
        }
    }

    fn sent(request_id: u64, target: PqTarget, claims_in: u32) -> PqEvent {
        PqEvent::MergeSent {
            request_id,
            target,
            proofs: 0,
            signatures: 0,
            claims_in,
            predicted: Nanos(0),
            idle: false,
        }
    }

    fn votes(request_id: u64, positions: &[usize]) -> PqMergeVotes {
        let mut words = [0; 32];
        positions.iter().for_each(|&position| words[position / 64] |= 1 << (position % 64));
        PqMergeVotes { request_id, slot: SLOT, committee: 0, positions: words }
    }

    fn settled(request_id: u64, claims: u32, failure: Option<PqMergeFailure>) -> PqEvent {
        PqEvent::MergeSettled { request_id, claims, failure }
    }

    const AGGREGATE_PROOF: PqTarget = PqTarget::Aggregate { slot: SLOT, committee: 0 };

    #[test]
    fn a_merge_answered_before_the_request_proves_its_votes() {
        let mut data = data();
        (0..3)
            .for_each(|position| data.apply(at(SLOT, 1_000 + u64::from(position)), vote(position)));
        data.apply(at(SLOT, 1_100), PqEvent::AggregateDuty {
            slot: SLOT,
            committee: 0,
            position: 1,
            due: Nanos(0),
        });
        data.apply(at(SLOT, 1_200), sent(7, AGGREGATE_PROOF, 0));
        data.apply_votes(&votes(7, &[0, 2]));
        data.apply(at(SLOT, 1_900), settled(7, 2, None));
        data.apply(at(SLOT, 7_000), PqEvent::ProofRead { target: AGGREGATE_PROOF, claims: 2 });

        let job = data.job_ids[&7];
        assert_eq!(data.jobs[job].outcome, JobOutcome::Ok);
        assert_eq!(data.jobs[job].new_votes(), 2);
        let proved: Vec<_> =
            data.slot(SLOT).votes.iter().map(|&id| data.votes[id].proved_by).collect();
        assert_eq!(proved, [Some(job), None, Some(job)]);
        let target = data.jobs[job].target;
        assert_eq!(data.targets[target].key, TargetKey::Aggregate { committee: 0, position: 1 });
        assert_eq!(
            (data.proven(target, f64::INFINITY), data.available(target, f64::INFINITY)),
            (2, 3)
        );
    }

    #[test]
    fn a_merge_answered_after_the_request_is_late_and_proves_nothing() {
        let mut data = data();
        data.apply(at(SLOT, 1_000), vote(0));
        data.apply(at(SLOT, 1_200), sent(7, AGGREGATE_PROOF, 0));
        data.apply_votes(&votes(7, &[0]));
        data.apply(at(SLOT, 6_000), PqEvent::ProofRead { target: AGGREGATE_PROOF, claims: 0 });
        data.apply(at(SLOT, 6_500), settled(7, 1, None));

        let job = &data.jobs[data.job_ids[&7]];
        assert_eq!(job.outcome, JobOutcome::Late);
        assert_eq!(data.votes[data.slot(SLOT).votes[0]].proved_by, None);
        assert_eq!(data.proven(job.target, f64::INFINITY), 0);
    }

    #[test]
    fn a_request_after_the_answer_turns_a_good_merge_late() {
        let mut data = data();
        data.apply(at(SLOT, 1_000), vote(0));
        data.apply(at(SLOT, 1_200), sent(7, AGGREGATE_PROOF, 0));
        data.apply_votes(&votes(7, &[0]));
        data.apply(at(SLOT, 6_500), settled(7, 1, None));
        assert_eq!(data.votes[data.slot(SLOT).votes[0]].proved_by, Some(data.job_ids[&7]));

        data.apply(at(SLOT, 6_000 - 1), PqEvent::ProofRead { target: AGGREGATE_PROOF, claims: 0 });
        assert_eq!(data.jobs[data.job_ids[&7]].outcome, JobOutcome::Late);
        assert_eq!(data.votes[data.slot(SLOT).votes[0]].proved_by, None);
    }

    #[test]
    fn a_refused_merge_keeps_its_reason_and_proves_nothing() {
        let mut data = data();
        data.apply(at(SLOT, 1_000), vote(0));
        data.apply(at(SLOT, 1_200), sent(7, AGGREGATE_PROOF, 0));
        data.apply_votes(&votes(7, &[0]));
        let refused = PqMergeFailure::ProverRefused { code: RefusalCode::InvalidSignature };
        data.apply(at(SLOT, 1_900), settled(7, 0, Some(refused)));

        let job = &data.jobs[data.job_ids[&7]];
        assert_eq!(job.outcome, JobOutcome::Refused(refused.reason()));
        assert_eq!(data.votes[data.slot(SLOT).votes[0]].proved_by, None);
    }

    #[test]
    fn a_block_merge_credits_the_aggregate_it_took() {
        let mut data = data();
        let aggregate = PqEvent::Aggregate {
            slot: SLOT,
            committee: 0,
            aggregator: 9,
            position: 2,
            attesters: 6,
            committee_len: 8,
            arrival: Some(42),
        };
        data.apply(at(SLOT, 8_500), aggregate);
        let block = PqTarget::Block { slot: SLOT + 2 };
        data.apply(at(SLOT, 8_600), PqEvent::BlockDuty { block_slot: SLOT + 2 });
        data.apply(at(SLOT, 9_000), sent(8, block, 0));
        data.apply(at(SLOT, 9_000), PqEvent::MergeProof {
            request_id: 8,
            arrival: 42,
            new_votes: 6,
        });
        data.apply(at(SLOT, 10_000), settled(8, 6, None));

        let job = data.job_ids[&8];
        let index = data.slot(SLOT).aggregates[0];
        assert_eq!(data.aggregates[index].used_in, Some((job, 6)));
        let target = data.jobs[job].target;
        assert_eq!(data.targets[target].slot, SLOT);
        assert_eq!(data.available(target, f64::INFINITY), 6);
    }

    #[test]
    fn pruning_old_slots_keeps_newer_ids_valid() {
        let mut data = data();
        data.apply(at(SLOT, 1_000), vote(0));
        let late_slot = SLOT + KEPT_SLOTS + INPUT_MARGIN_SLOTS + 1;
        let newer = PqEvent::Vote {
            slot: late_slot,
            committee: 0,
            position: 0,
            committee_len: 8,
            validator: 1,
        };
        data.apply(at(late_slot, 1_000), newer);
        data.prune(late_slot);

        assert!(data.slots.get(&SLOT).is_none());
        let id = data.slot(late_slot).votes[0];
        assert_eq!(data.votes[id].validator, 1);
        assert!(data.votes.get(id - 1).is_none());
    }
}
