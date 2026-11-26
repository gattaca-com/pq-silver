use std::{mem, ops::RangeInclusive};

use flux::{Timer, spine::SpineProducers};
use silver_beacon_state_data::{B256, Slot, pq::MIN_ATTESTATION_INCLUSION_DELAY_PQ};
use silver_common::{
    LeanVmResp, Nanos, TCacheProducer, TCacheReader, TProducer,
    leanvm::{ProofBody, ProofLen},
    ssz_view::{ATTESTATION_PQ_FIXED, AttestationPqView, MAX_VALIDATORS_PER_COMMITTEE},
    ticker::SlotTicker,
};

use super::{
    Claim, VerifiedVote,
    claims::ClaimCheck,
    cost_model::MergeShape,
    merge_planner::{Merge, MergePlanner, Scratch, Sent},
    proof_sources::ProofSources,
    proof_store::ProofStore,
    proof_targets::{LeafKey, ProofTargets},
    proved::POOL_SLOTS,
    running_proof::ProvedAggregate,
    slot_aggregates::AggregateRefused,
    stats::Stats,
};
use crate::{counters::BeaconStateCounters, tile::Producers};

struct InFlight {
    merge: Sent,
    predicted: Nanos,
    /// Since genesis, read once the request is written. A slow planner pass is
    /// not prover time.
    sent: Nanos,
    /// On the wall clock the round trip `Timer` uses.
    timer_start: Nanos,
}

/// The prover as the aggregator sees it: one request at a time, and none
/// before it is ready. There is one per aggregator, so its size does not
/// matter.
#[derive(Default)]
#[allow(clippy::large_enum_variant)]
enum LeanVm {
    #[default]
    NotReady,
    Idle,
    Busy {
        request_id: u64,
        in_flight: InFlight,
    },
}

impl LeanVm {
    fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    fn ready(&mut self) {
        if let Self::NotReady = self {
            *self = Self::Idle;
        }
    }

    /// Becomes idle if `request_id` is in flight, handing it back.
    fn take_answered(&mut self, request_id: u64) -> Option<InFlight> {
        match mem::take(self) {
            Self::Busy { request_id: id, in_flight } if id == request_id => {
                *self = Self::Idle;
                Some(in_flight)
            }
            other => {
                *self = other;
                None
            }
        }
    }
}

/// Why the planner runs at the end of this loop. The strongest wins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Trigger {
    /// A stored vote or aggregate, a state change, or the armed time.
    Event,
    /// A response freed the prover. A request sent now is not an idle start.
    Answer,
}

/// Events change state. Only `send_next` sends requests to leanVM.
pub struct PqAggregator {
    /// The newest slot whose block imported.
    block_imported: Slot,
    sources: ProofSources,
    proofs: ProofStore,
    targets: ProofTargets,
    /// The strongest trigger since the planner last ran.
    pending: Option<Trigger>,
    /// When the planner runs again if no event runs it first.
    timer: Option<Nanos>,
    leanvm: LeanVm,
    stats: Stats,
    scratch: Box<Scratch>,
    merge: Merge,
    claim_check: ClaimCheck,
    next_request_id: u64,
    round_trip: Timer,
}

impl Default for PqAggregator {
    fn default() -> Self {
        Self {
            block_imported: 0,
            sources: ProofSources::default(),
            proofs: ProofStore::default(),
            targets: ProofTargets::default(),
            pending: None,
            timer: None,
            leanvm: LeanVm::default(),
            stats: Stats::default(),
            scratch: Box::default(),
            merge: Merge::default(),
            claim_check: ClaimCheck::default(),
            next_request_id: 0,
            round_trip: Timer::new("silver", "leanvm_merge"),
        }
    }
}

impl PqAggregator {
    /// `last_position` is the last place a local aggregator holds in the
    /// vote's aggregation committee. It determines the aggregate proof
    /// deadline. Votes without a duty can still serve a local block proof.
    /// The first eligible vote opens its aggregate-proof target.
    pub fn add_vote(
        &mut self,
        vote: &VerifiedVote,
        last_position: Option<u64>,
        ticker: &SlotTicker,
    ) {
        let key = LeafKey::new(vote);
        if vote.committee_position >= vote.committee_len.min(MAX_VALIDATORS_PER_COMMITTEE) {
            let (committee_position, committee_len) = (vote.committee_position, vote.committee_len);
            silver_log::error!(
                slot = key.slot,
                committee_position,
                committee_len,
                "vote outside committee"
            );
            return;
        }
        if key.slot > ticker.current_slot().saturating_add(1) {
            silver_log::debug!(slot = key.slot, "vote ahead of the PQ source window");
            return;
        }
        let now = ticker.since_genesis();
        let due =
            last_position.map(|position| (position, ticker.pq_aggregate_due(key.slot, position)));
        let aggregate_proof_due =
            due.filter(|&(position, due)| now < self.stats.aggregate_proof_deadline(due, position));
        if due.is_some() && aggregate_proof_due.is_none() {
            silver_log::debug!(slot = key.slot, "vote after its aggregate proof's deadline");
        }
        if aggregate_proof_due.is_none() && !self.targets.block_wants_votes(key.slot) {
            return;
        }
        if let Err(refused) = self.sources.add_vote(vote, &mut self.proofs) {
            silver_log::debug!(slot = key.slot, ?refused, "vote not stored");
            return;
        }
        if let Some((last_position, due)) = aggregate_proof_due {
            self.targets.open_aggregate_proof(key, vote.committee(), due, last_position);
        }
        self.notify(Trigger::Event);
    }

    /// Only a newly stored aggregate triggers a pass.
    pub fn add_aggregate(
        &mut self,
        attestation: &[u8],
        attesters: &[u32],
        claims: &[Claim],
        proof: &[u8],
        ticker: &SlotTicker,
    ) {
        let ceiling = ticker.current_slot().saturating_add(1);
        let slot = (attestation.len() >= ATTESTATION_PQ_FIXED)
            .then(|| AttestationPqView::data(attestation).slot());
        if let Some(slot) = slot &&
            slot > ceiling
        {
            BeaconStateCounters::PqMergeClaimsOffered.add(claims.len() as u64);
            silver_log::debug!(slot, "aggregate ahead of the PQ source window");
            return;
        }
        match self.sources.add_aggregate(attestation, attesters, claims, proof, &mut self.proofs) {
            Ok(()) => self.notify(Trigger::Event),
            Err(AggregateRefused::Malformed) => {
                silver_log::error!(?slot, "verified aggregate does not fit a merge");
            }
            Err(refused) => {
                let slot = slot.unwrap();
                silver_log::debug!(slot, ?refused, "aggregate not stored");
            }
        }
    }

    /// A response to a request that is not in flight is logged and dropped.
    /// A body that cannot be read counts as no answer.
    pub fn on_response(&mut self, resp: LeanVmResp, now: Nanos, reader: &mut TCacheReader) {
        let request_id = resp.request_id();
        let Some(in_flight) = self.leanvm.take_answered(request_id) else {
            silver_log::error!(request_id, "leanvm response to no request in flight");
            return;
        };
        if !matches!(resp, LeanVmResp::NoAnswer { .. }) {
            self.round_trip.emit_latency_from_nanos(in_flight.timer_start, Nanos::now());
        }
        let acquired;
        let response = match resp {
            LeanVmResp::Proven { claims, proof, body, .. } => {
                // Hold the pin through settle so the checked bytes can replace the old proof.
                acquired = reader.is_open(body.id()).then(|| reader.acquire_strict(body)).flatten();
                let checked = acquired.as_ref().and_then(|read| {
                    let (body, _) = read.buffer().ok()?;
                    let proof = ProofLen { claims, proof }.split(body);
                    read.revalidate().ok()?;
                    Some(proof)
                });
                match checked {
                    Some(Ok(proof)) => Ok(proof),
                    Some(Err(reason)) => {
                        silver_log::warn!(request_id, ?reason, "leanvm response refused");
                        Err("malformed response")
                    }
                    None => {
                        silver_log::error!(request_id, "leanvm response unreadable");
                        Err("no answer")
                    }
                }
            }
            LeanVmResp::Refused { reason, .. } => {
                silver_log::warn!(request_id, ?reason, "leanvm prover rejected the batch");
                Err("rejected by the leanvm prover")
            }
            LeanVmResp::NoAnswer { .. } => Err("no answer"),
        };
        self.settle(in_flight, response, now);
        self.notify(Trigger::Answer);
    }

    pub fn on_prover_ready(&mut self) {
        self.leanvm.ready();
        self.notify(Trigger::Event);
    }

    /// Called as slot `floor + 1` starts. Its block may still take the votes
    /// and aggregates of `POOL_SLOTS` slots before `floor`.
    /// The in-flight request keeps the prover busy if its target is pruned.
    pub fn prune_before(&mut self, floor: Slot) {
        self.targets.prune_before(floor, &mut self.proofs);
        self.sources.prune_before(floor.saturating_sub(POOL_SLOTS), &mut self.proofs);
        self.notify(Trigger::Event);
    }

    /// An import can open older votes and aggregates for the next block proof.
    pub fn on_block_imported(&mut self, slot: Slot) {
        self.block_imported = self.block_imported.max(slot);
        self.notify(Trigger::Event);
    }

    /// Marks the votes of `validators` for attestation slot `slot` as included.
    pub fn on_chain(&mut self, slot: Slot, validators: &[u32]) {
        if slot >= self.block_imported {
            let imported = self.block_imported;
            silver_log::error!(slot, imported, "on-chain PQ attestation did not precede its block");
            return;
        }
        self.sources.include_on_chain(slot, validators, &mut self.proofs);
        self.notify(Trigger::Event);
    }

    /// `slots` are the block slots of `proposal_window` a local validator
    /// proposes.
    pub fn set_local_proposals(&mut self, slots: &[Slot], is_gloas: bool, ticker: &SlotTicker) {
        self.targets.set_local_proposals(slots, is_gloas, ticker);
        self.notify(Trigger::Event);
    }

    /// Whether a local block may include the votes of attestation slot `slot`.
    pub fn block_wants_votes(&self, slot: Slot) -> bool {
        self.targets.block_wants_votes(slot)
    }

    /// The block slots at `wall_slot` whose proofs may take aggregates now.
    /// The last is the last block whose pool holds `wall_slot`.
    pub fn proposal_window(wall_slot: Slot) -> RangeInclusive<Slot> {
        wall_slot + 1..=wall_slot + MIN_ATTESTATION_INCLUSION_DELAY_PQ - 1 + POOL_SLOTS
    }

    /// Keeps the stronger of `trigger` and the pending one.
    fn notify(&mut self, trigger: Trigger) {
        self.pending = Some(self.pending.map_or(trigger, |pending| pending.max(trigger)));
    }

    /// Brings the timer forward to `at`. `None` leaves it.
    fn arm(&mut self, at: Option<Nanos>) {
        if let Some(at) = at {
            self.timer = Some(self.timer.map_or(at, |held| held.min(at)));
        }
    }

    /// The tile calls this after processing the loop's events. A full tcache
    /// preserves the planner's trigger for the next loop.
    pub fn send_next(
        &mut self,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) {
        let now = ticker.since_genesis();
        if let LeanVm::Busy { in_flight, .. } = &self.leanvm {
            self.stats.overdue(in_flight.predicted, now.saturating_sub(in_flight.sent));
        }
        self.run_planner(now, ticker, tcache, producers);
    }

    fn planner(&self, now: Nanos) -> MergePlanner<'_> {
        MergePlanner {
            sources: &self.sources,
            proofs: &self.proofs,
            targets: &self.targets,
            stats: &self.stats,
            imported: self.block_imported,
            now,
        }
    }

    /// Returns the next gate of a target that still has no proof.
    fn take_best_aggregates(&mut self, now: Nanos) -> Option<Nanos> {
        let mut after = None;
        while let Some(slot) = self.targets.next_bare_block_proof(after) {
            after = Some(slot);
            let planner = self.planner(now);
            let Some(best) = planner.best_aggregate(slot) else { continue };
            let id = best.proof;
            let group = best.group;
            self.targets.take_best_aggregate(slot, id, group, &mut self.proofs);
        }
        self.planner(now).best_aggregate_gate()
    }

    /// Runs the planner if a trigger is pending or the timer is due.
    /// Block targets take their best aggregates even while the prover is busy.
    /// With a busy prover the trigger is dropped until the answer arrives.
    fn run_planner(
        &mut self,
        now: Nanos,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) {
        if self.timer.is_some_and(|at| now >= at) {
            self.timer = None;
            self.notify(Trigger::Event);
        }
        let Some(trigger) = self.pending.take() else { return };
        let gate = self.take_best_aggregates(now);
        if !self.leanvm.is_idle() {
            self.arm(gate);
            return;
        }
        let planner = MergePlanner {
            sources: &self.sources,
            proofs: &self.proofs,
            targets: &self.targets,
            stats: &self.stats,
            imported: self.block_imported,
            now,
        };
        let pass =
            planner.plan_next_merge(trigger != Trigger::Answer, &mut self.scratch, &mut self.merge);
        self.timer = pass.wake;
        let Some(merge) = pass.sent else { return };
        let Some(body) = tcache.write_with(self.merge.shape().request_bytes, |out| {
            self.merge.write(out, planner.proofs, planner.sources)
        }) else {
            self.pending = Some(trigger);
            return;
        };
        for id in self.merge.proof_ids() {
            self.proofs.share(id);
        }
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        let shape = self.merge.shape();
        let predicted = self.stats.cost().predict(shape);
        let sent = ticker.since_genesis();
        let timer_start = Nanos::now();
        let in_flight = InFlight { merge, predicted, sent, timer_start };
        self.leanvm = LeanVm::Busy { request_id, in_flight };
        producers.produce(self.merge.request(request_id, body, &self.proofs));
    }

    /// A read without a target does not train the deadline estimate.
    pub fn aggregate(
        &mut self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
        ticker: &SlotTicker,
    ) -> Option<ProvedAggregate<'_>> {
        let key = LeafKey { slot, committee_index, data_root };
        self.notify(Trigger::Event);
        let target = self.targets.aggregate_proofs().get(&key)?;
        self.stats.aggregate_proof_read(key.slot, target.due, target.last_position, ticker);
        target.proof.aggregate(&self.proofs)
    }

    pub fn on_block_proof_read(&mut self, block_slot: Slot, ticker: &SlotTicker) {
        self.stats.block_proof_read(block_slot, ticker);
        self.notify(Trigger::Event);
    }

    /// The attestations and proof for the body of the block at `slot`.
    pub fn block_proof(&self, slot: Slot) -> Option<(Vec<Vec<u8>>, &[u8])> {
        self.targets.block_proof(slot, &self.proofs)
    }

    /// The log line allows reconstructing each request's cost.
    /// Only requests that produce a proof train the model, since refusals may
    /// skip proving.
    fn settle(
        &mut self,
        in_flight: InFlight,
        response: Result<ProofBody<'_>, &'static str>,
        now: Nanos,
    ) {
        let InFlight { merge, predicted, sent, .. } = in_flight;
        let shape = *self.merge.shape();
        let slot = Some(merge.key.slot());
        let finished = self.targets.settle(
            &merge.key,
            response,
            self.merge.running_id(),
            &mut self.proofs,
            &mut self.claim_check,
            |proofs, visit| self.merge.visit_members(proofs, &self.sources, visit),
        );
        for id in self.merge.proof_ids() {
            self.proofs.release(id);
        }
        let late = finished.is_ok() && now > merge.deadline;
        let round_trip = now.saturating_sub(sent);
        let q = self.stats.cost().margin();
        let ratio = self.stats.record_answer(&shape, predicted, round_trip, finished.is_ok());
        let MergeShape { idle, proofs, signatures, claims_in, request_bytes } = shape;
        let claims_out = *finished.as_ref().unwrap_or(&0);
        let (round_trip_ms, predicted_ms) = (round_trip.as_millis(), predicted.as_millis());
        let outcome = if late { "late" } else { finished.err().unwrap_or("ok") };
        let target = merge.key.name();
        let (groups, new_votes) = (merge.groups, merge.new_votes);
        let slack_ms = merge.horizon.as_millis() - now.as_millis();
        silver_log::debug!(
            target,
            slot,
            groups,
            new_votes,
            slack_ms,
            idle,
            proofs,
            signatures,
            claims_in,
            claims_out,
            request_bytes,
            round_trip_ms,
            predicted_ms,
            q,
            ratio,
            outcome,
            "leanvm merge"
        );
    }
}
