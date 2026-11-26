use std::cmp::Reverse;

use flux::utils::ArrayVec;
use silver_beacon_state_data::Slot;
use silver_common::{Nanos, ssz_view::MAX_COMMITTEES_PER_SLOT_PQ};

pub(super) use self::pick::Merge;
use self::{pick::NamedData, queue::PickQueue};
use super::{
    bits::Bits,
    proof_sources::ProofSources,
    proof_store::{MAX_BLOCK_PROOFS, ProofStore},
    proof_targets::{AggregateTarget, BlockTarget, LeafKey, ProofTargets, TargetKey, pool},
    proved::{DATA_PER_SLOT, POOL_SLOTS},
    running_proof::RunningProof,
    slot_aggregates::StoredAggregate,
    slot_votes::VoteGroup,
    stats::Stats,
};
use crate::tile::IDLE_WAKE;

mod pick;
mod queue;

/// The slot clock counts whole milliseconds.
const TICK: Nanos = Nanos::from_millis(1);

/// The tile loop may wake late because it parks for up to `IDLE_WAKE`.
/// A held merge starts early to allow for the park and clock rounding.
const WAKE_SLACK: Nanos = Nanos(IDLE_WAKE.as_nanos() as u64 + TICK.0);

pub(super) struct Sent {
    pub key: TargetKey,
    pub new_votes: usize,
    pub groups: usize,
    pub horizon: Nanos,
    pub deadline: Nanos,
}

pub(super) struct Pass {
    pub sent: Option<Sent>,
    /// When the planner must run again if no event runs it first.
    pub wake: Option<Nanos>,
}

#[derive(Clone, Copy)]
struct Live {
    deadline: Nanos,
    waiting: usize,
    key: TargetKey,
}

// At most four retained duty slots with their leading groups.
const MAX_LIVE: usize =
    POOL_SLOTS as usize * DATA_PER_SLOT * MAX_COMMITTEES_PER_SLOT_PQ + MAX_BLOCK_PROOFS;
#[derive(Default)]
pub(super) struct Scratch {
    live: ArrayVec<Live, MAX_LIVE>,
    pick: PickQueue,
}

/// A pass decides which target merges next and what its merge takes.
/// It borrows what it reads and keeps nothing.
pub(super) struct MergePlanner<'a> {
    pub sources: &'a ProofSources,
    pub proofs: &'a ProofStore,
    pub targets: &'a ProofTargets,
    pub stats: &'a Stats,
    /// The newest slot whose block imported.
    pub imported: Slot,
    pub now: Nanos,
}

impl MergePlanner<'_> {
    /// A live block proof without a proof takes its best eligible
    /// aggregate as its proof, with no request: the highest rank, then the
    /// older slot, then the earlier arrival.
    pub(super) fn best_aggregate(&self, slot: Slot) -> Option<&StoredAggregate> {
        if !self.is_live_block_proof(slot) {
            return None;
        }
        let rank = |stored: &StoredAggregate| {
            stored.rank(stored.useful.count_outside(&Bits::default()), self.stats.cost())
        };
        let order = |left: &&StoredAggregate, right: &&StoredAggregate| {
            (rank(left).total_cmp(&rank(right)))
                .then(right.group.committee.slot().cmp(&left.group.committee.slot()))
                .then(right.arrival.cmp(&left.arrival))
        };
        self.block_aggregates(slot)
            .map(|(_, row)| row)
            .filter(|stored| stored.useful != Bits::default())
            .max_by(order)
    }

    pub(super) fn best_aggregate_gate(&self) -> Option<Nanos> {
        let mut wake = None;
        for (slot, block) in self.targets.bare_block_proofs() {
            if block.votes_open > self.now {
                Self::wake(&mut wake, block.votes_open);
            }
            if block.input_slots(slot, self.now, self.imported).start() != pool(slot).start() {
                Self::wake(&mut wake, block.older_open);
            }
        }
        wake
    }

    /// The planner picks the target with the earliest deadline and a
    /// waiting vote, and plans a merge to end by its horizon. In an
    /// idle pass, a target with a proof holds its merge back while a further
    /// one would still fit, until `wake`. A held merge keeps the lane.
    /// The pass returns, and no later target is tried before the wake.
    pub(super) fn plan_next_merge(
        &self,
        idle: bool,
        scratch: &mut Scratch,
        merge: &mut Merge,
    ) -> Pass {
        let mut wake = None;
        let live = &mut scratch.live;
        self.live(live, &mut scratch.pick);
        if let Some(gate) = self.next_gate(live) {
            Self::wake(&mut wake, gate);
        }
        for &Live { deadline, key, .. } in live.iter().filter(|live| live.waiting > 0) {
            let earlier = live.iter().take_while(|live| live.deadline < deadline);
            let horizon = self.horizon(earlier.map(|live| &live.key), deadline);
            self.pick(&key, horizon.saturating_sub(self.now), idle, &mut scratch.pick, merge);
            if merge.is_empty() {
                if horizon < deadline {
                    Self::wake(&mut wake, horizon);
                }
                continue;
            }
            // A held merge would start idle after a response and exceed its plan.
            if idle && let Some(at) = self.hold_until(merge, &key, horizon) {
                Self::wake(&mut wake, at);
                return Pass { sent: None, wake };
            }
            let sent = Sent {
                key,
                new_votes: merge.new_votes(),
                groups: merge.groups_len(),
                horizon,
                deadline,
            };
            return Pass { sent: Some(sent), wake };
        }
        Pass { sent: None, wake }
    }

    fn hold_until(&self, merge: &Merge, key: &TargetKey, horizon: Nanos) -> Option<Nanos> {
        let model = self.stats.cost();
        let send_at = horizon.saturating_sub(model.planned(merge.shape()));
        let wait = send_at.saturating_sub(self.now);
        let after = model.planned(&key.one_input_merge(Some(merge.claims())));
        let (running, _) = self.target(key);
        (running.id.is_some() && wait > WAKE_SLACK && after > wait).then(|| send_at - WAKE_SLACK)
    }

    /// The earliest deadline comes first, with ties favoring more waiting
    /// votes. An aggregate proof waits while its head does not lead its
    /// slot. A block packs only `DATA_PER_SLOT` heads of a slot.
    fn live(&self, live: &mut ArrayVec<Live, MAX_LIVE>, coverage: &mut PickQueue) {
        live.clear();
        let aggregate_proofs = (self.targets.aggregate_proofs().iter()).filter(|(key, target)| {
            self.sources.slot(key.slot).is_some_and(|entry| {
                entry.votes.leading().any(|data| *data == target.committee.data)
            })
        });
        let aggregate_proofs =
            aggregate_proofs.map(|(&target, _)| TargetKey::AggregateProof(target));
        let block_proofs =
            self.targets.block_proofs().keys().filter(|&&slot| self.is_live_block_proof(slot));
        let targets = aggregate_proofs.chain(block_proofs.map(|&slot| TargetKey::BlockProof(slot)));
        for key in targets {
            let (proof, deadline) = self.target(&key);
            if deadline > self.now && !proof.is_stopped() {
                live.push(Live { deadline, waiting: self.waiting(&key, coverage), key });
            }
        }
        live.sort_unstable_by_key(|live| (live.deadline, Reverse(live.waiting), live.key));
    }

    /// The clock opens the older slots of a block proof, and the votes of its
    /// newest slot. The earliest such time whose closed slots hold an input:
    /// among the block proofs of `live` for older slots, among all for votes.
    fn next_gate(&self, live: &[Live]) -> Option<Nanos> {
        let block_proofs = live.iter().filter_map(|live| match live.key {
            TargetKey::BlockProof(slot) => Some((slot, self.block(slot))),
            TargetKey::AggregateProof(_) => None,
        });
        let holds = |slot| {
            self.sources
                .slot(slot)
                .is_some_and(|entry| !entry.aggregates.is_empty() || !entry.votes.is_empty())
        };
        let behind_the_gate = |(slot, block): &(Slot, &BlockTarget)| {
            let opens = *block.input_slots(*slot, self.now, self.imported).start();
            (*pool(*slot).start()..opens).any(holds)
        };
        let older = block_proofs.filter(behind_the_gate).map(|(_, block)| block.older_open);
        let votes = (self.targets.block_proofs().iter())
            .filter(|(slot, block)| {
                self.now < block.votes_open &&
                    self.sources
                        .slot(*pool(**slot).end())
                        .is_some_and(|entry| !entry.votes.is_empty())
            })
            .map(|(_, block)| block.votes_open);
        older.chain(votes).min()
    }

    /// A block proof is live from its first aggregate of the newest slot
    /// it may include, or once a stored vote of that slot is eligible.
    fn is_live_block_proof(&self, slot: Slot) -> bool {
        let newest = *pool(slot).end();
        self.sources.slot(newest).is_some_and(|entry| {
            !entry.aggregates.is_empty() ||
                (self.now >= self.block(slot).votes_open && !entry.votes.is_empty())
        })
    }

    fn block(&self, slot: Slot) -> &BlockTarget {
        &self.targets.block_proofs()[&slot]
    }

    fn aggregate_proof(&self, key: &LeafKey) -> &AggregateTarget {
        &self.targets.aggregate_proofs()[key]
    }

    fn target(&self, key: &TargetKey) -> (&RunningProof, Nanos) {
        match key {
            TargetKey::AggregateProof(target) => {
                let target = self.aggregate_proof(target);
                (
                    &target.proof,
                    self.stats.aggregate_proof_deadline(target.due, target.last_position),
                )
            }
            TargetKey::BlockProof(slot) => {
                let block = self.block(*slot);
                (&block.proof, self.stats.block_proof_deadline(block.due))
            }
        }
    }

    fn block_aggregates(&self, slot: Slot) -> impl Iterator<Item = (usize, &StoredAggregate)> {
        self.block(slot)
            .input_slots(slot, self.now, self.imported)
            .filter_map(|input| self.sources.slot(input))
            .flat_map(|entry| entry.aggregates.indexed())
    }

    /// The heads block `slot` can name in its open vote slots. A proof never
    /// drops a head, so these are the heads it names, then the leading heads
    /// of each slot, the oldest slot first, while the data cap admits them.
    ///
    /// A leading head whose votes are all on chain keeps its place. A head
    /// outside the lead then waits, though the proof has room for it.
    fn block_heads(&self, slot: Slot) -> NamedData {
        let block = self.block(slot);
        let slots = block.vote_slots(slot, self.now, self.imported);
        let mut named = NamedData::of(&block.proof);
        for slot in slots {
            let Some(entry) = self.sources.slot(slot) else { continue };
            for data in entry.votes.leading() {
                if named.admits(data) {
                    named.add(data);
                }
            }
        }
        named
    }

    fn block_vote_groups(&self, slot: Slot) -> impl Iterator<Item = VoteGroup<'_>> {
        let slots = move || self.block(slot).vote_slots(slot, self.now, self.imported);
        let heads = self.block_heads(slot).into_heads();
        heads.filter(move |(slot, _)| slots().any(|open| open == *slot)).flat_map(|(slot, data)| {
            self.sources
                .slot(slot)
                .into_iter()
                .flat_map(move |entry| entry.votes.head_groups(&data))
        })
    }

    /// Votes `key` may merge at `now` that are neither in its proof nor on
    /// chain.
    fn waiting(&self, key: &TargetKey, coverage: &mut PickQueue) -> usize {
        match key {
            TargetKey::AggregateProof(target) => {
                let aggregate_proof = self.aggregate_proof(target);
                self.sources.slot(target.slot).map_or(0, |entry| aggregate_proof.waiting(entry))
            }
            TargetKey::BlockProof(slot) => {
                let (aggregates, votes) =
                    (self.block_aggregates(*slot), self.block_vote_groups(*slot));
                let proof = &self.block(*slot).proof;
                coverage.new_votes(aggregates.map(|(_, row)| row), votes, proof, self.sources)
            }
        }
    }

    /// When a merge of a target due at `deadline` must end: by then, and
    /// before the latest start of each `earlier` target still ahead.
    fn horizon<'a>(&self, earlier: impl Iterator<Item = &'a TargetKey>, deadline: Nanos) -> Nanos {
        (earlier.map(|key| self.latest_start(key)))
            .filter(|start| *start > self.now)
            .fold(deadline, Nanos::min)
    }

    /// The latest time a merge of one more input into `key` may start and
    /// still end by the deadline.
    fn latest_start(&self, key: &TargetKey) -> Nanos {
        let (proof, deadline) = self.target(key);
        let claims_in = proof.id.map(|id| self.proofs.claims(id).len());
        deadline.saturating_sub(self.stats.cost().planned(&key.one_input_merge(claims_in)))
    }

    /// Makes the planner run again by the first millisecond at or after `at`.
    fn wake(wake: &mut Option<Nanos>, at: Nanos) {
        let at = Nanos(at.0.next_multiple_of(TICK.0));
        *wake = Some(wake.map_or(at, |held| held.min(at)));
    }
}

#[cfg(test)]
mod tests;
