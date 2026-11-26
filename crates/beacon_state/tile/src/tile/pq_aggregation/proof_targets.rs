use std::{
    collections::BTreeMap,
    ops::{Bound, RangeInclusive},
};

use rustc_hash::FxHashMap;
use silver_beacon_state_data::{
    AGGREGATORS_PER_COMMITTEE, B256, Slot, pq::MIN_ATTESTATION_INCLUSION_DELAY_PQ,
};
use silver_common::{
    Nanos,
    leanvm::ProofBody,
    ssz_view::SingleAttestationPqView,
    ticker::{BASIS_POINTS, SlotTicker, attestation_due_bps},
};

use super::{
    claims::{ClaimCheck, Committee, VerifiedVote},
    cost_model::MergeShape,
    proof_sources::SourceSlot,
    proof_store::{MAX_AGGREGATE_PROOFS, ProofId, ProofStore},
    proved::POOL_SLOTS,
    running_proof::{ProvedGroup, RunningProof, VisitMember},
};
use crate::counters::BeaconStateCounters;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum TargetKey {
    AggregateProof(LeafKey),
    /// By block slot.
    BlockProof(Slot),
}

impl TargetKey {
    /// The attestation slot of an aggregate proof or the block slot of a block
    /// proof.
    pub(super) fn slot(&self) -> Slot {
        match self {
            Self::AggregateProof(target) => target.slot,
            Self::BlockProof(slot) => *slot,
        }
    }

    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::AggregateProof(_) => "aggregate_proof",
            Self::BlockProof(_) => "block_proof",
        }
    }

    /// A merge of one more input straight after a response, into a proof of
    /// `claims_in` claims or into none: a vote into an aggregate proof, a
    /// stored aggregate into a block proof. The model does not price
    /// request bytes.
    ///
    /// A block proof's input is priced as a proof of no claims. That is the
    /// smallest such merge, which is what a reserve needs.
    pub(super) fn one_input_merge(&self, claims_in: Option<usize>) -> MergeShape {
        let block = matches!(self, Self::BlockProof(_));
        let proofs = usize::from(claims_in.is_some()) + usize::from(block);
        let (signatures, claims_in) = (usize::from(!block), claims_in.unwrap_or(0));
        MergeShape { idle: false, proofs, signatures, claims_in, request_bytes: 0 }
    }
}

/// The proof of one local aggregator duty: the votes of one committee for
/// one attestation data.
pub(super) struct AggregateTarget {
    pub committee: Committee,
    pub due: Nanos,
    /// The last place a local aggregator of the committee holds.
    /// This position selects the deadline tracker.
    pub last_position: u64,
    pub proof: RunningProof,
}

impl AggregateTarget {
    /// Votes of `group` neither in the proof nor on chain.
    pub(super) fn waiting(&self, entry: &SourceSlot) -> usize {
        let covered = self.proof.covered(&self.committee);
        entry
            .votes
            .group(&self.committee)
            .map_or(0, |group| group.waiting(&covered, &entry.on_chain).count())
    }
}

/// The proof for a local proposal: stored aggregates and votes of the
/// `POOL_SLOTS` attestation slots its block may include.
pub(super) struct BlockTarget {
    pub due: Nanos,
    /// The attestation due time of the slot before. From then, that slot's
    /// block no longer takes the older slots' votes.
    pub older_open: Nanos,
    /// The last aggregate of the newest slot is due. Before it, aggregates
    /// are about to bring that slot's votes.
    pub votes_open: Nanos,
    pub proof: RunningProof,
}

impl BlockTarget {
    /// The attestation slots block `slot` may take at `now`. The older ones
    /// wait until block `slot − 1` imports or its attestations are due.
    pub(super) fn input_slots(
        &self,
        slot: Slot,
        now: Nanos,
        imported: Slot,
    ) -> RangeInclusive<Slot> {
        let (oldest, newest) = pool(slot).into_inner();
        let open = imported + 1 >= slot || now >= self.older_open;
        (if open { oldest } else { newest })..=newest
    }

    /// The newest input slot waits for its last aggregate to be due.
    pub(super) fn vote_slots(
        &self,
        slot: Slot,
        now: Nanos,
        imported: Slot,
    ) -> impl Iterator<Item = Slot> {
        let slots = self.input_slots(slot, now, imported);
        let (newest, open) = (*slots.end(), now >= self.votes_open);
        slots.filter(move |&input| open || input < newest)
    }
}

/// Owns the running proofs for local aggregator duties and block proposals.
/// Only the methods here change them.
#[derive(Default)]
pub(super) struct ProofTargets {
    aggregate_proofs: FxHashMap<LeafKey, AggregateTarget>,
    proved_aggregates: usize,
    /// By block slot.
    block_proofs: BTreeMap<Slot, BlockTarget>,
}

impl ProofTargets {
    pub(super) fn aggregate_proofs(&self) -> &FxHashMap<LeafKey, AggregateTarget> {
        &self.aggregate_proofs
    }

    pub(super) fn block_proofs(&self) -> &BTreeMap<Slot, BlockTarget> {
        &self.block_proofs
    }

    pub(super) fn bare_block_proofs(&self) -> impl Iterator<Item = (Slot, &BlockTarget)> {
        self.block_proofs
            .iter()
            .filter_map(|(&slot, block)| block.proof.id.is_none().then_some((slot, block)))
    }

    pub(super) fn next_bare_block_proof(&self, after: Option<Slot>) -> Option<Slot> {
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        self.block_proofs
            .range((lower, Bound::Unbounded))
            .find_map(|(&slot, target)| target.proof.id.is_none().then_some(slot))
    }

    pub(super) fn open_aggregate_proof(
        &mut self,
        key: LeafKey,
        committee: Committee,
        due: Nanos,
        last_position: u64,
    ) {
        let target = AggregateTarget { committee, due, last_position, proof: Default::default() };
        self.aggregate_proofs.entry(key).or_insert(target);
    }

    /// `slots` are coming block slots a local validator proposes. A slot no
    /// longer among them keeps its target until it is pruned.
    pub(super) fn set_local_proposals(
        &mut self,
        slots: &[Slot],
        is_gloas: bool,
        ticker: &SlotTicker,
    ) {
        let slot_ms = ticker.slot_duration().as_millis() as u64;
        let attestation_due =
            Nanos::from_millis(slot_ms * attestation_due_bps(is_gloas) / BASIS_POINTS);
        let last_aggregator = AGGREGATORS_PER_COMMITTEE as u64 - 1;
        for &slot in slots {
            self.block_proofs.entry(slot).or_insert_with(|| {
                let older_open = ticker.slot_start(slot.saturating_sub(1)) + attestation_due;
                let votes_open = ticker.pq_aggregate_due(*pool(slot).end(), last_aggregator);
                let due = ticker.slot_start(slot);
                BlockTarget { due, older_open, votes_open, proof: RunningProof::default() }
            });
        }
    }

    pub(super) fn block_wants_votes(&self, slot: Slot) -> bool {
        self.block_proofs.keys().any(|&block| pool(block).contains(&slot))
    }

    /// Keeps aggregate proofs from `floor` and block proofs after it.
    pub(super) fn prune_before(&mut self, floor: Slot, proofs: &mut ProofStore) {
        self.aggregate_proofs.retain(|key, target| {
            if key.slot >= floor {
                return true;
            }
            if let Some(id) = target.proof.id {
                proofs.release(id);
                self.proved_aggregates -= 1;
            }
            false
        });
        self.block_proofs.retain(|&slot, block| {
            if slot > floor {
                return true;
            }
            if let Some(id) = block.proof.id {
                proofs.release(id);
            }
            false
        });
    }

    pub(super) fn take_best_aggregate(
        &mut self,
        slot: Slot,
        id: ProofId,
        group: ProvedGroup,
        proofs: &mut ProofStore,
    ) {
        BeaconStateCounters::PqMergedClaims.set(proofs.claims(id).len() as u64);
        if let Some(block) = self.block_proofs.get_mut(&slot) {
            block.proof.take_aggregate(id, group, proofs);
        }
    }

    /// The merge's proof replaces the running proof if it proves exactly what
    /// was expected. The claims of the target's proof, or why the merge failed.
    pub(super) fn settle(
        &mut self,
        key: &TargetKey,
        response: Result<ProofBody<'_>, &'static str>,
        running: Option<ProofId>,
        proofs: &mut ProofStore,
        check: &mut ClaimCheck,
        visit: impl Fn(&ProofStore, &mut VisitMember<'_>) -> bool,
    ) -> Result<usize, &'static str> {
        let proof = match key {
            TargetKey::AggregateProof(target) => {
                self.aggregate_proofs.get_mut(target).map(|target| &mut target.proof)
            }
            TargetKey::BlockProof(slot) => {
                self.block_proofs.get_mut(slot).map(|block| &mut block.proof)
            }
        };
        let proof = proof.ok_or("the target was pruned")?;
        let aggregate = matches!(key, TargetKey::AggregateProof(_));
        let bare = proof.id.is_none();
        let allow_new = !aggregate || self.proved_aggregates < MAX_AGGREGATE_PROOFS;
        let settled = proof.settle(response, running, proofs, allow_new, check, visit);
        let (slot, target) = (key.slot(), key.name());
        if let Err(reason) = settled {
            silver_log::warn!(slot, target, reason, "merge failed");
            if proof.is_stopped() {
                silver_log::warn!(slot, target, "target stopped after repeated failures");
            }
            return Err(reason);
        }
        let claims = proofs.claims(proof.id.unwrap()).len();
        if aggregate {
            self.proved_aggregates += usize::from(bare);
        } else {
            BeaconStateCounters::PqMergedClaims.set(claims as u64);
        }
        Ok(claims)
    }

    pub(super) fn block_proof<'a>(
        &self,
        slot: Slot,
        proofs: &'a ProofStore,
    ) -> Option<(Vec<Vec<u8>>, &'a [u8])> {
        self.block_proofs.get(&slot)?.proof.block_attestations(proofs)
    }
}

/// The attestation slots a block at `block_slot` may include.
pub(super) fn pool(block_slot: Slot) -> RangeInclusive<Slot> {
    let newest = block_slot.saturating_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ);
    (newest + 1).saturating_sub(POOL_SLOTS)..=newest
}
