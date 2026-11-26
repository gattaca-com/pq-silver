use silver_beacon_state_data::Slot;

use super::{
    claims::{Claim, VerifiedVote},
    proof_store::ProofStore,
    proved::POOL_SLOTS,
    slot_aggregates::{AggregateRefused, SlotAggregates},
    slot_votes::{SlotVotes, VoteRefused},
};

pub(super) const SOURCE_SLOTS: usize = POOL_SLOTS as usize + 4;
const VALIDATOR_INDEX_CAP: usize = 1 << 22;

#[derive(Default)]
pub(super) struct OnChain {
    words: Vec<u64>,
}

impl OnChain {
    fn include(&mut self, slot: Slot, validators: &[u32]) {
        for &validator in validators {
            let index = validator as usize;
            if index >= VALIDATOR_INDEX_CAP {
                silver_log::error!(slot, validator, "on-chain PQ validator above the index cap");
                continue;
            }
            let word = index / u64::BITS as usize;
            if word >= self.words.len() {
                self.words.resize((word + 1).next_power_of_two(), 0);
            }
            self.words[word] |= 1 << (index % u64::BITS as usize);
        }
    }

    pub(super) fn contains(&self, validator: u32) -> bool {
        let index = validator as usize;
        self.words
            .get(index / u64::BITS as usize)
            .is_some_and(|word| word & (1 << (index % u64::BITS as usize)) != 0)
    }
}

#[derive(Default)]
pub(super) struct SourceSlot {
    slot: Option<Slot>,
    pub votes: SlotVotes,
    pub aggregates: SlotAggregates,
    pub on_chain: OnChain,
}

impl SourceSlot {
    fn clear(&mut self, proofs: &mut ProofStore) {
        self.slot = None;
        self.votes.clear();
        self.aggregates.clear(proofs);
        self.on_chain.words.clear();
    }
}

pub(super) struct ProofSources {
    slots: Box<[SourceSlot]>,
    floor: Slot,
    arrivals: u64,
}

impl Default for ProofSources {
    fn default() -> Self {
        Self {
            slots: std::iter::repeat_with(SourceSlot::default).take(SOURCE_SLOTS).collect(),
            floor: 0,
            arrivals: 0,
        }
    }
}

impl ProofSources {
    fn index(slot: Slot) -> usize {
        (slot % SOURCE_SLOTS as Slot) as usize
    }

    pub(super) fn slot(&self, slot: Slot) -> Option<&SourceSlot> {
        let entry = &self.slots[Self::index(slot)];
        (slot >= self.floor && entry.slot == Some(slot)).then_some(entry)
    }

    pub(super) fn store_slot(
        &mut self,
        slot: Slot,
        proofs: &mut ProofStore,
    ) -> Option<&mut SourceSlot> {
        if slot < self.floor {
            return None;
        }
        self.prune_before(slot.saturating_sub(SOURCE_SLOTS as Slot - 1), proofs);
        let entry = &mut self.slots[Self::index(slot)];
        debug_assert!(entry.slot.is_none() || entry.slot == Some(slot));
        entry.slot = Some(slot);
        Some(entry)
    }

    pub(super) fn add_vote(
        &mut self,
        vote: &VerifiedVote,
        proofs: &mut ProofStore,
    ) -> Result<(), VoteRefused> {
        let arrival = self.next_arrival();
        let committee = SlotVotes::check(vote)?;
        let slot = vote.slot();
        let entry = self.store_slot(slot, proofs).ok_or(VoteRefused::BeforeFloor)?;
        entry.votes.add(committee, vote, arrival)
    }

    pub(super) fn add_aggregate(
        &mut self,
        attestation: &[u8],
        attesters: &[u32],
        claims: &[Claim],
        proof: &[u8],
        proofs: &mut ProofStore,
    ) -> Result<(), AggregateRefused> {
        SlotAggregates::add(attestation, attesters, claims, proof, proofs, |slot, proofs| {
            let arrival = self.next_arrival();
            let entry = self.store_slot(slot, proofs)?;
            Some((arrival, &mut entry.aggregates, &entry.on_chain))
        })
    }

    fn next_arrival(&mut self) -> u64 {
        self.arrivals += 1;
        self.arrivals
    }

    pub(super) fn include_on_chain(
        &mut self,
        slot: Slot,
        validators: &[u32],
        proofs: &mut ProofStore,
    ) {
        let Some(entry) = self.store_slot(slot, proofs) else { return };
        entry.on_chain.include(slot, validators);
        entry.aggregates.exclude(&entry.on_chain, proofs);
    }

    pub(super) fn prune_before(&mut self, floor: Slot, proofs: &mut ProofStore) {
        if floor > self.floor {
            self.floor = floor;
            for entry in &mut self.slots {
                if entry.slot.is_some_and(|slot| slot < floor) {
                    entry.clear(proofs);
                }
            }
        }
    }
}
