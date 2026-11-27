use silver_beacon_state_data::{AGGREGATORS_PER_COMMITTEE, Slot};
use silver_common::{
    leanvm::{MAX_STARK_PROOF_SIZE, ProofBody, ProofLen},
    merkle::bitlist_len,
    ssz_view::{AttestationPqView, MAX_COMMITTEES_PER_SLOT_PQ, MAX_VALIDATORS_PER_COMMITTEE},
};

use super::{
    bits::Bits,
    claims::{Claim, Committee, MAX_GROUPS},
    cost_model::CostModel,
    proof_sources::OnChain,
    proof_store::{ProofId, ProofStore},
    running_proof::{MEMBER_BYTES, ProvedGroup},
};
use crate::counters::BeaconStateCounters;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AggregateRefused {
    NotLarger,
    TooManyGroups,
    BeforeFloor,
    Malformed,
}

pub(super) struct StoredAggregate {
    pub group: ProvedGroup,
    pub proof: ProofId,
    pub arrival: u64,
    pub useful: Bits,
    voters: usize,
}

impl StoredAggregate {
    pub(super) fn rank(&self, gain: usize, model: &CostModel) -> f64 {
        gain as f64 / self.seconds(model)
    }

    pub(super) fn seconds(&self, model: &CostModel) -> f64 {
        model.proof_seconds(self.voters)
    }
}

#[derive(Default)]
pub(super) struct SlotAggregates {
    entries: [[Option<StoredAggregate>; AGGREGATORS_PER_COMMITTEE]; MAX_COMMITTEES_PER_SLOT_PQ],
    len: usize,
}

impl SlotAggregates {
    pub(super) fn indexed(&self) -> impl Iterator<Item = (usize, &StoredAggregate)> {
        self.entries
            .iter()
            .flatten()
            .enumerate()
            .filter_map(|(index, entry)| entry.as_ref().map(|row| (index, row)))
    }

    pub(super) fn at(&self, at: usize) -> &StoredAggregate {
        self.entries[at / AGGREGATORS_PER_COMMITTEE][at % AGGREGATORS_PER_COMMITTEE]
            .as_ref()
            .unwrap()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn exclude(&mut self, on_chain: &OnChain, proofs: &ProofStore) {
        for held in self.entries.iter_mut().flatten().flatten() {
            held.useful = held
                .group
                .records(proofs, held.proof)
                .filter(|&(_, validator, _)| !on_chain.contains(validator))
                .map(|(position, _, _)| position)
                .collect();
        }
    }

    pub(super) fn clear(&mut self, proofs: &mut ProofStore) {
        for cell in self.entries.iter_mut().flatten() {
            if let Some(held) = cell.take() {
                proofs.release(held.proof);
            }
        }
        self.len = 0;
    }

    pub(super) fn add<'a>(
        attestation: &[u8],
        attesters: &[u32],
        claims: &[Claim],
        proof: &[u8],
        proofs: &mut ProofStore,
        store: impl FnOnce(Slot, &mut ProofStore) -> Option<(u64, &'a mut Self, &'a OnChain)>,
    ) -> Result<(), AggregateRefused> {
        let (index, positions) = AttestationPqView::one_committee_positions(attestation)
            .ok_or(AggregateRefused::Malformed)?;
        if index >= MAX_COMMITTEES_PER_SLOT_PQ {
            return Err(AggregateRefused::Malformed);
        }
        let positions: Bits = positions.collect();
        let voters = positions.count();
        if voters == 0 || attesters.len() != voters || claims.len() != voters {
            return Err(AggregateRefused::Malformed);
        }
        let mut order = [0; MAX_VALIDATORS_PER_COMMITTEE];
        let order = &mut order[..voters];
        for (index, rank) in order.iter_mut().enumerate() {
            *rank = index as u16;
        }
        let claim = |index: u16| &claims[usize::from(index)];
        order.sort_unstable_by(|&left, &right| claim(left).cmp(claim(right)));
        if order.windows(2).any(|pair| claim(pair[0]) == claim(pair[1])) ||
            proof.len() > MAX_STARK_PROOF_SIZE
        {
            return Err(AggregateRefused::Malformed);
        }

        BeaconStateCounters::PqMergeClaimsOffered.add(voters as u64);
        let data = AttestationPqView::data(attestation);
        let slot = data.slot();
        let committee = Committee { data: *data.as_bytes(), index };
        // Malformed aggregates must not advance the slot floor or consume an arrival.
        let (arrival, aggregates, on_chain) =
            store(slot, proofs).ok_or(AggregateRefused::BeforeFloor)?;
        let (cell, replaced) = aggregates.entries[index]
            .iter()
            .enumerate()
            .min_by_key(|(_, held)| held.as_ref().map(|held| (held.voters, held.arrival)))
            .unwrap();
        if replaced.as_ref().is_some_and(|held| voters <= held.voters) {
            return Err(AggregateRefused::NotLarger);
        }
        if aggregates.len == MAX_GROUPS && replaced.is_none() {
            return Err(AggregateRefused::TooManyGroups);
        }
        let cell = &mut aggregates.entries[index][cell];
        if let Some(replaced) = cell.take() {
            proofs.release(replaced.proof);
        } else {
            aggregates.len += 1;
        }

        let len = ProofLen { claims: voters as u32, proof: proof.len() as u32 };
        let (id, buffer) = proofs.take(len, voters * MEMBER_BYTES);
        let (body, members) = buffer.split_at_mut(len.bytes());
        ProofBody::write(body, order.iter().copied().map(claim), proof);
        let members = members.as_chunks_mut::<MEMBER_BYTES>().0;
        for (rank, &index) in order.iter().enumerate() {
            members[usize::from(index)][4..].copy_from_slice(&(rank as u16).to_le_bytes());
        }
        for (record, validator) in members.iter_mut().zip(attesters) {
            record[..4].copy_from_slice(&validator.to_le_bytes());
        }
        let committee_len = bitlist_len(AttestationPqView::aggregation_bits(attestation));
        let useful = positions
            .iter()
            .zip(attesters)
            .filter(|&(_, &validator)| !on_chain.contains(validator))
            .map(|(position, _)| position)
            .collect();
        *cell = Some(StoredAggregate {
            group: ProvedGroup { committee, committee_len, positions },
            voters,
            proof: id,
            arrival,
            useful,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests;
