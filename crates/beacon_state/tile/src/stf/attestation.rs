use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, BlockRoots, Checkpoint, Epoch, EpochReadView, EpochView, Immutable,
    PARTICIPATION_WEIGHTS, ParticipationWriteView, RootsView, SLOTS_PER_EPOCH, Slot,
    SlotStateWriteView, StateWriterView, TIMELY_HEAD_FLAG, TIMELY_SOURCE_FLAG, TIMELY_TARGET_FLAG,
    TreeSpec, ValidatorsView,
    bls::{self, SigBatch},
};
use silver_common::ssz_view::{
    ATTESTATION_FIXED, AttestationDataView, AttestationPqView, AttestationView, bitvector_word,
};

use crate::{
    error::{AttestationError, Result},
    merkle, ssz_hash,
    stf::{
        BASE_REWARD_FACTOR, EFFECTIVE_BALANCE_INCREMENT, EpochShuffling, PROPOSER_WEIGHT,
        ShufflingRef, StarkClaims, VoteBatch, VoteTarget, WEIGHT_DENOMINATOR,
        for_each_ssz_list_item, integer_sqrt, stark::AttestationStatements,
    },
    validate,
};

const GLOAS_PAYLOAD_ABSENT: u64 = 0;
const GLOAS_PAYLOAD_PRESENT: u64 = 1;

pub fn collect_sigs_attestations(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    attestation_data: &[u8],
    block_slot: Slot,
    shuffling: &ShufflingRef<'_>,
    sig_batch: &mut SigBatch,
) -> Result<(), AttestationError> {
    let current_epoch = block_slot / SLOTS_PER_EPOCH;
    for_each_ssz_list_item(
        attestation_data,
        |start, end| AttestationError::BadOffsets {
            start,
            end,
            parent_len: attestation_data.len(),
        },
        |att| {
            collect_sigs_single_attestation(
                imm,
                epoch,
                validators,
                att,
                current_epoch,
                shuffling,
                sig_batch,
            )
        },
    )
}

/// The slot of the block whose payload availability a vote at `att_slot` is
/// checked against. Gloas includes votes a slot later and checks the parent.
/// PQ includes them two slots later, so the voted block may be older.
pub(crate) fn voted_block_slot(
    block_roots: &RootsView<BlockRoots>,
    att_slot: Slot,
    parent_slot: Slot,
    block_slot: Slot,
    is_pq: bool,
) -> Slot {
    if is_pq {
        block_roots.latest_block_slot(att_slot, parent_slot, block_slot)
    } else {
        parent_slot
    }
}

pub(crate) fn attester_signing_root(
    imm: &Immutable,
    epoch: &EpochReadView,
    data: AttestationDataView,
) -> B256 {
    let domain = bls::compute_domain(
        bls::DOMAIN_BEACON_ATTESTER,
        epoch.fork_version_at(data.target_epoch()),
        &imm.genesis_validators_root,
    );
    bls::compute_signing_root(&ssz_hash::hash_attestation_data(data.as_bytes()), &domain)
}

/// The fields an attestation keeps across forks, read from its fork's layout.
pub(crate) struct Attestation<'a> {
    pub(crate) data: AttestationDataView<'a>,
    committee_bits: u64,
    aggregation_bits: &'a [u8],
    /// PQ has no `is_valid_indexed_attestation` to reject an attestation
    /// naming no committee, so it applies as a no-op.
    may_name_no_committee: bool,
}

impl<'a> Attestation<'a> {
    fn parse(att: &'a [u8], is_pq: bool) -> Result<Self, AttestationError> {
        if is_pq {
            return Self::pq(att);
        }
        if att.len() < ATTESTATION_FIXED {
            return Err(AttestationError::TooShort { len: att.len(), min: ATTESTATION_FIXED });
        }
        Ok(Self::electra(att))
    }

    fn electra(att: &'a [u8]) -> Self {
        debug_assert!(att.len() >= ATTESTATION_FIXED);
        Self {
            data: AttestationView::data(att),
            committee_bits: bitvector_word(AttestationView::committee_bits(att)),
            aggregation_bits: AttestationView::aggregation_bits(att),
            may_name_no_committee: false,
        }
    }

    fn pq(att: &'a [u8]) -> Result<Self, AttestationError> {
        if !AttestationPqView::check_canonical(att) {
            return Err(AttestationError::Malformed { len: att.len() });
        }
        let mut committee_bits = [0; 8];
        let bits = AttestationPqView::committee_bits(att);
        committee_bits[..bits.len()].copy_from_slice(bits);
        Ok(Self {
            data: AttestationPqView::data(att),
            committee_bits: u64::from_le_bytes(committee_bits),
            aggregation_bits: AttestationPqView::aggregation_bits(att),
            may_name_no_committee: true,
        })
    }
}

pub struct AttestedCommittees<'a> {
    shuffling: &'a EpochShuffling<'a>,
    slot: Slot,
    committee_bits: u64,
    agg_bits: &'a [u8],
}

impl<'a> AttestedCommittees<'a> {
    pub fn new(
        att: &'a [u8],
        is_pq: bool,
        shuffling: &'a EpochShuffling<'a>,
    ) -> Result<Self, AttestationError> {
        Self::of(&Attestation::parse(att, is_pq)?, shuffling)
    }

    fn of(
        att: &Attestation<'a>,
        shuffling: &'a EpochShuffling<'a>,
    ) -> Result<Self, AttestationError> {
        let committee_bits = att.committee_bits;
        if committee_bits == 0 && !att.may_name_no_committee {
            return Err(AttestationError::EmptyCommitteeBits);
        }
        let committees_per_slot = shuffling.committees_per_slot;
        if committees_per_slot < u64::BITS as usize && (committee_bits >> committees_per_slot) != 0
        {
            return Err(AttestationError::CommitteeBitsOverflow {
                committees_per_slot,
                bits: committee_bits,
            });
        }
        Ok(Self {
            shuffling,
            slot: att.data.slot(),
            committee_bits,
            agg_bits: att.aggregation_bits,
        })
    }

    pub(crate) fn resolve(
        att: &Attestation<'a>,
        shuffling: &'a ShufflingRef<'a>,
        is_current: bool,
        validators_count: usize,
    ) -> Result<Self, AttestationError> {
        let epoch_shuffling = shuffling.for_target(is_current);
        if epoch_shuffling.is_empty() {
            return Err(AttestationError::EmptyShuffling);
        }
        let committees = Self::of(att, epoch_shuffling)?;
        committees.check_indices_addressable(validators_count)?;
        Ok(committees)
    }

    fn indices(&self) -> impl Iterator<Item = usize> + use<'_> {
        let bits = self.committee_bits;
        (0..self.shuffling.committees_per_slot).filter(move |ci| bits & (1u64 << ci) != 0)
    }

    fn attested(&self, bit_pos: usize) -> bool {
        self.agg_bits.get(bit_pos / 8).is_some_and(|b| b & (1 << (bit_pos % 8)) != 0)
    }

    /// Named committees paired with their base offset into `aggregation_bits`,
    /// ascending — member `j` of a committee based at `offset` is bit
    /// `offset + j`.
    fn committees(&self) -> impl Iterator<Item = (&'a [u32], usize)> + use<'_, 'a> {
        let mut agg_offset = 0usize;
        self.indices().map(move |ci| {
            let committee = self.shuffling.committee(self.slot, ci);
            let base = agg_offset;
            agg_offset += committee.len();
            (committee, base)
        })
    }

    fn members(&self, attested: bool) -> impl Iterator<Item = u32> + use<'_, 'a> {
        self.committees().flat_map(move |(committee, base)| {
            committee
                .iter()
                .enumerate()
                .filter_map(move |(j, &vi)| (self.attested(base + j) == attested).then_some(vi))
        })
    }

    pub(crate) fn attesters(&self) -> impl Iterator<Item = u32> + use<'_, 'a> {
        self.members(true)
    }

    fn missed(&self) -> impl Iterator<Item = u32> + use<'_, 'a> {
        self.members(false)
    }

    /// Errors if the shuffling outlived the registry it was taken against, so
    /// callers may index the validator columns with what lands in `out`.
    pub fn attesters_into(
        &self,
        validators_count: usize,
        out: &mut Vec<u32>,
    ) -> Result<(), AttestationError> {
        self.check_indices_addressable(validators_count)?;
        out.clear();
        out.extend(self.attesters());
        Ok(())
    }

    fn check_indices_addressable(&self, validators_count: usize) -> Result<(), AttestationError> {
        if self.shuffling.indices_in_range(validators_count) {
            return Ok(());
        }
        Err(AttestationError::ValidatorOutOfRange {
            vi: self.shuffling.required_validator_count - 1,
            count: validators_count,
        })
    }

    fn member_count(&self) -> usize {
        self.committees().map(|(committee, _)| committee.len()).sum()
    }

    /// Popcount over exactly `members` bits, so the bitlist's length sentinel
    /// and any trailing junk are excluded — the same set [`Self::attested`]
    /// reports over, without walking the committees.
    fn attested_count(&self, members: usize) -> usize {
        let whole = members / 8;
        let head: u32 = self.agg_bits.iter().take(whole).map(|b| b.count_ones()).sum();
        let tail = match (members % 8, self.agg_bits.get(whole)) {
            (0, _) | (_, None) => 0,
            (rem, Some(b)) => (b & ((1u8 << rem) - 1)).count_ones(),
        };
        (head + tail) as usize
    }

    fn aggregates<'b>(&self, epoch_aggs: &'b [PublicKey]) -> impl Iterator<Item = &'b PublicKey> {
        let offset = (self.slot % SLOTS_PER_EPOCH) as usize * self.shuffling.committees_per_slot;
        self.indices().map(move |ci| &epoch_aggs[offset + ci])
    }

    pub fn push_aggregate_sig(
        &self,
        validators: &ValidatorsView,
        sig: &[u8; 96],
        signing_root: B256,
        sig_batch: &mut SigBatch,
    ) {
        let members = self.member_count();
        let attested = self.attested_count(members);
        if attested == 0 {
            sig_batch.poison();
            return;
        }

        // Usually there are many more attested than missed, so we can subtract it from
        // sum
        let pubkey = |vi: u32| validators.pubkey_decompressed(vi as usize);
        let attesters_are_majority = attested * 2 > members;
        match self.shuffling.committee_aggs.filter(|_| attesters_are_majority) {
            Some(aggs) => sig_batch.push_aggregate_subtracted(
                self.aggregates(aggs),
                self.missed().map(pubkey),
                sig,
                signing_root,
            ),
            None => sig_batch.push_aggregate(self.attesters().map(pubkey), sig, signing_root),
        }
    }
}

#[timed]
pub fn collect_sigs_single_attestation(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    att: &[u8],
    current_epoch: Epoch,
    shuffling: &ShufflingRef<'_>,
    sig_batch: &mut SigBatch,
) -> Result<(), AttestationError> {
    let data = AttestationView::data(att);
    let target_epoch = data.target_epoch();
    let is_current = target_epoch == current_epoch;
    let committees = AttestedCommittees::resolve(
        &Attestation::electra(att),
        shuffling,
        is_current,
        validators.count(),
    )?;

    let sig = AttestationView::signature(att);
    let signing_root = attester_signing_root(imm, epoch, data);

    committees.push_aggregate_sig(validators, sig, signing_root, sig_batch);
    Ok(())
}

/// Pass 2 — full data + state-dep validation, apply participation flags +
/// proposer rewards.
pub struct BlockAttestations<'a> {
    epoch: EpochView<'a>,
    current_epoch: Epoch,
    previous_epoch: Epoch,
    /// Gloas: the slot of the block's parent, which locates the payload
    /// availability bit every vote's `index` is checked against.
    parent_slot: Option<Slot>,
    post_gloas_fork: bool,
    is_pq: bool,
    min_inclusion_delay: Slot,
    base_reward_per_increment: u64,
    shuffling: &'a ShufflingRef<'a>,
}

impl<'a> BlockAttestations<'a> {
    pub fn new(
        view: &StateWriterView,
        epoch: EpochView<'a>,
        block_slot: Slot,
        parent_slot: Option<Slot>,
        shuffling: &'a ShufflingRef<'a>,
    ) -> Self {
        let current_epoch = block_slot / SLOTS_PER_EPOCH;
        Self {
            current_epoch,
            previous_epoch: current_epoch.saturating_sub(1),
            parent_slot,
            post_gloas_fork: epoch.post_gloas_fork(view.imm),
            is_pq: epoch.is_pq(view.imm),
            min_inclusion_delay: epoch.min_attestation_inclusion_delay(view.imm),
            base_reward_per_increment: EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR /
                integer_sqrt(view.slot.total_active_balance(current_epoch)),
            epoch,
            shuffling,
        }
    }

    #[timed]
    pub fn process_body(
        &self,
        view: &mut StateWriterView,
        attestation_data: &[u8],
        proposer_index: u32,
        votes_sink: &mut VoteBatch,
        active: &mut Vec<u32>,
        mut stark: Option<&mut StarkClaims>,
    ) -> Result<u64, AttestationError> {
        if attestation_data.is_empty() {
            return Ok(0);
        }
        let proposer_reward_denominator =
            (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
        let mut proposer_reward = 0u64;
        for_each_ssz_list_item(
            attestation_data,
            |start, end| AttestationError::BadOffsets {
                start,
                end,
                parent_len: attestation_data.len(),
            },
            |att| {
                let reward_numerator =
                    self.process(view, att, votes_sink, active, stark.as_deref_mut())?;
                proposer_reward += reward_numerator / proposer_reward_denominator;
                Ok(())
            },
        )?;

        let balance = view.balances.get(proposer_index as usize);
        view.balances.set(proposer_index, balance.saturating_add(proposer_reward));
        Ok(proposer_reward)
    }

    /// Returns the proposer reward numerator.
    fn process(
        &self,
        view: &mut StateWriterView,
        att: &[u8],
        votes_sink: &mut VoteBatch,
        active: &mut Vec<u32>,
        stark: Option<&mut StarkClaims>,
    ) -> Result<u64, AttestationError> {
        let current_slot = view.slot.state().slot;
        let Self { post_gloas_fork, min_inclusion_delay, .. } = *self;
        let att = Attestation::parse(att, self.is_pq)?;
        validate::validate_attestation_data_view(
            att.data,
            current_slot,
            self.current_epoch,
            self.previous_epoch,
            post_gloas_fork,
            min_inclusion_delay,
        )?;

        let parsed = ParsedAttestationData::parse(att.data);
        let is_current = self.target_is_current(parsed.target_epoch)?;
        parsed.check_source(self.justified(is_current))?;

        let payload_index =
            if post_gloas_fork { Some(self.payload_index(view, parsed.att_slot)?) } else { None };
        let flags = parsed.flags(
            |slot| view.block_roots.at_slot(slot),
            current_slot,
            payload_index,
            min_inclusion_delay,
        )?;

        let target = VoteTarget {
            block_root: *parsed.beacon_block_root,
            target_epoch: parsed.target_epoch,
            attestation_slot: parsed.att_slot,
            payload_present: parsed.payload_present(),
        };
        let statements = stark.map(|claims| claims.attestation(view.imm, &self.epoch, att.data));
        self.collect_participants(view.validators.count(), &att, is_current, active, statements)?;
        if active.is_empty() {
            return Ok(0);
        }
        votes_sink.push(target, active);
        let attesters = &*active;

        if flags == 0 {
            return Ok(0);
        }
        // Distinct `Previous`/`Current` types can't share one binding, so branch
        // and let each arm monomorphise the generic helper for its column.
        let validators = view.validators.reader();
        let applied = if is_current {
            self.apply_flags(&mut view.current_participation, &validators, attesters, flags)
        } else {
            self.apply_flags(&mut view.previous_participation, &validators, attesters, flags)
        };

        view.slot.epoch_balances_mut().add_target_attesters(is_current, applied.new_target_eb);

        if post_gloas_fork &&
            applied.first_participation_eb > 0 &&
            parsed.is_same_slot(|slot| view.block_roots.at_slot(slot))
        {
            accrue_builder_payment_weight(
                &mut view.slot,
                parsed.att_slot,
                is_current,
                applied.first_participation_eb,
            );
        }

        Ok(applied.proposer_reward_numerator)
    }

    fn payload_index(
        &self,
        view: &StateWriterView,
        att_slot: Slot,
    ) -> Result<u64, AttestationError> {
        let parent_slot = self.parent_slot.ok_or(AttestationError::MissingParentSlot)?;
        let slot_state = view.slot.state();
        let block_slot = voted_block_slot(
            &view.block_roots.reader(),
            att_slot,
            parent_slot,
            slot_state.slot,
            self.is_pq,
        );
        Ok(slot_state.payload_available(block_slot) as u64)
    }

    fn target_is_current(&self, target: Epoch) -> Result<bool, AttestationError> {
        let (curr, prev) = (self.current_epoch, self.previous_epoch);
        if target == curr {
            Ok(true)
        } else if target == prev {
            Ok(false)
        } else {
            Err(AttestationError::TargetEpochOutOfWindow { target, prev, curr })
        }
    }

    fn justified(&self, is_current: bool) -> Checkpoint {
        let es = self.epoch.state();
        if is_current { es.current_justified_checkpoint } else { es.previous_justified_checkpoint }
    }

    /// Append the attesting validator indices to `out`, in ascending order:
    /// committee order is shuffled, and a monotonic sweep makes the
    /// per-attester column reads that follow sequential. Each committee's
    /// attesters, in committee order, are also one of `statements`.
    fn collect_participants(
        &self,
        validator_count: usize,
        att: &Attestation<'_>,
        is_current: bool,
        out: &mut Vec<u32>,
        mut statements: Option<AttestationStatements<'_>>,
    ) -> Result<(), AttestationError> {
        let committees =
            AttestedCommittees::resolve(att, self.shuffling, is_current, validator_count)?;

        out.clear();
        let mut agg_offset = 0usize;
        for (committee, base) in committees.committees() {
            let before = out.len();
            for (j, &validator_idx) in committee.iter().enumerate() {
                if committees.attested(base + j) {
                    out.push(validator_idx);
                }
            }
            if out.len() == before {
                return Err(AttestationError::EmptyCommittee);
            }
            if let Some(statements) = &mut statements {
                statements.push(out[before..].iter().copied());
            }
            agg_offset += committee.len();
        }

        let bitlist_len = merkle::bitlist_len(att.aggregation_bits);
        if bitlist_len != agg_offset {
            return Err(AttestationError::BitlistLenMismatch {
                expected: agg_offset,
                got: bitlist_len,
            });
        }
        out.sort_unstable();
        Ok(())
    }

    fn apply_flags<M: TreeSpec<Val = u8>>(
        &self,
        participation: &mut ParticipationWriteView<M>,
        validators: &ValidatorsView,
        attesters: &[u32],
        flags: u8,
    ) -> AppliedFlags {
        let mut applied = AppliedFlags::default();
        let epoch_increments = self.epoch.increments();
        for &vi in attesters {
            let prev = participation.get(vi as usize);
            let gained = flags & !prev;
            if gained == 0 {
                continue;
            }
            let increments = epoch_increments.get(vi);
            let effective_balance = increments * EFFECTIVE_BALANCE_INCREMENT;
            debug_assert_eq!(
                effective_balance,
                validators.effective_balance(vi as usize),
                "stale effective-balance increment for validator {vi}",
            );
            let weight: u64 =
                (0..3).map(|fi| u64::from(gained >> fi & 1) * PARTICIPATION_WEIGHTS[fi]).sum();
            applied.proposer_reward_numerator +=
                increments * self.base_reward_per_increment * weight;
            if gained & TIMELY_TARGET_FLAG != 0 && !validators.is_slashed(vi as usize) {
                applied.new_target_eb += effective_balance;
            }
            if prev == 0 {
                applied.first_participation_eb += effective_balance;
            }
            participation.set(vi, prev | gained);
        }
        applied
    }
}

fn accrue_builder_payment_weight(
    slot: &mut SlotStateWriteView,
    att_slot: Slot,
    is_current: bool,
    first_participation_eb: u64,
) {
    let spe = SLOTS_PER_EPOCH as usize;
    let slot_in_epoch = att_slot as usize % spe;
    let ring = if is_current { spe + slot_in_epoch } else { slot_in_epoch };
    if slot.state().builder_pending_payments[ring].withdrawal.amount > 0 {
        slot.state_mut().builder_pending_payments[ring].weight += first_participation_eb;
    }
}

pub(crate) struct ParsedAttestationData<'a> {
    pub(crate) att_slot: Slot,
    index: u64,
    beacon_block_root: &'a B256,
    source_epoch: Epoch,
    source_root: &'a B256,
    pub(crate) target_epoch: Epoch,
    target_root: &'a B256,
}

impl<'a> ParsedAttestationData<'a> {
    pub(crate) fn parse(data: AttestationDataView<'a>) -> Self {
        Self {
            att_slot: data.slot(),
            index: data.index(),
            beacon_block_root: data.beacon_block_root(),
            source_epoch: data.source_epoch(),
            source_root: data.source_root(),
            target_epoch: data.target_epoch(),
            target_root: data.target_root(),
        }
    }

    pub(crate) fn check_source(&self, justified: Checkpoint) -> Result<(), AttestationError> {
        if self.source_epoch != justified.epoch || *self.source_root != justified.root {
            return Err(AttestationError::SourceMismatch {
                expected_epoch: justified.epoch,
                expected_root: justified.root,
                got_epoch: self.source_epoch,
                got_root: *self.source_root,
            });
        }
        Ok(())
    }

    /// Gloas: whether it votes for the block proposed at its slot. `root_at`
    /// is the state's `get_block_root_at_slot`.
    pub(crate) fn is_same_slot(&self, root_at: impl Fn(Slot) -> B256) -> bool {
        self.att_slot == 0 ||
            (*self.beacon_block_root == root_at(self.att_slot) &&
                *self.beacon_block_root != root_at(self.att_slot - 1))
    }

    pub(crate) fn payload_present(&self) -> bool {
        self.index == GLOAS_PAYLOAD_PRESENT
    }

    /// Gloas: whether `index` names the attested block's payload status,
    /// `payload_index` unless the block is from the vote's own slot. The
    /// payload is revealed after the block, so a same-slot vote must claim
    /// "absent".
    fn payload_matches(
        &self,
        root_at: impl Fn(Slot) -> B256,
        payload_index: u64,
    ) -> Result<bool, AttestationError> {
        let same_slot = self.is_same_slot(root_at);
        if self.index > GLOAS_PAYLOAD_PRESENT || same_slot && self.index != GLOAS_PAYLOAD_ABSENT {
            return Err(AttestationError::InvalidPayloadIndex { index: self.index });
        }
        Ok(same_slot || self.index == payload_index)
    }

    /// The spec's `get_attestation_participation_flag_indices`, as flag bits.
    /// `root_at` is the state's `get_block_root_at_slot`; `payload_index` is
    /// `None` before Gloas. A head vote is timely only at exactly the fork's
    /// minimum inclusion delay.
    pub(crate) fn flags(
        &self,
        root_at: impl Fn(Slot) -> B256,
        current_slot: Slot,
        payload_index: Option<u64>,
        min_inclusion_delay: Slot,
    ) -> Result<u8, AttestationError> {
        let expected_target_root = root_at(self.target_epoch * SLOTS_PER_EPOCH);
        let is_matching_target = *self.target_root == expected_target_root;
        let expected_head_root = root_at(self.att_slot);
        let mut is_matching_head =
            is_matching_target && *self.beacon_block_root == expected_head_root;
        if let Some(payload_index) = payload_index {
            is_matching_head &= self.payload_matches(&root_at, payload_index)?;
        }
        let inclusion_delay = current_slot.saturating_sub(self.att_slot);

        Ok((u8::from(inclusion_delay <= SLOTS_PER_EPOCH.isqrt()) * TIMELY_SOURCE_FLAG) |
            (u8::from(is_matching_target) * TIMELY_TARGET_FLAG) |
            (u8::from(is_matching_head && inclusion_delay == min_inclusion_delay) *
                TIMELY_HEAD_FLAG))
    }
}

#[derive(Default)]
struct AppliedFlags {
    proposer_reward_numerator: u64,
    /// Gloas builder-payment weight: effective balance of the attesters this
    /// attestation brought from no participation to some.
    first_participation_eb: u64,
    /// Unslashed attesters that newly earned TIMELY_TARGET.
    new_target_eb: u64,
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        B256, MIN_ATTESTATION_INCLUSION_DELAY, Slot, TIMELY_HEAD_FLAG, TIMELY_SOURCE_FLAG,
        TIMELY_TARGET_FLAG, pq::MIN_ATTESTATION_INCLUSION_DELAY_PQ,
    };
    use silver_common::ssz_view::{
        ATTESTATION_DATA_SIZE, ATTESTATION_PQ_FIXED, AttestationDataView,
    };

    use super::{
        ATTESTATION_FIXED, Attestation, AttestationError, AttestedCommittees, EpochShuffling,
        ParsedAttestationData,
    };

    const ROOT: B256 = [7; 32];

    /// A vote at slot 33 for the block at slot 32, its target, which the
    /// empty slot 33 carries forward. It claims the payload present.
    fn vote_bytes() -> [u8; ATTESTATION_DATA_SIZE] {
        let mut data = [0; ATTESTATION_DATA_SIZE];
        data[..8].copy_from_slice(&33u64.to_le_bytes());
        data[8..16].copy_from_slice(&1u64.to_le_bytes());
        data[16..48].copy_from_slice(&ROOT);
        data[88..96].copy_from_slice(&1u64.to_le_bytes());
        data[96..128].copy_from_slice(&ROOT);
        data
    }

    fn flags(current_slot: Slot, min_inclusion_delay: Slot) -> u8 {
        let data = vote_bytes();
        ParsedAttestationData::parse(AttestationDataView::new(&data))
            .flags(|_| ROOT, current_slot, Some(1), min_inclusion_delay)
            .unwrap()
    }

    #[test]
    fn head_is_timely_only_at_the_minimum_inclusion_delay() {
        let all = TIMELY_SOURCE_FLAG | TIMELY_TARGET_FLAG | TIMELY_HEAD_FLAG;
        let late = TIMELY_SOURCE_FLAG | TIMELY_TARGET_FLAG;
        assert_eq!(flags(34, MIN_ATTESTATION_INCLUSION_DELAY), all);
        assert_eq!(flags(35, MIN_ATTESTATION_INCLUSION_DELAY), late);
        assert_eq!(flags(35, MIN_ATTESTATION_INCLUSION_DELAY_PQ), all);
        assert_eq!(flags(36, MIN_ATTESTATION_INCLUSION_DELAY_PQ), late);
    }

    #[test]
    fn pq_attestation_reads_its_own_layout() {
        let committee_bits_len = ATTESTATION_PQ_FIXED - 4 - ATTESTATION_DATA_SIZE;
        let mut att = Vec::from((ATTESTATION_PQ_FIXED as u32).to_le_bytes());
        att.extend_from_slice(&vote_bytes());
        att.extend(std::iter::once(0b101).chain(std::iter::repeat_n(0, committee_bits_len - 1)));
        att.extend_from_slice(&[0b11, 0b1]);

        let parsed = Attestation::parse(&att, true).unwrap();
        assert_eq!(parsed.data.slot(), 33);
        assert_eq!(parsed.committee_bits, 0b101);
        assert_eq!(parsed.aggregation_bits, [0b11, 0b1]);

        att[0] += 1;
        assert!(Attestation::parse(&att, true).is_err(), "a misplaced offset is not canonical");
    }

    /// PQ drops `is_valid_indexed_attestation`, so an attestation naming no
    /// committee applies as a no-op instead of failing the block.
    #[test]
    fn only_pq_admits_an_attestation_naming_no_committee() {
        let shuffled: Vec<u32> = (0..64).collect();
        let shuffling = EpochShuffling::with_committees_per_slot(&shuffled, 2);
        let committee_bits_len = ATTESTATION_PQ_FIXED - 4 - ATTESTATION_DATA_SIZE;
        let mut pq = Vec::from((ATTESTATION_PQ_FIXED as u32).to_le_bytes());
        pq.extend_from_slice(&vote_bytes());
        pq.extend(std::iter::repeat_n(0, committee_bits_len));
        pq.push(0b1);

        let committees = AttestedCommittees::new(&pq, true, &shuffling).unwrap();
        assert_eq!(committees.committees().count(), 0);

        let mut electra = vec![0; ATTESTATION_FIXED];
        electra[..4].copy_from_slice(&(ATTESTATION_FIXED as u32).to_le_bytes());
        electra.push(0b1);
        assert!(matches!(
            AttestedCommittees::new(&electra, false, &shuffling),
            Err(AttestationError::EmptyCommitteeBits)
        ));
    }

    /// `attested_count` short-circuits the committee walk, so it has to agree
    /// with the `members` walk on every bitlist shape — including ones too
    /// short to cover the members.
    #[test]
    fn attested_count_matches_walk() {
        let shuffled: Vec<u32> = (0..640).collect();
        let shuffling = EpochShuffling::with_committees_per_slot(&shuffled, 2);

        for agg_bits in [
            vec![0xFF, 0xFF, 0xFF],
            vec![0b1010_1010, 0b0101_0101, 0b0000_0011],
            vec![0x00, 0x00, 0x00],
            vec![0xFF, 0x0F],
            vec![0xFF],
            vec![],
        ] {
            let committees = AttestedCommittees {
                shuffling: &shuffling,
                slot: 0,
                committee_bits: 0b11,
                agg_bits: &agg_bits,
            };
            let members = committees.member_count();
            assert_eq!(members, 20, "two 10-member committees");

            let walked = committees.attesters().count();
            assert_eq!(committees.attested_count(members), walked, "bits {agg_bits:?}");
        }
    }
}
