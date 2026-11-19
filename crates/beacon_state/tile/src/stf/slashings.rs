use core::cmp::max;

use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BuilderPendingPayment, EPOCHS_PER_SLASHINGS_VECTOR, Epoch,
    EpochBalancesRow, EpochView, Immutable, SLOTS_PER_EPOCH, SlotStateWriteView, SpecConfig,
    StateReadView, StateWriterView, ValidatorsView, Version,
    bls::{self, SigBatch},
    hash_tree_root_block_header,
    pq::xmss_pubkey,
    xmss::SignatureCheck,
};
use silver_common::ssz_view::{
    ATTESTATION_DATA_SIZE, AttestationDataView, AttesterSlashingPqView, BEACON_BLOCK_HEADER_SIZE,
    BeaconBlockHeaderView, IndexedAttestationPqView, PROPOSER_SLASHING_PQ_SIZE,
    PROPOSER_SLASHING_SIZE, ProposerSlashingPqView, ProposerSlashingView,
};
use silver_ssz::ssz_view::{IndexedAttestationView, MAX_ATTESTING_INDICES};

use crate::{
    error::{AttesterSlashingError, ProposerSlashingError, Result},
    stf::{
        StarkClaims, attestation::attester_signing_root, for_each_ssz_list_item,
        get_beacon_proposer_index, initiate_validator_exit,
    },
    validate,
};

const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 4096;

/// Parse + validate an AttesterSlashing's two inner IndexedAttestation
/// offsets.
fn attester_slashing_inner_offsets(
    slashing: &[u8],
) -> std::result::Result<(usize, usize), AttesterSlashingError> {
    if slashing.len() < 8 {
        return Err(AttesterSlashingError::TooShort { len: slashing.len(), min: 8 });
    }
    let off1 = u32::from_le_bytes(slashing[0..4].try_into().unwrap()) as usize;
    let off2 = u32::from_le_bytes(slashing[4..8].try_into().unwrap()) as usize;
    if off1 + 132 > slashing.len() || off2 + 132 > slashing.len() || off2 < off1 + 132 {
        return Err(AttesterSlashingError::BadInnerOffsets {
            off1,
            off2,
            slashing_len: slashing.len(),
        });
    }
    Ok((off1, off2))
}

/// Pass 1 — push both header sigs per slashing entry.
pub fn collect_sigs_proposer_slashings(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    data: &[u8],
    sig_batch: &mut SigBatch,
) -> Result<(), ProposerSlashingError> {
    let (fork_epoch, prev_ver, cur_ver) = epoch.fork_descriptor();
    let count = data.len() / PROPOSER_SLASHING_SIZE;
    let n = validators.count();
    for i in 0..count {
        let s: &[u8; PROPOSER_SLASHING_SIZE] =
            data[i * PROPOSER_SLASHING_SIZE..(i + 1) * PROPOSER_SLASHING_SIZE].try_into().unwrap();
        let vi = ProposerSlashingView::h1_proposer_index(s);
        if vi >= n as u64 {
            return Err(ProposerSlashingError::ValidatorOutOfRange { vi: vi as usize, count: n });
        }
        let vi = vi as u32;
        let h1_slot = ProposerSlashingView::h1_slot(s);
        let fv =
            bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, h1_slot / SLOTS_PER_EPOCH);
        let domain =
            bls::compute_domain(bls::DOMAIN_BEACON_PROPOSER, fv, &imm.genesis_validators_root);
        let sr1 = signing_root_for_block_header(&s[0..208], &domain);
        let sr2 = signing_root_for_block_header(&s[208..416], &domain);
        let sig1 = ProposerSlashingView::h1_signature(s);
        let sig2 = ProposerSlashingView::h2_signature(s);
        let pk = validators.pubkey_decompressed(vi as usize);
        sig_batch.push_one(pk, sig1, sr1);
        sig_batch.push_one(pk, sig2, sr2);
    }
    Ok(())
}

/// Spec `process_proposer_slashing`'s signature checks under PQ: both headers
/// sign at the proposer leaf of their shared slot.
#[timed]
pub fn verify_proposer_slashing_signatures_pq(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    data: &[u8],
) -> Result<(), ProposerSlashingError> {
    let (fork_epoch, prev_ver, cur_ver) = epoch.fork_descriptor();
    let n = validators.count();
    for s in data.chunks_exact(PROPOSER_SLASHING_PQ_SIZE) {
        let s: &[u8; PROPOSER_SLASHING_PQ_SIZE] = s.try_into().unwrap();
        let header = ProposerSlashingPqView::header_1(s);
        let vi = BeaconBlockHeaderView::proposer_index(header) as usize;
        if vi >= n {
            return Err(ProposerSlashingError::ValidatorOutOfRange { vi, count: n });
        }
        let header_epoch = BeaconBlockHeaderView::slot(header) / SLOTS_PER_EPOCH;
        let fork_version = bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, header_epoch);
        let domain = bls::compute_domain(
            bls::DOMAIN_BEACON_PROPOSER,
            fork_version,
            &imm.genesis_validators_root,
        );
        let checks =
            SignatureCheck::proposer_slashing(s, xmss_pubkey(validators.pubkey(vi)), &domain);
        let mut valid = [false; 2];
        SignatureCheck::verify_batch(checks, &mut valid);
        if valid != [true; 2] {
            return Err(ProposerSlashingError::BadSignature { vi });
        }
    }
    Ok(())
}

/// Requires verified BLS signatures. Rechecks slashability after earlier
/// entries, so a second slashing of the same validator rejects the block.
pub fn process_proposer_slashings(
    view: &mut StateWriterView,
    epoch: EpochView,
    cfg: &SpecConfig,
    data: &[u8],
) -> Result<u64, ProposerSlashingError> {
    let post_gloas_fork = epoch.post_gloas_fork(view.imm);
    let is_pq = epoch.is_pq(view.imm);
    let size = if is_pq { PROPOSER_SLASHING_PQ_SIZE } else { PROPOSER_SLASHING_SIZE };
    let n = view.validators.count();
    let proposer_index = get_beacon_proposer_index(&view.slot, epoch);
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let mut proposer_reward = 0;
    for s in data.chunks_exact(size) {
        let (h1, h2) = if is_pq {
            let s = s.try_into().unwrap();
            (ProposerSlashingPqView::header_1(s), ProposerSlashingPqView::header_2(s))
        } else {
            let s = s.try_into().unwrap();
            (ProposerSlashingView::header_1(s), ProposerSlashingView::header_2(s))
        };
        validate::validate_proposer_slashing_headers(h1, h2)?;
        let vi = BeaconBlockHeaderView::proposer_index(h1);
        if vi >= n as u64 {
            return Err(ProposerSlashingError::ValidatorOutOfRange { vi: vi as usize, count: n });
        }
        let vi = vi as u32;
        if !view.validators.reader().is_slashable(vi as usize, current_epoch) {
            return Err(ProposerSlashingError::NotSlashable {
                vi: vi as usize,
                pubkey: *view.validators.pubkey(vi as usize),
                epoch: current_epoch,
            });
        }
        proposer_reward += slash_validator(cfg, view, post_gloas_fork, vi, proposer_index);
    }
    Ok(proposer_reward)
}

fn clear_builder_payments_of(slot: &mut SlotStateWriteView, proposer_index: u32) {
    let proposer_index = proposer_index as u64;
    for ring in 0..slot.state().builder_pending_payments.len() {
        if slot.state().builder_pending_payments[ring].proposer_index == proposer_index {
            slot.state_mut().builder_pending_payments[ring] = BuilderPendingPayment::default();
        }
    }
}

/// Compute signing root for a `BeaconBlockHeader` (208-byte SSZ): slot,
/// proposer_index, parent_root, state_root, body_root.
#[timed]
pub(crate) fn signing_root_for_block_header(header: &[u8], domain: &B256) -> B256 {
    let hb: &[u8; BEACON_BLOCK_HEADER_SIZE] =
        header[..BEACON_BLOCK_HEADER_SIZE].try_into().unwrap();
    let h = BeaconBlockHeader {
        slot: BeaconBlockHeaderView::slot(hb),
        proposer_index: BeaconBlockHeaderView::proposer_index(hb),
        parent_root: *BeaconBlockHeaderView::parent_root(hb),
        state_root: *BeaconBlockHeaderView::state_root(hb),
        body_root: *BeaconBlockHeaderView::body_root(hb),
    };
    let object_root = hash_tree_root_block_header(&h);
    bls::compute_signing_root(&object_root, domain)
}

/// Pass 1 — push both IndexedAttestation aggregate sigs per slashing entry.
#[timed]
pub fn collect_sigs_attester_slashings(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    data: &[u8],
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) -> Result<(), AttesterSlashingError> {
    let fork = epoch.fork_descriptor();
    for_each_ssz_list_item(
        data,
        |start, end| AttesterSlashingError::BadOffsets { start, end, parent_len: data.len() },
        |slashing| {
            let (off1, off2) = attester_slashing_inner_offsets(slashing)?;
            let i1 = attesting_indices_bytes(slashing, off1, off2);
            let i2 = attesting_indices_bytes(slashing, off2, slashing.len());

            for (ia_off, ia_end, indices) in [(off1, off2, i1), (off2, slashing.len(), i2)] {
                let ia = &slashing[ia_off..ia_end];
                active_scratch.clear();
                let n_idx = indices.len() / 8;
                let count = validators.count();
                for k in 0..n_idx {
                    let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap());
                    if vi as usize >= count {
                        return Err(AttesterSlashingError::ValidatorOutOfRange {
                            vi: vi as usize,
                            count,
                        });
                    }
                    active_scratch.push(vi as u32);
                }
                let data = IndexedAttestationView::data(ia);
                let sig: &[u8; 96] = IndexedAttestationView::signature(ia);
                let signing_root = attester_signing_root(imm, fork, data);
                sig_batch.push_aggregate(
                    active_scratch.iter().map(|&vi| validators.pubkey_decompressed(vi as usize)),
                    sig,
                    signing_root,
                );
            }
            Ok(())
        },
    )
}

/// Walk two strictly-ascending u64-LE-packed lists in lockstep, invoking
/// `f(vi)` for each value present in both. O(n+m). Returning `true` from
/// `f` short-circuits — used by the gossip path on first slashable match;
/// the block path always returns `false` and traverses the full intersection.
pub(crate) fn for_each_sorted_intersection(i1: &[u8], i2: &[u8], mut f: impl FnMut(usize) -> bool) {
    let read = |s: &[u8], i: usize| u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().unwrap());
    let (n1, n2) = (i1.len() / 8, i2.len() / 8);
    let (mut a, mut b) = (0usize, 0usize);
    while a < n1 && b < n2 {
        let x = read(i1, a);
        let y = read(i2, b);
        match x.cmp(&y) {
            core::cmp::Ordering::Less => a += 1,
            core::cmp::Ordering::Greater => b += 1,
            core::cmp::Ordering::Equal => {
                if f(x as usize) {
                    return;
                }
                a += 1;
                b += 1;
            }
        }
    }
}

/// Pass 2 — validate data + state, slash the intersection. BLS verified.
pub fn process_attester_slashings(
    view: &mut StateWriterView,
    epoch: EpochView,
    cfg: &SpecConfig,
    data: &[u8],
    slashed_sink: &mut Vec<u32>,
    mut stark: Option<&mut StarkClaims>,
) -> Result<u64, AttesterSlashingError> {
    if data.is_empty() {
        return Ok(0);
    }
    let post_gloas_fork = epoch.post_gloas_fork(view.imm);
    let is_pq = epoch.is_pq(view.imm);
    let proposer_index = get_beacon_proposer_index(&view.slot, epoch);
    let n = view.validators.count();
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let fork = epoch.fork_descriptor();

    let mut proposer_reward = 0;
    for_each_ssz_list_item(
        data,
        |start, end| AttesterSlashingError::BadOffsets { start, end, parent_len: data.len() },
        |slashing| {
            let pair = SlashedAttestation::checked_pair(slashing, is_pq, n)?;
            let (i1, i2) = (pair[0].indices, pair[1].indices);
            if let Some(claims) = stark.as_deref_mut() {
                pair.iter().for_each(|attestation| attestation.push_claims(claims, view.imm, fork));
            }

            // Spec requires ≥1 currently-slashable validator in the
            // intersection; a no-op slashing makes the block invalid.
            let start = slashed_sink.len();
            let validators = view.validators.reader();
            for_each_sorted_intersection(i1, i2, |vi| {
                if vi < n && validators.is_slashable(vi, current_epoch) {
                    slashed_sink.push(vi as u32);
                }
                false
            });
            if slashed_sink.len() == start {
                return Err(AttesterSlashingError::NoSlashedIntersection);
            }
            for &vi in &slashed_sink[start..] {
                proposer_reward += slash_validator(cfg, view, post_gloas_fork, vi, proposer_index);
            }
            Ok(())
        },
    )?;
    Ok(proposer_reward)
}

/// Spec `on_attester_slashing` short of its `is_valid_indexed_attestation`
/// proofs: fills `equivocators` with the attestations' common attesters.
pub fn attester_slashing_equivocators(
    slashing: &[u8],
    is_pq: bool,
    validator_count: usize,
    equivocators: &mut Vec<u32>,
) -> Result<(), AttesterSlashingError> {
    let [first, second] = SlashedAttestation::checked_pair(slashing, is_pq, validator_count)?;
    equivocators.clear();
    for_each_sorted_intersection(first.indices, second.indices, |vi| {
        equivocators.push(vi as u32);
        false
    });
    Ok(())
}

fn check_attesting_indices(
    indices: &[u8],
    validator_count: usize,
) -> Result<(), AttesterSlashingError> {
    let Some(last) = indices.len().checked_sub(8) else {
        return Err(AttesterSlashingError::NoAttestingIndices);
    };
    if !indices_sorted_unique(indices) {
        return Err(AttesterSlashingError::IndicesNotSorted);
    }
    let last = u64::from_le_bytes(indices[last..].try_into().unwrap()) as usize;
    if last >= validator_count {
        return Err(AttesterSlashingError::ValidatorOutOfRange { vi: last, count: validator_count });
    }
    Ok(())
}

/// One attestation of an attester slashing, read from either fork's layout.
struct SlashedAttestation<'a> {
    data: AttestationDataView<'a>,
    indices: &'a [u8],
    /// Empty before PQ, where a BLS signature stands in for it.
    proof: &'a [u8],
}

impl<'a> SlashedAttestation<'a> {
    fn pair(
        slashing: &'a [u8],
        is_pq: bool,
    ) -> std::result::Result<[Self; 2], AttesterSlashingError> {
        if is_pq {
            if !AttesterSlashingPqView::check_size(slashing) {
                return Err(AttesterSlashingError::Malformed { len: slashing.len() });
            }
            return Ok([
                AttesterSlashingPqView::attestation_1(slashing),
                AttesterSlashingPqView::attestation_2(slashing),
            ]
            .map(|indexed| Self {
                data: IndexedAttestationPqView::data(indexed),
                indices: IndexedAttestationPqView::attesting_indices(indexed),
                proof: IndexedAttestationPqView::proof(indexed),
            }));
        }
        let (off1, off2) = attester_slashing_inner_offsets(slashing)?;
        let bls = |start: usize, end: usize| Self {
            data: AttestationDataView::new(slashing[start + 4..start + 132].try_into().unwrap()),
            indices: attesting_indices_bytes(slashing, start, end),
            proof: &[],
        };
        Ok([bls(off1, off2), bls(off2, slashing.len())])
    }

    /// Spec `is_slashable_attestation_data` on the pair, and
    /// `is_valid_indexed_attestation` short of its signature on each.
    fn checked_pair(
        slashing: &'a [u8],
        is_pq: bool,
        validator_count: usize,
    ) -> std::result::Result<[Self; 2], AttesterSlashingError> {
        let pair = Self::pair(slashing, is_pq)?;
        let [first, second] = &pair;
        if !is_slashable_attestation_data(first.data.as_bytes(), second.data.as_bytes()) {
            return Err(AttesterSlashingError::NotSlashableData);
        }
        check_attesting_indices(first.indices, validator_count)?;
        check_attesting_indices(second.indices, validator_count)?;
        Ok(pair)
    }

    /// Spec `is_valid_indexed_attestation`'s `stark.VerifyAggregates` call:
    /// `proof` over the one statement the attesters sign.
    fn push_claims(
        &self,
        claims: &mut StarkClaims,
        imm: &Immutable,
        fork: (Epoch, Version, Version),
    ) {
        let first_statement = claims.statement_count();
        let attesters = self
            .indices
            .chunks_exact(8)
            .map(|index| u64::from_le_bytes(index.try_into().unwrap()) as u32);
        claims.attestation(imm, fork, self.data).push(attesters);
        claims.push_proof(first_statement, self.proof);
    }
}

/// Gossip's dedup, ahead of any validity check: does the intersection of the
/// two attestations' indices name a validator `seen` has not? Out-of-range
/// indices count, as in the spec, so a bad index is a REJECT later rather than
/// an IGNORE here. `None` when the slashing does not parse.
pub fn attester_slashing_names_unseen(
    slashing: &[u8],
    seen: impl Fn(usize) -> bool,
) -> Option<bool> {
    let (off1, off2) = attester_slashing_inner_offsets(slashing).ok()?;
    let i1 = attesting_indices_bytes(slashing, off1, off2);
    let i2 = attesting_indices_bytes(slashing, off2, slashing.len());
    let mut unseen = false;
    for_each_sorted_intersection(i1, i2, |vi| {
        unseen = !seen(vi);
        unseen
    });
    Some(unseen)
}

/// Gossip-side `AttesterSlashing` validator (single slashing, not the
/// block-body list form).
/// On success, `equivocating_out` is filled with the in-range intersection of
/// the two attestations' indices (the validators to mark equivocating in fork
/// choice). Its contents are meaningless when this returns `false`.
#[timed]
pub fn validate_attester_slashing_for_gossip(
    view: &StateReadView,
    slashing: &[u8],
    equivocating_out: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) -> bool {
    let fork = view.epoch.fork_descriptor();
    let Ok((off1, off2)) = attester_slashing_inner_offsets(slashing) else {
        return false;
    };
    let d1 = &slashing[off1 + 4..off1 + 132];
    let d2 = &slashing[off2 + 4..off2 + 132];
    if !is_slashable_attestation_data(d1, d2) {
        return false;
    }
    let i1 = attesting_indices_bytes(slashing, off1, off2);
    let i2 = attesting_indices_bytes(slashing, off2, slashing.len());
    if i1.len() / 8 > MAX_ATTESTING_INDICES || i2.len() / 8 > MAX_ATTESTING_INDICES {
        return false;
    }
    if !indices_sorted_unique(i1) || !indices_sorted_unique(i2) {
        return false;
    }

    let current_epoch = view.slot.current_epoch();
    let count = view.validators.count();
    let validators = view.validators;
    equivocating_out.clear();
    let mut any_slashable = false;
    for_each_sorted_intersection(i1, i2, |vi| {
        let vi32 = vi as u32;
        if vi < count {
            equivocating_out.push(vi32);
            if validators.is_slashable(vi, current_epoch) {
                any_slashable = true;
            }
        }
        false
    });
    if !any_slashable {
        return false;
    }

    sig_batch.clear();
    for (ia_off, ia_end, indices) in [(off1, off2, i1), (off2, slashing.len(), i2)] {
        let ia = &slashing[ia_off..ia_end];
        let n_idx = indices.len() / 8;
        for k in 0..n_idx {
            let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap()) as usize;
            if vi >= count {
                return false;
            }
        }
        let data = IndexedAttestationView::data(ia);
        let sig: &[u8; 96] = IndexedAttestationView::signature(ia);
        let signing_root = attester_signing_root(view.imm, fork, data);
        sig_batch.push_aggregate(
            (0..n_idx).map(|k| {
                let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap()) as u32;
                view.validators.pubkey_decompressed(vi as usize)
            }),
            sig,
            signing_root,
        );
    }
    sig_batch.verify_all()
}

/// View an IndexedAttestation's attesting_indices SSZ bytes (skips the 228
/// byte fixed part: indices_offset(4) + data(128) + sig(96)).
#[inline]
pub(crate) fn attesting_indices_bytes(data: &[u8], start: usize, end: usize) -> &[u8] {
    if start + 228 > end || end > data.len() {
        return &[];
    }
    let slice = &data[start + 228..end];
    let whole = slice.len() - slice.len() % 8;
    &slice[..whole]
}

/// Returns the proposer's reward.
fn slash_validator(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    is_gloas: bool,
    vi: u32,
    proposer_index: u32,
) -> u64 {
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let effective_balance = view.validators.effective_balance(vi as usize);

    // The justification target sums count only unslashed attesters — drop the
    // contributions this validator already earned.
    let validators = view.validators.reader();
    let row = EpochBalancesRow {
        activation_epoch: validators.activation_epoch(vi as usize),
        exit_epoch: validators.exit_epoch(vi as usize),
        slashed: validators.is_slashed(vi as usize),
        effective_balance,
        previous_participation: view.previous_participation.get(vi as usize),
        current_participation: view.current_participation.get(vi as usize),
    };
    view.slot.epoch_balances_mut().remove_slashed(row, current_epoch);

    initiate_validator_exit(cfg, view, vi, current_epoch);
    view.validators.set_slashed(vi, true);
    let prev_wd = view.validators.withdrawable_epoch(vi as usize);
    let new_wd = max(prev_wd, current_epoch + EPOCHS_PER_SLASHINGS_VECTOR as u64);
    view.validators.set_withdrawable_epoch(vi, new_wd);

    // Spec: `state.slashings[current_epoch % SV] += effective_balance`.
    let bucket = (current_epoch % EPOCHS_PER_SLASHINGS_VECTOR as u64) as u32;
    let total = view.slashings.get(bucket as usize).saturating_add(effective_balance);
    view.slashings.set(bucket, total);

    let penalty = effective_balance / cfg.min_slashing_penalty_quotient;
    let bal_vi = view.balances.get(vi as usize);
    view.balances.set(vi, bal_vi.saturating_sub(penalty));

    // Spec: increase_balance(proposer, proposer_reward); increase_balance(
    // whistleblower, whistleblower_reward - proposer_reward). With no
    // explicit whistleblower (block-included slashings), whistleblower_index
    // defaults to proposer_index, so the proposer receives the full
    // whistleblower_reward.
    let whistleblower_reward = effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT;
    let bal_pi = view.balances.get(proposer_index as usize);
    view.balances.set(proposer_index, bal_pi.saturating_add(whistleblower_reward));

    if is_gloas {
        clear_builder_payments_of(&mut view.slot, vi);
    }
    whistleblower_reward
}

pub(crate) fn is_slashable_attestation_data(d1: &[u8], d2: &[u8]) -> bool {
    if d1.len() < ATTESTATION_DATA_SIZE || d2.len() < ATTESTATION_DATA_SIZE {
        return false;
    }
    let d1f = AttestationDataView::new(d1[..ATTESTATION_DATA_SIZE].try_into().unwrap());
    let d2f = AttestationDataView::new(d2[..ATTESTATION_DATA_SIZE].try_into().unwrap());
    let s1 = d1f.source_epoch();
    let t1 = d1f.target_epoch();
    let s2 = d2f.source_epoch();
    let t2 = d2f.target_epoch();

    // Double vote: distinct data, same target epoch.
    if d1 != d2 && t1 == t2 {
        return true;
    }
    // Surround vote: data_1 surrounds data_2.
    s1 < s2 && t2 < t1
}

/// Spec: SSZ List[uint64] invariant — strictly ascending.
pub(crate) fn indices_sorted_unique(indices: &[u8]) -> bool {
    let n = indices.len() / 8;
    if n < 2 {
        return true;
    }
    let read = |i: usize| u64::from_le_bytes(indices[i * 8..i * 8 + 8].try_into().unwrap());
    let mut prev = read(0);
    for i in 1..n {
        let curr = read(i);
        if curr <= prev {
            return false;
        }
        prev = curr;
    }
    true
}
