use silver_beacon_state_data::{
    Epoch, EpochView, EpochWriteView, MIN_SEED_LOOKAHEAD, PTC_SIZE, RandaoMixesView,
    SLOTS_PER_EPOCH, StateWriterView, ValidatorsView, bls::DOMAIN_PTC_ATTESTER,
    gloas::PtcCommittee,
};

use crate::{shuffling::Seed, stf::EpochShuffling};

const SPE: usize = SLOTS_PER_EPOCH as usize;

pub(crate) fn get_ptc<'a>(
    epoch: &EpochView<'a>,
    gloas_fork_epoch: Epoch,
    state_epoch: u64,
    slot: u64,
) -> Option<&'a PtcCommittee> {
    let target_epoch = slot / SLOTS_PER_EPOCH;
    if target_epoch < gloas_fork_epoch {
        return None;
    }
    epoch
        .ptc_window()
        .epoch_committees(state_epoch, target_epoch)
        .map(|committees| &committees[(slot % SLOTS_PER_EPOCH) as usize])
}

pub(crate) fn fill_epoch_ptc(
    out: &mut [PtcCommittee],
    validators: &ValidatorsView,
    randao: &RandaoMixesView,
    shuffling: &EpochShuffling<'_>,
    target_epoch: u64,
) {
    let ptc_seed = Seed::from_randao(randao, target_epoch, DOMAIN_PTC_ATTESTER);
    for (i, dst) in out.iter_mut().enumerate() {
        *dst = compute_ptc(
            validators,
            shuffling,
            &ptc_seed,
            target_epoch * SLOTS_PER_EPOCH + i as u64,
        );
    }
}

/// `compute_ptc`: balance-weighted selection of `PTC_SIZE` indices (with
/// duplicates) over the concatenation of `slot`'s committees.
pub(crate) fn compute_ptc(
    validators: &ValidatorsView,
    shuffling: &EpochShuffling<'_>,
    epoch_seed: &Seed,
    slot: u64,
) -> PtcCommittee {
    let mut committee = [0u64; PTC_SIZE];
    let mut indices = Vec::new();
    for ci in 0..shuffling.committees_per_slot {
        indices.extend_from_slice(shuffling.committee(slot, ci));
    }
    if indices.is_empty() {
        return committee;
    }

    balance_weighted_select(validators, &indices, &epoch_seed.for_slot(slot), &mut committee);
    committee
}

/// `compute_balance_weighted_selection` with `shuffle_indices=False` (the PTC
/// case): traverse `indices` in order, accepting each by effective-balance
/// rejection sampling until `out` is full. Mirrors the proposer/sync sampler.
fn balance_weighted_select(
    validators: &ValidatorsView,
    indices: &[u32],
    seed: &Seed,
    out: &mut [u64],
) {
    let draws = balance_weighted_draws(validators, indices.len(), |k| indices[k], seed);
    for (selected, position) in out.iter_mut().zip(draws) {
        *selected = indices[position] as u64;
    }
}

/// Endless: the candidates are cycled through in order until the caller stops.
pub(crate) fn balance_weighted_draws(
    validators: &ValidatorsView,
    count: usize,
    candidate: impl Fn(usize) -> u32,
    seed: &Seed,
) -> impl Iterator<Item = usize> {
    let total = count as u64;
    let mut draws = seed.draws();
    (0u64..).filter_map(move |i| {
        let position = (i % total) as usize;
        let effective_balance = validators.effective_balance(candidate(position) as usize);
        draws.accept(i, effective_balance).then_some(position)
    })
}

/// `lookahead` is [`EpochShuffling::lookahead`] from `current_epoch`.
pub fn process_ptc_window(
    view: &StateWriterView,
    epoch: &mut EpochWriteView,
    current_epoch: u64,
    lookahead: &EpochShuffling<'_>,
) {
    let mut new_epoch = vec![[0u64; PTC_SIZE]; SPE];
    fill_epoch_ptc(
        &mut new_epoch,
        &view.validators.reader(),
        &view.randao_mixes.reader(),
        lookahead,
        current_epoch + MIN_SEED_LOOKAHEAD + 1,
    );
    epoch.rotate_ptc_window(&new_epoch);
}
