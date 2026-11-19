use flux_profiler::timed;
use silver_beacon_state_data::{
    AGGREGATORS_PER_COMMITTEE, AggregationCommittee, Epoch, EpochWriteView, MIN_SEED_LOOKAHEAD,
    SLOTS_PER_EPOCH, StateWriterView, ValidatorsView, bls::DOMAIN_SELECTION_PROOF,
};

use crate::{
    shuffling::Seed,
    stf::{EpochShuffling, gloas::balance_weighted_draws},
};

/// Spec `process_aggregation_committee_window`. `lookahead` is
/// [`EpochShuffling::lookahead`] from `current_epoch`.
#[timed]
pub fn process_aggregation_committee_window(
    view: &StateWriterView,
    epoch: &mut EpochWriteView,
    current_epoch: Epoch,
    lookahead: &EpochShuffling<'_>,
) {
    let target_epoch = current_epoch + MIN_SEED_LOOKAHEAD + 1;
    let validators = view.validators.reader();
    let seed = Seed::from_randao(&view.randao_mixes.reader(), target_epoch, DOMAIN_SELECTION_PROOF);
    let start = target_epoch * SLOTS_PER_EPOCH;
    epoch.rotate_aggregation_committee_window(lookahead.committees_per_slot, |slot, index| {
        let slot = start + slot as u64;
        let committee_seed = seed.mixed_with(&[slot, index as u64]);
        aggregation_committee(&validators, lookahead.committee(slot, index), &committee_seed)
    });
}

/// Spec `compute_aggregation_committee`: members drawn by effective balance,
/// without replacement. Each draw samples the members not yet drawn, in
/// committee order, by stepping over the drawn members' positions.
fn aggregation_committee(
    validators: &ValidatorsView,
    members: &[u32],
    seed: &Seed,
) -> AggregationCommittee {
    let mut committee = AggregationCommittee::default();
    let mut drawn_positions = [0usize; AGGREGATORS_PER_COMMITTEE];
    let mut drawn = 0;
    while !committee.is_full() && drawn < members.len() {
        let draw_seed = seed.mixed_with(&[drawn as u64]);
        let position = draw_untaken(validators, members, &drawn_positions[..drawn], &draw_seed);
        committee.push(u64::from(members[position]));

        drawn_positions[drawn] = position;
        drawn += 1;
        drawn_positions[..drawn].sort_unstable();
    }
    committee
}

fn draw_untaken(
    validators: &ValidatorsView,
    members: &[u32],
    taken: &[usize],
    seed: &Seed,
) -> usize {
    debug_assert!(taken.is_sorted());
    let position_of =
        |k: usize| taken.iter().fold(k, |position, &t| position + usize::from(t <= position));
    let remaining = members.len() - taken.len();
    let mut draws =
        balance_weighted_draws(validators, remaining, |k| members[position_of(k)], seed);
    position_of(draws.next().expect("the draws never end"))
}

#[cfg(test)]
mod tests {
    use blst::min_pk::PublicKey;
    use silver_beacon_state_data::{FinalizedValidators, HashFormat, ValidatorsGroup, Withdrawals};

    use super::*;

    /// The spec's loop as written: draw from the candidates left, then drop
    /// the drawn one.
    fn by_the_spec(validators: &ValidatorsView, members: &[u32], seed: &Seed) -> Vec<u64> {
        let mut candidates = members.to_vec();
        let mut aggregators = Vec::new();
        while aggregators.len() < AGGREGATORS_PER_COMMITTEE && !candidates.is_empty() {
            let draw_seed = seed.mixed_with(&[aggregators.len() as u64]);
            let k =
                balance_weighted_draws(validators, candidates.len(), |k| candidates[k], &draw_seed)
                    .next()
                    .unwrap();
            aggregators.push(u64::from(candidates.remove(k)));
        }
        aggregators
    }

    /// Low balances make draws reject often, so later draws walk past the
    /// positions of earlier ones.
    #[test]
    fn draws_without_replacement_as_the_spec_does() {
        let mut group = ValidatorsGroup::new(
            FinalizedValidators::try_new(&[], None).unwrap(),
            HashFormat::Fixed,
        );
        let mut validators = group.roll_fresh();
        for i in 0..64u64 {
            let index =
                validators.append([i as u8; 48], PublicKey::default(), Withdrawals::default());
            validators.set_effective_balance(index, (1 + i % 7) * 1_000_000_000);
        }
        let validators = validators.reader();

        for (size, salt) in [(1, 0), (2, 1), (5, 2), (17, 3), (64, 4)] {
            let members: Vec<u32> = (0..size).map(|i| (i * 37 + salt) % 64).collect();
            let seed = Seed::new(&[salt as u8; 32], 9, DOMAIN_SELECTION_PROOF);
            assert_eq!(
                aggregation_committee(&validators, &members, &seed).as_slice(),
                by_the_spec(&validators, &members, &seed),
                "committee of {size}",
            );
        }
    }
}
