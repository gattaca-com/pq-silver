use super::{
    super::{
        greedy,
        test_util::{all_waiting, batch_input, claim, claims},
    },
    *,
};
use crate::tile::pq_aggregation::claims::Claim;

fn range(from: u8, to: u8) -> Vec<Claim> {
    (from..to).map(claim).collect()
}

fn covered(sets: &[Vec<Claim>], chosen: &[usize]) -> usize {
    let mut union: Vec<_> = chosen.iter().flat_map(|&i| sets[i].iter()).collect();
    union.sort_unstable();
    union.dedup();
    union.len()
}

/// Two subnets of 40 claims. Arrival order offers three partial children
/// of subnet 0 before the one child that holds all of subnet 1.
fn overlapping() -> Vec<Vec<Claim>> {
    vec![range(0, 30), range(10, 40), range(0, 40), range(100, 140)]
}

#[test]
fn it_covers_more_than_greedy_on_overlapping_children() {
    let sets = overlapping();
    let waiting = all_waiting(&sets, &[]);
    let greedy = greedy::next_batch(&batch_input(2, None, &waiting)).unwrap();
    let max_coverage = next_batch(&batch_input(2, None, &waiting)).unwrap();
    assert_eq!(covered(&sets, &greedy.indices), 40, "the first two arrivals");
    assert_eq!(max_coverage.indices, [2, 3]);
    assert_eq!(covered(&sets, &max_coverage.indices), 80);
}

#[test]
fn it_respects_the_limit() {
    let sets: Vec<_> = (0..20u8).map(|tag| claims(&[tag])).collect();
    let waiting = all_waiting(&sets, &[]);
    let batch = next_batch(&batch_input(16, None, &waiting)).unwrap();
    assert_eq!(batch.indices.len(), 16);

    let best = claims(&[200]);
    let waiting = all_waiting(&sets, &best);
    let batch = next_batch(&batch_input(15, Some(&best), &waiting)).unwrap();
    assert_eq!(batch.indices.len(), 15);
}

#[test]
fn it_skips_children_that_add_nothing() {
    let best = range(0, 10);
    let sets = [range(5, 10), claims(&[77])];
    let waiting = all_waiting(&sets, &best);
    let batch = next_batch(&batch_input(16, Some(&best), &waiting)).unwrap();
    assert_eq!(batch.indices, [1]);
}

#[test]
fn a_larger_group_than_the_bound_still_returns_a_valid_choice() {
    let sets: Vec<_> = (0..20u8).map(|tag| range(tag, tag + 5)).collect();
    let waiting = all_waiting(&sets, &[]);
    let batch = next_batch(&batch_input(3, None, &waiting)).unwrap();
    assert_eq!(batch.indices.len(), 3);
    assert_eq!(covered(&sets, &batch.indices), 15);
}
