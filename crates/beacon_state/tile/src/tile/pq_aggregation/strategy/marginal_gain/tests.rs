use std::ops::Range;

use super::*;

fn positions(committee: usize, members: Range<usize>) -> Positions {
    let committee = Committee { data: [0; ATTESTATION_DATA_SIZE], index: committee };
    Positions { committee, bits: members.collect() }
}

fn strategy(children: &[Positions]) -> MarginalGain {
    let mut strategy = MarginalGain::default();
    for (index, &child) in children.iter().enumerate() {
        assert!(strategy.arrived(index, child));
    }
    strategy
}

/// Positions the union of `picks` covers, over all committees.
fn gain(children: &[Positions], picks: impl IntoIterator<Item = usize>) -> usize {
    let mut have = [Bits::default(); 256];
    picks.into_iter().for_each(|pick| {
        let child = &children[pick];
        have[child.committee.index].union_with(&child.bits)
    });
    have.iter().map(|bits| bits.count_outside(&Bits::default())).sum()
}

/// The most any `limit` children cover, by enumeration.
fn optimum(children: &[Positions], limit: usize) -> usize {
    let subsets = 0u32..1 << children.len();
    let small = subsets.filter(|mask| mask.count_ones() as usize <= limit);
    let members = |mask: u32| (0..children.len()).filter(move |i| mask >> i & 1 == 1);
    small.map(|mask| gain(children, members(mask))).max().unwrap()
}

#[test]
fn it_matches_the_optimum_on_nested_groups() {
    let children = [
        positions(0, 0..10),
        positions(1, 0..25),
        positions(2, 0..12),
        positions(0, 0..30),
        positions(3, 0..18),
        positions(1, 0..5),
        positions(0, 0..20),
        positions(2, 0..40),
    ];
    let strategy = strategy(&children);
    for limit in 1..=5 {
        let batch = strategy.next_batch(limit).unwrap();
        assert_eq!(gain(&children, batch.indices.clone()), optimum(&children, limit), "{limit}");
    }
    assert_eq!(strategy.next_batch(5).unwrap().indices, [1, 3, 4, 7], "one per group");
}

#[test]
fn ties_go_to_the_earlier_arrival() {
    let children = [positions(0, 0..4), positions(1, 0..4), positions(0, 4..8)];
    let strategy = strategy(&children);
    assert_eq!(strategy.next_batch(1).unwrap().indices, [0]);
    assert_eq!(strategy.next_batch(2).unwrap().indices, [0, 1]);
}

#[test]
fn children_that_add_nothing_are_skipped() {
    let mut strategy = strategy(&[positions(0, 0..10), positions(0, 0..5)]);
    assert_eq!(strategy.next_batch(16).unwrap().indices, [0], "index 1 gains 0 after index 0");

    strategy.adopted(&Batch::new(vec![0]).unwrap());
    assert!(strategy.next_batch(16).is_none(), "index 1 adds nothing to the best proof");
    assert!(strategy.arrived(2, positions(0, 5..10)));
    assert_eq!(strategy.waiting(), 0, "index 2 adds nothing either");
    assert!(strategy.arrived(3, positions(0, 77..78)));
    assert_eq!(strategy.next_batch(16).unwrap().indices, [3]);
    assert_eq!(strategy.waiting(), 1);
}

/// A decoy that straddles two disjoint aggregates and arrives first.
#[test]
fn an_adversarial_decoy_costs_part_of_one_batch() {
    let children = [positions(0, 4..12), positions(0, 0..8), positions(0, 8..16)];
    let mut strategy = strategy(&children);
    let batch = strategy.next_batch(2).unwrap();
    assert_eq!(batch.indices, [0, 1]);
    assert_eq!(gain(&children, batch.indices.clone()), 12);
    assert_eq!(optimum(&children, 2), 16, "the two disjoint aggregates");

    strategy.adopted(&batch);
    assert_eq!(strategy.next_batch(2).unwrap().indices, [2], "the next batch recovers");
}

#[test]
fn a_merge_refuses_a_committee_beyond_the_cap() {
    let mut strategy = MarginalGain::default();
    for (index, data) in (0..MAX_GROUPS).enumerate() {
        let mut child = positions(0, 0..1);
        child.committee.data[0] = data as u8;
        assert!(strategy.arrived(index, child));
    }
    let mut new_data = positions(0, 0..1);
    new_data.committee.data[1] = 1;
    assert!(!strategy.arrived(MAX_GROUPS, new_data));
    assert!(strategy.arrived(MAX_GROUPS, positions(0, 1..2)), "a known committee still fits");
}
