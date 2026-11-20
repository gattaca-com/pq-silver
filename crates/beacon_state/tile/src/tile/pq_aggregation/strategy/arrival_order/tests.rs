use super::*;

fn strategy(positions: &[usize]) -> ArrivalOrder {
    let mut strategy = ArrivalOrder::default();
    for (index, &position) in positions.iter().enumerate() {
        assert!(strategy.arrived(index, position));
    }
    strategy
}

#[test]
fn votes_are_taken_in_arrival_order_up_to_the_limit() {
    let strategy = strategy(&(0..256).rev().collect::<Vec<_>>());
    let batch = strategy.next_batch(100).unwrap();
    assert_eq!(batch.indices, (0..100).collect::<Vec<_>>());
    assert_eq!(batch.log_inv_rate, 2);

    let all = strategy.next_batch(2048).unwrap();
    assert_eq!(all.indices.len(), 256, "all waiting votes under the limit");
}

#[test]
fn covered_and_already_picked_positions_are_skipped() {
    let mut strategy = strategy(&[1, 2, 3, 2, 4]);
    let batch = strategy.next_batch(16).unwrap();
    assert_eq!(batch.indices, [0, 1, 2, 4], "index 3 repeats position 2");
    assert_eq!(strategy.waiting(), 4);

    strategy.adopted(&Batch::new(vec![0, 1]).unwrap());
    assert!(strategy.arrived(5, 1), "a covered position fits but adds nothing");
    assert_eq!(strategy.next_batch(16).unwrap().indices, [2, 4]);
    assert_eq!(strategy.waiting(), 2);
    strategy.adopted(&Batch::new(vec![2, 4]).unwrap());
    assert!(strategy.next_batch(16).is_none(), "position 2 is covered");
    assert_eq!(strategy.waiting(), 0);
}

#[test]
fn a_position_beyond_the_largest_committee_is_refused() {
    let mut strategy = ArrivalOrder::default();
    assert!(!strategy.arrived(0, MAX_VALIDATORS_PER_COMMITTEE));
    assert!(strategy.arrived(0, MAX_VALIDATORS_PER_COMMITTEE - 1));
    assert_eq!(strategy.next_batch(1).unwrap().indices, [0]);
}
