use super::{
    super::test_util::{all_waiting, batch_input, claim, claims},
    *,
};

#[test]
fn claims_are_taken_in_arrival_order_up_to_the_limit() {
    let sets: Vec<_> = (0..=255).map(|tag| vec![claim(tag)]).collect();
    let waiting = all_waiting(&sets, &[]);
    let batch = next_batch(&batch_input(100, None, &waiting)).unwrap();
    assert_eq!(batch.indices, (0..100).collect::<Vec<_>>());
    assert_eq!(batch.log_inv_rate, 2);

    let all = next_batch(&batch_input(2048, None, &waiting)).unwrap();
    assert_eq!(all.indices.len(), 256, "all waiting claims under the limit");
}

#[test]
fn claims_that_add_nothing_are_skipped() {
    let best = claims(&[1, 2, 3]);
    let sets = [claims(&[2, 3]), claims(&[3, 4])];
    let waiting = all_waiting(&sets, &best);
    let batch = next_batch(&batch_input(16, Some(&best), &waiting)).unwrap();
    assert_eq!(batch.indices, [1]);

    let only_covered = &waiting[..1];
    assert!(next_batch(&batch_input(16, Some(&best), only_covered)).is_none());
}
