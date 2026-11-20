use super::{
    super::test_util::{batch_input, claim, claims, waiting_claims},
    *,
};
use crate::tile::pq_aggregation::strategy::BatchLimits;

#[test]
fn votes_are_taken_in_arrival_order_up_to_the_signature_limit() {
    let claims: Vec<_> = (0..=255).map(claim).collect();
    let waiting: Vec<_> = (0..claims.len())
        .map(|i| waiting_claims(i, ClaimsKind::Vote, &claims[i..=i], &[]))
        .collect();
    let limits = BatchLimits { max_signatures: 100, max_children: 16 };
    let batch = next_batch(&batch_input(limits, None, &waiting)).unwrap();
    assert_eq!(batch.indices, (0..100).collect::<Vec<_>>());
    assert_eq!(batch.log_inv_rate, 2);

    let all = next_batch(&batch_input(BatchLimits::LEAF, None, &waiting)).unwrap();
    assert_eq!(all.indices.len(), 256, "all waiting votes under the leaf limit");
}

#[test]
fn proofs_that_add_nothing_are_skipped() {
    let best = claims(&[1, 2, 3]);
    let covered = claims(&[2, 3]);
    let fresh = claims(&[3, 4]);
    let waiting = [
        waiting_claims(0, ClaimsKind::Aggregate, &covered, &best),
        waiting_claims(1, ClaimsKind::Aggregate, &fresh, &best),
    ];
    let batch = next_batch(&batch_input(BatchLimits::MERGE, Some(&best), &waiting)).unwrap();
    assert_eq!(batch.indices, [1]);

    let only_covered = [waiting_claims(0, ClaimsKind::Aggregate, &covered, &best)];
    assert!(next_batch(&batch_input(BatchLimits::MERGE, Some(&best), &only_covered)).is_none());
}

#[test]
fn the_best_proof_takes_one_child() {
    let sets: Vec<_> = (0..20u8).map(|tag| claims(&[tag])).collect();
    let waiting: Vec<_> = sets
        .iter()
        .enumerate()
        .map(|(i, c)| waiting_claims(i, ClaimsKind::Aggregate, c, &[]))
        .collect();
    let batch = next_batch(&batch_input(BatchLimits::MERGE, None, &waiting)).unwrap();
    assert_eq!(batch.indices.len(), 16);
    let best = claims(&[200]);
    let batch = next_batch(&batch_input(BatchLimits::MERGE, Some(&best), &waiting)).unwrap();
    assert_eq!(batch.indices.len(), 15);
}
