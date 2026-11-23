use silver_common::ssz_view::{
    ATTESTATION_DATA_SIZE, MAX_STARK_PROOF_SIZE, MAX_VALIDATORS_PER_COMMITTEE, XMSS_SIGNATURE_SIZE,
};

use super::{
    super::{
        claims::{Aggregate, Vote},
        leaf::LeafAggregation,
        merge::MergeAggregation,
        test_util::attestation,
        wire::{AggregateResponse, MAX_SIGNATURES},
    },
    *,
};

const DEADLINE: Nanos = Nanos::from_secs(8);

fn leaf(deadline: Nanos, votes: u16) -> LeafAggregation {
    let data = [0; ATTESTATION_DATA_SIZE];
    let mut leaf = LeafAggregation::new(data, MAX_VALIDATORS_PER_COMMITTEE, deadline);
    (0..votes).for_each(|tag| assert!(leaf.add(vote(tag))));
    leaf
}

fn aggregation(votes: u16) -> LeafAggregation {
    leaf(DEADLINE, votes)
}

fn vote(tag: u16) -> Vote {
    let mut pubkey = [0u8; 32];
    pubkey[..2].copy_from_slice(&tag.to_be_bytes());
    Vote::new(tag as usize, pubkey, [1; 32], &[tag as u8; XMSS_SIGNATURE_SIZE])
}

fn claim(tag: u16) -> Claim {
    vote(tag).claim
}

fn answer(tags: impl IntoIterator<Item = u16>) -> Vec<u8> {
    let mut claims: Vec<Claim> = tags.into_iter().map(claim).collect();
    claims.sort_unstable();
    AggregateResponse::encode(&claims, b"proof")
}

fn best_claims(core: &Aggregation) -> usize {
    core.best.as_ref().map_or(0, |best| best.claims.len())
}

/// Each child's claim `tag` sits at position `tag` of committee 0.
fn merge(children: impl IntoIterator<Item = impl AsRef<[u16]>>) -> MergeAggregation {
    let mut merge = MergeAggregation::new(DEADLINE);
    for tags in children {
        let tags = tags.as_ref();
        let mut claims = tags.iter().copied().map(claim).collect();
        let ssz = attestation(0, tags.iter().map(|&tag| tag as usize));
        assert!(merge.add(Aggregate::new(&mut claims, b"child", &ssz).unwrap()));
    }
    merge
}

fn priority(leaf: &LeafAggregation) -> Priority {
    leaf.priority(Nanos::ZERO).unwrap()
}

fn settle(leaf: &mut LeafAggregation, body: Option<&[u8]>) -> Result<(), &'static str> {
    let batch = leaf.next_batch(Nanos::ZERO).unwrap();
    leaf.finish(batch, body)
}

#[test]
fn batches_take_the_waiting_votes_up_to_the_limit() {
    assert_eq!(
        MAX_SIGNATURES, MAX_VALIDATORS_PER_COMMITTEE,
        "one batch holds the largest committee"
    );
    let first_votes = MAX_SIGNATURES as u16 - 2;
    let mut aggregation = aggregation(first_votes);
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    let first = aggregation.core.request(&batch).body();
    assert_eq!(first.len() / (64 + XMSS_SIGNATURE_SIZE), MAX_SIGNATURES - 2);

    aggregation.finish(batch, Some(&answer(0..first_votes))).unwrap();
    assert_eq!(aggregation.core.covered_indices().len(), MAX_SIGNATURES - 2);
    assert!(aggregation.add(vote(first_votes)));
    assert!(aggregation.add(vote(first_votes + 1)));
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices().len(), 2);
    let second = aggregation.core.request(&batch).body();
    assert!(second.windows(5).any(|window| window == b"proof"), "the best proof is the child");
    aggregation.finish(batch, Some(&answer(0..MAX_SIGNATURES as u16))).unwrap();
    assert!(aggregation.next_batch(Nanos::ZERO).is_none(), "nothing waits");
    assert_eq!(aggregation.core.covered_indices().len(), MAX_SIGNATURES);
    assert_eq!(best_claims(&aggregation.core), MAX_SIGNATURES);
    assert!(
        !aggregation.add(vote(MAX_SIGNATURES as u16)),
        "a position beyond the largest committee"
    );
}

#[test]
fn a_failure_leaves_the_waiting_claims_where_they_were() {
    let mut aggregation = aggregation(3);
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    let first = aggregation.core.request(&batch).body();
    assert_eq!(aggregation.finish(batch, None), Err("no answer"));
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(aggregation.core.request(&batch).body(), first);
}

#[test]
fn nothing_is_sent_at_the_deadline() {
    let mut aggregation = aggregation(1);
    assert!(aggregation.next_batch(DEADLINE).is_none());
    assert!(aggregation.priority(DEADLINE).is_none());
    let batch = aggregation.next_batch(DEADLINE - 1).unwrap();
    aggregation.finish(batch, Some(&answer([0]))).unwrap();
    assert!(aggregation.add(vote(1)));
    assert!(aggregation.next_batch(DEADLINE + Nanos(1)).is_none(), "the best proof stays past it");
    assert!(aggregation.core.best_proof().is_some());
}

#[test]
fn a_response_with_other_claims_is_refused() {
    let junk = b"\0junk".to_vec();
    for body in [answer([0, 1]), answer([1]), AggregateResponse::encode(&[], b"p"), junk] {
        let mut aggregation = aggregation(1);
        assert!(settle(&mut aggregation, Some(&body)).is_err());
        assert!(aggregation.core.best.is_none());
        assert!(aggregation.next_batch(Nanos::ZERO).is_some(), "the vote goes out again");
    }
}

#[test]
fn the_aggregation_stops_after_three_failures_and_a_success_resets_the_count() {
    let mut aggregation = aggregation(1);
    for _ in 0..2 {
        settle(&mut aggregation, None).unwrap_err();
    }
    settle(&mut aggregation, Some(&answer([0]))).unwrap();
    assert!(aggregation.add(vote(1)));
    for _ in 0..3 {
        settle(&mut aggregation, None).unwrap_err();
    }
    assert!(aggregation.core.is_stopped());
    assert!(aggregation.priority(Nanos::ZERO).is_none(), "stopped");
    assert!(aggregation.next_batch(Nanos::ZERO).is_none(), "stopped");
}

#[test]
fn a_non_contiguous_batch_is_checked_against_exactly_its_claims() {
    let mut merge = merge([vec![1, 2], vec![2, 3], vec![4], vec![3, 4, 5]]);
    let batch = merge.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices(), [0, 3], "two children cover 1..=5");

    let refused = merge.finish(batch, Some(&answer([1, 2, 3, 4])));
    assert_eq!(refused, Err("the proof covers other claims"), "claim 5 is missing");
    assert!(merge.core.best.is_none());

    let batch = merge.next_batch(Nanos::ZERO).unwrap();
    merge.finish(batch, Some(&answer([1, 2, 3, 4, 5]))).unwrap();
    assert_eq!(merge.core.covered_indices(), [0, 3]);
    assert_eq!(best_claims(&merge.core), 5);
    assert!(merge.next_batch(Nanos::ZERO).is_none(), "the others add nothing");
}

#[test]
fn merge_batches_respect_the_child_limit_with_the_best_proof_as_one() {
    let mut merge = merge((0..40).map(|tag| [tag]));
    let batch = merge.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices().len(), 16);
    assert_eq!(merge.core.request(&batch).proofs.len(), 16);
    merge.finish(batch, Some(&answer(0..16))).unwrap();
    let batch = merge.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices(), (16..31).collect::<Vec<_>>());
    assert_eq!(merge.core.request(&batch).proofs.len(), 16, "the best proof is one");
}

#[test]
fn a_proof_above_1_mib_is_refused() {
    let mut aggregation = aggregation(1);
    let body = AggregateResponse::encode(&[claim(0)], &vec![0; MAX_STARK_PROOF_SIZE + 1]);
    assert_eq!(settle(&mut aggregation, Some(&body)), Err("malformed response"));
    let body = AggregateResponse::encode(&[claim(0)], &vec![0; MAX_STARK_PROOF_SIZE]);
    settle(&mut aggregation, Some(&body)).unwrap();
}

#[test]
fn the_earliest_deadline_goes_first_whatever_the_kind() {
    let merge = merge([[1]]).priority(Nanos::ZERO).unwrap();
    assert!(priority(&leaf(DEADLINE - Nanos(1), 1)) > merge, "a leaf before a merge");
    assert!(merge > priority(&leaf(DEADLINE + Nanos(1), 100)), "despite fewer claims");
}

#[test]
fn then_the_most_new_claims_go_first() {
    let mut leaf = aggregation(3);
    assert!(priority(&leaf) > priority(&aggregation(2)));
    let merge = merge([[1]]).priority(Nanos::ZERO).unwrap();
    assert!(priority(&aggregation(2)) > merge, "whatever the kind");
    settle(&mut leaf, Some(&answer(0..3))).unwrap();
    assert!(leaf.priority(Nanos::ZERO).is_none(), "nothing new waits");
    (0..4).for_each(|tag| assert!(leaf.add(vote(tag))));
    assert_eq!(priority(&leaf), priority(&aggregation(1)), "only vote 3 is new");
}

#[test]
fn a_response_must_hold_exactly_the_union_of_its_claims() {
    let mut merge = merge([[1, 3], [2, 3]]);
    let batch = merge.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices(), [0, 1]);
    let proves = |tags: &[u16]| {
        let mut claims: Vec<_> = tags.iter().copied().map(claim).collect();
        claims.sort_unstable();
        merge.core.proves_exactly(&claims, &batch)
    };
    assert!(proves(&[1, 2, 3]));
    for tags in [&[1, 2][..], &[2, 3], &[1, 3], &[1, 2, 3, 4], &[0, 1, 2, 3]] {
        assert!(!proves(tags), "{tags:?}");
    }
}
