use silver_common::ssz_view::{MAX_VALIDATORS_PER_COMMITTEE, XMSS_SIGNATURE_SIZE};

use super::{
    super::{
        attestation,
        claims::{Aggregate, Vote},
        wire::aggregate_response,
    },
    *,
};

const DEADLINE: Nanos = Nanos::from_secs(8);

fn aggregation(votes: u16) -> Aggregation<Vote> {
    let mut aggregation = Aggregation::new(DEADLINE);
    (0..votes).for_each(|tag| assert!(aggregation.add(vote(tag))));
    aggregation
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
    aggregate_response(&claims, b"proof")
}

fn covered<C: VerifiedClaims>(aggregation: &Aggregation<C>) -> Vec<usize> {
    aggregation.best.as_ref().map_or_else(Vec::new, |best| best.covered_indices.clone())
}

fn merge(children: impl IntoIterator<Item = Aggregate>) -> Aggregation<Aggregate> {
    let mut aggregation = Aggregation::new(DEADLINE);
    children.into_iter().for_each(|child| assert!(aggregation.add(child)));
    aggregation
}

/// Claim `tag` sits at position `tag` of committee 0.
fn child(tags: &[u16]) -> Aggregate {
    let claims = tags.iter().copied().map(claim).collect();
    let ssz = attestation(0, tags.iter().map(|&tag| tag as usize));
    Aggregate::new(claims, b"child".to_vec(), ssz).unwrap()
}

fn settle<C: VerifiedClaims>(
    aggregation: &mut Aggregation<C>,
    body: Option<&[u8]>,
) -> Result<(), &'static str> {
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    aggregation.finish(batch, body)
}

#[test]
fn batches_take_the_waiting_votes_up_to_the_limit() {
    let max_votes = Vote::batch_limit(false);
    assert_eq!(max_votes, Vote::batch_limit(true), "the best proof takes no vote's place");
    assert_eq!(max_votes, MAX_VALIDATORS_PER_COMMITTEE, "one batch holds the largest committee");
    let first_votes = max_votes as u16 - 2;
    let mut aggregation = aggregation(first_votes);
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    let first = aggregation.request(&batch).body();
    assert_eq!(first.len() / (64 + XMSS_SIGNATURE_SIZE), max_votes - 2);

    aggregation.finish(batch, Some(&answer(0..first_votes))).unwrap();
    assert_eq!(covered(&aggregation).len(), max_votes - 2);
    assert!(aggregation.add(vote(first_votes)));
    assert!(aggregation.add(vote(first_votes + 1)));
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices().len(), 2);
    let second = aggregation.request(&batch).body();
    assert!(second.windows(5).any(|window| window == b"proof"), "the best proof is the child");
    aggregation.finish(batch, Some(&answer(0..max_votes as u16))).unwrap();
    assert!(aggregation.next_batch(Nanos::ZERO).is_none(), "nothing waits");
    assert_eq!(aggregation.covered().count(), max_votes);
    assert_eq!(aggregation.best.as_ref().map_or(0, |best| best.claims.len()), max_votes);
    assert!(!aggregation.add(vote(max_votes as u16)), "a position beyond the largest committee");
}

#[test]
fn a_failure_leaves_the_waiting_claims_where_they_were() {
    let mut aggregation = aggregation(3);
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    let first = aggregation.request(&batch).body();
    assert_eq!(aggregation.finish(batch, None), Err("no answer"));
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(aggregation.request(&batch).body(), first);
}

#[test]
fn nothing_is_sent_at_the_deadline() {
    let mut aggregation = aggregation(1);
    assert!(aggregation.next_batch(DEADLINE).is_none());
    let batch = aggregation.next_batch(DEADLINE - 1).unwrap();
    aggregation.finish(batch, Some(&answer([0]))).unwrap();
    assert!(aggregation.add(vote(1)));
    assert!(aggregation.next_batch(DEADLINE + Nanos(1)).is_none(), "the best proof stays past it");
    assert!(aggregation.proof().is_some());
}

#[test]
fn a_response_with_other_claims_is_refused() {
    let junk = b"\0junk".to_vec();
    for body in [answer([0, 1]), answer([1]), aggregate_response(&[], b"p"), junk] {
        let mut aggregation = aggregation(1);
        assert!(settle(&mut aggregation, Some(&body)).is_err());
        assert!(aggregation.best.is_none());
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
    assert!(aggregation.is_stopped());
    assert!(aggregation.next_batch(Nanos::ZERO).is_none(), "stopped");
}

#[test]
fn a_non_contiguous_batch_is_checked_against_exactly_its_claims() {
    let mut aggregation = merge([child(&[1, 2]), child(&[2, 3]), child(&[4]), child(&[3, 4, 5])]);
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices(), [0, 3], "two children cover 1..=5");

    let refused = aggregation.finish(batch, Some(&answer([1, 2, 3, 4])));
    assert_eq!(refused, Err("the proof covers other claims"), "claim 5 is missing");
    assert!(aggregation.best.is_none());

    settle(&mut aggregation, Some(&answer([1, 2, 3, 4, 5]))).unwrap();
    assert_eq!(covered(&aggregation), [0, 3]);
    assert_eq!(aggregation.best.as_ref().map_or(0, |best| best.claims.len()), 5);
    assert!(aggregation.next_batch(Nanos::ZERO).is_none(), "the others add nothing");
}

#[test]
fn merge_batches_respect_the_child_limit_with_the_best_proof_as_one() {
    let mut aggregation = merge((0..40).map(|tag| child(&[tag])));
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices().len(), 16);
    assert_eq!(aggregation.request(&batch).children.len(), 16);
    aggregation.finish(batch, Some(&answer(0..16))).unwrap();
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices(), (16..31).collect::<Vec<_>>());
    assert_eq!(aggregation.request(&batch).children.len(), 16, "the best proof is one");
}

#[test]
fn a_response_must_hold_exactly_the_union_of_its_claims() {
    let sets = [vec![claim(1), claim(3)], vec![claim(2), claim(3)], Vec::new()];
    let sets = || sets.iter().map(Vec::as_slice);
    let union = |tags: &[u16]| tags.iter().copied().map(claim).collect::<Vec<_>>();
    let mut sorted = union(&[1, 2, 3]);
    sorted.sort_unstable();
    assert!(is_union(&sorted, sets()));
    for tags in [&[1, 2][..], &[2, 3], &[1, 3], &[1, 2, 3, 4], &[0, 1, 2, 3]] {
        let mut claims = union(tags);
        claims.sort_unstable();
        assert!(!is_union(&claims, sets()), "{tags:?}");
    }
    assert!(is_union(&[], std::iter::empty()));
}
