use silver_common::ssz_view::XMSS_SIGNATURE_SIZE;

use super::{
    super::{
        claims::{Aggregate, Vote},
        wire::aggregate_response,
    },
    Strategy::*,
    *,
};

const DEADLINE: Nanos = Nanos::from_secs(8);

fn aggregation(votes: u16) -> Aggregation {
    let mut aggregation = Aggregation::new(BatchLimits::LEAF, Greedy, DEADLINE);
    (0..votes).for_each(|tag| aggregation.add(vote(tag)));
    aggregation
}

fn vote(tag: u16) -> VerifiedClaims {
    let mut pubkey = [0u8; 32];
    pubkey[..2].copy_from_slice(&tag.to_be_bytes());
    VerifiedClaims::Vote(Vote::new(
        tag as usize,
        pubkey,
        [1; 32],
        &[tag as u8; XMSS_SIGNATURE_SIZE],
    ))
}

fn claim(tag: u16) -> Claim {
    vote(tag).claims()[0]
}

fn answer(tags: impl IntoIterator<Item = u16>) -> Vec<u8> {
    let mut claims: Vec<Claim> = tags.into_iter().map(claim).collect();
    claims.sort_unstable();
    aggregate_response(&claims, b"proof")
}

fn covered(aggregation: &Aggregation) -> Vec<usize> {
    aggregation.best.as_ref().map_or_else(Vec::new, |best| best.covered_indices.clone())
}

fn merge(strategy: Strategy) -> Aggregation {
    Aggregation::new(BatchLimits::MERGE, strategy, DEADLINE)
}

fn child(tags: &[u16]) -> VerifiedClaims {
    let claims = tags.iter().copied().map(claim).collect();
    VerifiedClaims::Aggregate(Aggregate::new(claims, b"child".to_vec(), vec![7]).unwrap())
}

/// Takes the next batch at time 0 and settles it with `body`.
fn settle(aggregation: &mut Aggregation, body: Option<&[u8]>) -> Result<(), &'static str> {
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    aggregation.finish(batch, body)
}

#[test]
fn batches_take_the_waiting_votes_up_to_the_limit() {
    let max_signatures = BatchLimits::LEAF.max_signatures;
    let mut aggregation = aggregation(max_signatures as u16 + 2);
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    let first = aggregation.request(&batch).body();
    assert_eq!(first.len() / (64 + XMSS_SIGNATURE_SIZE), max_signatures);

    aggregation.finish(batch, Some(&answer(0..max_signatures as u16))).unwrap();
    assert_eq!(covered(&aggregation).len(), max_signatures);
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    let second = aggregation.request(&batch).body();
    assert!(second.windows(5).any(|window| window == b"proof"), "the best proof is the child");
    aggregation.finish(batch, Some(&answer(0..max_signatures as u16 + 2))).unwrap();
    assert!(aggregation.next_batch(Nanos::ZERO).is_none(), "nothing waits");
    assert_eq!(aggregation.covered().count(), max_signatures + 2);
    assert_eq!(aggregation.best.as_ref().map_or(0, |best| best.claims.len()), max_signatures + 2);
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
    aggregation.add(vote(1));
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
    aggregation.add(vote(1));
    for _ in 0..3 {
        settle(&mut aggregation, None).unwrap_err();
    }
    assert!(aggregation.is_stopped());
    assert!(aggregation.next_batch(Nanos::ZERO).is_none(), "stopped");
}

#[test]
fn a_non_contiguous_batch_is_checked_against_exactly_its_claims() {
    let mut aggregation = merge(MaxCoverage);
    [child(&[1, 2]), child(&[2, 3]), child(&[4]), child(&[3, 4, 5])]
        .into_iter()
        .for_each(|verified| aggregation.add(verified));
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
    let mut aggregation = merge(Greedy);
    (0..20).for_each(|tag| aggregation.add(child(&[tag])));
    let batch = aggregation.next_batch(Nanos::ZERO).unwrap();
    assert_eq!(batch.indices().len(), 16);
    aggregation.finish(batch, Some(&answer(0..16))).unwrap();
    assert_eq!(aggregation.next_batch(Nanos::ZERO).unwrap().indices(), [16, 17, 18, 19]);
}
