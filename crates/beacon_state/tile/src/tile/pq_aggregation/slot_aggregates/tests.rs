use std::ops::Range;

use silver_common::{
    Nanos,
    leanvm::{MAX_PROOF_CLAIMS, MAX_REQUEST_LEN, ProofBody, ProofLen},
};

use super::{
    super::{
        cost_model::MergeShape,
        proof_sources::ProofSources,
        stats::Stats,
        test_util::{DATA_MARKER_AT, Lane, aggregate_of, signature_batch},
    },
    *,
};

const SLOT: Slot = 7;

fn arriving(sources: &ProofSources) -> Vec<&StoredAggregate> {
    let mut held: Vec<_> =
        sources.slot(SLOT).unwrap().aggregates.indexed().map(|(_, row)| row).collect();
    held.sort_unstable_by_key(|row| row.arrival);
    held
}

fn voters(sources: &ProofSources) -> Vec<usize> {
    arriving(sources).iter().map(|held| held.voters).collect()
}

fn full_committee() -> (ProofSources, ProofStore) {
    let mut sources = ProofSources::default();
    let mut proofs = ProofStore::default();
    for size in [3, 2, 4, 5] {
        aggregate_of(SLOT, 0, 1, 0..size).store(&mut sources, &mut proofs).unwrap();
    }
    (sources, proofs)
}

#[test]
fn a_fifth_aggregate_of_a_committee_enters_only_when_strictly_larger() {
    let (mut sources, mut proofs) = full_committee();
    for size in [2, 1] {
        assert_eq!(
            aggregate_of(SLOT, 0, 1, 0..size).store(&mut sources, &mut proofs),
            Err(AggregateRefused::NotLarger)
        );
        assert_eq!(voters(&sources), [3, 2, 4, 5]);
    }
    aggregate_of(SLOT, 0, 1, 0..3).store(&mut sources, &mut proofs).unwrap();
    assert_eq!(voters(&sources), [3, 4, 5, 3], "the aggregate of 2 voters is gone");
    aggregate_of(SLOT, 1, 1, 0..1)
        .store(&mut sources, &mut proofs)
        .expect("another committee has room");
}

#[test]
fn a_slot_holds_at_most_max_groups() {
    let mut sources = ProofSources::default();
    let mut proofs = ProofStore::default();
    for at in 0..MAX_GROUPS {
        let (index, data) = (at % 16, (at / 16) as u8);
        aggregate_of(SLOT, index, data, 0..1).store(&mut sources, &mut proofs).unwrap();
    }
    assert_eq!(sources.slot(SLOT).unwrap().aggregates.indexed().count(), MAX_GROUPS);
    let mut full = ProofSources::default();
    full.store_slot(SLOT, &mut proofs).unwrap().aggregates.len = MAX_GROUPS;
    assert_eq!(
        aggregate_of(SLOT, 0, 1, 0..1).store(&mut full, &mut proofs),
        Err(AggregateRefused::TooManyGroups)
    );
    aggregate_of(SLOT + 1, 0, 9, 0..1)
        .store(&mut sources, &mut proofs)
        .expect("the cap is per slot");
}

#[test]
fn two_data_of_one_committee_are_two_groups_under_one_cap() {
    let mut sources = ProofSources::default();
    let mut proofs = ProofStore::default();
    for (data, size) in [(1, 1), (2, 2), (1, 3), (2, 4)] {
        aggregate_of(SLOT, 0, data, 0..size).store(&mut sources, &mut proofs).unwrap();
    }
    let committees: Vec<_> =
        arriving(&sources).iter().map(|held| held.group.committee.data[DATA_MARKER_AT]).collect();
    assert_eq!(committees, [1, 2, 1, 2]);
    assert_eq!(
        aggregate_of(SLOT, 0, 3, 0..1).store(&mut sources, &mut proofs),
        Err(AggregateRefused::NotLarger),
        "a third data waits too"
    );
    aggregate_of(SLOT, 0, 2, 0..2).store(&mut sources, &mut proofs).unwrap();
    assert_eq!(voters(&sources), [2, 3, 4, 2]);
}

#[test]
fn pruning_drops_older_slots_and_keeps_the_floor() {
    let mut sources = ProofSources::default();
    let mut proofs = ProofStore::default();
    for slot in [SLOT - 1, SLOT, SLOT + 1] {
        aggregate_of(slot, 0, 1, 0..1).store(&mut sources, &mut proofs).unwrap();
    }
    sources.prune_before(SLOT, &mut proofs);
    assert!(sources.slot(SLOT - 1).is_none());
    assert_eq!(sources.slot(SLOT).unwrap().aggregates.indexed().count(), 1);
    assert_eq!(sources.slot(SLOT + 1).unwrap().aggregates.indexed().count(), 1);
    assert_eq!(
        aggregate_of(SLOT - 1, 0, 1, 0..2).store(&mut sources, &mut proofs),
        Err(AggregateRefused::BeforeFloor)
    );
    assert!(sources.slot(SLOT - 1).is_none());
}

#[derive(Clone)]
enum Change {
    Add(Slot, usize, Range<usize>),
    Include(Slot, &'static [u32]),
    Prune(Slot),
}

/// Every order of `0..len`.
fn orders(len: usize) -> Vec<Vec<usize>> {
    if len == 0 {
        return vec![Vec::new()];
    }
    let shorter = orders(len - 1).into_iter();
    let insert = |order: Vec<usize>| {
        (0..len).map(move |at| {
            let mut order = order.clone();
            order.insert(at, len - 1);
            order
        })
    };
    shorter.flat_map(insert).collect()
}

#[test]
fn useful_equals_on_chain_after_add_exclude_and_prune_in_any_order() {
    let changes = [
        Change::Add(SLOT, 0, 0..6),
        Change::Add(SLOT + 1, 1, 2..8),
        Change::Include(SLOT, &[1, 4, 9]),
        Change::Include(SLOT + 1, &[2, 3]),
        Change::Prune(SLOT + 1),
    ];
    let mut members = 0;
    for order in orders(changes.len()) {
        let mut sources = ProofSources::default();
        let mut proofs = ProofStore::default();
        let mut floor = 0;
        for (step, &at) in order.iter().enumerate() {
            match changes[at].clone() {
                Change::Add(slot, index, voters) => {
                    assert_eq!(
                        aggregate_of(slot, index, 1, voters).store(&mut sources, &mut proofs),
                        if slot >= floor { Ok(()) } else { Err(AggregateRefused::BeforeFloor) }
                    );
                }
                Change::Include(slot, validators) => {
                    sources.include_on_chain(slot, validators, &mut proofs)
                }
                Change::Prune(next_floor) => {
                    floor = floor.max(next_floor);
                    sources.prune_before(next_floor, &mut proofs);
                }
            }
            for slot in [SLOT, SLOT + 1] {
                let Some(entry) = sources.slot(slot) else { continue };
                for (_, held) in entry.aggregates.indexed() {
                    for (position, validator, _) in held.group.records(&proofs, held.proof) {
                        let on_chain = slot >= floor &&
                            order[..=step].iter().any(|&at| {
                                matches!(changes[at], Change::Include(included, validators)
                                if included == slot && validators.contains(&validator))
                            });
                        assert_eq!(entry.on_chain.contains(validator), on_chain);
                        assert_eq!(held.useful.contains(position), !on_chain);
                        members += 1;
                    }
                }
            }
        }
    }
    assert!(members > 0, "some orders keep aggregates");
}

#[test]
fn an_aggregate_fully_on_chain_stays_and_counts_for_its_committee() {
    let (mut sources, mut proofs) = full_committee();
    sources.include_on_chain(SLOT, &[0, 1, 2, 3, 4], &mut proofs);
    assert!(arriving(&sources).iter().all(|entry| entry.useful == Bits::default()));
    assert_eq!(
        aggregate_of(SLOT, 0, 1, 0..2).store(&mut sources, &mut proofs),
        Err(AggregateRefused::NotLarger)
    );
    aggregate_of(SLOT, 0, 1, 0..3).store(&mut sources, &mut proofs).unwrap();
    assert_eq!(voters(&sources), [3, 4, 5, 3], "the aggregate of 2 voters is gone");
}

#[test]
fn equal_smallest_aggregates_give_way_in_arrival_order() {
    let mut sources = ProofSources::default();
    let mut proofs = ProofStore::default();
    for (data, size) in [(1, 1), (2, 1), (3, 2), (4, 2), (5, 3)] {
        aggregate_of(SLOT, 0, data, 0..size).store(&mut sources, &mut proofs).unwrap();
    }
    let data: Vec<_> =
        arriving(&sources).iter().map(|held| held.group.committee.data[DATA_MARKER_AT]).collect();
    assert_eq!(data, [2, 3, 4, 5]);
}

#[test]
fn an_aggregate_that_would_pass_max_request_len_is_left_out() {
    let sample = MergeShape { proofs: 1, claims_in: MAX_PROOF_CLAIMS, ..signature_batch(0) };
    let mut stats = Stats::default();
    let predicted = stats.cost().predict(&sample);
    stats.record_answer(&sample, predicted, predicted, true);
    let mut lane = Lane::with_stats(stats, 1);
    let block = SLOT + 4;
    lane.propose(&[block]);
    lane.import(block - 1);
    lane.at(Nanos::from_secs(100));
    lane.sources.include_on_chain(SLOT + 2, &[99], &mut lane.proofs);
    lane.add_aggregate(aggregate_of(SLOT + 2, 0, 1, 99..100));
    for position in 0..3 {
        lane.add_aggregate(aggregate_of(SLOT, 0, 1, position..position + 1));
    }

    // Inflate stored proofs to exercise the request cap independently of proof
    // admission.
    let huge = vec![0; MAX_REQUEST_LEN / 2];
    let source = lane.sources.store_slot(SLOT, &mut lane.proofs).unwrap();
    for aggregate in source.aggregates.entries.iter_mut().flatten().flatten() {
        let old = aggregate.proof;
        let claims = lane.proofs.claims(old).to_vec();
        let members = lane.proofs.tail(old, MEMBER_BYTES).to_vec();
        let len = ProofLen { claims: claims.len() as u32, proof: huge.len() as u32 };
        let (id, bytes) = lane.proofs.take(len, members.len());
        let (request, tail) = bytes.split_at_mut(len.bytes());
        ProofBody::write(request, claims.iter(), &huge);
        tail.copy_from_slice(&members);
        lane.proofs.release(old);
        aggregate.proof = id;
    }
    let sent = lane.send(false).unwrap();
    assert_eq!(sent.shape.proofs, 1);
    assert_eq!(sent.shape.request_bytes, sent.body.len());
}
