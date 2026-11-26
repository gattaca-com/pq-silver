use std::ops::Range;

use silver_beacon_state_data::AGGREGATORS_PER_COMMITTEE;
use silver_common::{
    leanvm::MAX_SIGNATURES,
    ssz_view::{ATTESTATION_DATA_SIZE, MAX_ATTESTATIONS_PQ, MAX_VALIDATORS_PER_COMMITTEE},
    ticker::MAXIMUM_GOSSIP_CLOCK_DISPARITY,
};

use super::{
    super::{
        aggregator::PqAggregator,
        claims::{ClaimCheck, MAX_GROUPS},
        proof_targets::LeafKey,
        proved::DATA_PER_SLOT,
        test_util::{
            Answer, Lane, SLOT, SLOT_MS, Single, aggregate_of, answer, group_of, visit_groups,
        },
    },
    queue::Source,
    *,
};

/// The position 0 aggregate proof is due 7.2 seconds into the slot.
const AGGREGATE_DUE_MS: u64 = SLOT_MS + 7_200;

const IDLE: bool = true;
const AFTER_ANSWER: bool = false;
const NORMAL: u64 = 2;
const FAST: u64 = 100;

#[test]
fn the_257th_aggregate_proof_is_refused_while_the_held_proofs_are_served() {
    let mut lane = Lane::new(FAST);
    let mut keys = Vec::new();
    let due = lane.ticker.pq_aggregate_due(SLOT, 0);
    for at in 0..=256 {
        let data = (at / 16) as u8;
        let index = at % 16;
        let group = group_of(data, SLOT, index, &[0]);
        let key = LeafKey { slot: SLOT, committee_index: index as u64, data_root: [data; 32] };
        lane.targets.open_aggregate_proof(key, group.committee, due, 0);
        let groups = vec![group];
        let body = answer(&groups, b"held");
        let settled = lane.targets.settle(
            &TargetKey::AggregateProof(key),
            body.parse(),
            None,
            &mut lane.proofs,
            &mut ClaimCheck::default(),
            |_, visit| visit_groups(&groups, visit),
        );
        if at < 256 {
            assert_eq!(settled, Ok(1));
            keys.push(key);
        } else {
            assert_eq!(settled, Err("too many aggregate proofs"));
            assert!(lane.targets.aggregate_proofs()[&key].proof.aggregate(&lane.proofs).is_none());
        }
    }
    for key in keys {
        let served = lane.targets.aggregate_proofs()[&key].proof.aggregate(&lane.proofs).unwrap();
        let mut bytes = vec![0; served.ssz_len()];
        served.write_ssz(&mut bytes);
        assert!(bytes.ends_with(b"held"));
    }
}

impl Lane {
    fn with_proved_vote() -> Self {
        let mut lane = Self::new(NORMAL);
        lane.votes(0..1);
        let first = lane.send(IDLE).unwrap();
        assert!(lane.answer(first, Answer::Proof).is_ok());
        lane
    }

    fn served(&self, index: u64) -> usize {
        self.targets
            .aggregate_proofs()
            .get(&key(index))
            .and_then(|target| target.proof.id)
            .map_or(0, |id| self.proofs.claims(id).len())
    }

    fn latest_start(&self, index: u64) -> Nanos {
        self.planner().latest_start(&TargetKey::AggregateProof(key(index)))
    }

    /// A pull of the aggregate proof of committee 0, due at 7.2 s, 2 s before
    /// it is due.
    fn pull_2_s_early(&mut self) {
        self.at(due() - Nanos::from_secs(2));
        self.stats.aggregate_proof_read(SLOT, due(), 0, &self.ticker);
    }

    /// Two aggregate proofs: committee 0 due at 7.2 s, committee 2
    /// at 8.4 s.
    fn two_proved_aggregate_proofs() -> Self {
        let mut lane = Self::new(NORMAL);
        lane.vote_of(0, 0, 0);
        lane.vote_of(2, 2, 0);
        let earlier = lane.send(IDLE).unwrap();
        assert_eq!(earlier.aggregate_key().committee_index, 0);
        assert!(lane.answer(earlier, Answer::Proof).is_ok());
        let later = lane.send(AFTER_ANSWER).unwrap();
        assert_eq!(later.aggregate_key().committee_index, 2);
        assert!(lane.answer(later, Answer::Proof).is_ok());
        lane
    }

    /// An aggregate proof of one vote that, 600 ms before its deadline,
    /// holds back a last merge of ten votes in an idle pass.
    fn holding_a_last_merge() -> Self {
        let mut lane = Self::with_proved_vote();
        lane.at(deadline() - Nanos::from_millis(600));
        lane.votes(1..11);
        assert!(lane.send(IDLE).is_none(), "no further merge would fit after this one");
        lane
    }
}

#[test]
#[should_panic(expected = "aggregate request shorter than its slice")]
fn a_slice_longer_than_the_request_is_a_bug() {
    let mut lane = Lane::new(NORMAL);
    lane.votes(0..1);
    let planner = lane.planner();
    let mut merge = Merge::default();
    let pass = planner.plan_next_merge(true, &mut Scratch::default(), &mut merge);
    assert!(pass.sent.is_some());
    let mut body = vec![0; merge.shape().request_bytes + 1];
    merge.write(&mut body, planner.proofs, planner.sources);
}

fn key(index: u64) -> LeafKey {
    LeafKey { slot: SLOT, committee_index: index, data_root: [1; 32] }
}

fn deadline() -> Nanos {
    due() - gossip_clock_disparity()
}

fn gossip_clock_disparity() -> Nanos {
    u64::try_from(MAXIMUM_GOSSIP_CLOCK_DISPARITY.as_nanos()).unwrap().into()
}

/// Of an aggregate proof whose last local aggregator holds position 0.
fn due() -> Nanos {
    Nanos::from_millis(AGGREGATE_DUE_MS)
}

#[test]
fn without_a_proof_near_its_deadline_the_first_merge_takes_what_fits() {
    let mut lane = Lane::new(NORMAL);
    lane.votes(0..100);
    lane.at(deadline() - Nanos::from_millis(500));
    let sent = lane.send(IDLE).unwrap();
    assert!((1..100).contains(&sent.shape.signatures));
    assert!(lane.answer(sent, Answer::Proof).is_ok());
    assert!(lane.now() <= deadline(), "{:?} > {:?}", lane.now(), deadline());
}

#[test]
fn votes_that_arrive_during_a_merge_go_in_the_next() {
    let mut lane = Lane::new(NORMAL);
    lane.votes(0..1);
    let first = lane.send(IDLE).unwrap();
    lane.votes(1..3);
    assert!(lane.answer(first, Answer::Proof).is_ok());
    let second = lane.send(AFTER_ANSWER).unwrap();
    assert_eq!(second.shape.signatures, 2);
    assert_eq!(lane.answer(second, Answer::Proof), Ok(3));
}

#[test]
fn a_held_merge_sends_all_its_votes_and_ends_by_its_deadline() {
    let late = Nanos::from_millis(IDLE_WAKE.as_millis() as u64);
    for delay in [Nanos::ZERO, late] {
        let mut lane = Lane::holding_a_last_merge();
        lane.at(lane.wake.unwrap() + delay);
        let last = lane.send(IDLE).unwrap();
        assert_eq!(last.shape.signatures, 10);
        let ends = lane.now() + lane.stats.cost().planned(&last.shape);
        assert!(ends <= deadline(), "{ends:?} > {:?}", deadline());
        if delay == Nanos::ZERO {
            assert!(deadline() - ends <= WAKE_SLACK, "it starts as late as it may");
        }
    }
}

#[test]
fn a_vote_that_arrives_during_a_hold_joins_the_merge() {
    let mut lane = Lane::holding_a_last_merge();
    let held = lane.wake.unwrap();
    lane.votes(11..12);
    assert!(lane.send(IDLE).is_none());
    let wake_at = lane.wake.unwrap();
    assert!(wake_at < held, "one more vote starts the merge earlier");
    lane.at(wake_at);
    assert_eq!(lane.send(IDLE).unwrap().shape.signatures, 11);
}

#[test]
fn straight_after_an_answer_the_last_merge_goes_out_at_once() {
    let mut lane = Lane::with_proved_vote();
    lane.at(deadline() - Nanos::from_millis(600));
    lane.votes(1..11);
    let last = lane.send(AFTER_ANSWER).expect("a held merge would start idle");
    assert_eq!(last.shape.signatures, 10);
}

#[test]
fn a_merge_with_room_for_another_after_it_goes_out_at_once() {
    let mut lane = Lane::with_proved_vote();
    lane.votes(1..11);
    assert_eq!(lane.send(IDLE).unwrap().shape.signatures, 10);
}

#[test]
fn a_slower_lane_shrinks_later_merges_and_the_last_answer_is_served() {
    let near_deadline = |slower: bool| {
        let mut lane = Lane::with_proved_vote();
        if slower {
            lane.slowdown = 3;
        }
        lane.votes(1..2);
        let second = lane.send(AFTER_ANSWER).unwrap();
        assert!(lane.answer(second, Answer::Proof).is_ok());

        lane.at(deadline() - Nanos::from_secs(2));
        lane.votes(2..200);
        let last = lane.send_when_due();
        let signatures = last.shape.signatures;
        assert!(lane.answer(last, Answer::Proof).is_ok());
        assert_eq!(lane.served(0), 2 + signatures, "the last proof that finished");
        signatures
    };
    let (usual, slower) = (near_deadline(false), near_deadline(true));
    assert!(slower < usual, "{slower} < {usual}");
}

#[test]
fn a_merge_that_ends_after_the_deadline_is_late_and_still_accepted() {
    let mut lane = Lane::with_proved_vote();
    lane.votes(1..50);
    let last = lane.send(AFTER_ANSWER).unwrap();
    lane.slowdown = 20;
    assert_eq!(lane.served(0), 1, "a read at the deadline");
    let deadline = last.merge.deadline;
    assert_eq!(lane.answer(last, Answer::Proof), Ok(50));
    assert!(lane.now() > deadline, "late");
    assert!(lane.send(AFTER_ANSWER).is_none(), "the aggregate proof is past its deadline");
}

#[test]
fn two_aggregate_proofs_of_one_deadline_both_merge() {
    let mut lane = Lane::new(NORMAL);
    lane.vote_of(1, 0, 0);
    (0..2).for_each(|position| lane.vote_of(0, 0, position));
    let first = lane.send(IDLE).unwrap();
    assert_eq!(first.aggregate_key().committee_index, 0, "the most waiting votes");
    assert!(lane.answer(first, Answer::Proof).is_ok());
    let second = lane.send(AFTER_ANSWER).unwrap();
    assert_eq!(second.aggregate_key().committee_index, 1);
    assert!(lane.answer(second, Answer::Proof).is_ok());
    assert_eq!((lane.served(0), lane.served(1)), (2, 1));
}

#[test]
fn the_earlier_deadline_goes_first_and_a_later_merge_leaves_it_room() {
    let mut lane = Lane::new(NORMAL);
    lane.vote_of(2, 2, 0);
    lane.vote_of(0, 0, 0);
    let first = lane.send(IDLE).unwrap();
    assert_eq!(first.aggregate_key().committee_index, 0, "due at 7.2 s, before 8.4 s");
    assert!(lane.answer(first, Answer::Proof).is_ok());

    lane.at(deadline() - Nanos::from_secs(1));
    (1..300).for_each(|position| lane.vote_of(2, 2, position));
    let later = lane.send(IDLE).unwrap();
    assert_eq!(later.aggregate_key().committee_index, 2);
    assert!(lane.answer(later, Answer::Proof).is_ok());
    assert!(lane.now() <= lane.latest_start(0), "{:?} > {:?}", lane.now(), lane.latest_start(0));
}

#[test]
fn past_its_latest_start_an_earlier_aggregate_proof_reserves_no_room() {
    let mut lane = Lane::two_proved_aggregate_proofs();
    lane.at(deadline() - Nanos::from_millis(100));
    assert!(lane.latest_start(0) < lane.now());
    lane.vote_of(2, 2, 1);
    let later = lane.send(IDLE).expect("the earlier aggregate proof can no longer use the room");
    assert_eq!(later.aggregate_key().committee_index, 2);
}

#[test]
fn an_aggregate_proof_refused_for_an_earlier_reserve_merges_when_the_reserve_ends() {
    let mut lane = Lane::two_proved_aggregate_proofs();
    let latest_start = lane.latest_start(0);
    lane.at(latest_start - Nanos::from_millis(100));
    lane.vote_of(2, 2, 1);
    assert!(lane.send(IDLE).is_none(), "no merge of the later aggregate proof ends in time");
    let wake_at = lane.wake.expect("the reserve ends");
    assert!(wake_at >= latest_start && wake_at - latest_start < TICK);

    lane.at(wake_at);
    let later = lane.send(IDLE).expect("no event came, and the reserve ended");
    assert_eq!(later.aggregate_key().committee_index, 2);
    assert_eq!(later.shape.signatures, 1);
}

#[test]
fn failures_keep_the_proof_and_three_in_a_row_stop_the_aggregate_proof() {
    let mut lane = Lane::with_proved_vote();
    lane.votes(1..2);
    for answer in [Answer::Refusal, Answer::OtherClaims, Answer::Lost] {
        let sent = lane.send(AFTER_ANSWER).unwrap();
        assert_eq!(sent.shape.signatures, 1, "the vote is picked again");
        assert!(lane.answer(sent, answer).is_err());
        assert_eq!(lane.served(0), 1, "the proof stays");
    }
    assert!(lane.send(AFTER_ANSWER).is_none(), "stopped");
    assert!(lane.wake.is_none());
}

#[test]
fn a_success_between_failures_resets_their_count() {
    let mut lane = Lane::new(NORMAL);
    for position in 0..4 {
        lane.votes(position..position + 1);
        let failed = lane.send(IDLE).unwrap();
        assert!(lane.answer(failed, Answer::Refusal).is_err());
        let proved = lane.send(AFTER_ANSWER).unwrap();
        assert!(lane.answer(proved, Answer::Proof).is_ok());
    }
    assert_eq!(lane.served(0), 4);
}

#[test]
fn votes_on_chain_are_not_merged() {
    let mut lane = Lane::new(NORMAL);
    lane.votes(0..3);
    lane.sources.include_on_chain(SLOT, &[0, 2], &mut lane.proofs);
    let sent = lane.send(IDLE).unwrap();
    assert_eq!(sent.shape.signatures, 1, "position 1 alone");
    assert_eq!(lane.answer(sent, Answer::Proof), Ok(1));

    lane.sources.include_on_chain(SLOT, &[3], &mut lane.proofs);
    lane.votes(3..4);
    assert!(lane.send(IDLE).is_none(), "its only waiting vote is on chain");
    assert!(lane.wake.is_none());
}

#[test]
fn a_lost_overdue_merge_shrinks_the_next_merge_until_it_is_answered() {
    let after_a_lost_merge = |overdue: bool| {
        let mut lane = Lane::new(NORMAL);
        lane.vote_of(0, 0, 0);
        let lost = lane.send(IDLE).unwrap();
        if overdue {
            let predicted = lane.stats.cost().predict(&lost.shape);
            assert!(lane.stats.overdue(predicted, predicted * 4u64));
        }
        assert!(lane.answer(lost, Answer::Lost).is_err());

        lane.at(deadline() - Nanos::from_secs(2));
        (0..300).for_each(|position| lane.vote_of(1, 0, position));
        let next = lane.send(IDLE).unwrap();
        assert_eq!(next.aggregate_key().committee_index, 1);
        let signatures = next.shape.signatures;
        assert!(lane.answer(next, Answer::Proof).is_ok());
        assert!(lane.stats.cost().margin() < 1.01, "the answer cleared the floor");
        signatures
    };
    let (usual, raised) = (after_a_lost_merge(false), after_a_lost_merge(true));
    assert!(raised < usual / 2, "{raised} against {usual}");
}

#[test]
fn an_early_pull_moves_only_the_aggregate_proofs_of_its_position() {
    let mut lane = Lane::new(NORMAL);
    lane.vote_of(0, 0, 0);
    lane.vote_of(2, 2, 0);
    let first = lane.send(IDLE).unwrap().merge.deadline;
    assert_eq!(first, deadline(), "committee 0 goes first");
    let latest_start = lane.latest_start(2);

    lane.pull_2_s_early();
    assert_eq!(lane.latest_start(2), latest_start);
    let later = lane.send(IDLE).expect("committee 0 is at its deadline");
    assert_eq!(later.aggregate_key().committee_index, 2);
    assert_eq!(later.merge.deadline, first + Nanos::from_millis(1_200));
}

/// A local proposal whose newest attestation slot is `SLOT`.
const BLOCK: Slot = SLOT + 2;

impl Lane {
    /// The groups of the block proof at `slot`, or `None` without one.
    fn block_groups(&self, slot: Slot) -> Option<usize> {
        let proof = &self.targets.block_proofs().get(&slot)?.proof;
        proof.id.map(|_| proof.groups().len())
    }

    fn waiting_for(&self, slot: Slot) -> usize {
        self.planner().waiting(&TargetKey::BlockProof(slot), &mut Box::<PickQueue>::default())
    }

    fn merge_all(&mut self) -> Vec<TargetKey> {
        let mut merged = Vec::new();
        while let Some(sent) = self.send(AFTER_ANSWER) {
            merged.push(sent.merge.key);
            assert!(self.answer(sent, Answer::Proof).is_ok());
        }
        merged
    }
}

#[test]
fn without_a_local_proposal_aggregates_are_stored_and_nothing_is_sent() {
    let mut lane = Lane::new(NORMAL);
    lane.aggregate(SLOT, 0, 0..4);
    lane.take_best_aggregates();
    assert!(lane.send(IDLE).is_none());
    assert_eq!(lane.sources.slot(SLOT).unwrap().aggregates.indexed().count(), 1);
    assert!(lane.targets.block_proof(BLOCK, &lane.proofs).is_none());
}

#[test]
fn two_committees_merge_into_one_block_proof() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.aggregate(SLOT, 0, 0..4);
    lane.aggregate(SLOT, 1, 0..4);
    lane.take_best_aggregates();
    assert_eq!(lane.block_groups(BLOCK), Some(1));
    let sent = lane.send(IDLE).expect("the other committee waits");
    assert_eq!(sent.merge.key, TargetKey::BlockProof(BLOCK));
    assert_eq!(sent.shape.proofs, 2, "the running proof and the other aggregate");
    assert!(lane.answer(sent, Answer::Proof).is_ok());
    assert_eq!(lane.block_groups(BLOCK), Some(2));
    assert_eq!(
        lane.targets.block_proof(BLOCK, &lane.proofs).unwrap().0.len(),
        1,
        "one attestation data"
    );
}

#[test]
fn a_better_aggregate_of_the_same_committee_merges_only_if_it_adds_votes() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.aggregate(SLOT, 0, 0..4);
    lane.take_best_aggregates();
    lane.aggregate(SLOT, 0, 1..3);
    assert!(lane.send(IDLE).is_none(), "its votes are in the proof");
    lane.aggregate(SLOT, 0, 2..6);
    let sent = lane.send(IDLE).expect("two new votes");
    assert_eq!(sent.merge.new_votes, 2);
}

#[test]
fn an_aggregate_proof_with_the_earlier_deadline_goes_before_a_block_proof() {
    let mut lane = Lane::new(NORMAL);
    lane.votes(0..1);
    lane.propose(&[BLOCK]);
    lane.aggregate(SLOT, 0, 0..4);
    lane.aggregate(SLOT, 1, 0..4);
    lane.take_best_aggregates();
    let target = lane.send(IDLE).unwrap();
    assert_eq!(target.merge.key, TargetKey::AggregateProof(key(0)), "the earlier deadline");
    assert!(lane.answer(target, Answer::Proof).is_ok());
    let block = lane.send(AFTER_ANSWER).unwrap();
    assert_eq!(block.merge.key, TargetKey::BlockProof(BLOCK));
}

#[test]
fn older_slots_wait_for_the_block_before() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.aggregate(SLOT, 0, 0..4);
    lane.aggregate(SLOT - 1, 0, 0..4);
    lane.take_best_aggregates();
    assert_eq!(lane.block_groups(BLOCK), Some(1));
    assert!(lane.send(IDLE).is_none(), "block BLOCK - 1 may include slot SLOT - 1");
    lane.import(BLOCK - 1);
    let sent = lane.send(IDLE).expect("the older slot opened");
    assert_eq!(sent.shape.proofs, 2);
}

#[test]
fn without_the_block_before_older_slots_open_at_its_attestation_due_time() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.aggregate(SLOT, 0, 0..4);
    lane.aggregate(SLOT - 1, 0, 0..4);
    lane.take_best_aggregates();
    assert!(lane.send(IDLE).is_none());
    let due = lane.ticker.slot_start(BLOCK - 1) + Nanos::from_millis(3_999);
    assert_eq!(lane.wake, Some(due), "3333 bps of 12 s, in whole milliseconds");
    lane.at(due - TICK);
    assert!(lane.send(IDLE).is_none());
    lane.at(due);
    assert_eq!(lane.send(IDLE).expect("the gate is open").shape.proofs, 2);
}

#[test]
fn votes_on_chain_are_no_gain() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.sources.include_on_chain(SLOT, &[0, 1, 2, 3], &mut lane.proofs);
    lane.aggregate(SLOT, 0, 0..4);
    lane.aggregate(SLOT, 1, 0..4);
    lane.take_best_aggregates();
    assert!(lane.send(IDLE).is_none());
    assert_eq!(lane.block_groups(BLOCK), None, "an aggregate fully on chain is never taken");
    lane.aggregate(SLOT, 2, 2..6);
    lane.take_best_aggregates();
    assert_eq!(lane.block_groups(BLOCK), Some(1));
}

#[test]
fn three_failures_stop_a_block_proof_and_its_initial_proof_is_still_served() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.aggregate(SLOT, 0, 0..4);
    lane.aggregate(SLOT, 1, 0..4);
    lane.take_best_aggregates();
    for answer in [Answer::Refusal, Answer::OtherClaims, Answer::Lost] {
        let sent = lane.send(AFTER_ANSWER).expect("the aggregate waits again");
        assert!(lane.answer(sent, answer).is_err());
        assert_eq!(lane.block_groups(BLOCK), Some(1), "the running proof stays");
    }
    assert!(lane.send(AFTER_ANSWER).is_none(), "stopped");
    assert_eq!(lane.targets.block_proof(BLOCK, &lane.proofs).unwrap().1, b"proof");
}

#[test]
fn two_proposals_merge_by_deadline() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK + 1, BLOCK]);
    for slot in [SLOT + 1, SLOT] {
        lane.aggregate(slot, 0, 0..4);
        lane.aggregate(slot, 1, 0..4);
    }
    lane.take_best_aggregates();
    let targets = lane.merge_all();
    assert_eq!(targets, [TargetKey::BlockProof(BLOCK), TargetKey::BlockProof(BLOCK + 1)]);
}

#[test]
fn a_proposal_learnt_after_its_aggregates_still_gets_a_proof() {
    let mut lane = Lane::new(NORMAL);
    lane.aggregate(SLOT, 0, 0..4);
    lane.take_best_aggregates();
    lane.propose(&[BLOCK]);
    lane.take_best_aggregates();
    assert_eq!(lane.block_groups(BLOCK), Some(1));
}

#[test]
fn a_group_past_max_groups_is_left_out() {
    let mut lane = Lane::new(FAST);
    lane.propose(&[BLOCK]);
    lane.import(BLOCK - 1);
    for slot in SLOT - 3..=SLOT {
        (0..16).for_each(|index| lane.aggregate(slot, index, 0..1));
    }
    lane.add_aggregate(aggregate_of(SLOT, 0, 0, 1..2));
    lane.take_best_aggregates();
    lane.merge_all();
    assert_eq!(lane.block_groups(BLOCK), Some(MAX_GROUPS));
    assert_eq!(lane.waiting_for(BLOCK), 1, "the second data of committee 0 waits");
}

#[test]
fn a_block_proof_and_its_aggregates_live_until_its_own_slot_is_pruned() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.aggregate(SLOT, 0, 0..4);
    lane.aggregate(SLOT, 1, 0..4);
    lane.targets.prune_before(BLOCK - 1, &mut lane.proofs);
    lane.import(BLOCK - 1);
    lane.take_best_aggregates();
    assert_eq!(lane.block_groups(BLOCK), Some(1), "aggregate taken after the prune");
    assert!(lane.targets.block_proof(BLOCK, &lane.proofs).is_some());
    let sent = lane.send(IDLE).expect("the other aggregate waits");
    assert_eq!(sent.shape.proofs, 2, "the running proof and the other aggregate");

    lane.targets.prune_before(BLOCK, &mut lane.proofs);
    assert!(lane.targets.block_proof(BLOCK, &lane.proofs).is_none());
    assert_eq!(lane.answer(sent, Answer::Proof), Err("the target was pruned"));
}

#[test]
fn an_early_read_moves_the_block_proof_deadline() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.aggregate(SLOT, 0, 0..4);
    lane.aggregate(SLOT, 1, 0..4);
    lane.take_best_aggregates();
    let start = lane.ticker.slot_start(BLOCK);
    let first = lane.send(IDLE).unwrap();
    assert_eq!(first.merge.deadline, start - gossip_clock_disparity(), "before any read");
    assert!(lane.answer(first, Answer::Proof).is_ok());

    let before = BLOCK - 1;
    lane.at(lane.ticker.slot_start(before) - Nanos::from_secs(2));
    lane.stats.block_proof_read(before, &lane.ticker);
    lane.aggregate(SLOT, 2, 0..4);
    let second = lane.send(IDLE).expect("committee 2 waits");
    assert_eq!(second.merge.deadline, start - Nanos::from_secs(2));
}

#[test]
fn a_block_proof_names_at_most_four_data_of_a_slot() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    for data in 1..=5 {
        lane.add_aggregate(aggregate_of(SLOT, data as usize, data, 0..4));
    }
    lane.take_best_aggregates();
    while let Some(sent) = lane.send(AFTER_ANSWER) {
        assert!(lane.answer(sent, Answer::Proof).is_ok());
    }
    assert_eq!(lane.targets.block_proof(BLOCK, &lane.proofs).unwrap().0.len(), DATA_PER_SLOT);
    assert_eq!(lane.waiting_for(BLOCK), 4, "the votes of the fifth data wait");
}

impl Lane {
    /// A vote of committee 0 for `data`, whose last local aggregator holds
    /// position 0.
    fn vote_for(&mut self, data: u16, position: usize) {
        let committee_len = MAX_VALIDATORS_PER_COMMITTEE;
        let single = Single { slot: SLOT, index: 0, data, position, committee_len };
        self.add_vote(single, Some(0));
    }
}

#[test]
fn only_the_four_leading_heads_of_a_slot_merge() {
    let mut lane = Lane::new(NORMAL);
    (0..20).for_each(|junk| lane.vote_for(100 + junk, 30 + junk as usize));
    (0..30).for_each(|position| lane.vote_for(1, position));
    let mut merged = Vec::new();
    while let Some(sent) = lane.send(AFTER_ANSWER) {
        merged.push(sent.aggregate_key().data_root[0]);
        assert!(lane.answer(sent, Answer::Proof).is_ok());
    }
    assert_eq!(merged, [1, 100, 101, 102], "the large head, then the earliest junk");
    assert_eq!(lane.served(0), 30);
}

#[test]
fn an_aggregate_proof_merges_once_its_head_leads() {
    let mut lane = Lane::new(NORMAL);
    for data in 1..=4 {
        (0..2).for_each(|vote| lane.vote_for(data, 2 * data as usize + vote));
    }
    lane.vote_for(5, 20);
    while let Some(sent) = lane.send(AFTER_ANSWER) {
        assert_ne!(sent.aggregate_key().data_root[0], 5, "the fifth head does not lead");
        assert!(lane.answer(sent, Answer::Proof).is_ok());
    }
    (21..23).for_each(|position| lane.vote_for(5, position));
    let sent = lane.send(IDLE).expect("the fifth head leads");
    assert_eq!((sent.aggregate_key().data_root[0], sent.shape.signatures), (5, 3));
}

impl Lane {
    /// A vote of committee `index` of `slot` for `data`, with no aggregate
    /// proof duty.
    fn gap_vote(&mut self, slot: Slot, index: u64, data: u16, position: usize) {
        let committee_len = MAX_VALIDATORS_PER_COMMITTEE;
        let single = Single { slot, index, data, position, committee_len };
        self.add_vote(single, None);
    }

    /// Votes of committee `index` of `slot` for data `slot`, as `aggregate`
    /// gives, with no aggregate proof duty.
    fn gap_votes(&mut self, slot: Slot, index: u64, positions: Range<usize>) {
        positions.for_each(|position| self.gap_vote(slot, index, slot as u16, position));
    }

    /// The last aggregate due time of `SLOT`: its stored votes open then.
    fn vote_gate(&self) -> Nanos {
        self.ticker.pq_aggregate_due(SLOT, AGGREGATORS_PER_COMMITTEE as u64 - 1)
    }
}

#[test]
fn a_gap_vote_merges_into_a_block_proof_without_aggregates_after_the_vote_gate() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.gap_votes(SLOT, 0, 0..1);
    lane.take_best_aggregates();
    assert_eq!(lane.block_groups(BLOCK), None, "no eligible aggregate");
    let gate = lane.vote_gate();
    lane.at(gate - TICK);
    assert!(lane.send(IDLE).is_none(), "aggregates may still bring the vote");
    assert_eq!(lane.wake, Some(gate));
    lane.at(gate);
    let sent = lane.send(IDLE).expect("the gate is open");
    assert_eq!((sent.merge.key, sent.shape.signatures), (TargetKey::BlockProof(BLOCK), 1));
    assert!(lane.answer(sent, Answer::Proof).is_ok());
    assert_eq!(lane.block_groups(BLOCK), Some(1));
}

#[test]
fn a_gap_vote_an_aggregate_covers_before_the_gate_is_never_sent() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.gap_votes(SLOT, 0, 0..4);
    lane.aggregate(SLOT, 0, 0..4);
    lane.take_best_aggregates();
    lane.at(lane.vote_gate());
    assert!(lane.send(IDLE).is_none(), "the aggregate taken covers every vote");
    assert_eq!(lane.block_groups(BLOCK), Some(1));
}

#[test]
fn a_second_aggregate_of_a_heard_committee_competes_with_its_gap_votes() {
    for (new_votes, proofs, signatures) in [(10, 1, 10), (60, 2, 0)] {
        let mut lane = Lane::new(NORMAL);
        lane.propose(&[BLOCK]);
        lane.aggregate(SLOT, 0, 0..10);
        lane.take_best_aggregates();
        lane.aggregate(SLOT, 0, 0..10 + new_votes);
        lane.gap_votes(SLOT, 0, 10..10 + new_votes);
        lane.at(lane.vote_gate());
        let sent = lane.send(AFTER_ANSWER).unwrap();
        assert_eq!((sent.shape.proofs, sent.shape.signatures), (proofs, signatures));
        assert_eq!(sent.merge.new_votes, new_votes);
    }
}

#[test]
fn a_gap_vote_on_chain_is_not_merged() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.gap_votes(SLOT, 0, 0..3);
    lane.sources.include_on_chain(SLOT, &[0, 2], &mut lane.proofs);
    lane.at(lane.vote_gate());
    assert_eq!(lane.send(IDLE).unwrap().shape.signatures, 1, "position 1 alone");
}

#[test]
fn gap_votes_of_an_older_slot_wait_for_the_block_before() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.gap_votes(SLOT, 0, 0..1);
    lane.gap_votes(SLOT - 2, 0, 0..1);
    lane.at(lane.vote_gate());
    let first = lane.send(IDLE).unwrap();
    assert_eq!(first.shape.signatures, 1, "the vote of SLOT alone");
    assert!(lane.answer(first, Answer::Proof).is_ok());
    assert!(lane.send(AFTER_ANSWER).is_none());
    let older_open = lane.ticker.slot_start(BLOCK - 1) + Nanos::from_millis(3_999);
    assert_eq!(lane.wake, Some(older_open));
    lane.at(older_open);
    assert_eq!(lane.send(IDLE).unwrap().shape.signatures, 1, "the vote of SLOT - 2");
}

#[test]
fn three_thousand_gap_votes_go_in_merges_of_at_most_max_signatures() {
    let mut lane = Lane::new(FAST);
    lane.propose(&[BLOCK]);
    (0..2).for_each(|index| lane.gap_votes(SLOT, index, 0..1_500));
    lane.at(lane.vote_gate());
    let mut merged = 0;
    while let Some(sent) = lane.send(AFTER_ANSWER) {
        assert!(sent.shape.signatures <= MAX_SIGNATURES);
        merged += sent.shape.signatures;
        assert!(lane.answer(sent, Answer::Proof).is_ok());
    }
    assert_eq!(merged, 3_000);
}

#[test]
fn a_vote_with_a_duty_feeds_its_aggregate_proof_and_the_block_proof() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    lane.vote_of(0, 0, 0);
    let target = lane.send(IDLE).unwrap();
    assert_eq!(target.merge.key, TargetKey::AggregateProof(key(0)));
    assert!(lane.answer(target, Answer::Proof).is_ok());
    lane.at(lane.vote_gate());
    let block = lane.send(IDLE).unwrap();
    assert_eq!((block.merge.key, block.shape.signatures), (TargetKey::BlockProof(BLOCK), 1));
}

#[test]
fn the_proposal_window_ends_at_the_last_block_whose_pool_holds_the_wall_slot() {
    let window = PqAggregator::proposal_window(SLOT);
    assert_eq!(*window.start(), SLOT + 1);
    let last = *window.end();
    assert_eq!(*pool(last).start(), SLOT);
    assert!(*pool(last + 1).start() > SLOT);
}

/// The data of the honest head of `after_a_junk_flood`.
fn honest_data() -> [u8; ATTESTATION_DATA_SIZE] {
    let single = Single { slot: SLOT, index: 0, data: SLOT as u16, position: 0, committee_len: 1 };
    single.with(0, |vote| vote.committee().data)
}

/// 500 single votes of distinct heads over the pool of `BLOCK`, then 1,600
/// of one head in 16 committees of `SLOT`. Older slots are open.
fn after_a_junk_flood() -> Lane {
    let mut lane = Lane::new(FAST);
    lane.propose(&[BLOCK]);
    lane.import(BLOCK - 1);
    for junk in 0..500 {
        let (slot, at) = (SLOT - 3 + junk % 4, junk / 4);
        lane.gap_vote(slot, at % 16, 1_000 + junk as u16, (at / 16) as usize);
    }
    (0..16).for_each(|index| lane.gap_votes(SLOT, index, 100..200));
    lane.at(lane.vote_gate());
    lane
}

#[test]
fn a_junk_flood_cannot_lock_out_the_honest_gap_votes() {
    let mut lane = after_a_junk_flood();
    let mut first = true;
    while let Some(sent) = lane.send(AFTER_ANSWER) {
        let (expected, shape) = (&sent.expected, &sent.shape);
        let honest = expected.iter().filter(|group| group.committee.data == honest_data());
        if first {
            assert_eq!(honest.map(|group| group.members.len()).sum::<usize>(), 1_600);
            first = false;
        }
        assert!(shape.signatures <= MAX_SIGNATURES && expected.len() <= MAX_GROUPS);
        let mut heads: Vec<_> =
            expected.iter().map(|group| (group.slot, group.committee.data)).collect();
        heads.sort_unstable();
        heads.dedup();
        assert!(heads.len() <= MAX_ATTESTATIONS_PQ);
        for slot in pool(BLOCK) {
            assert!(heads.iter().filter(|(of, _)| *of == slot).count() <= DATA_PER_SLOT);
        }
        assert!(lane.answer(sent, Answer::Proof).is_ok());
        let (attestations, _) = lane.targets.block_proof(BLOCK, &lane.proofs).unwrap();
        assert!(attestations.len() <= MAX_ATTESTATIONS_PQ);
    }
    assert!(!first, "a merge went out");
    assert_eq!(lane.waiting_for(BLOCK), 0, "no pass sends an empty merge");
}

#[test]
fn a_block_proof_merge_gets_at_most_max_groups_vote_groups() {
    let mut lane = Lane::new(FAST);
    lane.propose(&[BLOCK]);
    lane.import(BLOCK - 1);
    for slot in [SLOT - 1, SLOT] {
        for data in 1..=3 {
            let positions = 10 * data as usize..11 * data as usize;
            (0..16).for_each(|index| {
                positions.clone().for_each(|at| lane.gap_vote(slot, index, data, at))
            });
        }
    }
    lane.at(lane.vote_gate());
    let planner = lane.planner();
    let votes = offered_votes(&planner);
    assert_eq!(votes.len(), MAX_GROUPS, "of 96 groups that wait");
    assert!(votes.iter().all(|group| group.committee().data[100] > 1), "the largest heads first");
}

fn offered_votes<'a>(planner: &MergePlanner<'a>) -> Vec<VoteGroup<'a>> {
    let mut queue = PickQueue::default();
    queue.queue_block_votes(
        planner.block_vote_groups(BLOCK),
        planner.sources,
        &planner.block(BLOCK).proof,
        planner.stats.cost(),
    );
    std::iter::from_fn(|| queue.pop())
        .map(|candidate| {
            let Source::Votes(index) = candidate.source else { unreachable!() };
            planner.sources.slot(candidate.slot).unwrap().votes.at(index)
        })
        .collect()
}

/// The heads of `SLOT` among the vote groups block `BLOCK` is offered.
fn offered_heads(lane: &Lane) -> Vec<[u8; ATTESTATION_DATA_SIZE]> {
    let planner = lane.planner();
    let votes = offered_votes(&planner);
    assert!(votes.iter().all(|group| group.slot() == SLOT));
    let mut heads: Vec<_> = votes.iter().map(|group| group.committee().data).collect();
    heads.sort_unstable();
    heads.dedup();
    heads
}

#[test]
fn a_named_heads_votes_merge_past_larger_heads_the_proof_cannot_name() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    for data in 1..=4 {
        lane.add_aggregate(aggregate_of(SLOT, data as usize, data, 0..4));
    }
    lane.take_best_aggregates();
    lane.merge_all();
    assert_eq!(lane.targets.block_proof(BLOCK, &lane.proofs).unwrap().0.len(), DATA_PER_SLOT);
    for junk in 0..5 {
        (0..16).for_each(|index| lane.gap_vote(SLOT, index, 100 + junk, 10 + junk as usize));
    }
    (4..6).for_each(|position| lane.gap_vote(SLOT, 1, 1, position));

    lane.at(lane.vote_gate());
    let named = aggregate_of(SLOT, 1, 1, 0..4).group().committee.data;
    assert_eq!(offered_heads(&lane), [named]);
    let sent = lane.send(AFTER_ANSWER).expect("the gap votes of a named head");
    assert_eq!((sent.shape.signatures, sent.merge.new_votes), (2, 2));
}

#[test]
fn a_flood_does_not_widen_what_a_block_proof_is_offered() {
    let mut lane = Lane::new(NORMAL);
    lane.propose(&[BLOCK]);
    for junk in 0..2_000 {
        lane.gap_vote(SLOT, junk % 16, 1_000 + junk as u16, (junk / 16) as usize);
    }
    (0..16).for_each(|index| lane.gap_votes(SLOT, index, 200..202));

    lane.at(lane.vote_gate());
    let planner = lane.planner();
    let votes = offered_votes(&planner);
    assert!(votes.len() <= DATA_PER_SLOT * 16);
    let honest = votes.iter().filter(|group| group.committee().data == honest_data());
    assert_eq!(honest.count(), 16);
    assert!(offered_heads(&lane).len() <= DATA_PER_SLOT);
}

mod picking {
    use std::ops::Range;

    use silver_beacon_state_data::Slot;
    use silver_common::{
        Nanos,
        leanvm::{
            MAX_PROOF_CLAIMS, MAX_PROOFS, MAX_REQUEST_LEN, MAX_SIGNATURES, SIGNED_CLAIM_SIZE,
        },
        ssz_view::{
            ATTESTATION_DATA_SIZE, MAX_ATTESTATIONS_PQ, MAX_STARK_PROOF_SIZE,
            MAX_VALIDATORS_PER_COMMITTEE,
        },
    };

    use super::super::super::{
        claims::{Claim, ClaimCheck, MAX_GROUPS},
        cost_model::MergeShape,
        proof_targets::TargetKey,
        proved::DATA_PER_SLOT,
        stats::Stats,
        test_util::{
            AggregateFixture, DATA_MARKER_AT, Group, Lane, Member, Sent, Single, aggregate_of,
            answer, claim_of, signature_batch, visit_groups,
        },
    };

    const SLOT: Slot = 20;
    const BLOCK: Slot = SLOT + 4;
    const NOW: Nanos = Nanos::from_secs(100);
    const FAR: Nanos = Nanos::from_secs(10_000);

    /// The guard never binds.
    fn roomy() -> Stats {
        let mut stats = Stats::default();
        let sample = MergeShape { proofs: 1, claims_in: MAX_PROOF_CLAIMS, ..signature_batch(0) };
        let predicted = stats.cost().predict(&sample);
        stats.record_answer(&sample, predicted, predicted, true);
        stats
    }

    /// Only one input passes the guard.
    fn tight() -> Stats {
        let mut stats = Stats::default();
        let sample = signature_batch(1);
        let round_trip = Nanos::from_millis(1);
        let predicted = stats.cost().predict(&sample);
        stats.record_answer(&sample, predicted, round_trip, true);
        stats.overdue(round_trip, round_trip * 3u64);
        stats
    }

    fn running_at(index: usize, positions: Range<usize>) -> Vec<Group> {
        vec![aggregate_of(SLOT, index, 9, positions).group()]
    }

    struct Setup {
        lane: Lane,
        running: Vec<Group>,
        running_proof: Vec<u8>,
        horizon: Nanos,
        idle: bool,
    }

    impl Setup {
        fn new(stats: Stats) -> Self {
            let mut lane = Lane::with_stats(stats, 1);
            lane.propose(&[BLOCK]);
            lane.import(BLOCK - 1);
            // Make the block live without adding a competing proof.
            let position = MAX_VALIDATORS_PER_COMMITTEE - 1;
            lane.sources.include_on_chain(SLOT + 2, &[position as u32], &mut lane.proofs);
            lane.add_aggregate(aggregate_of(SLOT + 2, 15, 99, position..position + 1));
            Self {
                lane,
                running: Vec::new(),
                running_proof: b"running".to_vec(),
                horizon: FAR,
                idle: false,
            }
        }

        fn with_full_aggregates() -> Self {
            let mut setup = Self::new(roomy());
            for slot in SLOT - 1..SLOT + 2 {
                for index in 0..16 {
                    for data in 1..=4 {
                        setup.aggregate(aggregate_of(
                            slot,
                            index,
                            data,
                            0..MAX_VALIDATORS_PER_COMMITTEE,
                        ));
                    }
                }
            }
            setup
        }

        fn aggregate(&mut self, aggregate: AggregateFixture) {
            self.lane.add_aggregate(aggregate);
        }

        fn votes(&mut self, slot: Slot, index: u64, data: u16, positions: Range<usize>) {
            for position in positions {
                let committee_len = MAX_VALIDATORS_PER_COMMITTEE;
                let single = Single { slot, index, data, position, committee_len };
                self.lane.add_vote(single, None);
            }
        }

        fn pick(&mut self) -> Option<Sent> {
            let due = self.lane.ticker.slot_start(BLOCK);
            let deadline = self.lane.stats.block_proof_deadline(due);
            let time = self.horizon.saturating_sub(NOW).max(Nanos::from_millis(1));
            self.lane.at(deadline.saturating_sub(time));
            if !self.running.is_empty() {
                let body = answer(&self.running, &self.running_proof);
                self.lane
                    .targets
                    .settle(
                        &TargetKey::BlockProof(BLOCK),
                        body.parse(),
                        None,
                        &mut self.lane.proofs,
                        &mut ClaimCheck::default(),
                        |_, visit| visit_groups(&self.running, visit),
                    )
                    .unwrap();
            }
            let sent = self.lane.send(self.idle)?;
            assert_eq!(sent.shape.request_bytes, sent.body.len());
            Some(sent)
        }
    }

    fn signatures(sent: &Sent) -> usize {
        sent.shape.signatures
    }

    fn picked_aggregates(setup: &Setup, sent: &Sent) -> usize {
        sent.shape.proofs - usize::from(!setup.running.is_empty())
    }

    fn picked(sent: &Sent) -> Vec<(Slot, usize, usize)> {
        sent.request
            .split(&sent.body)
            .unwrap()
            .signatures
            .iter()
            .map(|record| {
                let claim: &Claim = record.first_chunk().unwrap();
                sent.expected
                    .iter()
                    .find_map(|group| {
                        let member = group.members.iter().find(|member| &member.claim == claim)?;
                        Some((group.slot, group.committee.index, member.position))
                    })
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn a_covered_or_on_chain_vote_is_never_sent() {
        let mut setup = Setup::new(roomy());
        setup.running = vec![aggregate_of(SLOT, 0, 1, 0..10).group()];
        setup.votes(SLOT, 0, 1, 5..13);
        setup.votes(SLOT, 1, 1, 0..2);
        setup.lane.sources.include_on_chain(SLOT, &[11, 0, 1], &mut setup.lane.proofs);
        let merge = setup.pick().unwrap();
        assert_eq!(picked(&merge), [(SLOT, 0, 10), (SLOT, 0, 12)]);
        assert_eq!(merge.merge.new_votes, 2);
    }

    #[test]
    fn no_pick_is_planned_to_end_after_the_horizon() {
        let vote_horizon = NOW + Nanos::from_millis(975);
        let rows = [
            (false, false, false, vote_horizon),
            (true, false, false, vote_horizon),
            (true, true, false, vote_horizon),
            (true, false, true, NOW + Nanos::from_secs(1)),
        ];
        let mut running_signatures = 0;
        for (with_running, idle, with_aggregates, horizon) in rows {
            let mut setup = Setup::new(roomy());
            setup.horizon = horizon;
            setup.idle = idle;
            if with_running {
                setup.running = running_at(1, 0..1);
            }
            if with_aggregates {
                for position in 0..10 {
                    setup.aggregate(aggregate_of(SLOT, position, 1, 0..1));
                }
            } else {
                setup.votes(SLOT, 0, 1, 0..200);
            }

            let merge = setup.pick().unwrap();
            let ends = NOW + setup.lane.stats.cost().planned(&merge.shape);
            assert!(
                ends <= setup.horizon,
                "running={with_running}, idle={idle}, aggregates={with_aggregates}: {ends:?} > {:?}",
                setup.horizon
            );
            if with_aggregates {
                assert!((1..10).contains(&picked_aggregates(&setup, &merge)));
            } else {
                let signatures = signatures(&merge);
                assert!(signatures > 0);
                let more = MergeShape { signatures: signatures + 1, ..*&merge.shape };
                assert!(NOW + setup.lane.stats.cost().planned(&more) > setup.horizon);
                if with_running && !idle {
                    running_signatures = signatures;
                    let positions: Vec<_> =
                        picked(&merge).into_iter().map(|(_, _, position)| position).collect();
                    assert_eq!(positions, (0..signatures).collect::<Vec<_>>(), "in arrival order");
                }
                if idle {
                    assert!(
                        signatures < running_signatures,
                        "{signatures} >= {running_signatures}"
                    );
                }
            }
        }
    }

    #[test]
    fn without_a_proof_only_the_first_vote_skips_the_fit() {
        let mut setup = Setup::new(roomy());
        setup.votes(SLOT, 0, 1, 0..3);
        setup.horizon = NOW;
        let merge = setup.pick().unwrap();
        assert_eq!(signatures(&merge), 1);
    }

    #[test]
    fn one_input_always_passes_the_guard() {
        let rows = [
            (Stats::default(), 5, 0, 0, false),
            (tight(), 5, 0, 0, true),
            (Stats::default(), 0, 3, 1, false),
            (tight(), 0, 1, 2_048, true),
        ];
        for (model, votes, aggregates, voters_per_aggregate, tight_guard) in rows {
            let mut setup = Setup::new(model);
            setup.votes(SLOT, 0, 1, 0..votes);
            for at in 0..aggregates {
                let first = at * voters_per_aggregate;
                setup.aggregate(aggregate_of(SLOT, 0, 1, first..first + voters_per_aggregate));
            }
            let merge = setup.pick().unwrap();
            assert_eq!(signatures(&merge) + picked_aggregates(&setup, &merge), 1);
            if tight_guard {
                assert!(setup.lane.stats.cost().planned(&merge.shape) > Nanos::from_millis(2));
            }
        }
    }

    #[test]
    fn a_merge_is_planned_at_most_twice_the_longest_round_trip() {
        let round_trip = Nanos::from_secs(1);
        let mut stats = Stats::default();
        let sample = signature_batch(128);
        let predicted = stats.cost().predict(&sample);
        stats.record_answer(&sample, predicted, round_trip, true);
        let mut setup = Setup::new(stats);
        setup.votes(SLOT, 0, 1, 0..300);
        let merge = setup.pick().unwrap();
        assert!(setup.lane.stats.cost().planned(&merge.shape) <= round_trip * 2u64);
        assert!((2..300).contains(&signatures(&merge)));
    }

    #[test]
    fn a_group_beyond_max_groups_is_left_out() {
        let mut setup = Setup::new(roomy());
        for at in 0..MAX_GROUPS {
            let (index, data) = ((at % 16) as u64, at / 16);
            setup.votes(SLOT, index, data as u16, data..data + 1);
        }
        setup.running = vec![aggregate_of(SLOT + 2, 15, 99, 0..1).group()];
        let merge = setup.pick().unwrap();
        assert_eq!(signatures(&merge), MAX_GROUPS - 1);
        assert_eq!(merge.expected.len(), MAX_GROUPS);
    }

    /// Picked aggregates, signatures and new votes.
    fn counts(setup: &Setup, sent: &Sent) -> (usize, usize, usize) {
        (picked_aggregates(setup, sent), signatures(sent), sent.merge.new_votes)
    }

    #[test]
    fn equal_rank_takes_the_older_slot_then_the_earlier_arrival() {
        let mut setup = Setup::new(tight());
        setup.aggregate(aggregate_of(SLOT + 1, 0, 1, 0..4));
        setup.aggregate(aggregate_of(SLOT, 0, 2, 0..4));
        setup.aggregate(aggregate_of(SLOT, 1, 1, 0..4));
        let merge = setup.pick().unwrap();
        assert_eq!(picked_aggregates(&setup, &merge), 1);
        let [group] = &merge.expected[..] else { panic!("one group goes out") };
        assert_eq!(
            (group.slot, group.committee.index, group.committee.data[DATA_MARKER_AT]),
            (SLOT, 0, 2)
        );
    }

    #[test]
    fn a_picked_aggregate_shrinks_the_votes_of_its_group() {
        let mut setup = Setup::new(roomy());
        setup.aggregate(aggregate_of(SLOT, 0, 1, 0..80));
        setup.votes(SLOT, 0, 1, 30..100);
        let merge = setup.pick().unwrap();
        assert_eq!(counts(&setup, &merge), (1, 20, 100));
        let positions: Vec<_> =
            picked(&merge).into_iter().map(|(_, _, position)| position).collect();
        assert_eq!(positions, (80..100).collect::<Vec<_>>());
    }

    #[test]
    fn a_merge_takes_at_most_max_proofs_with_the_running_proof_as_one() {
        for (running, aggregates) in [(true, 15), (false, 16)] {
            let mut setup = Setup::new(roomy());
            if running {
                setup.running = running_at(1, 0..1);
            }
            (0..20).for_each(|at| {
                setup.aggregate(aggregate_of(SLOT, at % 16, 1, at / 16..at / 16 + 1))
            });
            let merge = setup.pick().unwrap();
            assert_eq!(picked_aggregates(&setup, &merge), aggregates);
            assert_eq!(merge.shape.proofs, MAX_PROOFS);
        }
    }

    #[test]
    fn an_aggregate_or_a_vote_group_beyond_max_proof_claims_is_left_out() {
        for with_aggregate in [false, true] {
            let mut setup = Setup::new(roomy());
            // Repeat one position with distinct claims to isolate the claim cap.
            let mut group = aggregate_of(SLOT, 0, 1, 0..1).group();
            let member = group.members[0];
            group.members = (0..MAX_PROOF_CLAIMS)
                .map(|at| Member { claim: claim_of(0, 1, at), ..member })
                .collect();
            setup.running = vec![group];
            if with_aggregate {
                setup.aggregate(aggregate_of(SLOT, 0, 1, 5..6));
            }
            setup.votes(SLOT, 0, 1, 6..7);
            assert!(setup.pick().is_none());
        }
    }

    #[test]
    fn a_merge_is_cut_before_it_passes_max_request_len() {
        let mut setup = Setup::new(roomy());
        let full =
            |slot, index, data| aggregate_of(slot, index, data, 0..MAX_VALIDATORS_PER_COMMITTEE);
        let running: Vec<Group> =
            (0..26).map(|at| full(SLOT, at % 16, 1 + (at / 16) as u8).group()).collect();
        setup.running = running;
        setup.running_proof = vec![0; MAX_STARK_PROOF_SIZE];
        for at in 26..41 {
            let mut aggregate = full(SLOT, at % 16, 1 + (at / 16) as u8);
            aggregate.proof = vec![0; MAX_STARK_PROOF_SIZE];
            setup.aggregate(aggregate);
        }
        setup.votes(SLOT, 9, 3, 0..MAX_VALIDATORS_PER_COMMITTEE);

        let merge = setup.pick().unwrap();
        assert_eq!(picked_aggregates(&setup, &merge), MAX_PROOFS - 1);
        assert!(signatures(&merge) < MAX_SIGNATURES);
        let len = merge.body.len();
        let more = len + SIGNED_CLAIM_SIZE;
        assert!(len <= MAX_REQUEST_LEN && more > MAX_REQUEST_LEN, "cut at the bound");
    }

    #[test]
    fn a_vote_group_ranked_below_refused_aggregates_is_still_picked() {
        let mut setup = Setup::new(roomy());
        setup.running = running_at(1, 0..1);
        for at in 0..35 {
            setup.aggregate(aggregate_of(SLOT, at % 16, 2 + (at / 16) as u8, 0..60));
        }
        setup.votes(SLOT, 0, 9, 0..5);
        let merge = setup.pick().unwrap();
        assert_eq!(counts(&setup, &merge), (15, 5, 15 * 60 + 5));
    }

    fn data_groups(slot: Slot, index: usize, last_data: u8) -> Vec<Group> {
        (1..=last_data).map(|data| aggregate_of(slot, index, data, 0..4).group()).collect()
    }

    #[test]
    fn a_second_committee_of_a_taken_data_is_taken() {
        let mut setup = Setup::new(roomy());
        (1..=4).for_each(|data| setup.aggregate(aggregate_of(SLOT, 0, data, 0..4)));
        setup.aggregate(aggregate_of(SLOT, 1, 4, 0..4));
        let merge = setup.pick().unwrap();
        assert_eq!(picked_aggregates(&setup, &merge), 5);
    }

    #[test]
    fn the_data_of_the_running_proof_count_first() {
        let mut setup = Setup::new(roomy());
        setup.running = data_groups(SLOT, 0, 4);
        setup.aggregate(aggregate_of(SLOT, 0, 5, 0..4));
        setup.aggregate(aggregate_of(SLOT, 1, 4, 0..4));
        let merge = setup.pick().unwrap();
        assert_eq!(picked_aggregates(&setup, &merge), 1);
        let committee = &merge.expected.last().unwrap().committee;
        assert_eq!((committee.index, committee.data[DATA_MARKER_AT]), (1, 4), "a held data");
    }

    #[test]
    fn a_vote_group_of_a_fifth_data_is_left_out() {
        let mut setup = Setup::new(roomy());
        setup.running = data_groups(SLOT, 0, 3);
        setup.aggregate(aggregate_of(SLOT, 0, 4, 0..80));
        setup.votes(SLOT, 1, 5, 0..3);
        let sent = setup.pick().unwrap();
        assert_eq!(picked_aggregates(&setup, &sent), 1);
        assert_eq!(signatures(&sent), 0);
    }

    #[test]
    fn a_seventeenth_data_is_left_out() {
        let mut setup = Setup::new(roomy());
        let index = |slot: Slot| (slot + 2 - SLOT) as usize;
        let running = (SLOT - 2..=SLOT).flat_map(|slot| data_groups(slot, index(slot), 4));
        setup.running = running.collect();
        for slot in SLOT + 1..=SLOT + 2 {
            (1..=4).for_each(|data| setup.aggregate(aggregate_of(slot, index(slot), data, 0..4)));
        }
        let merge = setup.pick().unwrap();
        assert_eq!(picked_aggregates(&setup, &merge), 4, "the data of SLOT + 1 make 16");
        assert!(merge.expected[setup.running.len()..].iter().all(|group| group.slot == SLOT + 1));
    }

    fn assert_merge_caps(sent: &Sent) -> Vec<(Slot, [u8; ATTESTATION_DATA_SIZE])> {
        assert!(sent.shape.proofs <= MAX_PROOFS && signatures(sent) <= MAX_SIGNATURES);
        assert!(sent.body.len() <= MAX_REQUEST_LEN);
        let expected = &sent.expected;
        let members: usize = expected.iter().map(|group| group.members.len()).sum();
        assert!(expected.len() <= MAX_GROUPS && members <= MAX_PROOF_CLAIMS);
        let heads = heads(expected);
        assert!(heads.len() <= MAX_ATTESTATIONS_PQ);
        heads
    }

    fn heads(groups: &[Group]) -> Vec<(Slot, [u8; ATTESTATION_DATA_SIZE])> {
        let mut heads: Vec<_> =
            groups.iter().map(|group| (group.slot, group.committee.data)).collect();
        heads.sort_unstable();
        heads.dedup();
        heads
    }

    #[test]
    fn votes_go_by_head_votes_then_older_slot_then_gain_then_arrival() {
        let first = |votes: &[(Slot, u64, u16, Range<usize>)]| {
            let mut setup = Setup::new(tight());
            for (slot, index, data, positions) in votes {
                setup.votes(*slot, *index, *data, positions.clone());
            }
            picked(&setup.pick().unwrap())[0]
        };
        assert_eq!(first(&[(SLOT + 1, 0, 1, 0..2), (SLOT, 0, 2, 0..2)]), (SLOT, 0, 0));
        let split = [(SLOT, 0, 1, 0..1), (SLOT, 1, 1, 0..1), (SLOT, 2, 2, 0..2)];
        assert_eq!(first(&split), (SLOT, 2, 0), "two votes in one group beat one");
        assert_eq!(first(&[(SLOT, 1, 1, 0..1), (SLOT, 0, 2, 0..1)]), (SLOT, 1, 0));
        let more_head_votes =
            [(SLOT, 0, 1, 0..2), (SLOT, 1, 2, 0..1), (SLOT, 2, 2, 0..1), (SLOT, 3, 2, 0..1)];
        assert_eq!(first(&more_head_votes), (SLOT, 1, 0));
        let earlier = [(SLOT + 1, 0, 1, 0..1), (SLOT, 2, 1, 0..1), (SLOT, 1, 1, 3..4)];
        assert_eq!(first(&earlier), (SLOT, 2, 0));
    }

    #[test]
    fn a_junk_flood_cannot_lock_out_a_large_group() {
        let mut setup = Setup::new(roomy());
        for slot in [SLOT, SLOT + 1] {
            for junk in 0..3 {
                let position = junk as usize;
                (0..16)
                    .for_each(|index| setup.votes(slot, index, 100 + junk, position..position + 1));
            }
        }
        (0..16).for_each(|index| setup.votes(SLOT + 1, index, 1, 3..23));
        let merge = setup.pick().unwrap();
        let picked = picked(&merge);
        let honest =
            picked.iter().filter(|(slot, _, position)| *slot == SLOT + 1 && *position >= 3);
        assert_eq!(honest.count(), 320);
        assert_eq!(merge.expected.len(), MAX_GROUPS);
    }

    #[test]
    fn the_data_cap_names_the_heads_with_the_most_votes() {
        let mut setup = Setup::new(roomy());
        (1..=5).for_each(|data| setup.votes(SLOT, data.into(), data, 0..data.into()));
        let merge = setup.pick().unwrap();
        let named: Vec<_> = merge.expected.iter().map(|group| group.committee.data[100]).collect();
        assert_eq!(named, [5, 4, 3, 2]);
    }

    #[test]
    fn every_cap_binds_under_a_flood_of_heads() {
        let mut setup = Setup::with_full_aggregates();
        for at in 0..2_000 {
            let (slot, at) = (SLOT + at % 2, at / 2);
            let position = (at / 16) as usize;
            setup.votes(slot, at % 16, 1_000 + at as u16, position..position + 1);
        }
        setup.votes(SLOT, 0, 5, 100..MAX_VALIDATORS_PER_COMMITTEE);

        let heads = assert_merge_caps(&setup.pick().unwrap());
        for slot in SLOT - 2..SLOT + 2 {
            assert!(heads.iter().filter(|(of, _)| *of == slot).count() <= DATA_PER_SLOT);
        }
    }
}
