use super::{
    super::{
        proof_sources::ProofSources,
        proof_store::ProofStore,
        test_util::{DATA_MARKER_AT, Single},
    },
    *,
};

const SLOT: Slot = 7;

impl Single {
    fn at(position: usize) -> Self {
        Self { slot: SLOT, index: 0, data: 1, position, committee_len: 16 }
    }
}

impl Single {
    fn add(&self, store: &mut ProofSources, tag: u64) -> Result<(), VoteRefused> {
        self.with(tag, |vote| store.add_vote(vote, &mut ProofStore::default()))
    }
}

fn groups(store: &ProofSources, slot: Slot) -> impl Iterator<Item = VoteGroup<'_>> {
    store.slot(slot).into_iter().flat_map(|entry| {
        let votes = &entry.votes;
        (0..votes.heads.len()).flat_map(|row| votes.head_groups(&votes.heads.get(row).data))
    })
}

fn arrivals(group: VoteGroup) -> Vec<u64> {
    group.votes().map(|vote| vote.arrival).collect()
}

fn head(data: u16) -> [u8; ATTESTATION_DATA_SIZE] {
    Single { data, ..Single::at(0) }.with(0, |vote| vote.committee().data)
}

fn head_votes(store: &ProofSources, data: u16) -> usize {
    store.slot(SLOT).map_or(0, |entry| entry.votes.head_votes(&head(data)))
}

/// The leading heads of `SLOT`, by their `Single::data`.
fn leading(store: &ProofSources) -> Vec<u8> {
    store
        .slot(SLOT)
        .into_iter()
        .flat_map(|entry| entry.votes.leading())
        .map(|data| data[DATA_MARKER_AT])
        .collect()
}

#[test]
fn a_position_outside_the_committee_is_refused() {
    let mut store = ProofSources::default();
    let outside = Single { committee_len: 10, ..Single::at(10) };
    assert_eq!(outside.add(&mut store, 0), Err(VoteRefused::OutsideCommittee));

    let committee_len = MAX_VALIDATORS_PER_COMMITTEE + 5;
    let beyond = Single { committee_len, ..Single::at(MAX_VALIDATORS_PER_COMMITTEE) };
    assert_eq!(beyond.add(&mut store, 1), Err(VoteRefused::OutsideCommittee));
    let last = Single { committee_len, ..Single::at(MAX_VALIDATORS_PER_COMMITTEE - 1) };
    assert_eq!(last.add(&mut store, 2), Ok(()));
    assert_eq!(groups(&store, SLOT).count(), 1);
}

#[test]
fn a_second_vote_at_a_held_position_is_refused_and_the_first_stays() {
    let mut store = ProofSources::default();
    assert_eq!(Single::at(3).add(&mut store, 0), Ok(()));
    assert_eq!(Single::at(3).add(&mut store, 1), Err(VoteRefused::PositionHeld));
    let [group] = &groups(&store, SLOT).collect::<Vec<_>>()[..] else { panic!("one group") };
    let group = *group;
    assert_eq!(arrivals(group), [1]);
    assert_eq!(
        group.votes().next().unwrap().record()[size_of::<Claim>()],
        0,
        "the first signature"
    );
}

#[test]
fn the_same_position_for_another_head_is_refused_and_the_first_stays() {
    let mut store = ProofSources::default();
    assert_eq!(Single::at(3).add(&mut store, 0), Ok(()));
    let other_head = Single { data: 2, ..Single::at(3) };
    assert_eq!(other_head.add(&mut store, 1), Err(VoteRefused::PositionHeld));
    let [group] = &groups(&store, SLOT).collect::<Vec<_>>()[..] else { panic!("one group") };
    let group = *group;
    assert_eq!((group.committee().data[DATA_MARKER_AT], arrivals(group)), (1, vec![1]));
    assert_eq!((head_votes(&store, 1), head_votes(&store, 2)), (1, 0));
}

#[test]
fn memory_stays_bounded_by_positions() {
    let mut store = ProofSources::default();
    let committee_len = MAX_VALIDATORS_PER_COMMITTEE;
    let vote = |position: usize, data| Single { data, committee_len, ..Single::at(position) };
    for position in 0..committee_len {
        assert_eq!(vote(position, position as u16).add(&mut store, position as u64), Ok(()));
    }
    for position in 0..committee_len {
        let refused = vote(position, (committee_len + position) as u16).add(&mut store, 0);
        assert_eq!(refused, Err(VoteRefused::PositionHeld));
    }
    let votes: usize = groups(&store, SLOT).map(|group| group.len()).sum();
    assert_eq!(votes, MAX_VALIDATORS_PER_COMMITTEE);
}

#[test]
fn a_committee_index_past_the_last_is_refused() {
    let mut store = ProofSources::default();
    let index = MAX_COMMITTEES_PER_SLOT_PQ as u64;
    let unknown = Single { index, ..Single::at(0) };
    assert_eq!(unknown.add(&mut store, 0), Err(VoteRefused::UnknownCommittee));
    assert!(groups(&store, SLOT).next().is_none());
    assert_eq!(Single { index: index - 1, ..Single::at(0) }.add(&mut store, 1), Ok(()));
}

/// A vote for the head `data` in committee `data`.
fn head_vote(data: u16, position: usize) -> Single {
    Single { data, index: data.into(), ..Single::at(position) }
}

/// Heads 1 to 5 with 1, 3, 2, 1 and 2 votes, at arrivals 1 to 9.
fn five_heads() -> ProofSources {
    let mut store = ProofSources::default();
    let mut arrival = 0;
    for (data, votes) in [(1, 1), (2, 3), (3, 2), (4, 1), (5, 2)] {
        for position in 0..votes {
            arrival += 1;
            assert_eq!(head_vote(data, position).add(&mut store, arrival), Ok(()));
        }
    }
    store
}

#[test]
fn the_heads_with_the_most_votes_lead() {
    let mut store = five_heads();
    assert_eq!(leading(&store), [2, 3, 5, 1], "of two heads of one vote, the earlier leads");
    store.prune_before(SLOT + 1, &mut ProofStore::default());
    assert_eq!(head_votes(&store, 2), 0);
    assert!(leading(&store).is_empty());
}

#[test]
fn a_head_outside_the_lead_overtakes() {
    let mut store = five_heads();
    for (arrival, position) in [(10, 1), (11, 2)] {
        assert_eq!(head_vote(4, position).add(&mut store, arrival), Ok(()));
    }
    assert_eq!(leading(&store), [2, 4, 3, 5], "of two heads of three votes, the earlier leads");
}

#[test]
fn a_late_large_group_is_stored_after_a_flood_of_heads() {
    let mut store = ProofSources::default();
    let committee_len = MAX_VALIDATORS_PER_COMMITTEE;
    for at in 0..1_000 {
        let (index, position) = ((at % 16) as u64, at / 16);
        let junk = Single { index, data: 1_000 + at as u16, committee_len, ..Single::at(position) };
        assert_eq!(junk.add(&mut store, at as u64), Ok(()));
    }
    for position in 100..200 {
        let honest = Single { committee_len, ..Single::at(position) };
        assert_eq!(honest.add(&mut store, position as u64), Ok(()));
    }
    assert_eq!(groups(&store, SLOT).count(), 1_001);
    assert_eq!((head_votes(&store, 1), head_votes(&store, 1_000)), (100, 1));
}

#[test]
fn pruning_drops_older_slots_and_keeps_the_floor() {
    let mut store = ProofSources::default();
    for slot in [SLOT - 1, SLOT, SLOT + 1] {
        assert_eq!(Single { slot, ..Single::at(0) }.add(&mut store, slot), Ok(()));
    }
    store.prune_before(SLOT, &mut ProofStore::default());
    assert!(groups(&store, SLOT - 1).next().is_none());
    assert_eq!((groups(&store, SLOT).count(), groups(&store, SLOT + 1).count()), (1, 1));

    let below = Single { slot: SLOT - 1, ..Single::at(1) };
    assert_eq!(below.add(&mut store, 9), Err(VoteRefused::BeforeFloor));
    assert!(groups(&store, SLOT - 1).next().is_none());
    store.prune_before(SLOT - 2, &mut ProofStore::default());
    assert_eq!(below.add(&mut store, 10), Err(VoteRefused::BeforeFloor), "the floor never falls");
}
