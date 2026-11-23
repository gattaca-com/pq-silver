use std::collections::{BTreeMap, BTreeSet};

use silver_common::{
    merkle::bitlist_len,
    ssz_view::{ATTESTATION_PQ_FIXED, COMMITTEE_BITS_SIZE_PQ, bitvector_word, variable_list_items},
};

use super::{super::strategy::Committee, *};

const COMMITTEE_LEN: usize = 9;

/// Committee `index` voting `data` in `slot`. Position `p` is validator
/// `100 * index + p`.
fn group_of(data: u8, slot: Slot, index: usize, positions: &[usize]) -> Group {
    let mut bytes = [data; ATTESTATION_DATA_SIZE];
    bytes[..8].copy_from_slice(&slot.to_le_bytes());
    let member = |&position: &usize| {
        let validator = (100 * index + position) as u32;
        let mut claim = [slot as u8; 64];
        claim[0] = validator as u8;
        Member { position, validator, claim }
    };
    Group {
        committee: Committee { data: bytes, index },
        slot,
        committee_len: COMMITTEE_LEN,
        members: positions.iter().map(member).collect(),
    }
}

fn group(slot: Slot, index: usize, positions: &[usize]) -> Group {
    group_of(1, slot, index, positions)
}

fn proved(groups: impl IntoIterator<Item = Group>, proof: &[u8]) -> Proved {
    let groups = united(groups);
    let claims = claims_of(&groups);
    Proved { groups, claims, proof: proof.to_vec() }
}

fn answer(groups: &[Group], proof: &[u8]) -> Vec<u8> {
    AggregateResponse::encode(&claims_of(groups), proof)
}

fn votes(attestation: &[u8]) -> Vec<usize> {
    let bits = AttestationPqView::aggregation_bits(attestation);
    (0..bitlist_len(bits)).filter(|p| bits[p / 8] >> (p % 8) & 1 == 1).collect()
}

/// Slots 10 and 11 rolled into one proof.
fn rolled() -> Rolling {
    let mut rolling = Rolling::default();
    rolling.start_with(10, proved([group(10, 0, &[1, 2]), group(10, 1, &[3])], b"ten"));
    let taken = proved([group(11, 0, &[4])], b"eleven");
    let request = rolling.roll_request(&taken.claims, &taken.proof).unwrap();
    assert_eq!(request.proofs.len(), 2);
    assert!(request.output.is_none(), "a roll proves every claim of both");
    let all = [group(10, 0, &[1, 2]), group(10, 1, &[3]), group(11, 0, &[4])];
    rolling.finish(RollingJob::Roll { slot: 11, taken }, Some(&answer(&all, b"both"))).unwrap();
    rolling
}

#[test]
fn groups_of_one_data_become_one_attestation_in_committee_order() {
    let groups = [
        group_of(1, 5, 2, &[0, 8]),
        group_of(1, 5, 0, &[1]),
        group_of(2, 5, 0, &[4]),
        group_of(1, 5, 2, &[3, 8]),
    ];
    let attestations = proved(groups, b"proof").on_chain().encoded();

    let [first, second] = &attestations[..] else { panic!("one attestation per data") };
    assert_eq!(AttestationPqView::data(first).as_bytes()[8..], [1; ATTESTATION_DATA_SIZE - 8]);
    assert_eq!(bitvector_word(AttestationPqView::committee_bits(first)), 0b101);
    assert_eq!(bitlist_len(AttestationPqView::aggregation_bits(first)), 2 * COMMITTEE_LEN);
    let committee_2 = COMMITTEE_LEN;
    assert_eq!(votes(first), [1, committee_2, committee_2 + 3, committee_2 + 8]);
    assert!(AttestationPqView::check_canonical(first));

    assert_eq!(votes(second), [4]);
    assert!(AttestationPqView::check_canonical(second));
}

#[test]
fn a_block_gets_the_newest_proof_old_enough_to_include() {
    let rolling = rolled();
    assert!(!rolling.awaits(11) && rolling.awaits(12));
    assert!(rolling.block_proof(11).is_none(), "slot 10 is too new for block 11");

    let (attestations, proof) = rolling.block_proof(12).unwrap();
    assert_eq!((attestations.len(), proof), (1, &b"ten"[..]), "slot 11 is too new for block 12");

    let (attestations, proof) = rolling.block_proof(13).unwrap();
    assert_eq!((attestations.len(), proof), (2, &b"both"[..]));
}

#[test]
fn votes_a_block_included_are_proved_out() {
    let mut rolling = rolled();
    assert!(rolling.next_reduction().is_none(), "nothing to leave out");

    rolling.include_on_chain(10, &[1, 103]);
    rolling.include_on_chain(11, &[1]);
    let kept = rolling.next_reduction().unwrap();
    assert_eq!(kept, [group(10, 0, &[2]), group(11, 0, &[4])], "validator 1 voted in slot 10");

    let claims = claims_of(&kept);
    let request = rolling.reduce_request(&claims).unwrap();
    assert_eq!((request.proofs.len(), request.output), (1, Some(&claims[..])));
    let reduce = RollingJob::Reduce { groups: kept.clone(), claims: claims_of(&kept) };
    rolling.finish(reduce, Some(&answer(&kept, b"less"))).unwrap();
    assert!(rolling.next_reduction().is_none());
    assert_eq!(rolling.block_proof(13).unwrap().1, b"less");
}

#[test]
fn votes_too_old_are_proved_out_and_an_empty_proof_is_dropped() {
    let mut rolling = rolled();
    rolling.expire_before(11);
    assert_eq!(rolling.next_reduction().unwrap(), [group(11, 0, &[4])]);
    assert!(!rolling.awaits(10), "an expired slot is not taken in");

    rolling.expire_before(12);
    assert!(rolling.next_reduction().is_none(), "nothing is left to prove");
    assert!(rolling.current.is_none());
}

#[test]
fn a_refused_or_wrong_answer_keeps_the_proof() {
    let mut rolling = rolled();
    let taken = proved([group(12, 0, &[5])], b"twelve");
    let roll = RollingJob::Roll { slot: 12, taken };
    let wrong = answer(&[group(12, 0, &[5])], b"wrong");
    assert_eq!(rolling.finish(roll, Some(&wrong)), Err("the proof covers other claims"));
    assert_eq!(rolling.block_proof(13).unwrap().1, b"both");
    assert!(!rolling.awaits(12), "the lost slot is not tried again");

    let groups = vec![group(11, 0, &[4])];
    let reduce = RollingJob::Reduce { claims: claims_of(&groups), groups };
    assert_eq!(rolling.finish(reduce, None), Err("no answer"));
    assert_eq!(rolling.block_proof(13).unwrap().1, b"both");
}

#[test]
fn failed_reduction_waits_for_the_next_change() {
    let mut rolling = rolled();
    rolling.include_on_chain(10, &[1]);
    let groups = rolling.next_reduction().unwrap();
    let reduce = RollingJob::Reduce { claims: claims_of(&groups), groups };
    assert_eq!(rolling.finish(reduce, None), Err("no answer"));
    assert!(rolling.next_reduction().is_none(), "no retry until the pool changes");

    rolling.include_on_chain(11, &[104]);
    assert!(rolling.next_reduction().is_some());
}

/// Spec `compute_on_chain_aggregate` written plainly: group by data in
/// first-seen order, unite each committee's positions, encode bit by bit.
fn reference(groups: &[&Group]) -> Vec<Vec<u8>> {
    type Committees = BTreeMap<usize, (usize, BTreeSet<usize>)>;
    let mut by_data: Vec<(&[u8; ATTESTATION_DATA_SIZE], Committees)> = Vec::new();
    for group in groups {
        let data = &group.committee.data;
        if !by_data.iter().any(|(held, _)| *held == data) {
            by_data.push((data, BTreeMap::new()));
        }
        let (_, committees) = by_data.iter_mut().find(|(held, _)| *held == data).unwrap();
        let (_, positions) = (committees.entry(group.committee.index))
            .or_insert((group.committee_len, BTreeSet::new()));
        positions.extend(group.members.iter().map(|member| member.position));
    }
    let encode = |(data, committees): &(&[u8; ATTESTATION_DATA_SIZE], Committees)| {
        let mut out = (ATTESTATION_PQ_FIXED as u32).to_le_bytes().to_vec();
        out.extend_from_slice(*data);
        let committee_bits = committees.keys().fold(0u64, |bits, &index| bits | 1 << index);
        out.extend_from_slice(&committee_bits.to_le_bytes()[..COMMITTEE_BITS_SIZE_PQ]);
        let total: usize = committees.values().map(|(len, _)| len).sum();
        let mut bits = vec![0u8; total / 8 + 1];
        let mut offset = 0;
        for (len, positions) in committees.values() {
            for p in positions {
                bits[(offset + p) / 8] |= 1 << ((offset + p) % 8);
            }
            offset += len;
        }
        bits[total / 8] |= 1 << (total % 8);
        out.extend_from_slice(&bits);
        out
    };
    by_data.iter().map(encode).collect()
}

#[test]
fn on_chain_attestations_match_the_plain_reference() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % bound as u64) as usize
    };
    for _ in 0..300 {
        let committee_len = |data: u8, index: usize| 1 + (data as usize * 31 + index * 7) % 40;
        let groups: Vec<_> = (0..1 + next(12))
            .map(|_| {
                let (data, index) = (next(3) as u8, next(MAX_COMMITTEES_PER_SLOT_PQ));
                let len = committee_len(data, index);
                let mut positions: Vec<_> = (0..1 + next(4)).map(|_| next(len)).collect();
                positions.sort_unstable();
                positions.dedup();
                Group { committee_len: len, ..group_of(data, 5, index, &positions) }
            })
            .collect();
        let covered: Vec<_> = (0..groups.len()).filter(|_| next(4) != 0).collect();
        if covered.is_empty() {
            continue;
        }
        let on_chain = OnChainAttestations { groups: &groups, covered: Some(&covered) };
        let expected = reference(&covered.iter().map(|&index| &groups[index]).collect::<Vec<_>>());

        let mut list = vec![0xaa];
        on_chain.write_list(&mut list).unwrap();
        let written: Vec<_> = variable_list_items(&list[1..]).collect();
        assert_eq!(on_chain.len(), expected.len());
        assert_eq!(written, expected.iter().map(Vec::as_slice).collect::<Vec<_>>());
        assert!(written.iter().all(|attestation| AttestationPqView::check_canonical(attestation)));
    }
}

#[test]
fn a_committee_whose_groups_disagree_on_its_size_writes_no_list() {
    let groups = [group(5, 3, &[0]), Group { committee_len: 10, ..group(5, 3, &[1]) }];
    let on_chain = OnChainAttestations { groups: &groups, covered: None };
    assert!(on_chain.write_list(&mut Vec::new()).is_none());
}

#[test]
fn a_union_holds_every_claim_of_both_and_no_other() {
    let claims = |tags: &[u8]| tags.iter().map(|&tag| [tag; 64]).collect::<Vec<_>>();
    let union = |of: &[u8], a: &[u8], b: &[u8]| is_union(&claims(of), &claims(a), &claims(b));
    assert!(union(&[1, 2, 3, 4], &[1, 3], &[2, 3, 4]));
    assert!(union(&[1, 2], &[1, 2], &[]));
    assert!(!union(&[1, 2], &[1, 3], &[2]), "misses 3");
    assert!(!union(&[1, 2, 3], &[1], &[2]), "adds 3");
}

#[test]
fn reductions_are_looked_for_only_after_votes_go_on_chain_or_grow_old() {
    let mut rolling = rolled();
    assert!(rolling.next_reduction().is_none());
    assert!(!rolling.stale, "nothing changed since");

    rolling.include_on_chain(10, &[999]);
    assert!(rolling.stale);
    assert!(rolling.next_reduction().is_none(), "validator 999 is not in the proof");
    assert!(!rolling.stale);

    rolling.expire_before(rolling.floor);
    assert!(!rolling.stale, "the floor did not move");
    rolling.expire_before(11);
    assert!(rolling.next_reduction().is_some());
    assert!(rolling.stale, "kept until the reduction lands");
}
