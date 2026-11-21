use silver_common::{merkle::bitlist_len, ssz_view::ATTESTATION_DATA_SIZE};

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
    let request = rolling.roll_request(&taken).unwrap();
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
    let attestations = proved(groups, b"proof").attestations();

    let [first, second] = &attestations[..] else { panic!("one attestation per data") };
    assert_eq!(AttestationPqView::data(first).as_bytes()[8..], [1; ATTESTATION_DATA_SIZE - 8]);
    assert_eq!(AttestationPqView::committee_bits(first), &[0b101, 0]);
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
    let reduce = RollingJob::Reduce { groups: kept.clone() };
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

    let reduce = RollingJob::Reduce { groups: vec![group(11, 0, &[4])] };
    assert_eq!(rolling.finish(reduce, None), Err("no answer"));
    assert_eq!(rolling.block_proof(13).unwrap().1, b"both");
}
