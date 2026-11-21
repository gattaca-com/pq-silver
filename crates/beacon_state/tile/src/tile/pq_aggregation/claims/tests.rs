use silver_common::ssz_view::ATTESTATION_DATA_SIZE;

use super::{
    super::{strategy::Bits, test_util::attestation_in},
    *,
};

const SLOT: Slot = 9;

fn claims(tags: &[u8]) -> Vec<Claim> {
    tags.iter().map(|&tag| [tag; 64]).collect()
}

#[test]
fn an_aggregate_reads_its_group_from_its_attestation() {
    let ssz = attestation_in(SLOT, 3, [1, 5, 2047]);
    let aggregate =
        Aggregate::new(&ssz, &[70, 80, 90], claims(&[9, 8, 7]), b"proof".to_vec()).unwrap();
    assert_eq!(aggregate.claims, claims(&[7, 8, 9]), "sorted for the leanVM sidecar");

    let group = aggregate.group;
    assert_eq!(group.slot, SLOT);
    assert_eq!(group.committee.index, 3);
    assert_eq!(group.committee.data, AttestationPqView::data(&ssz).as_bytes()[..]);
    assert_eq!(group.positions().bits, [1, 5, 2047].into_iter().collect::<Bits>());
    let members: Vec<_> =
        group.members.iter().map(|member| (member.position, member.validator)).collect();
    assert_eq!(members, [(1, 70), (5, 80), (2047, 90)], "voters keep committee order");
    assert_eq!(group.members[0].claim, [9; 64]);
    assert_eq!(group.bitlist(), AttestationPqView::aggregation_bits(&ssz));
}

#[test]
fn an_aggregate_with_inconsistent_voters_is_refused() {
    let new = |tags: &[u8], ssz: Vec<u8>| {
        let attesters: Vec<u32> = (0..tags.len() as u32).collect();
        Aggregate::new(&ssz, &attesters, claims(tags), b"proof".to_vec())
    };
    let attestation = |positions: &[usize]| attestation_in(SLOT, 0, positions.iter().copied());
    assert!(new(&[1, 2], attestation(&[0])).is_none(), "fewer positions than claims");
    assert!(new(&[1], attestation(&[0, 1])).is_none(), "more positions than claims");
    assert!(new(&[1, 1], attestation(&[0, 1])).is_none(), "two voters with one claim");
    assert!(new(&[], attestation(&[])).is_none(), "no claims");
    assert!(new(&[1], vec![7]).is_none(), "not canonical");
    let one_attester = Aggregate::new(&attestation(&[0, 1]), &[4], claims(&[1, 2]), Vec::new());
    assert!(one_attester.is_none(), "fewer attesters than claims");

    let mut two_committees = attestation(&[0]);
    two_committees[4 + ATTESTATION_DATA_SIZE] |= 0b10;
    assert!(new(&[1], two_committees).is_none(), "two committees");

    let mut too_long = attestation(&[0]);
    let sentinel = too_long.len() - 1;
    too_long[sentinel] = 0b10;
    assert!(new(&[1], too_long).is_none(), "a committee above the largest");
}
