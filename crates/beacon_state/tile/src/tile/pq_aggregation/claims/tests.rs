use super::*;

fn attestation(committee_index: usize, positions: &[usize]) -> Vec<u8> {
    let data = [3; ATTESTATION_DATA_SIZE];
    let committee_len = MAX_VALIDATORS_PER_COMMITTEE;
    let positions = positions.iter().copied();
    AttestationPqView::encode_one_committee(&data, committee_index, committee_len, positions)
        .unwrap()
}

fn claims(tags: &[u8]) -> Vec<Claim> {
    tags.iter().map(|&tag| [tag; 64]).collect()
}

#[test]
fn an_aggregate_reads_its_positions_from_its_attestation() {
    let ssz = attestation(3, &[1, 5, 2047]);
    let aggregate = Aggregate::new(claims(&[9, 8, 7, 8]), b"proof".to_vec(), ssz).unwrap();
    let positions = aggregate.positions();
    assert_eq!(positions.committee, Committee { data: [3; ATTESTATION_DATA_SIZE], index: 3 });
    assert_eq!(positions.bits.count(), 3, "a repeated claim counts once");
    assert!([1, 5, 2047].iter().all(|&position| positions.bits.contains(position)));
}

#[test]
fn an_aggregate_with_inconsistent_positions_is_refused() {
    let new = |tags: &[u8], ssz: Vec<u8>| Aggregate::new(claims(tags), b"proof".to_vec(), ssz);
    assert!(new(&[1, 2], attestation(0, &[0])).is_none(), "fewer positions than claims");
    assert!(new(&[1], attestation(0, &[0, 1])).is_none(), "more positions than claims");
    assert!(new(&[], attestation(0, &[])).is_none(), "no claims");
    assert!(new(&[1], vec![7]).is_none(), "not canonical");

    let mut two_committees = attestation(0, &[0]);
    two_committees[4 + ATTESTATION_DATA_SIZE] |= 0b10;
    assert!(new(&[1], two_committees).is_none(), "two committees");

    let mut too_long = attestation(0, &[0]);
    let sentinel = too_long.len() - 1;
    too_long[sentinel] = 0b10;
    assert!(new(&[1], too_long).is_none(), "a committee above the largest");
}
