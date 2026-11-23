use silver_common::ssz_view::ATTESTATION_DATA_SIZE;

use super::{
    super::{strategy::Bits, test_util::attestation},
    *,
};

fn claims(tags: &[u8]) -> Vec<Claim> {
    tags.iter().map(|&tag| [tag; 64]).collect()
}

#[test]
fn an_aggregate_reads_its_positions_from_its_attestation() {
    let ssz = attestation(3, [1, 5, 2047]);
    let mut claims = claims(&[9, 8, 7, 8]);
    let aggregate = Aggregate::new(&mut claims, b"proof", &ssz).unwrap();
    let positions = aggregate.positions;
    assert_eq!(positions.committee, Committee { data: [3; ATTESTATION_DATA_SIZE], index: 3 });
    assert_eq!(positions.bits.count(), 3, "a repeated claim counts once");
    assert_eq!(positions.bits, [1, 5, 2047].into_iter().collect::<Bits>());
}

#[test]
fn an_aggregate_with_inconsistent_positions_is_refused() {
    let new =
        |tags: &[u8], ssz: Vec<u8>| Aggregate::new(&mut claims(tags), b"proof", &ssz).is_some();
    assert!(!new(&[1, 2], attestation(0, [0])), "fewer positions than claims");
    assert!(!new(&[1], attestation(0, [0, 1])), "more positions than claims");
    assert!(!new(&[], attestation(0, [])), "no claims");
    assert!(!new(&[1], vec![7]), "not canonical");

    let mut two_committees = attestation(0, [0]);
    two_committees[4 + ATTESTATION_DATA_SIZE] |= 0b10;
    assert!(!new(&[1], two_committees), "two committees");

    let mut too_long = attestation(0, [0]);
    let sentinel = too_long.len() - 1;
    too_long[sentinel] = 0b10;
    assert!(!new(&[1], too_long), "a committee above the largest");
}
