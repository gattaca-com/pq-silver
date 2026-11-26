use silver_common::ssz_view::{ATTESTATION_DATA_SIZE, AttestationPqView, MAX_STARK_PROOF_SIZE};

use super::{
    super::{
        bits::Bits, proof_sources::ProofSources, proof_store::ProofStore, test_util::attestation_in,
    },
    *,
};

const SLOT: Slot = 9;

fn claims(tags: &[u8]) -> Vec<Claim> {
    tags.iter().map(|&tag| [tag; 64]).collect()
}

#[test]
fn an_aggregate_reads_its_group_from_its_attestation() {
    let ssz = attestation_in(SLOT, 3, [1, 5, 2047]);
    let mut sources = ProofSources::default();
    let mut proofs = ProofStore::default();
    sources.add_aggregate(&ssz, &[70, 80, 90], &claims(&[9, 8, 7]), b"proof", &mut proofs).unwrap();
    let aggregate = sources.slot(SLOT).unwrap().aggregates.indexed().next().unwrap().1;
    assert_eq!(proofs.claims(aggregate.proof), claims(&[7, 8, 9]), "sorted for leanVM");
    let group = &aggregate.group;
    assert_eq!(group.committee.slot(), SLOT);
    assert_eq!(group.committee.index, 3);
    assert_eq!(group.committee.data, AttestationPqView::data(&ssz).as_bytes()[..]);
    assert_eq!(group.positions, [1, 5, 2047].into_iter().collect::<Bits>());
    let records: Vec<_> = group.records(&proofs, aggregate.proof).collect();
    assert_eq!(records, [(1, 70, &[9; 64]), (5, 80, &[8; 64]), (2047, 90, &[7; 64])]);
    assert_eq!(group.committee_len, 2048);
}

#[test]
fn an_aggregate_with_inconsistent_voters_is_refused() {
    let new = |tags: &[u8], ssz: Vec<u8>| {
        let attesters: Vec<u32> = (0..tags.len() as u32).collect();
        ProofSources::default().add_aggregate(
            &ssz,
            &attesters,
            &claims(tags),
            b"proof",
            &mut ProofStore::default(),
        )
    };
    let attestation = |positions: &[usize]| attestation_in(SLOT, 0, positions.iter().copied());
    assert!(new(&[1, 2], attestation(&[0])).is_err(), "fewer positions than claims");
    assert!(new(&[1], attestation(&[0, 1])).is_err(), "more positions than claims");
    assert!(new(&[1, 1], attestation(&[0, 1])).is_err(), "two voters with one claim");
    assert!(new(&[], attestation(&[])).is_err(), "no claims");
    assert!(new(&[1], vec![7]).is_err(), "not canonical");
    let one_attester = ProofSources::default().add_aggregate(
        &attestation(&[0, 1]),
        &[4],
        &claims(&[1, 2]),
        &[],
        &mut ProofStore::default(),
    );
    assert!(one_attester.is_err(), "fewer attesters than claims");

    let mut two_committees = attestation(&[0]);
    two_committees[4 + ATTESTATION_DATA_SIZE] |= 0b10;
    assert!(new(&[1], two_committees).is_err(), "two committees");

    let mut too_long = attestation(&[0]);
    let sentinel = too_long.len() - 1;
    too_long[sentinel] = 0b10;
    assert!(new(&[1], too_long).is_err(), "a committee above the largest");
}

#[test]
fn an_aggregate_with_an_oversized_proof_is_refused() {
    let attestation = attestation_in(SLOT, 0, [0]);
    let aggregate_with = |proof_len| {
        ProofSources::default().add_aggregate(
            &attestation,
            &[0],
            &claims(&[1]),
            &vec![0; proof_len],
            &mut ProofStore::default(),
        )
    };
    assert!(aggregate_with(MAX_STARK_PROOF_SIZE).is_ok());
    assert!(aggregate_with(MAX_STARK_PROOF_SIZE + 1).is_err());
}
