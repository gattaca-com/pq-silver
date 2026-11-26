use super::super::test_util::{FakeProof, Lane, SLOT, aggregate_of};

#[test]
fn stored_proof_bytes_match_the_response_body() {
    let mut lane = Lane::new(1);
    let mut fixture = aggregate_of(SLOT, 0, 1, 1..4);
    fixture.claims.reverse();
    lane.add_aggregate(fixture);
    let entry = lane.sources.slot(SLOT).unwrap().aggregates.indexed().next().unwrap().1;
    let id = entry.proof;
    let response = FakeProof::new(lane.proofs.claims(id), b"proof");
    assert_eq!(lane.proofs.bytes(id), response.bytes);
}
