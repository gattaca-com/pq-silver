use silver_common::ssz_view::{SINGLE_ATT_PQ_SIZE, XMSS_SIGNATURE_SIZE};

use super::{
    super::{claims::Claim, wire::aggregate_response},
    *,
};

const SINGLE: [u8; SINGLE_ATT_PQ_SIZE] = [0; SINGLE_ATT_PQ_SIZE];

fn verified(tag: u8) -> VerifiedVote<'static> {
    VerifiedVote {
        single: &SINGLE,
        data_root: [9; 32],
        message: [1; 32],
        pubkey: [tag; 32],
        committee_position: tag as usize,
        committee_len: 8,
    }
}

fn claim(tag: u8) -> Claim {
    Vote::new(0, [tag; 32], [1; 32], &[0; XMSS_SIGNATURE_SIZE]).claim
}

#[test]
fn the_attestation_marks_the_covered_positions() {
    let mut leaf = LeafAggregation::new(&verified(0), Nanos::MAX);
    (0..3).for_each(|tag| assert!(leaf.add(&verified(tag))));
    assert!(leaf.attestation(0).is_none(), "no proof yet");
    let batch = leaf.core.next_batch(Nanos::ZERO).unwrap();
    let claims: Vec<Claim> = (0..3).map(claim).collect();
    leaf.core.finish(batch, Some(&aggregate_response(&claims, b"proof"))).unwrap();
    let ssz = leaf.attestation(0).unwrap();
    assert!(AttestationPqView::check_canonical(&ssz));
    assert_eq!(AttestationPqView::aggregation_bits(&ssz), [0b0000_0111, 1]);
}
