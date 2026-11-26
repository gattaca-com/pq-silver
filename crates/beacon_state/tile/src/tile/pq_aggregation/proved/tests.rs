use silver_common::{
    merkle::bitlist_len,
    ssz_view::{ATTESTATION_DATA_SIZE, bitvector_word},
};

use super::{
    super::test_util::{COMMITTEE_LEN, group_of, running_of},
    *,
};

fn votes(attestation: &[u8]) -> Vec<usize> {
    let bits = AttestationPqView::aggregation_bits(attestation);
    (0..bitlist_len(bits)).filter(|p| bits[p / 8] >> (p % 8) & 1 == 1).collect()
}

#[test]
fn groups_of_one_data_become_one_attestation_in_committee_order() {
    let groups = [
        group_of(1, 5, 2, &[0, 8]),
        group_of(1, 5, 0, &[1]),
        group_of(2, 5, 0, &[4]),
        group_of(1, 5, 2, &[3, 8]),
    ];
    let (running, _) = running_of(&groups, b"proof");
    let attestations = on_chain_attestations(running.groups());

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
