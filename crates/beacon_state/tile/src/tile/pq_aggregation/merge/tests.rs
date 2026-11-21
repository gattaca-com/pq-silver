use silver_common::merkle::bitlist_len;

use super::*;

fn aggregate(data: u8, committee: usize, len: usize, positions: &[usize]) -> Vec<u8> {
    let data = [data; ATTESTATION_DATA_SIZE];
    let positions = positions.iter().copied();
    AttestationPqView::encode_one_committee(&data, committee, len, positions).unwrap()
}

fn votes(attestation: &[u8]) -> Vec<usize> {
    let bits = AttestationPqView::aggregation_bits(attestation);
    (0..bitlist_len(bits)).filter(|p| bits[p / 8] >> (p % 8) & 1 == 1).collect()
}

#[test]
fn aggregates_of_one_data_become_one_attestation_in_committee_order() {
    let aggregates = [
        aggregate(1, 2, 9, &[0, 8]),
        aggregate(1, 0, 5, &[1]),
        aggregate(2, 0, 5, &[4]),
        aggregate(1, 2, 9, &[3, 8]),
    ];
    let on_chain = on_chain_aggregates(aggregates.iter().map(Vec::as_slice));

    let [first, second] = &on_chain[..] else { panic!("one attestation per data") };
    assert_eq!(AttestationPqView::data(first).as_bytes(), &[1; ATTESTATION_DATA_SIZE]);
    assert_eq!(AttestationPqView::committee_bits(first), &[0b101, 0]);
    assert_eq!(bitlist_len(AttestationPqView::aggregation_bits(first)), 5 + 9);
    assert_eq!(votes(first), [1, 5, 5 + 3, 5 + 8], "committee 0, then the union of committee 2");
    assert!(AttestationPqView::check_canonical(first));

    assert_eq!(second, &aggregates[2], "a lone aggregate is unchanged");
}
