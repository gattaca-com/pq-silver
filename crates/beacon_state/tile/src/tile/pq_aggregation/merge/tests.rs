use std::collections::{BTreeMap, BTreeSet};

use silver_common::{
    merkle::bitlist_len,
    ssz_view::{ATTESTATION_PQ_FIXED, variable_list_items},
};

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
    let covered: Vec<_> = (0..aggregates.len()).collect();
    let mut attestations = Arena::default();
    aggregates.iter().for_each(|aggregate| attestations.push(aggregate));
    let on_chain = OnChainAggregates { attestations: &attestations, covered: &covered };
    assert_eq!(on_chain.len(), 2, "one attestation per data");
    let mut list = Vec::new();
    on_chain.write_list(&mut list).unwrap();

    let [first, second] = &variable_list_items(&list).collect::<Vec<_>>()[..] else {
        panic!("one attestation per data")
    };
    assert_eq!(AttestationPqView::data(first).as_bytes(), &[1; ATTESTATION_DATA_SIZE]);
    assert_eq!(AttestationPqView::committee_bits(first), &[0b101, 0]);
    assert_eq!(bitlist_len(AttestationPqView::aggregation_bits(first)), 5 + 9);
    assert_eq!(votes(first), [1, 5, 5 + 3, 5 + 8], "committee 0, then the union of committee 2");
    assert!(AttestationPqView::check_canonical(first));

    assert_eq!(*second, aggregates[2], "a lone aggregate is unchanged");
}

/// Spec `compute_on_chain_aggregate` written plainly: group by data in
/// arrival order, unite each committee's positions, encode bit by bit.
fn reference(aggregates: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut groups: Vec<(&[u8], BTreeMap<usize, (usize, BTreeSet<usize>)>)> = Vec::new();
    for &aggregate in aggregates {
        let data = AttestationPqView::data(aggregate).as_bytes().as_slice();
        if !groups.iter().any(|(held, _)| *held == data) {
            groups.push((data, BTreeMap::new()));
        }
        let (_, committees) = groups.iter_mut().find(|(held, _)| *held == data).unwrap();
        let len = bitlist_len(AttestationPqView::aggregation_bits(aggregate));
        let (_, positions) =
            committees.entry(committee_of(aggregate)).or_insert((len, BTreeSet::new()));
        positions.extend(votes(aggregate));
    }
    let encode = |(data, committees): &(&[u8], BTreeMap<usize, (usize, BTreeSet<usize>)>)| {
        let mut out = (ATTESTATION_PQ_FIXED as u32).to_le_bytes().to_vec();
        out.extend_from_slice(data);
        let committee_bits = committees.keys().fold(0u16, |bits, &index| bits | 1 << index);
        out.extend_from_slice(&committee_bits.to_le_bytes());
        let total: usize = committees.values().map(|(len, _)| len).sum();
        let mut bits = vec![0u8; total / 8 + 1];
        let mut offset = 0;
        for (len, positions) in committees.values() {
            positions.iter().for_each(|p| bits[(offset + p) / 8] |= 1 << ((offset + p) % 8));
            offset += len;
        }
        bits[total / 8] |= 1 << (total % 8);
        out.extend_from_slice(&bits);
        out
    };
    groups.iter().map(encode).collect()
}

#[test]
fn write_list_matches_the_plain_reference() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % bound as u64) as usize
    };
    for _ in 0..300 {
        let committee_len =
            |data: u8, committee: usize| 1 + (data as usize * 31 + committee * 7) % 40;
        let aggregates: Vec<_> = (0..1 + next(12))
            .map(|_| {
                let (data, committee) = (next(3) as u8, next(MAX_COMMITTEES_PER_SLOT_PQ));
                let len = committee_len(data, committee);
                let positions: Vec<_> = (0..1 + next(4)).map(|_| next(len)).collect();
                aggregate(data, committee, len, &positions)
            })
            .collect();
        let covered: Vec<_> = (0..aggregates.len()).filter(|_| next(4) != 0).collect();
        if covered.is_empty() {
            continue;
        }
        let mut attestations = Arena::default();
        aggregates.iter().for_each(|aggregate| attestations.push(aggregate));
        let on_chain = OnChainAggregates { attestations: &attestations, covered: &covered };

        let mut list = vec![0xaa];
        on_chain.write_list(&mut list).unwrap();
        let written: Vec<_> = variable_list_items(&list[1..]).collect();
        let covered: Vec<_> = covered.iter().map(|&index| aggregates[index].as_slice()).collect();
        let expected = reference(&covered);
        assert_eq!(on_chain.len(), expected.len());
        assert_eq!(written, expected.iter().map(Vec::as_slice).collect::<Vec<_>>());
        assert!(written.iter().all(|attestation| AttestationPqView::check_canonical(attestation)));
    }
}

#[test]
fn committee_whose_aggregates_disagree_on_its_size_writes_no_list() {
    let aggregates = [aggregate(1, 3, 9, &[0]), aggregate(1, 3, 10, &[1])];
    let mut attestations = Arena::default();
    aggregates.iter().for_each(|aggregate| attestations.push(aggregate));
    let on_chain = OnChainAggregates { attestations: &attestations, covered: &[0, 1] };
    assert!(on_chain.write_list(&mut Vec::new()).is_none());
}
