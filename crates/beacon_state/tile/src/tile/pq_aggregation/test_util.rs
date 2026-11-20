use silver_common::ssz_view::{
    ATTESTATION_DATA_SIZE, AttestationPqView, MAX_VALIDATORS_PER_COMMITTEE,
};

/// An `AttestationPq` of committee `index`, in the largest committee.
pub(in crate::tile) fn attestation(
    index: usize,
    positions: impl IntoIterator<Item = usize>,
) -> Vec<u8> {
    let data = [3; ATTESTATION_DATA_SIZE];
    AttestationPqView::encode_one_committee(&data, index, MAX_VALIDATORS_PER_COMMITTEE, positions)
        .unwrap()
}
