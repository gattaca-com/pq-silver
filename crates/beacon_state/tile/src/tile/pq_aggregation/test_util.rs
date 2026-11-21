use silver_common::ssz_view::{
    ATTESTATION_DATA_SIZE, AttestationPqView, MAX_VALIDATORS_PER_COMMITTEE,
};

/// An `AttestationPq` of committee `index`, in the largest committee.
pub(in crate::tile) fn attestation(
    index: usize,
    positions: impl IntoIterator<Item = usize>,
) -> Vec<u8> {
    attestation_in(0x0303_0303_0303_0303, index, positions)
}

pub(in crate::tile) fn attestation_in(
    slot: u64,
    index: usize,
    positions: impl IntoIterator<Item = usize>,
) -> Vec<u8> {
    let mut data = [3; ATTESTATION_DATA_SIZE];
    data[..8].copy_from_slice(&slot.to_le_bytes());
    AttestationPqView::encode_one_committee(&data, index, MAX_VALIDATORS_PER_COMMITTEE, positions)
        .unwrap()
}
