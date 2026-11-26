use silver_beacon_state_data::Slot;
use silver_common::ssz_view::{AttestationPqView, MAX_ATTESTATIONS_PQ, MAX_COMMITTEES_PER_SLOT_PQ};

use super::{claims::MAX_GROUPS, running_proof::ProvedGroup};

/// Attestation slots a block proof may cover. A merge tells `MAX_GROUPS`
/// committees apart. Votes 2 to 5 slots old still earn the timely-source flag.
pub(super) const POOL_SLOTS: Slot = (MAX_GROUPS / MAX_COMMITTEES_PER_SLOT_PQ) as Slot;

/// The attestation data of one slot a block packs at most. Each slot a
/// block may include keeps its share of `MAX_ATTESTATIONS_PQ`.
pub(super) const DATA_PER_SLOT: usize = MAX_ATTESTATIONS_PQ / POOL_SLOTS as usize;

/// Spec `compute_on_chain_aggregate`, per attestation data: its committees in
/// index order. `groups` holds one group per committee and data.
pub(super) fn on_chain_attestations<'a>(
    groups: impl Iterator<Item = &'a ProvedGroup> + Clone,
) -> Vec<Vec<u8>> {
    let mut data_order: Vec<&ProvedGroup> = Vec::new();
    for group in groups.clone() {
        if !data_order.iter().any(|first| first.committee.data == group.committee.data) {
            data_order.push(group);
        }
    }
    let attestation = |first: &&ProvedGroup| {
        let data = &first.committee.data;
        let mut committees: Vec<_> = groups
            .clone()
            .filter(|group| group.committee.data == *data)
            .map(|group| (group.committee.index, group.bitlist()))
            .collect();
        committees.sort_unstable_by_key(|(index, _)| *index);
        let committees = committees.iter().map(|(index, votes)| (*index, votes.as_slice()));
        AttestationPqView::encode_committees(data, committees)
            .expect("committees of one data ascend in range")
    };
    data_order.iter().map(attestation).collect()
}

#[cfg(test)]
mod tests;
