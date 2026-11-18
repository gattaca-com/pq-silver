use silver_beacon_state_data::StateView;
use silver_common::progressive::{ProgressiveContainer, active_fields};

use crate::{merkle::B256, ssz_hash::hash_common_fields, ssz_hash_gloas::gloas_fields};

/// The PQ `BeaconState`: Gloas less its sync committees and the EIP-8483
/// registrations, plus the two preregistration lists.
pub(crate) enum BeaconStatePq {}

impl ProgressiveContainer for BeaconStatePq {
    const ACTIVE_FIELDS: B256 = active_fields(50, &[22, 23, 46, 47]);
}

impl BeaconStatePq {
    pub(crate) fn hash_tree_root(rv: &StateView) -> B256 {
        let slot = rv.slot.state();
        let common = hash_common_fields(rv, slot.latest_block_hash);

        // `common[22..24]` are the removed sync committees.
        let mut roots = [B256::default(); 46];
        roots[..22].copy_from_slice(&common[..22]);
        roots[22..36].copy_from_slice(&common[24..]);
        roots[36..44].copy_from_slice(&gloas_fields(rv));
        roots[44] = rv.preregistrations.validators_root();
        roots[45] = rv.preregistrations.builders_root();
        Self::root_of_active_fields(&roots)
    }
}
