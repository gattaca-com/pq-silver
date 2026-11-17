use flux_profiler::timed;

use super::{ExecutionRequestsPqView, attestation::attestation_proof_root};
use crate::{
    merkle::{B256, FixedContainer, ZERO_HASH, hash_fixed_bytes, hash_variable_list},
    progressive::{ProgressiveContainer, ProgressiveHasher, active_fields},
    ssz_hash::hash_eth1_data_bytes,
    ssz_view::{
        AttestationPqView, AttesterSlashingPqView, BeaconBlockBodyPqView, DepositView,
        ProposerSlashingPqView, SignedExecutionPayloadBidPqView,
    },
};

impl ProgressiveContainer for BeaconBlockBodyPqView {
    const ACTIVE_FIELDS: B256 = active_fields(14, &[7, 8, 9, 11]);
}

impl BeaconBlockBodyPqView {
    #[timed]
    pub fn hash_tree_root(body: &[u8]) -> B256 {
        if !Self::check_canonical(body) {
            return ZERO_HASH;
        }
        Self::progressive_root(&[
            hash_fixed_bytes(Self::randao_reveal(body)),
            hash_eth1_data_bytes(Self::eth1_data(body)),
            *Self::graffiti(body),
            ProposerSlashingPqView::hash_list(
                ProgressiveHasher::new(),
                Self::proposer_slashings(body),
            ),
            hash_variable_list(
                ProgressiveHasher::new(),
                Self::attester_slashings(body),
                AttesterSlashingPqView::root_of_canonical,
            ),
            hash_variable_list(
                ProgressiveHasher::new(),
                Self::attestations(body),
                AttestationPqView::root_of_canonical,
            ),
            DepositView::hash_list(ProgressiveHasher::new(), Self::deposits(body)),
            ZERO_HASH,
            ZERO_HASH,
            ZERO_HASH,
            SignedExecutionPayloadBidPqView::hash_tree_root(Self::signed_execution_payload_bid(
                body,
            )),
            ZERO_HASH,
            ExecutionRequestsPqView::hash_tree_root(Self::parent_execution_requests(body)),
            attestation_proof_root(Self::proof(body)),
        ])
    }
}
