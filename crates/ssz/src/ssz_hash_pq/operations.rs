use flux_profiler::timed;

use crate::{
    merkle::{B256, FixedContainer, hash_concat},
    ssz_hash::hash_signed_beacon_block_header,
    ssz_view::{
        PROPOSER_SLASHING_PQ_SIZE, ProposerSlashingPqView, SIGNED_BEACON_BLOCK_HEADER_PQ_SIZE,
    },
};

impl FixedContainer for ProposerSlashingPqView {
    const SSZ_SIZE: usize = PROPOSER_SLASHING_PQ_SIZE;

    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let (header_1, header_2) = bytes.split_at(SIGNED_BEACON_BLOCK_HEADER_PQ_SIZE);
        hash_concat(
            &hash_signed_beacon_block_header(header_1),
            &hash_signed_beacon_block_header(header_2),
        )
    }
}
