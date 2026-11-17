use flux_profiler::timed;

use crate::{
    merkle::{B256, FixedContainer, hash_concat, hash_fixed_bytes},
    ssz_hash::hash_beacon_block_header_bytes,
    ssz_view::{
        BEACON_BLOCK_HEADER_SIZE, PROPOSER_SLASHING_PQ_SIZE, ProposerSlashingPqView, XMSSSignature,
    },
};

fn signed_header_root(header: &[u8; BEACON_BLOCK_HEADER_SIZE], signature: &XMSSSignature) -> B256 {
    hash_concat(&hash_beacon_block_header_bytes(header), &hash_fixed_bytes(signature))
}

impl FixedContainer for ProposerSlashingPqView {
    const SSZ_SIZE: usize = PROPOSER_SLASHING_PQ_SIZE;

    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let d: &[u8; PROPOSER_SLASHING_PQ_SIZE] = bytes.try_into().unwrap();
        hash_concat(
            &signed_header_root(Self::header_1(d), Self::signature_1(d)),
            &signed_header_root(Self::header_2(d), Self::signature_2(d)),
        )
    }
}
