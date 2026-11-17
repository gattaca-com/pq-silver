use flux_profiler::timed;

use super::ExecutionRequestsPqView;
use crate::{
    merkle::{B256, ZERO_HASH, hash_fixed_bytes, merkleize},
    ssz_view::{
        ExecutionPayloadBidView, ExecutionPayloadEnvelopeView, SignedExecutionPayloadBidPqView,
        SignedExecutionPayloadEnvelopePqView,
    },
};

impl SignedExecutionPayloadBidPqView {
    #[timed]
    pub fn hash_tree_root(d: &[u8]) -> B256 {
        if !Self::check_size(d) {
            return ZERO_HASH;
        }
        merkleize(&[
            ExecutionPayloadBidView::hash_tree_root(Self::message(d)),
            hash_fixed_bytes(Self::signature(d)),
        ])
    }
}

impl ExecutionPayloadEnvelopeView {
    #[timed]
    pub fn hash_tree_root_pq(d: &[u8]) -> B256 {
        Self::hash_tree_root_with(d, ExecutionRequestsPqView::hash_tree_root)
    }
}

impl SignedExecutionPayloadEnvelopePqView {
    #[timed]
    pub fn hash_tree_root(d: &[u8]) -> B256 {
        if !Self::check_size(d) {
            return ZERO_HASH;
        }
        merkleize(&[
            ExecutionPayloadEnvelopeView::hash_tree_root_pq(Self::message(d)),
            hash_fixed_bytes(Self::signature(d)),
        ])
    }
}
