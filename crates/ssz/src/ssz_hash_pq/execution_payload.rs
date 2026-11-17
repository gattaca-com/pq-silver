use flux_profiler::timed;

use super::ExecutionRequestsPqView;
use crate::{
    merkle::{B256, ZERO_HASH, hash_fixed_bytes, merkleize, uint64_chunk},
    progressive::ProgressiveContainer,
    ssz_view::{
        ExecutionPayloadBidView, ExecutionPayloadEnvelopeView, ExecutionPayloadView,
        SignedExecutionPayloadBidPqView, SignedExecutionPayloadEnvelopePqView,
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
    /// The Gloas envelope over PQ `ExecutionRequests`.
    #[timed]
    pub fn hash_tree_root_pq(d: &[u8]) -> B256 {
        if !Self::check_size(d) {
            return ZERO_HASH;
        }
        Self::progressive_root(&[
            ExecutionPayloadView::hash_tree_root_gloas(Self::payload(d)),
            ExecutionRequestsPqView::hash_tree_root(Self::execution_requests(d)),
            uint64_chunk(Self::builder_index(d)),
            *Self::beacon_block_root(d),
            *Self::parent_beacon_block_root(d),
        ])
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
