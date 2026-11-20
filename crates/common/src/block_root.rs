use silver_common::{
    merkle::{B256, merkleize, uint64_chunk},
    ssz_hash::hash_tree_root_body_fulu,
    ssz_view::{
        BeaconBlockBodyGloasView, BeaconBlockBodyPqView, SignedBeaconBlockPqView,
        SignedBeaconBlockView,
    },
};

/// SSZ `body_root` of a `BeaconBlockBody` given its raw SSZ bytes.
/// Returns `[0u8; 32]` if `body.len()` is below the post-Electra fixed
/// prefix size — mirrors the spec-compliant fallback in
/// `silver_common::ssz_hash::hash_tree_root_body_fulu`.
pub fn body_root(body: &[u8]) -> B256 {
    hash_tree_root_body_fulu(body)
}

/// SSZ `block_root` of a `BeaconBlockHeader` derived from a
/// `SignedBeaconBlock` buffer. Identical to `hash_tree_root` of the inner
/// `BeaconBlock`: both merkleize the same five leaves once the body is
/// replaced by `body_root`. This is the value used as
/// `DataColumnsByRootIdentifier.block_root` in DA RPC requests.
pub fn block_root_fulu(signed_block: &[u8]) -> B256 {
    block_root_from_body(
        signed_block,
        hash_tree_root_body_fulu(SignedBeaconBlockView::body(signed_block)),
    )
}

pub fn block_root_gloas(signed_block: &[u8]) -> B256 {
    block_root_from_body(
        signed_block,
        BeaconBlockBodyGloasView::hash_tree_root(SignedBeaconBlockView::body(signed_block)),
    )
}

pub fn block_root_pq(signed_block: &[u8]) -> B256 {
    header_root(
        SignedBeaconBlockPqView::slot(signed_block),
        SignedBeaconBlockPqView::proposer_index(signed_block),
        SignedBeaconBlockPqView::parent_root(signed_block),
        SignedBeaconBlockPqView::state_root(signed_block),
        BeaconBlockBodyPqView::hash_tree_root(SignedBeaconBlockPqView::body(signed_block)),
    )
}

pub fn block_root(signed_block: &[u8], is_gloas: bool) -> B256 {
    if is_gloas { block_root_gloas(signed_block) } else { block_root_fulu(signed_block) }
}

fn block_root_from_body(signed_block: &[u8], body_root: B256) -> B256 {
    header_root(
        SignedBeaconBlockView::slot(signed_block),
        SignedBeaconBlockView::proposer_index(signed_block),
        SignedBeaconBlockView::parent_root(signed_block),
        SignedBeaconBlockView::state_root(signed_block),
        body_root,
    )
}

fn header_root(
    slot: u64,
    proposer_index: u64,
    parent_root: &B256,
    state_root: &B256,
    body_root: B256,
) -> B256 {
    merkleize(&[
        uint64_chunk(slot),
        uint64_chunk(proposer_index),
        *parent_root,
        *state_root,
        body_root,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_root_too_short_returns_zero_hash() {
        // Less than the 396-byte fixed prefix → zero root.
        assert_eq!(body_root(&[0u8; 100]), [0u8; 32]);
    }

    #[test]
    fn body_root_is_deterministic() {
        let body = [0u8; 396];
        assert_eq!(body_root(&body), body_root(&body));
    }
}
