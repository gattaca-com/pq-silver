use silver_crypto_simd::xmss::{BottomTree, SecretKey};
use silver_ssz::{
    ssz_hash::compute_signing_root,
    ssz_view::{
        EXECUTION_PAYLOAD_BID_MIN, ExecutionPayloadBidView, PROPOSER_PREFERENCES_SIZE,
        SIGNED_PQ_FIXED, SIGNED_PROPOSER_PREFERENCES_PQ_SIZE, XMSSSignature,
    },
};

use super::{FIRST_SLOT_LEAF, LeafOffset, SignatureCheck, compute_xmss_leaf_index};
use crate::types::B256;

const DOMAIN: B256 = [3; 32];

/// Signs at the leaves around `FIRST_SLOT_LEAF`, which share one bottom tree.
struct Signer {
    key: SecretKey,
    bottom: BottomTree,
}

impl Signer {
    fn new() -> Self {
        let key = SecretKey::new(&[7; 32]);
        let bottom = key.bottom_tree((FIRST_SLOT_LEAF >> 16) as u32);
        Self { key, bottom }
    }

    fn sign(&self, signing_root: &B256, leaf_index: u64) -> XMSSSignature {
        self.key.sign(&self.bottom, signing_root, leaf_index as u32)
    }
}

#[test]
fn signature_at_another_message_types_leaf_is_rejected() {
    let signer = Signer::new();
    let pubkey = signer.key.public_key();
    let unsigned = [0u8; SIGNED_PROPOSER_PREFERENCES_PQ_SIZE];
    let signing_root =
        SignatureCheck::proposer_preferences(&unsigned, &pubkey, &DOMAIN).signing_root;

    let signed_at = |leaf_offset| {
        let mut signed = unsigned;
        signed[PROPOSER_PREFERENCES_SIZE..]
            .copy_from_slice(&signer.sign(&signing_root, compute_xmss_leaf_index(0, leaf_offset)));
        signed
    };
    let at_own_leaf = signed_at(LeafOffset::ProposerPreferences);
    let at_ptc_leaf = signed_at(LeafOffset::PtcAttester);

    let checks = [&at_own_leaf, &at_ptc_leaf]
        .map(|signed| SignatureCheck::proposer_preferences(signed, &pubkey, &DOMAIN));
    let mut valid = [false; 2];
    SignatureCheck::verify_batch(&checks, &mut valid);
    assert_eq!(valid, [true, false]);
    assert_eq!(checks.map(|check| check.verify()), valid);
}

#[test]
fn bid_verifies_only_at_a_bid_leaf() {
    let signer = Signer::new();
    let pubkey = signer.key.public_key();
    let mut signed_bid = vec![0u8; SIGNED_PQ_FIXED + EXECUTION_PAYLOAD_BID_MIN];
    signed_bid[..4].copy_from_slice(&(SIGNED_PQ_FIXED as u32).to_le_bytes());
    signed_bid[SIGNED_PQ_FIXED + 188..][..4]
        .copy_from_slice(&(EXECUTION_PAYLOAD_BID_MIN as u32).to_le_bytes());
    let signing_root = compute_signing_root(
        &ExecutionPayloadBidView::hash_tree_root(&signed_bid[SIGNED_PQ_FIXED..]),
        &DOMAIN,
    );

    let last_bid_leaf = FIRST_SLOT_LEAF - 1;
    signed_bid[4..SIGNED_PQ_FIXED].copy_from_slice(&signer.sign(&signing_root, last_bid_leaf));
    let check = SignatureCheck::execution_payload_bid(&signed_bid, &pubkey, &DOMAIN).unwrap();
    assert!(check.verify());

    let proposer_leaf = compute_xmss_leaf_index(0, LeafOffset::BeaconProposer);
    signed_bid[4..SIGNED_PQ_FIXED].copy_from_slice(&signer.sign(&signing_root, proposer_leaf));
    assert!(SignatureCheck::execution_payload_bid(&signed_bid, &pubkey, &DOMAIN).is_none());
}
