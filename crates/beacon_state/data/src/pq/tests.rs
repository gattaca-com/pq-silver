use silver_ssz::ssz_view::{VRF_PROOF_SIZE, VRF_TREE_DEPTH};

use super::*;

/// A BLS key's first byte has its compression flag set.
fn legacy_key() -> BLSPubkey {
    let mut key = [0x11; 48];
    key[0] = 0xa5;
    key
}

fn b256(hex: &str) -> B256 {
    hex::decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn requests_name_xmss_keys_by_their_last_32_bytes() {
    let xmss = xmss_pubkey_padded(&[0x22; 32]);
    assert!(!KeyScheme::Xmss.is_legacy(&xmss));
    assert!(KeyScheme::Xmss.is_legacy(&legacy_key()));
    assert!(!KeyScheme::Bls.is_legacy(&legacy_key()), "a BLS registry has no legacy keys");

    assert_eq!(KeyScheme::Xmss.request_pubkey(&legacy_key()), xmss_pubkey_padded(&[0x11; 32]));
    assert_eq!(KeyScheme::Bls.request_pubkey(&legacy_key()), legacy_key());
}

/// Spec `compute_legacy_xmss_pubkey` and `compute_legacy_vrf_root` as of
/// `4c296784`: keccak256 of the BLS key and a one-byte domain. The roots
/// come from a reference Keccak outside this crate.
#[test]
fn legacy_deposits_derive_their_keys_from_the_bls_key() {
    let xmss = b256("61bbbd1d135b03659ec259668deaae000b58fd9b2bc30145dfb0d0e8b504452c");
    let vrf_root = b256("cb9d96c7f52678e22304e20a8119555677907e5e9f94cd45a72f960b7dcc74b5");

    assert_eq!(KeyScheme::Xmss.deposit_pubkey(&legacy_key()), xmss_pubkey_padded(&xmss));
    assert_eq!(deposit_vrf_root(&legacy_key(), &[0x33; 96]), vrf_root);

    let fresh = xmss_pubkey_padded(&[0x22; 32]);
    assert_eq!(KeyScheme::Xmss.deposit_pubkey(&fresh), fresh);
    assert_eq!(deposit_vrf_root(&fresh, &[0x33; 96]), [0x33; 32]);
}

/// leanVM's `VrfKey::new(seed, slot..slot + 1).proof(slot)`: the secret
/// of `validator.md` `compute_vrf_secret`, then siblings that hold no slot
/// of the key's range, which leanVM replaces by surrogates.
fn one_slot_key_proof(seed: &B256, slot: Slot) -> VRFProof {
    let mut proof = [0; VRF_PROOF_SIZE];
    let (secret, siblings) = proof.split_at_mut(32);
    secret.copy_from_slice(&keccak256(&[b"VRF_SECRET", &seed[..], &slot.to_le_bytes()].concat()));
    for (height, sibling) in siblings.chunks_exact_mut(32).enumerate() {
        let index = (slot >> height) ^ 1;
        let surrogate =
            [b"VRF_SURROGATE", &seed[..], &index.to_le_bytes(), &[height as u8]].concat();
        sibling.copy_from_slice(&keccak256(&surrogate));
    }
    proof
}

/// Roots of the one-slot keys `0..1` and `5..6` in leanVM's
/// `crates/lean_vrf/tests/lean_vrf.rs`, the tree a validator client
/// builds. Negative cases follow the spec's `test_vrf_proof.py`.
#[test]
fn vrf_proofs_reveal_the_secret_their_slot_commits_to() {
    let seed = keccak256(b"leanxmss vrf test");
    let root_0 = b256("a642d9ee60c7f8f63e57df2c93caf0a7644e611311e534f800254039c0a324c2");
    let root_5 = b256("d2b0026ddf95eebe4a37660ccd1f7d089b573dbe4e348b6addf08bde1bc886f6");
    assert!(is_valid_vrf_proof(&one_slot_key_proof(&seed, 0), 0, &root_0));

    let proof = one_slot_key_proof(&seed, 5);
    assert!(is_valid_vrf_proof(&proof, 5, &root_5));
    assert!(!is_valid_vrf_proof(&proof, 4, &root_5), "wrong slot");
    assert!(!is_valid_vrf_proof(&proof, 5 + (1 << VRF_TREE_DEPTH), &root_5), "high slot bits");
    assert!(!is_valid_vrf_proof(&proof, 5, &root_0), "other validator");

    let mut wrong_secret = proof;
    wrong_secret[0] ^= 1;
    assert!(!is_valid_vrf_proof(&wrong_secret, 5, &root_5), "wrong secret");
}
