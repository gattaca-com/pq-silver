use silver_crypto_simd::xmss::keccak::keccak256;
use silver_ssz::ssz_view::{VRFProof, XMSS_PUBKEY_SIZE, XMSSPubkey};

use crate::{
    merkle::{hash_fixed_bytes, sha256},
    types::{B256, BLSPubkey, Slot, Version},
};

pub const PQ_FORK_VERSION: Version = [0xe0, 0, 0, 0];
pub const MIN_ATTESTATION_INCLUSION_DELAY_PQ: Slot = 2;

/// How a registry's pubkeys are interpreted. Every record keeps the 48-byte
/// form; an XMSS key is `XMSS_DEPOSIT_PREFIX ++ pubkey`, the form EL requests
/// carry, so lookups by request pubkey need no conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyScheme {
    Bls,
    Xmss,
}

impl KeyScheme {
    /// Root of a pubkey in its 48-byte form: a `Bytes48` for BLS, a `Bytes32`
    /// for XMSS.
    #[inline]
    pub fn pubkey_root(self, pubkey: &BLSPubkey) -> B256 {
        match self {
            Self::Bls => hash_fixed_bytes(pubkey),
            Self::Xmss => *xmss_pubkey(pubkey),
        }
    }

    /// Whether a request names a BLS key under a registry of XMSS keys: one
    /// made before the PQ fork.
    #[inline]
    pub fn is_legacy(self, pubkey: &BLSPubkey) -> bool {
        self == Self::Xmss && pubkey[..XMSS_DEPOSIT_PREFIX_LEN] != [0; XMSS_DEPOSIT_PREFIX_LEN]
    }

    /// Spec `compute_deposit_pubkey`, in the registry's 48-byte form. A
    /// legacy key is replaced by the XMSS key derived from it.
    pub fn deposit_pubkey(self, pubkey: &BLSPubkey) -> BLSPubkey {
        if self.is_legacy(pubkey) {
            xmss_pubkey_padded(&legacy_hash(pubkey, LEGACY_XMSS_PUBKEY_DOMAIN))
        } else {
            *pubkey
        }
    }

    /// The registry key a request names: under PQ, spec
    /// `XMSSPubkey(pubkey[16:])`, whatever the prefix holds.
    pub fn request_pubkey(self, pubkey: &BLSPubkey) -> BLSPubkey {
        match self {
            Self::Bls => *pubkey,
            Self::Xmss => xmss_pubkey_padded(pubkey[XMSS_DEPOSIT_PREFIX_LEN..].try_into().unwrap()),
        }
    }
}

const LEGACY_XMSS_PUBKEY_DOMAIN: u8 = 0x00;
const LEGACY_VRF_ROOT_DOMAIN: u8 = 0x01;

fn legacy_hash(pubkey: &BLSPubkey, domain: u8) -> B256 {
    let mut preimage = [0; 48 + 1];
    preimage[..48].copy_from_slice(pubkey);
    preimage[48] = domain;
    sha256(&preimage)
}

/// Spec `compute_deposit_vrf_root`: a PQ deposit carries its validator's VRF
/// root in the first 32 bytes of its signature field.
pub fn deposit_vrf_root(pubkey: &BLSPubkey, signature: &[u8; 96]) -> B256 {
    if KeyScheme::Xmss.is_legacy(pubkey) {
        legacy_hash(pubkey, LEGACY_VRF_ROOT_DOMAIN)
    } else {
        signature[..32].try_into().unwrap()
    }
}

const XMSS_DEPOSIT_PREFIX_LEN: usize = 48 - XMSS_PUBKEY_SIZE;

/// The 48-byte form of an XMSS key.
pub fn xmss_pubkey_padded(pubkey: &XMSSPubkey) -> BLSPubkey {
    let mut padded = [0; 48];
    padded[XMSS_DEPOSIT_PREFIX_LEN..].copy_from_slice(pubkey);
    padded
}

/// The XMSS key inside its 48-byte form.
pub fn xmss_pubkey(padded: &BLSPubkey) -> &XMSSPubkey {
    debug_assert!(padded[..XMSS_DEPOSIT_PREFIX_LEN].iter().all(|&b| b == 0));
    padded[XMSS_DEPOSIT_PREFIX_LEN..].try_into().unwrap()
}

/// The secret `proof` reveals, which its slot's leaf commits to.
pub fn vrf_secret(proof: &VRFProof) -> &B256 {
    proof[..32].try_into().unwrap()
}

const VRF_LEAF_DOMAIN: &[u8; 8] = b"VRF_LEAF";

/// Spec `compute_vrf_leaf`.
fn vrf_leaf(secret: &B256, index: Slot) -> B256 {
    let mut preimage = [0; VRF_LEAF_DOMAIN.len() + 32 + 8];
    preimage[..8].copy_from_slice(VRF_LEAF_DOMAIN);
    preimage[8..40].copy_from_slice(secret);
    preimage[40..].copy_from_slice(&index.to_le_bytes());
    keccak256(&preimage)
}

/// Spec `is_valid_vrf_proof`: `proof` reveals the secret that leaf `slot` of
/// the tree under `vrf_root` commits to.
pub fn is_valid_vrf_proof(proof: &VRFProof, slot: Slot, vrf_root: &B256) -> bool {
    let mut node = vrf_leaf(vrf_secret(proof), slot);
    let mut pair = [0; 64];
    for (height, sibling) in proof[32..].chunks_exact(32).enumerate() {
        let (left, right) =
            if (slot >> height) & 1 == 1 { (sibling, &node[..]) } else { (&node[..], sibling) };
        pair[..32].copy_from_slice(left);
        pair[32..].copy_from_slice(right);
        node = keccak256(&pair);
    }
    node == *vrf_root
}

#[cfg(test)]
mod tests {
    use silver_ssz::ssz_view::VRF_PROOF_SIZE;

    use super::*;

    /// A BLS key's first byte has its compression flag set.
    fn legacy_key() -> BLSPubkey {
        let mut key = [0x11; 48];
        key[0] = 0xa5;
        key
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

    /// Spec `compute_legacy_xmss_pubkey` and `compute_legacy_vrf_root`:
    /// sha256 of the BLS key with a one-byte domain.
    #[test]
    fn legacy_deposits_derive_their_keys_from_the_bls_key() {
        let mut preimage = legacy_key().to_vec();
        preimage.push(0x00);
        let xmss = sha256(&preimage);
        *preimage.last_mut().unwrap() = 0x01;
        let vrf_root = sha256(&preimage);

        assert_eq!(KeyScheme::Xmss.deposit_pubkey(&legacy_key()), xmss_pubkey_padded(&xmss));
        assert_eq!(deposit_vrf_root(&legacy_key(), &[0x33; 96]), vrf_root);

        let fresh = xmss_pubkey_padded(&[0x22; 32]);
        assert_eq!(KeyScheme::Xmss.deposit_pubkey(&fresh), fresh);
        assert_eq!(deposit_vrf_root(&fresh, &[0x33; 96]), [0x33; 32]);
    }

    /// The pyspec's `is_valid_vrf_proof` accepts this proof, whose element `i`
    /// is `[i; 32]`, at slot 1430 under this root, and rejects it at 1431.
    #[test]
    fn vrf_proof_opens_only_its_slot() {
        let slot = 1430;
        let mut proof = [0u8; VRF_PROOF_SIZE];
        for (i, node) in proof.chunks_exact_mut(32).enumerate() {
            node.fill(i as u8);
        }
        let root: B256 =
            hex::decode("95a44af3d2071823fba9b2329913d39c29ea84da1eb5bca96c429087d9d4688c")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(is_valid_vrf_proof(&proof, slot, &root));
        assert!(!is_valid_vrf_proof(&proof, slot + 1, &root));

        proof[VRF_PROOF_SIZE - 1] ^= 1;
        assert!(!is_valid_vrf_proof(&proof, slot, &root));
    }
}
