use silver_crypto_simd::xmss::keccak::keccak256;
use silver_ssz::ssz_view::{VRFProof, XMSS_PUBKEY_SIZE, XMSSPubkey};

use crate::{
    merkle::hash_fixed_bytes,
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

    /// A registry key in its scheme's own width: 48 bytes for BLS, 32 for
    /// XMSS.
    #[inline]
    pub fn public_key(self, pubkey: &BLSPubkey) -> &[u8] {
        match self {
            Self::Bls => pubkey,
            Self::Xmss => &pubkey[XMSS_DEPOSIT_PREFIX_LEN..],
        }
    }
}

const LEGACY_XMSS_PUBKEY_DOMAIN: u8 = 0x00;
const LEGACY_VRF_ROOT_DOMAIN: u8 = 0x01;

fn legacy_hash(pubkey: &BLSPubkey, domain: u8) -> B256 {
    let mut preimage = [0; 48 + 1];
    preimage[..48].copy_from_slice(pubkey);
    preimage[48] = domain;
    keccak256(&preimage)
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

/// The secret `proof` reveals, which the RANDAO mix takes in.
pub fn vrf_secret(proof: &VRFProof) -> &B256 {
    proof[..32].try_into().unwrap()
}

const VRF_LEAF_DOMAIN: &[u8; 8] = b"VRF_LEAF";

/// Spec `compute_vrf_leaf`.
fn vrf_leaf(secret: &B256, index: Slot) -> B256 {
    const SECRET_AT: usize = VRF_LEAF_DOMAIN.len();
    const INDEX_AT: usize = SECRET_AT + 32;
    let mut preimage = [0; INDEX_AT + 8];
    preimage[..SECRET_AT].copy_from_slice(VRF_LEAF_DOMAIN);
    preimage[SECRET_AT..INDEX_AT].copy_from_slice(secret);
    preimage[INDEX_AT..].copy_from_slice(&index.to_le_bytes());
    keccak256(&preimage)
}

/// Spec `is_valid_vrf_proof`: `proof` reveals the secret that leaf `slot` of
/// the tree under `vrf_root` commits to. The leaf commits to the whole slot;
/// only its low `VRF_TREE_DEPTH` bits choose the path.
pub fn is_valid_vrf_proof(proof: &VRFProof, slot: Slot, vrf_root: &B256) -> bool {
    let mut node = vrf_leaf(vrf_secret(proof), slot);
    let mut pair = [0; 64];
    for (height, sibling) in proof[32..].as_chunks().0.iter().enumerate() {
        let (left, right) =
            if (slot >> height) & 1 == 1 { (sibling, &node) } else { (&node, sibling) };
        pair[..32].copy_from_slice(left);
        pair[32..].copy_from_slice(right);
        node = keccak256(&pair);
    }
    node == *vrf_root
}

#[cfg(test)]
mod tests;
