use silver_ssz::ssz_view::{XMSS_PUBKEY_SIZE, XMSSPubkey};

use crate::{
    merkle::hash_fixed_bytes,
    types::{B256, BLSPubkey, Version},
};

pub const PQ_FORK_VERSION: Version = [0xe0, 0, 0, 0];

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
