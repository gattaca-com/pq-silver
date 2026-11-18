use std::sync::LazyLock;

use blst::min_pk::PublicKey;
use silver_state_memory::RetainedVec;

use crate::{pq::KeyScheme, types::B256};

/// The infinity point: no signature verifies against it, so BLS checks on an
/// XMSS registry fail closed.
static NO_BLS_KEY: LazyLock<PublicKey> = LazyLock::new(PublicKey::default);

/// One validator's identity beside its 48-byte pubkey.
#[derive(Clone, Copy, PartialEq)]
pub enum SchemeKey {
    /// Decompressed once, for signature checks.
    Bls(PublicKey),
    Xmss {
        vrf_root: B256,
    },
}

impl SchemeKey {
    #[inline]
    pub(super) fn bls(&self) -> &PublicKey {
        match self {
            Self::Bls(key) => key,
            Self::Xmss { .. } => &NO_BLS_KEY,
        }
    }

    #[inline]
    pub(super) fn vrf_root(&self) -> Option<&B256> {
        match self {
            Self::Bls(_) => None,
            Self::Xmss { vrf_root } => Some(vrf_root),
        }
    }
}

/// [`SchemeKey`] for every finalized validator, in the registry's one scheme.
pub(super) enum SchemeColumn {
    Bls(RetainedVec<PublicKey>),
    Xmss(RetainedVec<B256>),
}

impl SchemeColumn {
    pub(super) fn with_capacity(scheme: KeyScheme, capacity: usize) -> Self {
        match scheme {
            KeyScheme::Bls => Self::Bls(RetainedVec::with_capacity(capacity)),
            KeyScheme::Xmss => Self::Xmss(RetainedVec::with_capacity(capacity)),
        }
    }

    #[inline]
    pub(super) fn scheme(&self) -> KeyScheme {
        match self {
            Self::Bls(_) => KeyScheme::Bls,
            Self::Xmss(_) => KeyScheme::Xmss,
        }
    }

    pub(super) fn resize(&mut self, count: usize) {
        match self {
            Self::Bls(keys) => keys.resize(count, PublicKey::default()),
            Self::Xmss(roots) => roots.resize(count, B256::default()),
        }
    }

    pub(super) fn grow_to(&mut self, capacity: usize) {
        match self {
            Self::Bls(keys) => keys.grow_to(capacity),
            Self::Xmss(roots) => roots.grow_to(capacity),
        }
    }

    #[inline]
    pub(super) fn set(&mut self, i: usize, key: SchemeKey) {
        match (self, key) {
            (Self::Bls(keys), SchemeKey::Bls(key)) => keys[i] = key,
            (Self::Xmss(roots), SchemeKey::Xmss { vrf_root }) => roots[i] = vrf_root,
            _ => panic!("validator {i}'s key does not match the registry's scheme"),
        }
    }

    #[inline]
    pub(super) fn bls(&self, i: usize) -> &PublicKey {
        match self {
            Self::Bls(keys) => &keys[i],
            Self::Xmss(_) => &NO_BLS_KEY,
        }
    }

    #[inline]
    pub(super) fn vrf_root(&self, i: usize) -> Option<&B256> {
        match self {
            Self::Bls(_) => None,
            Self::Xmss(roots) => Some(&roots[i]),
        }
    }
}
