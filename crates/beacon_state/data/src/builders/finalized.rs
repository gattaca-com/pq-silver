use std::io::{self, Write};

use silver_ssz::ssz_view::XMSS_PUBKEY_SIZE;
use silver_state_memory::RetainedVec;

use crate::{
    DecomposeError,
    decompose::common::checked_count,
    gloas::{BUILDER_REGISTRY_LIMIT, Builder, builder_capacity},
    pq::{KeyScheme, xmss_pubkey, xmss_pubkey_padded},
    types::BLSPubkey,
};

/// The SSZ `Builder` past its pubkey: version, execution_address, balance,
/// deposit_epoch, withdrawable_epoch.
const BUILDER_SSZ_AFTER_PUBKEY: usize = 1 + 20 + 8 + 8 + 8;

pub struct FinalizedBuilders {
    /// Its length is the builder count, so a racing reader's slice never
    /// covers slots its block has not filled.
    pub(super) builders: RetainedVec<Builder>,
    scheme: KeyScheme,
}

impl Default for FinalizedBuilders {
    fn default() -> Self {
        Self::from_ssz(&[], KeyScheme::Bls).expect("empty builders registry is valid")
    }
}

impl FinalizedBuilders {
    pub(crate) fn from_ssz(bytes: &[u8], scheme: KeyScheme) -> Result<Self, DecomposeError> {
        let size = ssz_size(scheme);
        let count = checked_count(bytes.len(), size, "builders", BUILDER_REGISTRY_LIMIT)?;

        // One allocation: the capacity-sized registry, filled in place from the
        // SSZ bytes (no intermediate parsed buffer).
        let mut builders = RetainedVec::with_capacity(builder_capacity(count));
        let pubkey_len = size - BUILDER_SSZ_AFTER_PUBKEY;
        builders.extend(bytes.chunks_exact(size).map(|s| {
            let (pubkey, s) = s.split_at(pubkey_len);
            let pubkey: BLSPubkey = match scheme {
                KeyScheme::Bls => pubkey.try_into().unwrap(),
                KeyScheme::Xmss => xmss_pubkey_padded(pubkey.try_into().unwrap()),
            };
            Builder {
                pubkey,
                version: s[0],
                execution_address: s[1..21].try_into().unwrap(),
                balance: u64::from_le_bytes(s[21..29].try_into().unwrap()),
                deposit_epoch: u64::from_le_bytes(s[29..37].try_into().unwrap()),
                withdrawable_epoch: u64::from_le_bytes(s[37..45].try_into().unwrap()),
            }
        }));

        Ok(Self { builders, scheme })
    }

    #[inline]
    pub fn scheme(&self) -> KeyScheme {
        self.scheme
    }

    pub(crate) fn ssz_len(&self) -> usize {
        self.len() * ssz_size(self.scheme)
    }

    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for b in self.as_slice() {
            match self.scheme {
                KeyScheme::Bls => w.write_all(&b.pubkey)?,
                KeyScheme::Xmss => w.write_all(xmss_pubkey(&b.pubkey))?,
            }
            w.write_all(&[b.version])?;
            w.write_all(&b.execution_address)?;
            w.write_all(&b.balance.to_le_bytes())?;
            w.write_all(&b.deposit_epoch.to_le_bytes())?;
            w.write_all(&b.withdrawable_epoch.to_le_bytes())?;
        }
        Ok(())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.builders.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.builders.is_empty()
    }

    #[inline]
    pub(super) fn get(&self, i: usize) -> Option<&Builder> {
        self.builders.get(i)
    }

    #[inline]
    pub(super) fn as_slice(&self) -> &[Builder] {
        &self.builders
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.builders.capacity()
    }

    pub(super) fn ensure_capacity(&mut self, end: usize) {
        if end > self.builders.capacity() {
            self.builders.grow_to(builder_capacity(end));
        }
    }
}

fn ssz_size(scheme: KeyScheme) -> usize {
    let pubkey_len = match scheme {
        KeyScheme::Bls => 48,
        KeyScheme::Xmss => XMSS_PUBKEY_SIZE,
    };
    pubkey_len + BUILDER_SSZ_AFTER_PUBKEY
}
