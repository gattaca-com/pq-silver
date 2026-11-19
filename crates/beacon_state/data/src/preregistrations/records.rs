use std::io::{self, Write};

use silver_ssz::ssz_view::XMSSPubkey;

use super::list::Record;
use crate::{
    decompose::u64_le,
    merkle::{merkleize, uint64_chunk},
    types::{B256, Slot},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidatorPreregistration {
    pub pubkey: XMSSPubkey,
    pub withdrawal_credentials: B256,
    pub vrf_root: B256,
    pub expiry_slot: Slot,
}

impl Record for ValidatorPreregistration {
    const SSZ_SIZE: usize = 32 + 32 + 32 + 8;

    fn from_ssz(s: &[u8]) -> Self {
        Self {
            pubkey: s[..32].try_into().unwrap(),
            withdrawal_credentials: s[32..64].try_into().unwrap(),
            vrf_root: s[64..96].try_into().unwrap(),
            expiry_slot: u64_le(s, 96),
        }
    }

    fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.pubkey)?;
        w.write_all(&self.withdrawal_credentials)?;
        w.write_all(&self.vrf_root)?;
        w.write_all(&self.expiry_slot.to_le_bytes())
    }

    fn hash_tree_root(&self) -> B256 {
        merkleize(&[
            self.pubkey,
            self.withdrawal_credentials,
            self.vrf_root,
            uint64_chunk(self.expiry_slot),
        ])
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BuilderPreregistration {
    pub pubkey: XMSSPubkey,
    pub withdrawal_credentials: B256,
    pub expiry_slot: Slot,
}

impl Record for BuilderPreregistration {
    const SSZ_SIZE: usize = 32 + 32 + 8;

    fn from_ssz(s: &[u8]) -> Self {
        Self {
            pubkey: s[..32].try_into().unwrap(),
            withdrawal_credentials: s[32..64].try_into().unwrap(),
            expiry_slot: u64_le(s, 64),
        }
    }

    fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.pubkey)?;
        w.write_all(&self.withdrawal_credentials)?;
        w.write_all(&self.expiry_slot.to_le_bytes())
    }

    fn hash_tree_root(&self) -> B256 {
        merkleize(&[self.pubkey, self.withdrawal_credentials, uint64_chunk(self.expiry_slot)])
    }
}
