use std::io::{self, Write};

use silver_ssz::ssz_view::XMSSPubkey;

use crate::{
    DecomposeError,
    decompose::{common::checked_count, u64_le},
    merkle::{hash_list, merkleize, uint64_chunk},
    progressive::ProgressiveHasher,
    types::{B256, Slot},
};

pub const PREREGISTRATIONS_LIMIT: usize = 1 << 19;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidatorPreregistration {
    pub pubkey: XMSSPubkey,
    pub withdrawal_credentials: B256,
    pub vrf_root: B256,
    pub expiry_slot: Slot,
}

impl ValidatorPreregistration {
    pub(crate) const SSZ_SIZE: usize = 32 + 32 + 32 + 8;

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

    pub fn hash_tree_root(&self) -> B256 {
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

impl BuilderPreregistration {
    pub(crate) const SSZ_SIZE: usize = 32 + 32 + 8;

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

    pub fn hash_tree_root(&self) -> B256 {
        merkleize(&[self.pubkey, self.withdrawal_credentials, uint64_chunk(self.expiry_slot)])
    }
}

/// The two PQ preregistration lists, which change together: deposit
/// requests append or overwrite, and the epoch sweep drops expired records.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Preregistrations {
    pub validators: Vec<ValidatorPreregistration>,
    pub builders: Vec<BuilderPreregistration>,
}

impl Preregistrations {
    pub(crate) fn from_ssz(validators: &[u8], builders: &[u8]) -> Result<Self, DecomposeError> {
        let check = |bytes: &[u8], size, field| {
            checked_count(bytes.len(), size, field, PREREGISTRATIONS_LIMIT)
        };
        let validator_size = ValidatorPreregistration::SSZ_SIZE;
        let builder_size = BuilderPreregistration::SSZ_SIZE;
        check(validators, validator_size, "validator_preregistrations")?;
        check(builders, builder_size, "builder_preregistrations")?;
        Ok(Self {
            validators: validators
                .chunks_exact(validator_size)
                .map(ValidatorPreregistration::from_ssz)
                .collect(),
            builders: builders
                .chunks_exact(builder_size)
                .map(BuilderPreregistration::from_ssz)
                .collect(),
        })
    }

    pub fn validators_root(&self) -> B256 {
        hash_list(ProgressiveHasher::new(), self.validators.iter().map(|p| p.hash_tree_root()))
    }

    pub fn builders_root(&self) -> B256 {
        hash_list(ProgressiveHasher::new(), self.builders.iter().map(|p| p.hash_tree_root()))
    }

    pub(crate) fn validators_ssz_len(&self) -> usize {
        self.validators.len() * ValidatorPreregistration::SSZ_SIZE
    }

    pub(crate) fn builders_ssz_len(&self) -> usize {
        self.builders.len() * BuilderPreregistration::SSZ_SIZE
    }

    pub(crate) fn write_validators_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.validators.iter().try_for_each(|p| p.write_ssz(w))
    }

    pub(crate) fn write_builders_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.builders.iter().try_for_each(|p| p.write_ssz(w))
    }
}
