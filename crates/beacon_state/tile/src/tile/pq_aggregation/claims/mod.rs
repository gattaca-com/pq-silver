use silver_beacon_state_data::{B256, Slot};
pub use silver_common::leanvm::Claim;
use silver_common::{
    leanvm::MAX_PROOF_CLAIMS,
    ssz_view::{
        ATTESTATION_DATA_SIZE, AttestationDataView, MAX_COMMITTEES_PER_SLOT_PQ,
        MAX_VALIDATORS_PER_COMMITTEE, SINGLE_ATT_PQ_SIZE, SingleAttestationPqView,
    },
};

pub(super) struct ClaimCheck {
    seen: [u64; MAX_PROOF_CLAIMS.div_ceil(64)],
    remaining: usize,
}

impl Default for ClaimCheck {
    fn default() -> Self {
        Self { seen: [0; MAX_PROOF_CLAIMS.div_ceil(64)], remaining: 0 }
    }
}

impl ClaimCheck {
    pub(super) fn reset(&mut self, len: usize) {
        self.seen[..len.div_ceil(64)].fill(0);
        self.remaining = len;
    }

    pub(super) fn mark(&mut self, index: usize) {
        let (word, bit) = (&mut self.seen[index / 64], 1 << (index % 64));
        if *word & bit == 0 {
            *word |= bit;
            self.remaining -= 1;
        }
    }

    pub(super) fn complete(&self) -> bool {
        self.remaining == 0
    }
}

pub fn claim(pubkey: &[u8; 32], message: &[u8; 32]) -> Claim {
    let mut claim = [0; 64];
    claim[..32].copy_from_slice(pubkey);
    claim[32..].copy_from_slice(message);
    claim
}

/// A single attestation whose XMSS signature the tile has verified, with the
/// facts only the tile has.
pub struct VerifiedVote<'a> {
    pub single: &'a [u8; SINGLE_ATT_PQ_SIZE],
    pub data_root: B256,
    pub message: [u8; 32],
    pub pubkey: [u8; 32],
    pub validator: u32,
    /// Index in the committee, which has `committee_len` members.
    pub committee_position: usize,
    pub committee_len: usize,
}

impl VerifiedVote<'_> {
    pub(super) fn slot(&self) -> Slot {
        SingleAttestationPqView::data(self.single).slot()
    }

    pub(super) fn committee(&self) -> Committee {
        let data = *SingleAttestationPqView::data(self.single).as_bytes();
        Committee { data, index: SingleAttestationPqView::committee_index(self.single) as usize }
    }
}

/// Most committees one merge tells apart. Honest aggregates of a slot name
/// few attestation data.
pub(super) const MAX_GROUPS: usize = 4 * MAX_COMMITTEES_PER_SLOT_PQ;
const _: () = assert!(MAX_PROOF_CLAIMS == MAX_GROUPS * MAX_VALIDATORS_PER_COMMITTEE);

/// One committee voting for one attestation data. Aggregates of two
/// committees share no claim.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Committee {
    pub data: [u8; ATTESTATION_DATA_SIZE],
    pub index: usize,
}

impl Committee {
    pub(super) fn slot(&self) -> Slot {
        AttestationDataView::new(&self.data).slot()
    }
}

#[cfg(test)]
mod tests;
