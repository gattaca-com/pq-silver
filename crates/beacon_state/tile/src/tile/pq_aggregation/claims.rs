use silver_beacon_state_data::{B256, Slot};
use silver_common::{
    Nanos,
    merkle::bitlist_len,
    ssz_view::{AttestationPqView, MAX_STARK_PROOF_SIZE, SINGLE_ATT_PQ_SIZE, XMSS_SIGNATURE_SIZE},
};

use super::strategy::{Committee, Positions};

/// `pubkey | message`, so byte order is the leanVM sidecar's claim order.
pub type Claim = [u8; 64];

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
    /// Index in the committee, which has `committee_len` members.
    pub committee_position: usize,
    pub committee_len: usize,
    /// Since genesis. A vote buffered for its block keeps its arrival.
    pub received: Nanos,
}

pub struct Vote {
    pub(super) committee_position: usize,
    pub(super) claim: Claim,
    pub(super) signature: Box<[u8; XMSS_SIGNATURE_SIZE]>,
}

impl Vote {
    /// The caller has verified `signature` over `message` for `pubkey`.
    pub fn new(
        committee_position: usize,
        pubkey: [u8; 32],
        message: [u8; 32],
        signature: &[u8; XMSS_SIGNATURE_SIZE],
    ) -> Self {
        let claim = claim(&pubkey, &message);
        Self { committee_position, claim, signature: Box::new(*signature) }
    }
}

/// One voter of a committee: its place in the committee and its claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub(super) position: usize,
    pub(super) validator: u32,
    pub(super) claim: Claim,
}

/// One committee's votes for one attestation data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub(super) committee: Committee,
    pub(super) slot: Slot,
    pub(super) committee_len: usize,
    /// Ascending by position, without repeats.
    pub(super) members: Vec<Member>,
}

impl Group {
    pub(super) fn positions(&self) -> Positions {
        let bits = self.members.iter().map(|member| member.position).collect();
        Positions { committee: self.committee, bits }
    }

    /// The votes as an SSZ `Bitlist` of the committee's length.
    pub(super) fn bitlist(&self) -> Vec<u8> {
        let mut bits = vec![0; self.committee_len / 8 + 1];
        for member in &self.members {
            bits[member.position / 8] |= 1 << (member.position % 8);
        }
        bits[self.committee_len / 8] |= 1 << (self.committee_len % 8);
        bits
    }
}

pub struct Aggregate {
    /// Sorted, without repeats.
    pub(super) claims: Vec<Claim>,
    pub(super) proof: Vec<u8>,
    pub(super) group: Group,
}

impl Aggregate {
    /// `attestation` is an `AttestationPq` of one committee. `attesters` and
    /// `claims` are its voters, in committee order. The caller has verified
    /// `proof` for `claims`: our own proof, or a received one that a leanVM
    /// sidecar `verify` accepted. `None` for no voter, a proof above the size
    /// bound, an `attestation` not of one committee, or voters that do not
    /// match its positions one for one.
    pub fn new(
        attestation: &[u8],
        attesters: &[u32],
        mut claims: Vec<Claim>,
        proof: Vec<u8>,
    ) -> Option<Self> {
        let (index, positions) = AttestationPqView::one_committee_positions(attestation)?;
        let positions: Vec<usize> = positions.collect();
        let voters = positions.len();
        if voters == 0 || attesters.len() != voters || claims.len() != voters {
            return None;
        }
        let members = (positions.iter().zip(attesters).zip(&claims))
            .map(|((&position, &validator), &claim)| Member { position, validator, claim })
            .collect();
        claims.sort_unstable();
        claims.dedup();
        let data = AttestationPqView::data(attestation);
        let group = Group {
            committee: Committee { data: *data.as_bytes(), index },
            slot: data.slot(),
            committee_len: bitlist_len(AttestationPqView::aggregation_bits(attestation)),
            members,
        };
        (claims.len() == voters && proof.len() <= MAX_STARK_PROOF_SIZE).then_some(Self {
            claims,
            proof,
            group,
        })
    }
}

#[cfg(test)]
mod tests;
