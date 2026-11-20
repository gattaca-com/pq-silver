use silver_beacon_state_data::B256;
use silver_common::ssz_view::{MAX_STARK_PROOF_SIZE, SINGLE_ATT_PQ_SIZE, XMSS_SIGNATURE_SIZE};

use super::strategy::ClaimsKind;

/// `pubkey | message`, so byte order is the leanVM sidecar's claim order.
pub type Claim = [u8; 64];

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
        let mut claim = [0; 64];
        claim[..32].copy_from_slice(&pubkey);
        claim[32..].copy_from_slice(&message);
        Self { committee_position, claim, signature: Box::new(*signature) }
    }
}

pub struct Aggregate {
    /// Sorted, without repeats.
    pub(super) claims: Vec<Claim>,
    pub(super) proof: Vec<u8>,
    /// The aggregate's `AttestationPq` SSZ, for the block body.
    pub(super) attestation: Vec<u8>,
}

impl Aggregate {
    /// The caller has verified `proof` for `claims`: our own proof, or a
    /// received one that a leanVM sidecar `verify` accepted. `None` for no
    /// claims or a proof above the size bound.
    pub fn new(mut claims: Vec<Claim>, proof: Vec<u8>, attestation: Vec<u8>) -> Option<Self> {
        claims.sort_unstable();
        claims.dedup();
        (!claims.is_empty() && proof.len() <= MAX_STARK_PROOF_SIZE).then_some(Self {
            claims,
            proof,
            attestation,
        })
    }
}

pub enum VerifiedClaims {
    Vote(Vote),
    Aggregate(Aggregate),
}

impl VerifiedClaims {
    pub(super) fn kind(&self) -> ClaimsKind {
        match self {
            Self::Vote(_) => ClaimsKind::Vote,
            Self::Aggregate(_) => ClaimsKind::Aggregate,
        }
    }

    /// Sorted and without repeats.
    pub fn claims(&self) -> &[Claim] {
        match self {
            Self::Vote(vote) => std::slice::from_ref(&vote.claim),
            Self::Aggregate(aggregate) => &aggregate.claims,
        }
    }
}
