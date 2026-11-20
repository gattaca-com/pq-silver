use silver_beacon_state_data::B256;
use silver_common::ssz_view::{MAX_STARK_PROOF_SIZE, SINGLE_ATT_PQ_SIZE, XMSS_SIGNATURE_SIZE};

use super::wire::AggregateRequest;

/// `pubkey | message`, so byte order is the leanVM sidecar's claim order.
pub type Claim = [u8; 64];

/// Most leanXMSS records in one request.
const MAX_RECORDS: usize = 2048;
/// Most children in one request.
const MAX_CHILDREN: usize = 16;

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

/// What one aggregation proves: a vote for a leaf, an aggregate for a merge.
pub trait VerifiedClaims {
    /// Sorted and without repeats.
    fn claims(&self) -> &[Claim];

    /// The most of these one batch takes, given whether a best proof exists.
    fn batch_limit(has_best_proof: bool) -> usize;

    fn add_to<'a>(&'a self, request: &mut AggregateRequest<'a>);
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

impl VerifiedClaims for Vote {
    fn claims(&self) -> &[Claim] {
        std::slice::from_ref(&self.claim)
    }

    /// The best proof is the only child.
    fn batch_limit(_: bool) -> usize {
        MAX_RECORDS
    }

    fn add_to<'a>(&'a self, request: &mut AggregateRequest<'a>) {
        request.records.push((&self.claim, &self.signature));
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

impl VerifiedClaims for Aggregate {
    fn claims(&self) -> &[Claim] {
        &self.claims
    }

    /// The best proof counts as one child.
    fn batch_limit(has_best_proof: bool) -> usize {
        MAX_CHILDREN - usize::from(has_best_proof)
    }

    fn add_to<'a>(&'a self, request: &mut AggregateRequest<'a>) {
        request.children.push((&self.claims, &self.proof));
    }
}
