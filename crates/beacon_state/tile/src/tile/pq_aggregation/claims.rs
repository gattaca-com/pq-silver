use silver_beacon_state_data::B256;
use silver_common::ssz_view::{
    ATTESTATION_DATA_SIZE, AttestationPqView, MAX_STARK_PROOF_SIZE, MAX_VALIDATORS_PER_COMMITTEE,
    SINGLE_ATT_PQ_SIZE, XMSS_SIGNATURE_SIZE,
};

use super::{
    strategy::{ArrivalOrder, MarginalGain, Strategy},
    wire::AggregateRequest,
};

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
    type Strategy: Strategy;

    /// Whether these are a merge's. A merge goes before any leaf.
    const MERGE: bool;

    /// Sorted and without repeats.
    fn claims(&self) -> &[Claim];

    /// Where `claims` sit in their committee, for the strategy.
    fn positions(&self) -> <Self::Strategy as Strategy>::Positions;

    /// The most of these one batch takes, given whether a best proof exists.
    fn batch_limit(has_best_proof: bool) -> usize;

    fn add_to<'a>(&'a self, request: &mut AggregateRequest<'a>);
}

/// Positions in one committee, one bit each.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bits([u64; MAX_VALIDATORS_PER_COMMITTEE / 64]);

impl Bits {
    /// `false` if `position` was set already. Panics at or above
    /// `MAX_VALIDATORS_PER_COMMITTEE`.
    pub fn insert(&mut self, position: usize) -> bool {
        let (word, bit) = (&mut self.0[position / 64], 1 << (position % 64));
        let fresh = *word & bit == 0;
        *word |= bit;
        fresh
    }

    pub fn count(&self) -> usize {
        self.0.iter().map(|word| word.count_ones() as usize).sum()
    }

    /// How many of these `have` lacks.
    pub fn count_outside(&self, have: &Bits) -> usize {
        let outside = self.0.iter().zip(&have.0).map(|(word, have)| word & !have);
        outside.map(|word| word.count_ones() as usize).sum()
    }

    pub fn union_with(&mut self, other: &Bits) {
        self.0.iter_mut().zip(&other.0).for_each(|(word, other)| *word |= other);
    }
}

/// One committee voting for one attestation data. Aggregates of two
/// committees share no claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committee {
    pub(super) data: [u8; ATTESTATION_DATA_SIZE],
    pub(super) index: u8,
}

/// The committee positions of an aggregate's claims.
#[derive(Clone, Copy, Debug)]
pub struct Positions {
    pub committee: Committee,
    pub bits: Bits,
}

impl Positions {
    /// `None` unless `attestation` is a canonical `AttestationPq` of one
    /// committee with at most `MAX_VALIDATORS_PER_COMMITTEE` members.
    fn of_attestation(attestation: &[u8]) -> Option<Self> {
        if !AttestationPqView::check_canonical(attestation) {
            return None;
        }
        let committees = u16::from_le_bytes(*AttestationPqView::committee_bits(attestation));
        let aggregation = AttestationPqView::aggregation_bits(attestation);
        // The highest set bit ends the bitlist; a canonical last byte has one.
        let len = aggregation.len() * 8 - 1 - aggregation.last()?.leading_zeros() as usize;
        if committees.count_ones() != 1 || len > MAX_VALIDATORS_PER_COMMITTEE {
            return None;
        }
        let mut bits = Bits::default();
        for position in (0..len).filter(|&p| aggregation[p / 8] >> (p % 8) & 1 == 1) {
            bits.insert(position);
        }
        let data = *AttestationPqView::data(attestation).as_bytes();
        let committee = Committee { data, index: committees.trailing_zeros() as u8 };
        Some(Self { committee, bits })
    }
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
    type Strategy = ArrivalOrder;

    const MERGE: bool = false;

    fn claims(&self) -> &[Claim] {
        std::slice::from_ref(&self.claim)
    }

    fn positions(&self) -> usize {
        self.committee_position
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
    /// Read from `attestation`; as many as `claims`.
    positions: Positions,
}

impl Aggregate {
    /// The caller has verified `proof` for `claims`: our own proof, or a
    /// received one that a leanVM sidecar `verify` accepted. `None` for no
    /// claims, a proof above the size bound, or an `attestation` that is not
    /// of one committee or names another number of positions than claims.
    pub fn new(mut claims: Vec<Claim>, proof: Vec<u8>, attestation: Vec<u8>) -> Option<Self> {
        claims.sort_unstable();
        claims.dedup();
        let positions = Positions::of_attestation(&attestation)?;
        let consistent = positions.bits.count() == claims.len();
        (consistent && !claims.is_empty() && proof.len() <= MAX_STARK_PROOF_SIZE).then_some(Self {
            claims,
            proof,
            attestation,
            positions,
        })
    }
}

impl VerifiedClaims for Aggregate {
    type Strategy = MarginalGain;

    const MERGE: bool = true;

    fn claims(&self) -> &[Claim] {
        &self.claims
    }

    fn positions(&self) -> Positions {
        self.positions
    }

    /// The best proof counts as one child.
    fn batch_limit(has_best_proof: bool) -> usize {
        MAX_CHILDREN - usize::from(has_best_proof)
    }

    fn add_to<'a>(&'a self, request: &mut AggregateRequest<'a>) {
        request.children.push((&self.claims, &self.proof));
    }
}

#[cfg(test)]
mod tests;
