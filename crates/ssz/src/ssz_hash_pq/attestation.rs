use flux_profiler::timed;

use crate::{
    merkle::{
        B256, MerkleStack, ZERO_HASH, bitlist_len, hash_bitlist, hash_bytelist, hash_concat,
        hash_uint64_list, merkleize, uint64_chunk,
    },
    progressive::{ProgressiveContainer, ProgressiveHasher, active_fields},
    ssz_hash::hash_attestation_data,
    ssz_view::{
        AttestationPqView, AttesterSlashingPqView, IndexedAttestationPqView, MAX_STARK_PROOF_SIZE,
        SignedAggregateAndProofPqView,
    },
};

/// `AttestationProof`: a plain `ByteList[MAX_STARK_PROOF_SIZE]`.
pub(crate) fn attestation_proof_root(proof: &[u8]) -> B256 {
    hash_bytelist(MerkleStack::new(MAX_STARK_PROOF_SIZE / 32), proof)
}

impl ProgressiveContainer for AttestationPqView {
    const ACTIVE_FIELDS: B256 = active_fields(4, &[2]);
}

impl AttestationPqView {
    #[timed]
    pub fn hash_tree_root(d: &[u8]) -> B256 {
        if !Self::check_canonical(d) {
            return ZERO_HASH;
        }
        Self::root_of_canonical(d)
    }

    pub(crate) fn root_of_canonical(d: &[u8]) -> B256 {
        debug_assert!(Self::check_canonical(d));
        let aggregation_bits = Self::aggregation_bits(d);
        let aggregation_bits_root =
            hash_bitlist(ProgressiveHasher::new(), aggregation_bits, bitlist_len(aggregation_bits));
        let data_root = hash_attestation_data(&d[4..132]);
        let mut committee_bits = ZERO_HASH;
        committee_bits[..Self::committee_bits(d).len()].copy_from_slice(Self::committee_bits(d));
        Self::root_of_active_fields(&[aggregation_bits_root, data_root, committee_bits])
    }
}

impl ProgressiveContainer for IndexedAttestationPqView {
    const ACTIVE_FIELDS: B256 = active_fields(3, &[]);
}

impl IndexedAttestationPqView {
    #[timed]
    pub fn hash_tree_root(d: &[u8]) -> B256 {
        if !Self::check_size(d) {
            return ZERO_HASH;
        }
        Self::root_of_canonical(d)
    }

    fn root_of_canonical(d: &[u8]) -> B256 {
        debug_assert!(Self::check_size(d));
        let indices = Self::attesting_indices(d);
        Self::root_of_active_fields(&[
            hash_uint64_list(ProgressiveHasher::new(), indices, indices.len() / 8),
            hash_attestation_data(&d[4..132]),
            attestation_proof_root(Self::proof(d)),
        ])
    }
}

impl AttesterSlashingPqView {
    #[timed]
    pub fn hash_tree_root(d: &[u8]) -> B256 {
        if !Self::check_size(d) {
            return ZERO_HASH;
        }
        Self::root_of_canonical(d)
    }

    pub(crate) fn root_of_canonical(d: &[u8]) -> B256 {
        debug_assert!(Self::check_size(d));
        hash_concat(
            &IndexedAttestationPqView::root_of_canonical(Self::attestation_1(d)),
            &IndexedAttestationPqView::root_of_canonical(Self::attestation_2(d)),
        )
    }
}

impl SignedAggregateAndProofPqView {
    /// Root of the signed `AggregateAndProof`, a plain Container.
    #[timed]
    pub fn message_root(d: &[u8]) -> B256 {
        if !Self::check_size(d) {
            return ZERO_HASH;
        }
        merkleize(&[
            uint64_chunk(Self::aggregator_index(d)),
            AttestationPqView::root_of_canonical(Self::aggregate(d)),
            attestation_proof_root(Self::proof(d)),
        ])
    }
}

/// Root of an unsigned `AggregateAndProof`; `ZERO_HASH` when `aggregate` is
/// not a canonical PQ `Attestation`.
pub fn hash_tree_root_aggregate_and_proof(
    aggregator_index: u64,
    aggregate: &[u8],
    proof: &[u8],
) -> B256 {
    if !AttestationPqView::check_canonical(aggregate) {
        return ZERO_HASH;
    }
    merkleize(&[
        uint64_chunk(aggregator_index),
        AttestationPqView::root_of_canonical(aggregate),
        attestation_proof_root(proof),
    ])
}
