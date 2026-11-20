//! Post-quantum aggregation: votes and aggregates proved into one growing
//! proof by the leanVM sidecar, a separate process.
//!
//! A leaf proves the votes of one committee for one attestation data. A
//! merge proves the aggregates of one slot for the block body. Each extends
//! its best proof batch by batch.
//!
//! [`PqAggregator`] routes verified claims and responses, and keeps one
//! request in flight. Each aggregation owns its verified claims, its best
//! proof and every check on a response. Its strategy picks the next batch
//! and never sees claim bytes.

mod aggregation;
mod aggregator;
mod claims;
mod leaf;
mod merge;
mod strategy;
pub(super) mod wire;

use aggregation::Aggregation;
pub use aggregator::PqAggregator;
pub use claims::{Aggregate, Claim, VerifiedVote};

/// An `AttestationPq` of committee `index`, in the largest committee.
#[cfg(test)]
pub(in crate::tile) fn attestation(
    index: usize,
    positions: impl IntoIterator<Item = usize>,
) -> Vec<u8> {
    use silver_common::ssz_view::{
        ATTESTATION_DATA_SIZE, AttestationPqView, MAX_VALIDATORS_PER_COMMITTEE,
    };
    let data = [3; ATTESTATION_DATA_SIZE];
    AttestationPqView::encode_one_committee(&data, index, MAX_VALIDATORS_PER_COMMITTEE, positions)
        .unwrap()
}
