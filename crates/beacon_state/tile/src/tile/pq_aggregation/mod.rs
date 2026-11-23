//! Post-quantum aggregation: votes and aggregates proved into one growing
//! proof by the leanVM sidecar, a separate process.
//!
//! A leaf proves the votes of one committee for one attestation data. A
//! merge proves the aggregates of one slot for the block body. Each extends
//! its best proof batch by batch.
//!
//! [`PqAggregator`] routes verified claims and responses, and keeps one
//! request in flight. A leaf or a merge owns its strategy, which picks the
//! next batch and never sees claim bytes. Its core owns the verified claims,
//! the best proof and every check on a response.

mod aggregation;
mod aggregator;
mod arena;
mod claims;
mod leaf;
mod merge;
mod strategy;
#[cfg(test)]
pub(super) mod test_util;
pub(super) mod wire;

pub use aggregator::PqAggregator;
pub use claims::{Aggregate, Claim, VerifiedVote, claim};
