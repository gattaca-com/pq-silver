//! Post-quantum aggregation: votes and aggregates proved into one growing
//! proof by the leanVM sidecar, a separate process.
//!
//! An aggregation keeps one proof and extends it batch by batch. A leaf
//! proves the votes of one committee for one attestation data. A merge
//! proves the aggregates of one slot for the block body.
//!
//! [`PqAggregator`] owns every aggregation and talks to the spine: it routes
//! verified claims and responses, and keeps one request in flight. Each
//! aggregation owns its verified claims, its proof and every check on a
//! response. A strategy only
//! picks the next batch, from a view that holds no bytes.

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
