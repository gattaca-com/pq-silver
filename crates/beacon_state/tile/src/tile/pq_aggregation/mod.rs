//! Post-quantum aggregation for local aggregator duties and block proposals.
//!
//! `ProofSources` stores verified votes and aggregates.
//! `ProofTargets` holds the proofs each duty or proposal needs.
//! The target with the earliest deadline goes first.
//! The planner sizes each merge using the learnt request cost.
//! [`PqAggregator`] keeps one leanVM request in flight.

mod aggregator;
mod bits;
mod claims;
mod cost_model;
mod deadline_tracker;
mod merge_planner;
mod proof_sources;
mod proof_store;
mod proof_targets;
mod proved;
mod running_proof;
mod segments;
mod slot_aggregates;
mod slot_votes;
mod stats;
#[cfg(test)]
pub(super) mod test_util;

pub use aggregator::PqAggregator;
pub use claims::{Claim, VerifiedVote, claim};
