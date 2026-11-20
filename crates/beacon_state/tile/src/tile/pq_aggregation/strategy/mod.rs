mod greedy;
mod max_coverage;
#[cfg(test)]
mod test_util;

use super::claims::Claim;

const LOG_INV_RATE: u8 = 2;

#[derive(Clone, Debug)]
pub enum Strategy {
    Greedy,
    MaxCoverage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchLimits {
    pub max_signatures: usize,
    /// The best proof counts as one child.
    pub max_children: usize,
}

impl BatchLimits {
    pub const LEAF: Self = Self { max_signatures: 2048, max_children: 16 };
    pub const MERGE: Self = Self { max_signatures: 0, max_children: 16 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimsKind {
    Vote,
    Aggregate,
}

pub struct WaitingClaims<'a> {
    pub index: usize,
    pub kind: ClaimsKind,
    /// Sorted, without repeats.
    pub claims: &'a [Claim],
    /// How many of `claims` the best proof lacks.
    pub new_claim_count: usize,
}

/// What a strategy sees: no bytes, no clock, no spine.
pub struct BatchInput<'a> {
    pub limits: BatchLimits,
    /// Sorted.
    pub best_claims: Option<&'a [Claim]>,
    pub waiting: &'a [WaitingClaims<'a>],
}

/// VerifiedClaims indices to prove on top of the best proof: ascending, without
/// repeats, never empty.
#[derive(Debug)]
pub struct Batch {
    indices: Vec<usize>,
    log_inv_rate: u8,
}

impl Batch {
    /// `None` when `indices` is empty.
    fn new(mut indices: Vec<usize>) -> Option<Self> {
        indices.sort_unstable();
        let picked = indices.len();
        indices.dedup();
        debug_assert_eq!(indices.len(), picked, "a strategy repeated an index");
        (!indices.is_empty()).then_some(Self { indices, log_inv_rate: LOG_INV_RATE })
    }

    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    pub fn log_inv_rate(&self) -> u8 {
        self.log_inv_rate
    }
}

impl BatchInput<'_> {
    /// The child limit left once the best proof takes its place.
    fn new_child_limit(&self) -> usize {
        self.limits.max_children.saturating_sub(usize::from(self.best_claims.is_some()))
    }
}

impl Strategy {
    pub(super) fn next_batch(&mut self, input: &BatchInput) -> Option<Batch> {
        match self {
            Self::Greedy => greedy::next_batch(input),
            Self::MaxCoverage => max_coverage::next_batch(input),
        }
    }
}

#[cfg(test)]
mod tests;
