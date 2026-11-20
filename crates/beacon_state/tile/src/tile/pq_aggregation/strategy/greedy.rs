use super::{Batch, BatchInput};

/// The first waiting `VerifiedClaims` that add a claim, in arrival order, up
/// to the limit.
pub(super) fn next_batch(input: &BatchInput) -> Option<Batch> {
    let adds_claims = input.waiting.iter().filter(|waiting| waiting.new_claim_count > 0);
    Batch::new(adds_claims.take(input.limit).map(|waiting| waiting.index).collect())
}

#[cfg(test)]
mod tests;
