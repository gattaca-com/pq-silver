use super::{Batch, BatchInput, ClaimsKind, WaitingClaims};

/// Every waiting `VerifiedClaims` that adds a claim, in arrival order, within
/// the batch limits.
pub(super) fn next_batch(input: &BatchInput) -> Option<Batch> {
    let mut indices = pick(input, ClaimsKind::Vote, input.limits.max_signatures);
    indices.extend(pick(input, ClaimsKind::Aggregate, input.new_child_limit()));
    Batch::new(indices)
}

/// The first `limit` waiting `VerifiedClaims` of `kind` that add a claim.
pub(super) fn pick(input: &BatchInput, kind: ClaimsKind, limit: usize) -> Vec<usize> {
    let adds_claims =
        |waiting: &&WaitingClaims| waiting.kind == kind && waiting.new_claim_count > 0;
    input.waiting.iter().filter(adds_claims).take(limit).map(|waiting| waiting.index).collect()
}

#[cfg(test)]
mod tests;
