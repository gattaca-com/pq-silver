use super::*;

pub fn claim(tag: u8) -> Claim {
    [tag; 64]
}

pub fn claims(tags: &[u8]) -> Vec<Claim> {
    tags.iter().copied().map(claim).collect()
}

/// Each of `sets` as waiting claims, at its own index.
pub fn all_waiting<'a>(sets: &'a [Vec<Claim>], best_claims: &[Claim]) -> Vec<WaitingClaims<'a>> {
    let waiting = |(index, claims): (usize, &'a Vec<Claim>)| {
        let new_claim_count = claims.iter().filter(|c| !best_claims.contains(c)).count();
        WaitingClaims { index, claims, new_claim_count }
    };
    sets.iter().enumerate().map(waiting).collect()
}

pub fn batch_input<'a>(
    limit: usize,
    best_claims: Option<&'a [Claim]>,
    waiting: &'a [WaitingClaims<'a>],
) -> BatchInput<'a> {
    BatchInput { limit, best_claims, waiting }
}
