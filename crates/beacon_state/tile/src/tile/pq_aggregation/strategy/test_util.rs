use super::*;

pub fn claim(tag: u8) -> Claim {
    [tag; 64]
}

pub fn claims(tags: &[u8]) -> Vec<Claim> {
    tags.iter().copied().map(claim).collect()
}

pub fn waiting_claims<'a>(
    index: usize,
    kind: ClaimsKind,
    claims: &'a [Claim],
    best_claims: &[Claim],
) -> WaitingClaims<'a> {
    let new_claim_count = claims.iter().filter(|c| !best_claims.contains(c)).count();
    WaitingClaims { index, kind, claims, new_claim_count }
}

pub fn batch_input<'a>(
    limits: BatchLimits,
    best_claims: Option<&'a [Claim]>,
    waiting: &'a [WaitingClaims<'a>],
) -> BatchInput<'a> {
    BatchInput { limits, best_claims, waiting }
}
