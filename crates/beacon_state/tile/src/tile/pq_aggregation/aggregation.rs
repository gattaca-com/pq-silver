use silver_common::Nanos;

use super::{
    claims::{Claim, VerifiedClaims},
    strategy::{Batch, BatchInput, Strategy, WaitingClaims},
    wire::{AggregateRequest, decode_aggregate_response},
};

const MAX_FAILURES: u8 = 3;

/// The proof an aggregation holds. `claims` is exactly the union of the
/// claims of the verified claims at `covered_indices`.
struct BestProof {
    /// Sorted, without repeats.
    claims: Vec<Claim>,
    proof: Vec<u8>,
    /// Indices into the verified claims, ascending.
    covered_indices: Vec<usize>,
}

impl BestProof {
    fn covers(&self, index: usize) -> bool {
        self.covered_indices.binary_search(&index).is_ok()
    }
}

/// The aggregation of one key: it owns the verified claims, the best proof and
/// every check, and never decides what to prove. The strategy decides.
pub struct Aggregation<C> {
    strategy: Strategy,
    deadline: Nanos,
    verified: Vec<C>,
    best: Option<BestProof>,
    /// Failed batches since the best proof last grew.
    failures: u8,
}

impl<C: VerifiedClaims> Aggregation<C> {
    pub fn new(strategy: Strategy, deadline: Nanos) -> Self {
        Self { strategy, deadline, verified: Vec::new(), best: None, failures: 0 }
    }

    pub fn add(&mut self, verified: C) {
        self.verified.push(verified);
    }

    /// The verified claims the best proof covers, in arrival order.
    pub fn covered(&self) -> impl Iterator<Item = &C> {
        let best = self.best.iter().flat_map(|best| &best.covered_indices);
        best.map(|&index| &self.verified[index])
    }

    /// The claims of the best proof, and the proof.
    pub fn proof(&self) -> Option<(&[Claim], &[u8])> {
        self.best.as_ref().map(|best| (best.claims.as_slice(), best.proof.as_slice()))
    }

    pub fn is_stopped(&self) -> bool {
        self.failures >= MAX_FAILURES
    }

    /// `None` at or past the deadline, once stopped, or when the strategy
    /// picks nothing.
    pub fn next_batch(&mut self, now: Nanos) -> Option<Batch> {
        if now >= self.deadline || self.is_stopped() {
            return None;
        }
        let best = self.best.as_ref();
        let lacks =
            |claim: &&Claim| best.is_none_or(|best| best.claims.binary_search(claim).is_err());
        let waiting: Vec<WaitingClaims> = (self.verified.iter().enumerate())
            .filter(|&(index, _)| !self.is_covered(index))
            .map(|(index, verified)| {
                let claims = verified.claims();
                let new_claim_count = claims.iter().filter(lacks).count();
                WaitingClaims { index, claims, new_claim_count }
            })
            .collect();
        let best_claims = best.map(|best| best.claims.as_slice());
        let input = BatchInput { limit: self.batch_limit(), best_claims, waiting: &waiting };
        let batch = self.strategy.next_batch(&input)?;
        self.accepts(&batch).then_some(batch)
    }

    pub fn request(&self, batch: &Batch) -> AggregateRequest<'_> {
        let children = (self.best.iter())
            .map(|best| (best.claims.as_slice(), best.proof.as_slice()))
            .collect();
        let log_inv_rate = batch.log_inv_rate();
        let mut request = AggregateRequest { log_inv_rate, children, records: Vec::new() };
        for &index in batch.indices() {
            self.verified[index].add_to(&mut request);
        }
        request
    }

    /// Settles `batch` with the leanVM sidecar's response body, or `None`
    /// without an answer. The response's proof becomes the best proof only if
    /// it proves exactly the claims of the covered verified claims and the
    /// batch. A refusal counts as a failure.
    pub fn finish(&mut self, batch: Batch, body: Option<&[u8]>) -> Result<(), &'static str> {
        let best = body.ok_or("no answer").and_then(|body| self.adopt_response(body, &batch));
        self.failures = if best.is_ok() { 0 } else { self.failures + 1 };
        best
    }

    fn is_covered(&self, index: usize) -> bool {
        self.best.as_ref().is_some_and(|best| best.covers(index))
    }

    fn batch_limit(&self) -> usize {
        C::batch_limit(self.best.is_some())
    }

    /// A batch above the batch limit or with verified claims that are not
    /// waiting is a strategy bug.
    fn accepts(&self, batch: &Batch) -> bool {
        let indices = batch.indices();
        let all_waiting =
            indices.iter().all(|&index| index < self.verified.len() && !self.is_covered(index));
        let ok = all_waiting && indices.len() <= self.batch_limit();
        if !ok {
            silver_log::error!("strategy returned an invalid batch");
            debug_assert!(false, "strategy returned an invalid batch");
        }
        ok
    }

    fn adopt_response(&mut self, body: &[u8], batch: &Batch) -> Result<(), &'static str> {
        let (claims, proof) = decode_aggregate_response(body)?;
        let mut expected: Vec<Claim> =
            self.best.iter().flat_map(|best| best.claims.iter().copied()).collect();
        expected.extend(batch.indices().iter().flat_map(|&index| self.verified[index].claims()));
        expected.sort_unstable();
        expected.dedup();
        if claims != expected {
            return Err("the proof covers other claims");
        }
        let mut covered_indices =
            self.best.take().map_or_else(Vec::new, |best| best.covered_indices);
        covered_indices.extend(batch.indices());
        covered_indices.sort_unstable();
        self.best = Some(BestProof { claims, proof: proof.to_vec(), covered_indices });
        Ok(())
    }
}

#[cfg(test)]
mod tests;
