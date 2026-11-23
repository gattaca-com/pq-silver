use std::cmp::Reverse;

use silver_common::{Nanos, TCacheProducer, TCacheRead, TProducer, ssz_view::XMSS_SIGNATURE_SIZE};

use super::{
    arena::Arena,
    claims::Claim,
    strategy::Batch,
    wire::{AggregateRequest, AggregateResponse, MAX_REQUEST_LEN},
};

const MAX_FAILURES: u8 = 3;

/// Claims verified by a signature or a proof.
enum VerifiedClaims {
    /// A vote: its claim and leanXMSS signature.
    Signature(Claim, Box<[u8; XMSS_SIGNATURE_SIZE]>),
    /// An aggregate: its index in the proof arenas.
    Proof(usize),
}

/// The aggregates' claims and proofs, one run each per aggregate.
#[derive(Default)]
struct ProofArenas {
    /// Each run sorted, without repeats.
    claims: Arena<Claim>,
    proofs: Arena<u8>,
}

/// `claims` is exactly the union of the verified claims at `covered_indices`.
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

/// How much an aggregation wants the leanVM sidecar; the highest goes first.
/// Fields compare in declaration order.
///
/// A leaf of slot `S` ends at `aggregate_due(S)`. A merge for the block of
/// slot `B` ends at `slot_start(B)`, later than the due time of `B - 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority {
    /// The earliest deadline first, leaf or merge.
    pub deadline: Reverse<Nanos>,
    /// Then the most waiting verified claims that add something.
    pub waiting: usize,
}

/// The core of one aggregation: its verified claims, the best proof and every
/// check. Its wrapper picks the batches.
pub struct Aggregation {
    deadline: Nanos,
    verified: Vec<VerifiedClaims>,
    proofs: ProofArenas,
    best: Option<BestProof>,
    /// Failed batches since the best proof last grew.
    failures: u8,
}

impl Aggregation {
    pub fn new(deadline: Nanos) -> Self {
        let (verified, proofs) = (Vec::new(), ProofArenas::default());
        Self { deadline, verified, proofs, best: None, failures: 0 }
    }

    /// Empty again, keeping its buffers.
    pub fn reset(&mut self, deadline: Nanos) {
        self.deadline = deadline;
        self.verified.clear();
        self.proofs.claims.clear();
        self.proofs.proofs.clear();
        self.best = None;
        self.failures = 0;
    }

    /// The vote takes the next index.
    pub fn add_signature(&mut self, claim: Claim, signature: Box<[u8; XMSS_SIGNATURE_SIZE]>) {
        self.verified.push(VerifiedClaims::Signature(claim, signature));
    }

    /// The aggregate takes the next index. `claims` are sorted, without
    /// repeats.
    pub fn add_proof(&mut self, claims: &[Claim], proof: &[u8]) {
        debug_assert!(claims.is_sorted_by(|a, b| a < b), "claims sorted, without repeats");
        self.verified.push(VerifiedClaims::Proof(self.proofs.claims.len()));
        self.proofs.claims.push(claims);
        self.proofs.proofs.push(proof);
    }

    /// Indices of the verified claims the best proof covers, ascending.
    pub fn covered_indices(&self) -> &[usize] {
        self.best.as_ref().map_or(&[], |best| &best.covered_indices)
    }

    pub fn best_proof(&self) -> Option<(&[Claim], &[u8])> {
        self.best.as_ref().map(|best| (best.claims.as_slice(), best.proof.as_slice()))
    }

    pub fn is_stopped(&self) -> bool {
        self.failures >= MAX_FAILURES
    }

    /// `None` at or past its deadline, once stopped, or with nothing waiting.
    pub fn priority(&self, now: Nanos, waiting: usize) -> Option<Priority> {
        let open = now < self.deadline && !self.is_stopped() && waiting > 0;
        open.then_some(Priority { deadline: Reverse(self.deadline), waiting })
    }

    /// `batch` if it holds at most `limit` verified claims, all waiting.
    /// Anything else is a strategy bug. A bug counts as a failure, so it
    /// cannot repeat forever.
    pub fn check_batch(&mut self, batch: Option<Batch>, limit: usize) -> Option<Batch> {
        let batch = batch.filter(|batch| self.is_valid_batch(batch, limit));
        if batch.is_none() {
            silver_log::error!("strategy returned no valid batch");
            debug_assert!(false, "strategy returned no valid batch");
            self.failures += 1;
        }
        batch
    }

    /// Writes the request of `batch` to `tcache`. `None` for a full tcache:
    /// the batch is dropped and its verified claims still wait.
    pub fn write_request(
        &self,
        batch: Batch,
        tcache: &mut TProducer,
    ) -> Option<(Batch, TCacheRead)> {
        let request = self.request(&batch);
        debug_assert!(request.len() <= MAX_REQUEST_LEN, "a request above the protocol bounds");
        let body = tcache.write_with(request.len(), |out| request.write(out))?;
        Some((batch, body))
    }

    fn request(&self, batch: &Batch) -> AggregateRequest<'_> {
        let proofs = (self.best.iter())
            .map(|best| (best.claims.as_slice(), best.proof.as_slice()))
            .collect();
        let log_inv_rate = batch.log_inv_rate();
        let mut request = AggregateRequest { log_inv_rate, proofs, signatures: Vec::new() };
        for &index in batch.indices() {
            match &self.verified[index] {
                VerifiedClaims::Signature(claim, signature) => {
                    request.signatures.push((claim, signature))
                }
                &VerifiedClaims::Proof(at) => {
                    request.proofs.push((self.proofs.claims.get(at), self.proofs.proofs.get(at)))
                }
            }
        }
        request
    }

    fn claims(&self, index: usize) -> &[Claim] {
        match &self.verified[index] {
            VerifiedClaims::Signature(claim, _) => std::slice::from_ref(claim),
            &VerifiedClaims::Proof(at) => self.proofs.claims.get(at),
        }
    }

    /// Settles `batch` with the leanVM sidecar's response body, or `None`
    /// without an answer. The response's proof becomes the best proof only if
    /// it proves exactly the claims of the covered verified claims and the
    /// batch. A refusal counts as a failure.
    pub fn finish(&mut self, batch: &Batch, body: Option<&[u8]>) -> Result<(), &'static str> {
        let best = body.ok_or("no answer").and_then(|body| self.adopt_response(body, batch));
        self.failures = if best.is_ok() { 0 } else { self.failures + 1 };
        best
    }

    fn is_covered(&self, index: usize) -> bool {
        self.best.as_ref().is_some_and(|best| best.covers(index))
    }

    fn is_valid_batch(&self, batch: &Batch, limit: usize) -> bool {
        let indices = batch.indices();
        let all_waiting =
            indices.iter().all(|&index| index < self.verified.len() && !self.is_covered(index));
        all_waiting && indices.len() <= limit
    }

    fn adopt_response(&mut self, body: &[u8], batch: &Batch) -> Result<(), &'static str> {
        let AggregateResponse { claims, proof } = AggregateResponse::decode(body)?;
        if !self.proves_exactly(&claims, batch) {
            return Err("the proof covers other claims");
        }
        let mut covered_indices =
            self.best.take().map_or_else(Vec::new, |best| best.covered_indices);
        covered_indices.extend(batch.indices());
        covered_indices.sort_unstable();
        self.best = Some(BestProof { claims, proof: proof.to_vec(), covered_indices });
        Ok(())
    }

    /// Whether strictly ascending `claims` is exactly the claims of the best
    /// proof and of `batch`. Each set walks `claims` once and marks its own;
    /// all must be marked.
    fn proves_exactly(&self, claims: &[Claim], batch: &Batch) -> bool {
        let best = self.best.iter().map(|best| best.claims.as_slice());
        let batch_claims = batch.indices().iter().map(|&index| self.claims(index));
        let mut seen = vec![false; claims.len()];
        for set in best.chain(batch_claims) {
            let mut index = 0;
            for claim in set {
                index += claims[index..].iter().take_while(|&lower| lower < claim).count();
                if claims.get(index) != Some(claim) {
                    return false;
                }
                seen[index] = true;
            }
        }
        seen.into_iter().all(|seen| seen)
    }
}

#[cfg(test)]
mod tests;
