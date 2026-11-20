use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, binary_heap::PeekMut},
};

use silver_common::{Nanos, TCacheProducer, TCacheRead, TProducer};

use super::{
    claims::{Claim, VerifiedClaims},
    strategy::{Batch, Strategy},
    wire::{AggregateRequest, MAX_REQUEST_LEN, decode_aggregate_response},
};

const MAX_FAILURES: u8 = 3;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority {
    /// A merge goes before any leaf.
    merge: bool,
    /// Then the earliest deadline.
    deadline: Reverse<Nanos>,
    /// Then the most waiting claims that add something.
    waiting: usize,
}

/// The aggregation of one key. It owns the verified claims, the best proof and
/// every check. Its strategy decides what to prove.
pub struct Aggregation<C: VerifiedClaims> {
    strategy: C::Strategy,
    deadline: Nanos,
    verified: Vec<C>,
    best: Option<BestProof>,
    /// Failed batches since the best proof last grew.
    failures: u8,
}

impl<C: VerifiedClaims> Aggregation<C> {
    pub fn new(deadline: Nanos) -> Self {
        let strategy = C::Strategy::default();
        Self { strategy, deadline, verified: Vec::new(), best: None, failures: 0 }
    }

    /// `false` if the strategy refuses the positions of `verified`.
    pub fn add(&mut self, verified: C) -> bool {
        let fits = self.strategy.arrived(self.verified.len(), verified.positions());
        if fits {
            self.verified.push(verified);
        }
        fits
    }

    /// The verified claims the best proof covers, in arrival order.
    pub fn covered(&self) -> impl Iterator<Item = &C> {
        let best = self.best.iter().flat_map(|best| &best.covered_indices);
        best.map(|&index| &self.verified[index])
    }

    pub fn proof(&self) -> Option<(&[Claim], &[u8])> {
        self.best.as_ref().map(|best| (best.claims.as_slice(), best.proof.as_slice()))
    }

    pub fn is_stopped(&self) -> bool {
        self.failures >= MAX_FAILURES
    }

    /// `None` when it has nothing to send: past its deadline, stopped, or
    /// nothing waiting adds a claim. The strategy keeps the count.
    pub fn priority(&self, now: Nanos) -> Option<Priority> {
        let waiting = self.strategy.waiting();
        let sends = now < self.deadline && !self.is_stopped() && waiting > 0;
        sends.then_some(Priority { merge: C::MERGE, deadline: Reverse(self.deadline), waiting })
    }

    /// The next batch, with its request written to `tcache`. `None` for a
    /// strategy bug, or a full tcache: the batch is dropped and its claims
    /// still wait.
    pub fn next_request(
        &mut self,
        now: Nanos,
        tcache: &mut TProducer,
    ) -> Option<(Batch, TCacheRead)> {
        let batch = self.next_batch(now)?;
        let request = self.request(&batch);
        debug_assert!(request.len() <= MAX_REQUEST_LEN, "a request above the protocol bounds");
        let body = tcache.write_with(request.len(), |out| request.write(out))?;
        Some((batch, body))
    }

    /// `None` exactly when `priority` is, unless the strategy has a bug. A
    /// bug counts as a failure, so it cannot repeat forever.
    fn next_batch(&mut self, now: Nanos) -> Option<Batch> {
        self.priority(now)?;
        let batch = self.strategy.next_batch(self.batch_limit());
        let batch = batch.filter(|batch| self.accepts(batch));
        if batch.is_none() {
            silver_log::error!("strategy returned no valid batch");
            debug_assert!(false, "strategy returned no valid batch");
            self.failures += 1;
        }
        batch
    }

    fn request(&self, batch: &Batch) -> AggregateRequest<'_> {
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

    /// `false` for a batch above the batch limit or with verified claims that
    /// are not waiting.
    fn accepts(&self, batch: &Batch) -> bool {
        let indices = batch.indices();
        let all_waiting =
            indices.iter().all(|&index| index < self.verified.len() && !self.is_covered(index));
        all_waiting && indices.len() <= self.batch_limit()
    }

    fn adopt_response(&mut self, body: &[u8], batch: &Batch) -> Result<(), &'static str> {
        let (claims, proof) = decode_aggregate_response(body)?;
        let best = self.best.iter().map(|best| best.claims.as_slice());
        let batch_claims = batch.indices().iter().map(|&index| self.verified[index].claims());
        if !is_union(&claims, best.chain(batch_claims)) {
            return Err("the proof covers other claims");
        }
        let mut covered_indices =
            self.best.take().map_or_else(Vec::new, |best| best.covered_indices);
        covered_indices.extend(batch.indices());
        covered_indices.sort_unstable();
        self.best = Some(BestProof { claims, proof: proof.to_vec(), covered_indices });
        self.strategy.adopted(batch);
        Ok(())
    }
}

/// Whether strictly ascending `claims` is exactly the union of `sets`, each
/// sorted without repeats. A merge of the sets: no copy, no sort.
fn is_union<'a>(claims: &[Claim], sets: impl Iterator<Item = &'a [Claim]>) -> bool {
    // Slices order by their first claim first, so the top holds the least.
    let mut heads: BinaryHeap<Reverse<&[Claim]>> =
        sets.filter(|set| !set.is_empty()).map(Reverse).collect();
    for claim in claims {
        let mut found = false;
        while let Some(mut top) = heads.peek_mut() {
            match top.0[0].cmp(claim) {
                // `claims` passed this one without taking it.
                Ordering::Less => return false,
                Ordering::Greater => break,
                Ordering::Equal => {
                    found = true;
                    top.0 = &top.0[1..];
                    if top.0.is_empty() {
                        PeekMut::pop(top);
                    }
                }
            }
        }
        if !found {
            return false;
        }
    }
    heads.is_empty()
}

#[cfg(test)]
mod tests;
