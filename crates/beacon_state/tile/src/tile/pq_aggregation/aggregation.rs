use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, binary_heap::PeekMut},
};

use silver_common::{Nanos, TCacheProducer, TCacheRead, TProducer, ssz_view::XMSS_SIGNATURE_SIZE};

use super::{
    claims::Claim,
    strategy::Batch,
    wire::{AggregateRequest, MAX_REQUEST_LEN, decode_aggregate_response},
};

const MAX_FAILURES: u8 = 3;

/// One verified item to prove: its claims and what it adds to a request.
pub enum Item {
    /// A vote: its claim and leanXMSS signature, as a record.
    Record(Claim, Box<[u8; XMSS_SIGNATURE_SIZE]>),
    /// An aggregate: its claims, sorted without repeats, and their proof.
    Child(Vec<Claim>, Vec<u8>),
}

impl Item {
    fn claims(&self) -> &[Claim] {
        match self {
            Self::Record(claim, _) => std::slice::from_ref(claim),
            Self::Child(claims, _) => claims,
        }
    }

    fn add_to<'a>(&'a self, request: &mut AggregateRequest<'a>) {
        match self {
            Self::Record(claim, signature) => request.records.push((claim, signature)),
            Self::Child(claims, proof) => request.children.push((claims, proof)),
        }
    }
}

/// `claims` is exactly the union of the items at `covered_indices`.
struct BestProof {
    /// Sorted, without repeats.
    claims: Vec<Claim>,
    proof: Vec<u8>,
    /// Indices into the items, ascending.
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
    pub merge: bool,
    /// Then the earliest deadline.
    pub deadline: Reverse<Nanos>,
    /// Then the most waiting items that add something.
    pub waiting: usize,
}

/// The core of one aggregation: its items, the best proof and every check.
/// Its wrapper picks the batches.
pub struct Aggregation {
    deadline: Nanos,
    items: Vec<Item>,
    best: Option<BestProof>,
    /// Failed batches since the best proof last grew.
    failures: u8,
}

impl Aggregation {
    pub fn new(deadline: Nanos) -> Self {
        Self { deadline, items: Vec::new(), best: None, failures: 0 }
    }

    /// The item takes the next index.
    pub fn add(&mut self, item: Item) {
        self.items.push(item);
    }

    /// Indices of the items the best proof covers, ascending.
    pub fn covered(&self) -> &[usize] {
        self.best.as_ref().map_or(&[], |best| &best.covered_indices)
    }

    pub fn proof(&self) -> Option<(&[Claim], &[u8])> {
        self.best.as_ref().map(|best| (best.claims.as_slice(), best.proof.as_slice()))
    }

    pub fn is_stopped(&self) -> bool {
        self.failures >= MAX_FAILURES
    }

    /// The deadline, or `None` once it may not send: at or past the
    /// deadline, or stopped.
    pub fn open_deadline(&self, now: Nanos) -> Option<Reverse<Nanos>> {
        (now < self.deadline && !self.is_stopped()).then_some(Reverse(self.deadline))
    }

    /// `batch` if it holds at most `limit` items, all waiting. Anything else
    /// is a strategy bug. A bug counts as a failure, so it cannot repeat
    /// forever.
    pub fn accept(&mut self, batch: Option<Batch>, limit: usize) -> Option<Batch> {
        let batch = batch.filter(|batch| self.accepts(batch, limit));
        if batch.is_none() {
            silver_log::error!("strategy returned no valid batch");
            debug_assert!(false, "strategy returned no valid batch");
            self.failures += 1;
        }
        batch
    }

    /// Writes the request of `batch` to `tcache`. `None` for a full tcache:
    /// the batch is dropped and its items still wait.
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
        let children = (self.best.iter())
            .map(|best| (best.claims.as_slice(), best.proof.as_slice()))
            .collect();
        let log_inv_rate = batch.log_inv_rate();
        let mut request = AggregateRequest { log_inv_rate, children, records: Vec::new() };
        for &index in batch.indices() {
            self.items[index].add_to(&mut request);
        }
        request
    }

    /// Settles `batch` with the leanVM sidecar's response body, or `None`
    /// without an answer. The response's proof becomes the best proof only if
    /// it proves exactly the claims of the covered items and the batch. A
    /// refusal counts as a failure.
    pub fn finish(&mut self, batch: &Batch, body: Option<&[u8]>) -> Result<(), &'static str> {
        let best = body.ok_or("no answer").and_then(|body| self.adopt_response(body, batch));
        self.failures = if best.is_ok() { 0 } else { self.failures + 1 };
        best
    }

    fn is_covered(&self, index: usize) -> bool {
        self.best.as_ref().is_some_and(|best| best.covers(index))
    }

    fn accepts(&self, batch: &Batch, limit: usize) -> bool {
        let indices = batch.indices();
        let all_waiting =
            indices.iter().all(|&index| index < self.items.len() && !self.is_covered(index));
        all_waiting && indices.len() <= limit
    }

    fn adopt_response(&mut self, body: &[u8], batch: &Batch) -> Result<(), &'static str> {
        let (claims, proof) = decode_aggregate_response(body)?;
        let best = self.best.iter().map(|best| best.claims.as_slice());
        let batch_claims = batch.indices().iter().map(|&index| self.items[index].claims());
        if !is_union(&claims, best.chain(batch_claims)) {
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
