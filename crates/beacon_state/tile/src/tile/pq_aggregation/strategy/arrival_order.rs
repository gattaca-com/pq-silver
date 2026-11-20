use silver_common::ssz_view::MAX_VALIDATORS_PER_COMMITTEE;

use super::{super::claims::Bits, Batch, Strategy};

/// Votes in arrival order, the first at each position not covered, up to the
/// limit.
#[derive(Default)]
pub struct ArrivalOrder {
    /// Positions the best proof covers or a waiting vote holds.
    seen: Bits,
    /// Indices of the votes at positions not covered, one per position, in
    /// arrival order.
    waiting: Vec<usize>,
}

impl Strategy for ArrivalOrder {
    /// The vote's committee position.
    type Positions = usize;

    /// A vote at a seen position adds nothing, so it does not wait.
    fn arrived(&mut self, index: usize, position: usize) -> bool {
        let fits = position < MAX_VALIDATORS_PER_COMMITTEE;
        if fits && self.seen.insert(position) {
            self.waiting.push(index);
        }
        fits
    }

    fn adopted(&mut self, batch: &Batch) {
        self.waiting.retain(|index| batch.indices().binary_search(index).is_err());
    }

    fn next_batch(&self, limit: usize) -> Option<Batch> {
        Batch::new(self.waiting.iter().copied().take(limit).collect())
    }

    fn waiting(&self) -> usize {
        self.waiting.len()
    }
}

#[cfg(test)]
mod tests;
