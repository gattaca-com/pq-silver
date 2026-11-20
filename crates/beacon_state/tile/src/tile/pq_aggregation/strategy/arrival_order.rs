use silver_common::ssz_view::MAX_VALIDATORS_PER_COMMITTEE;

use super::{super::claims::Bits, Batch, Strategy};

/// Votes in arrival order, each at a position neither covered nor picked
/// earlier in the batch, up to the limit.
#[derive(Default)]
pub struct ArrivalOrder {
    /// Positions the best proof covers.
    covered: Bits,
    /// Votes at positions not covered, in arrival order.
    waiting: Vec<Waiting>,
}

struct Waiting {
    index: usize,
    position: usize,
}

impl Strategy for ArrivalOrder {
    /// The vote's committee position.
    type Positions = usize;

    fn arrived(&mut self, index: usize, position: usize) -> bool {
        let fits = position < MAX_VALIDATORS_PER_COMMITTEE;
        if fits {
            self.waiting.push(Waiting { index, position });
        }
        fits
    }

    fn adopted(&mut self, batch: &Batch) {
        for waiting in &self.waiting {
            if batch.indices().binary_search(&waiting.index).is_ok() {
                self.covered.insert(waiting.position);
            }
        }
        self.waiting.retain(|waiting| !self.covered.contains(waiting.position));
    }

    fn next_batch(&self, limit: usize) -> Option<Batch> {
        let mut picked = self.covered;
        let fresh = self.waiting.iter().filter(|waiting| picked.insert(waiting.position));
        Batch::new(fresh.take(limit).map(|waiting| waiting.index).collect())
    }
}

#[cfg(test)]
mod tests;
