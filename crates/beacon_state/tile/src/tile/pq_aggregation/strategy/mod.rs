mod arrival_order;
mod marginal_gain;

pub use arrival_order::ArrivalOrder;
pub use marginal_gain::MarginalGain;

const LOG_INV_RATE: u8 = 2;

/// Picks the batches of one aggregation. It keeps its own view of committee
/// positions, fed by events, and never sees claim bytes.
pub trait Strategy: Default {
    /// What the strategy reads of one verified claims.
    type Positions;

    /// The verified claims at `index` arrived, above every earlier index.
    /// `false` refuses them: their positions do not fit the view.
    fn arrived(&mut self, index: usize, positions: Self::Positions) -> bool;

    /// The best proof now covers `batch` as well.
    fn adopted(&mut self, batch: &Batch);

    /// At most `limit` waiting indices that add positions. `None` when none
    /// does.
    fn next_batch(&self, limit: usize) -> Option<Batch>;
}

/// Indices of verified claims to prove on top of the best proof: ascending,
/// without repeats, never empty.
#[derive(Debug)]
pub struct Batch {
    indices: Vec<usize>,
    log_inv_rate: u8,
}

impl Batch {
    /// `None` when `indices` is empty.
    fn new(mut indices: Vec<usize>) -> Option<Self> {
        indices.sort_unstable();
        let picked = indices.len();
        indices.dedup();
        debug_assert_eq!(indices.len(), picked, "a strategy repeated an index");
        (!indices.is_empty()).then_some(Self { indices, log_inv_rate: LOG_INV_RATE })
    }

    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    pub fn log_inv_rate(&self) -> u8 {
        self.log_inv_rate
    }
}

#[cfg(test)]
mod tests;
