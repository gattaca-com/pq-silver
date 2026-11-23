mod arrival_order;
mod bits;
mod marginal_gain;

pub use arrival_order::ArrivalOrder;
pub use bits::Bits;
pub(super) use marginal_gain::MAX_GROUPS;
pub use marginal_gain::{Committee, MarginalGain, Positions};

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

    /// How many waiting indices add positions. Zero exactly when `next_batch`
    /// is `None`.
    fn waiting(&self) -> usize;
}

/// Indices of verified claims to prove on top of the best proof: ascending,
/// without repeats, never empty.
#[derive(Debug)]
pub struct Batch {
    indices: Vec<usize>,
}

impl Batch {
    /// `None` when `indices` is empty.
    fn new(mut indices: Vec<usize>) -> Option<Self> {
        indices.sort_unstable();
        debug_assert!(
            indices.windows(2).all(|pair| pair[0] < pair[1]),
            "a strategy repeated an index"
        );
        (!indices.is_empty()).then_some(Self { indices })
    }

    pub fn indices(&self) -> &[usize] {
        &self.indices
    }
}

#[cfg(test)]
mod tests;
