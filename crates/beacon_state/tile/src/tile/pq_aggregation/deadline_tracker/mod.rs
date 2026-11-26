use std::collections::VecDeque;

use silver_common::{Nanos, ticker::MAXIMUM_GOSSIP_CLOCK_DISPARITY};

const WINDOW: usize = 32;

/// Tracks how far ahead of the spec due time a proof is read.
/// Uses the earliest of the last `WINDOW` reads.
/// Before the first read, uses the gossip clock disparity.
#[derive(Default)]
pub(super) struct DeadlineTracker {
    /// How early each read came before its due time.
    early_reads: VecDeque<Nanos>,
}

impl DeadlineTracker {
    pub(super) fn deadline(&self, due: Nanos) -> Nanos {
        due.saturating_sub(self.early_read())
    }

    pub(super) fn early_read(&self) -> Nanos {
        self.early_reads.iter().copied().max().unwrap_or_else(|| {
            u64::try_from(MAXIMUM_GOSSIP_CLOCK_DISPARITY.as_nanos())
                .expect("the gossip clock disparity fits in nanoseconds")
                .into()
        })
    }

    /// Reads at or after `due` contribute zero.
    /// Reads before `opens` are ignored.
    pub(super) fn record_read(&mut self, due: Nanos, read: Nanos, opens: Nanos) {
        if read >= opens {
            if self.early_reads.len() == WINDOW {
                self.early_reads.pop_front();
            }
            self.early_reads.push_back(due.saturating_sub(read));
        }
    }
}

#[cfg(test)]
mod tests;
