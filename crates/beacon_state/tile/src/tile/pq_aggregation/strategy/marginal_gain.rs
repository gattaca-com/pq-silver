use std::cmp::Reverse;

use silver_common::ssz_view::{ATTESTATION_DATA_SIZE, MAX_COMMITTEES_PER_SLOT_PQ};

use super::{Batch, Bits, Strategy};

/// Most committees one merge tells apart. Honest aggregates of a slot name
/// few attestation data.
pub(in super::super) const MAX_GROUPS: usize = 4 * MAX_COMMITTEES_PER_SLOT_PQ;

/// One committee voting for one attestation data. Aggregates of two
/// committees share no claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committee {
    pub data: [u8; ATTESTATION_DATA_SIZE],
    pub index: usize,
}

/// The committee positions of an aggregate's claims.
#[derive(Clone, Copy, Debug)]
pub struct Positions {
    pub committee: Committee,
    pub bits: Bits,
}

/// Marginal-gain greedy: the child that adds the most positions first, ties
/// to the earlier arrival. Gain is monotone and submodular, so a batch gains
/// at least `1 - 1/e` of the best batch.
#[derive(Default)]
pub struct MarginalGain {
    /// One per group. Claims of two groups never overlap.
    committees: Vec<Committee>,
    /// Per group, the positions the best proof covers.
    have: Vec<Bits>,
    /// Children that add a position, in arrival order.
    waiting: Vec<Waiting>,
}

struct Waiting {
    index: usize,
    group: usize,
    bits: Bits,
}

impl Waiting {
    fn gain(&self, have: &[Bits]) -> usize {
        self.bits.count_outside(&have[self.group])
    }
}

struct Candidate {
    /// Index into `waiting`.
    waiting: usize,
    gain: usize,
}

impl MarginalGain {
    /// Empty again, keeping its buffers.
    pub fn clear(&mut self) {
        self.committees.clear();
        self.have.clear();
        self.waiting.clear();
    }
}

impl Strategy for MarginalGain {
    type Positions = Positions;

    /// A child that adds nothing to the best proof does not wait.
    fn arrived(&mut self, index: usize, positions: Positions) -> bool {
        let known = self.committees.iter().position(|&c| c == positions.committee);
        let group = match known {
            Some(group) => group,
            None if self.committees.len() < MAX_GROUPS => {
                self.committees.push(positions.committee);
                self.have.push(Bits::default());
                self.committees.len() - 1
            }
            None => return false,
        };
        let waiting = Waiting { index, group, bits: positions.bits };
        if waiting.gain(&self.have) > 0 {
            self.waiting.push(waiting);
        }
        true
    }

    fn adopted(&mut self, batch: &Batch) {
        for waiting in &self.waiting {
            if batch.indices().binary_search(&waiting.index).is_ok() {
                self.have[waiting.group].union_with(&waiting.bits);
            }
        }
        self.waiting.retain(|waiting| waiting.gain(&self.have) > 0);
    }

    /// Picking a child changes the gains of its group only.
    fn next_batch(&self, limit: usize) -> Option<Batch> {
        let mut have = self.have.clone();
        let gain = |waiting| Candidate { waiting, gain: self.waiting[waiting].gain(&have) };
        let mut candidates: Vec<_> =
            (0..self.waiting.len()).map(gain).filter(|candidate| candidate.gain > 0).collect();
        let mut picks = Vec::new();
        while picks.len() < limit {
            let rank = |candidate: &&Candidate| (candidate.gain, Reverse(candidate.waiting));
            let Some(best) = candidates.iter().max_by_key(rank) else { break };
            let picked = &self.waiting[best.waiting];
            picks.push(picked.index);
            have[picked.group].union_with(&picked.bits);
            candidates.retain_mut(|candidate| {
                let child = &self.waiting[candidate.waiting];
                if child.group == picked.group {
                    candidate.gain = child.gain(&have);
                }
                candidate.gain > 0
            });
        }
        Batch::new(picks)
    }

    fn waiting(&self) -> usize {
        self.waiting.len()
    }
}

#[cfg(test)]
mod tests;
