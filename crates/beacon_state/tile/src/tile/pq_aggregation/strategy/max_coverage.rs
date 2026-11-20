use std::cmp::Reverse;

use rustc_hash::FxHashMap;

use super::{Batch, BatchInput, WaitingClaims};

/// Largest group of overlapping children that is enumerated exhaustively.
/// Above it, only the children with the most new claims are enumerated.
const MAX_EXHAUSTIVE_GROUP: usize = 12;

/// The children with the most new claims, within the limit.
pub(super) fn next_batch(input: &BatchInput) -> Option<Batch> {
    Batch::new(Candidates::new(input).choose(input.limit))
}

/// Children with new claims, each as the dense ids of those claims.
struct Candidates<'a> {
    waiting: Vec<&'a WaitingClaims<'a>>,
    ids: Vec<Vec<usize>>,
}

/// The `(gain, members)` of the best subset of one group, for each size.
type BestBySize = Vec<(usize, Vec<usize>)>;

impl<'a> Candidates<'a> {
    fn new(input: &'a BatchInput) -> Self {
        let best_claims = input.best_claims.unwrap_or_default();
        let waiting: Vec<_> =
            input.waiting.iter().filter(|waiting| waiting.new_claim_count > 0).collect();
        let mut dense = FxHashMap::default();
        let ids = waiting
            .iter()
            .map(|waiting| {
                let new =
                    waiting.claims.iter().filter(|claim| best_claims.binary_search(claim).is_err());
                new.map(|claim| {
                    let next = dense.len();
                    *dense.entry(claim).or_insert(next)
                })
                .collect()
            })
            .collect();
        Self { waiting, ids }
    }

    /// Groups of candidates linked by shared claims. Claims never span two
    /// groups, so the gains of groups add up.
    fn groups(&self) -> Vec<Vec<usize>> {
        let mut parent: Vec<usize> = (0..self.waiting.len()).collect();
        let mut owner = FxHashMap::default();
        for (candidate, ids) in self.ids.iter().enumerate() {
            for &id in ids {
                let other = *owner.entry(id).or_insert(candidate);
                let (a, b) = (root(&mut parent, candidate), root(&mut parent, other));
                parent[a] = b;
            }
        }
        let mut groups: FxHashMap<usize, Vec<usize>> = FxHashMap::default();
        for candidate in 0..parent.len() {
            groups.entry(root(&mut parent, candidate)).or_default().push(candidate);
        }
        let mut groups: Vec<_> = groups.into_values().collect();
        groups.sort_unstable();
        groups
    }

    fn best_by_size(&self, mut group: Vec<usize>, budget: usize) -> BestBySize {
        if group.len() > MAX_EXHAUSTIVE_GROUP {
            group.sort_by_key(|&c| Reverse(self.waiting[c].new_claim_count));
            group.truncate(MAX_EXHAUSTIVE_GROUP);
        }
        let mut distinct: Vec<usize> = group.iter().flat_map(|&c| &self.ids[c]).copied().collect();
        distinct.sort_unstable();
        distinct.dedup();
        let words = distinct.len().div_ceil(64);
        let sets: Vec<Vec<u64>> = group
            .iter()
            .map(|&c| {
                let mut bits = vec![0u64; words];
                for id in &self.ids[c] {
                    let local = distinct.binary_search(id).unwrap();
                    bits[local / 64] |= 1 << (local % 64);
                }
                bits
            })
            .collect();

        let size_max = group.len().min(budget);
        let mut best_by_size: BestBySize = vec![(0, Vec::new()); size_max + 1];
        for mask in 1u32..(1 << group.len()) {
            let size = mask.count_ones() as usize;
            if size > size_max {
                continue;
            }
            let mut union = vec![0u64; words];
            let members = (0..group.len()).filter(|i| mask >> i & 1 == 1);
            members.clone().for_each(|i| union.iter_mut().zip(&sets[i]).for_each(|(u, s)| *u |= s));
            let gain = union.iter().map(|word| word.count_ones() as usize).sum();
            if gain > best_by_size[size].0 || best_by_size[size].1.is_empty() {
                best_by_size[size] = (gain, members.map(|i| group[i]).collect());
            }
        }
        best_by_size
    }

    /// Knapsack over the groups: the most gain, then the fewest children,
    /// with at most `budget` children.
    fn choose(&self, budget: usize) -> Vec<usize> {
        let per_group: Vec<BestBySize> =
            self.groups().into_iter().map(|group| self.best_by_size(group, budget)).collect();
        let mut dp = vec![vec![(0usize, 0usize); budget + 1]; per_group.len() + 1];
        let mut take = vec![vec![0usize; budget + 1]; per_group.len()];
        for (i, by_size) in per_group.iter().enumerate() {
            for b in 0..=budget {
                let mut top = (dp[i][b].0, Reverse(dp[i][b].1));
                for (size, (gain, _)) in by_size.iter().enumerate().skip(1).take(b) {
                    let candidate = (dp[i][b - size].0 + gain, Reverse(dp[i][b - size].1 + size));
                    if candidate > top {
                        top = candidate;
                        take[i][b] = size;
                    }
                }
                dp[i + 1][b] = (top.0, top.1.0);
            }
        }
        let mut chosen = Vec::new();
        let mut room = budget;
        for (i, by_size) in per_group.iter().enumerate().rev() {
            let size = take[i][room];
            chosen.extend(by_size[size].1.iter().map(|&c| self.waiting[c].index));
            room -= size;
        }
        chosen
    }
}

fn root(parent: &mut [usize], mut node: usize) -> usize {
    while parent[node] != node {
        parent[node] = parent[parent[node]];
        node = parent[node];
    }
    node
}

#[cfg(test)]
mod tests;
