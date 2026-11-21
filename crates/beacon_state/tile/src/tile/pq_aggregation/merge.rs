use silver_common::{Nanos, TCacheRead, TProducer};

use super::{
    aggregation::{Aggregation, Priority, VerifiedClaims},
    claims::{Aggregate, Group},
    rolling::{Proved, on_chain_attestations, united},
    strategy::{Batch, MarginalGain, Strategy},
    wire::MAX_PROOFS,
};

/// The aggregates of one attestation slot, proved as one proof. It ends when
/// the next slot starts; the rolling proof then takes it in.
pub(super) struct MergeAggregation {
    /// The votes of each aggregate.
    groups: Vec<Group>,
    strategy: MarginalGain,
    pub(super) core: Aggregation,
}

impl MergeAggregation {
    pub(super) fn new(deadline: Nanos) -> Self {
        let (groups, strategy) = (Vec::new(), MarginalGain::default());
        Self { groups, strategy, core: Aggregation::new(deadline) }
    }

    /// `false` once the merge holds too many committees for another.
    pub(super) fn add(&mut self, aggregate: Aggregate) -> bool {
        let fits = self.strategy.arrived(self.groups.len(), aggregate.group.positions());
        if fits {
            self.groups.push(aggregate.group);
            self.core.add(VerifiedClaims::Proof(aggregate.claims, aggregate.proof));
        }
        fits
    }

    /// `None` when it has nothing to send: past its deadline, stopped, or no
    /// waiting aggregate adds a position.
    pub(super) fn priority(&self, now: Nanos) -> Option<Priority> {
        self.core.priority(now, self.strategy.waiting())
    }

    /// `None` exactly when `priority` is, unless the strategy has a bug. The
    /// best proof counts as one of `MAX_PROOFS`.
    pub(super) fn next_batch(&mut self, now: Nanos) -> Option<Batch> {
        self.priority(now)?;
        let limit = MAX_PROOFS - usize::from(self.core.best_proof().is_some());
        self.core.check_batch(self.strategy.next_batch(limit), limit)
    }

    pub(super) fn next_request(
        &mut self,
        now: Nanos,
        tcache: &mut TProducer,
    ) -> Option<(Batch, TCacheRead)> {
        self.next_batch(now).and_then(|batch| self.core.write_request(batch, tcache))
    }

    pub(super) fn finish(&mut self, batch: Batch, body: Option<&[u8]>) -> Result<(), &'static str> {
        self.core.finish(&batch, body).map(|()| self.strategy.adopted(&batch))
    }

    fn covered_groups(&self) -> impl Iterator<Item = Group> + '_ {
        self.core.covered_indices().iter().map(|&index| self.groups[index].clone())
    }

    /// The best proof and the votes it covers. `None` without a best proof.
    pub(super) fn proved(&self) -> Option<Proved> {
        let (claims, proof) = self.core.best_proof()?;
        Some(Proved::new(self.covered_groups(), claims.to_vec(), proof.to_vec()))
    }

    /// The attestations the best proof covers, with it, for a block body.
    pub(super) fn block_proof(&self) -> Option<(Vec<Vec<u8>>, &[u8])> {
        let (_, proof) = self.core.best_proof()?;
        Some((on_chain_attestations(&united(self.covered_groups())), proof))
    }
}
