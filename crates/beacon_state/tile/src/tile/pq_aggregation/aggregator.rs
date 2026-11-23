use std::{cmp::Reverse, mem};

use flux::spine::SpineProducers;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_common::{
    LeanVmHealthEvent, LeanVmReq, LeanVmResp, Nanos, TCacheRead, TCacheReader, TProducer,
    ssz_view::{MAX_VALIDATORS_PER_COMMITTEE, SingleAttestationPqView},
    ticker::SlotTicker,
};

use super::{
    Aggregate, VerifiedVote,
    claims::Vote,
    leaf::{LeafAggregation, LeafKey, ProvedAggregate},
    merge::{MergeAggregation, OnChainAggregates},
    strategy::Batch,
};
use crate::tile::Producers;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AggregationKey {
    Leaf(LeafKey),
    Merge(Slot),
}

impl AggregationKey {
    fn slot(&self) -> Slot {
        match self {
            Self::Leaf(leaf) => leaf.slot,
            Self::Merge(slot) => *slot,
        }
    }
}

/// The leanVM sidecar as the aggregator sees it: one request at a time, and
/// none while it is down.
#[derive(Default)]
enum LeanVm {
    #[default]
    Down,
    Idle,
    Busy {
        request_id: u64,
        key: AggregationKey,
        batch: Batch,
    },
}

impl LeanVm {
    fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    fn up(&mut self) {
        if let Self::Down = self {
            *self = Self::Idle;
        }
    }

    /// The batch that was in flight, now lost.
    fn down(&mut self) -> Option<(AggregationKey, Batch)> {
        match mem::take(self) {
            Self::Busy { key, batch, .. } => Some((key, batch)),
            Self::Down | Self::Idle => None,
        }
    }

    /// Becomes idle if `request_id` is in flight, handing back its batch.
    fn take_answered(&mut self, request_id: u64) -> Option<(AggregationKey, Batch)> {
        match mem::take(self) {
            Self::Busy { request_id: id, key, batch } if id == request_id => {
                *self = Self::Idle;
                Some((key, batch))
            }
            other => {
                *self = other;
                None
            }
        }
    }
}

/// Every aggregation this node runs. One `LeanVmReq` is in flight at a time,
/// across all aggregations. Events only change state; `send_next` sends.
#[derive(Default)]
pub struct PqAggregator {
    leaves: FxHashMap<LeafKey, LeafAggregation>,
    merges: FxHashMap<Slot, MergeAggregation>,
    /// A pruned merge, whose buffers the next merge reuses.
    spare_merge: Option<MergeAggregation>,
    /// An event changed state since `send_next` last found nothing to send.
    changed: bool,
    leanvm: LeanVm,
    next_request_id: u64,
}

impl PqAggregator {
    pub fn add_vote(&mut self, vote: VerifiedVote, ticker: &SlotTicker) {
        let leaf = LeafKey::new(&vote);
        if vote.committee_position >= vote.committee_len.min(MAX_VALIDATORS_PER_COMMITTEE) {
            let (committee_position, committee_len) = (vote.committee_position, vote.committee_len);
            silver_log::error!(
                slot = leaf.slot,
                committee_position,
                committee_len,
                "vote outside committee"
            );
            return;
        }
        // TODO: the aggregate due time stands in for the VC's pull. A VC that
        // pulls later gets a proof frozen at the due time. Consider ending on
        // the last local aggregator's pull instead.
        let deadline = ticker.aggregate_due(leaf.slot);
        if ticker.since_genesis() >= deadline {
            silver_log::debug!(slot = leaf.slot, "vote after the aggregation deadline");
            return;
        }
        let aggregation = self.leaves.entry(leaf).or_insert_with(|| {
            let data = SingleAttestationPqView::data(vote.single);
            LeafAggregation::new(*data.as_bytes(), vote.committee_len, deadline)
        });
        let (position, signature) =
            (vote.committee_position, SingleAttestationPqView::signature(vote.single));
        let added = aggregation.add(Vote::new(position, vote.pubkey, vote.message, signature));
        debug_assert!(added, "the position was checked against the largest committee");
        self.changed = true;
    }

    /// `aggregate` is verified, for the block of `slot`. A merge refuses it
    /// once it holds too many committees.
    pub fn add_aggregate(&mut self, slot: Slot, aggregate: Aggregate<'_>, ticker: &SlotTicker) {
        let deadline = ticker.slot_start(slot);
        if ticker.since_genesis() >= deadline {
            silver_log::debug!(slot, "aggregate after the merge deadline");
            return;
        }
        let spare = &mut self.spare_merge;
        let merge = self.merges.entry(slot).or_insert_with(|| match spare.take() {
            Some(mut merge) => {
                merge.reset(deadline);
                merge
            }
            None => MergeAggregation::new(deadline),
        });
        if !merge.add(aggregate) {
            silver_log::warn!(slot, "aggregate dropped: the merge holds too many committees");
            return;
        }
        self.changed = true;
    }

    /// A response to a request that is not in flight is ignored. A body that
    /// cannot be read counts as no answer.
    pub fn on_response(&mut self, resp: LeanVmResp, reader: &mut TCacheReader) {
        let acquired = resp.body.map(|read| reader.acquire(read));
        let body = acquired.as_ref().and_then(|acquired| acquired.buffer().ok());
        if body.is_none() && acquired.is_some() {
            silver_log::error!(request_id = resp.request_id, "leanvm response unreadable");
        }
        let Some((key, batch)) = self.leanvm.take_answered(resp.request_id) else { return };
        self.finish(key, batch, body.map(|(body, _)| body));
        self.changed = true;
    }

    /// A leanVM sidecar that goes down fails the batch in flight at once. The
    /// transport's `None` answer for it comes later and is ignored.
    pub fn on_health(&mut self, health: LeanVmHealthEvent) {
        if health.ready {
            self.leanvm.up();
        } else if let Some((key, batch)) = self.leanvm.down() {
            self.finish(key, batch, None);
        }
        self.changed = true;
    }

    /// Drops the aggregations of slots before `floor`. The request in flight
    /// for one still occupies the leanVM sidecar until its response arrives.
    pub fn prune_before(&mut self, floor: Slot) {
        self.leaves.retain(|leaf, _| leaf.slot >= floor);
        if let Some((_, pruned)) = self.merges.extract_if(|&slot, _| slot < floor).last() {
            self.spare_merge = Some(pruned);
        }
    }

    /// Sends a batch of the highest priority aggregation, if the leanVM
    /// sidecar is idle. The tile calls it once per loop, after the events.
    ///
    /// It returns at once until an event changes state. A full tcache leaves
    /// `changed` set, so the next loop retries. It is not a failure.
    pub fn send_next(
        &mut self,
        ticker: &SlotTicker,
        tcache: &mut TProducer,
        producers: &mut Producers,
    ) {
        if !self.changed || !self.leanvm.is_idle() {
            return;
        }
        let now = ticker.since_genesis();
        let Some(key) = self.highest_priority(now) else {
            self.changed = false;
            return;
        };
        // `None`: the tcache is full, or a strategy bug counted a failure. The
        // next loop retries.
        let Some((batch, body)) = self.write_request(key, now, tcache) else { return };
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.leanvm = LeanVm::Busy { request_id, key, batch };
        producers.produce(LeanVmReq { request_id, body });
    }

    pub fn aggregate(
        &self,
        slot: Slot,
        committee_index: u64,
        data_root: B256,
    ) -> Option<ProvedAggregate<'_>> {
        self.leaves.get(&LeafKey { slot, committee_index, data_root })?.proved(committee_index)
    }

    pub fn block_proof(&self, slot: Slot) -> Option<(OnChainAggregates<'_>, &[u8])> {
        self.merges.get(&slot)?.block_proof()
    }

    /// A pruned aggregation drops `batch`.
    fn finish(&mut self, key: AggregationKey, batch: Batch, body: Option<&[u8]>) {
        let settled = match key {
            AggregationKey::Leaf(leaf) => (self.leaves.get_mut(&leaf))
                .map(|leaf| (leaf.finish(batch, body), leaf.core.is_stopped())),
            AggregationKey::Merge(slot) => (self.merges.get_mut(&slot))
                .map(|merge| (merge.finish(batch, body), merge.core.is_stopped())),
        };
        let Some((Err(reason), stopped)) = settled else { return };
        let slot = key.slot();
        silver_log::warn!(slot, reason, "aggregation batch failed");
        if stopped {
            silver_log::warn!(slot, "aggregation stopped after repeated failures");
        }
    }

    /// The next batch of `key`, with its request written to `tcache`.
    fn write_request(
        &mut self,
        key: AggregationKey,
        now: Nanos,
        tcache: &mut TProducer,
    ) -> Option<(Batch, TCacheRead)> {
        match key {
            AggregationKey::Leaf(leaf) => self.leaves.get_mut(&leaf)?.next_request(now, tcache),
            AggregationKey::Merge(slot) => self.merges.get_mut(&slot)?.next_request(now, tcache),
        }
    }

    /// Ties go to the lower key, so the order is total and deterministic.
    fn highest_priority(&self, now: Nanos) -> Option<AggregationKey> {
        let leaves = self.leaves.iter().filter_map(|(&leaf, aggregation)| {
            Some((aggregation.priority(now)?, Reverse(AggregationKey::Leaf(leaf))))
        });
        let merges = self.merges.iter().filter_map(|(&slot, aggregation)| {
            Some((aggregation.priority(now)?, Reverse(AggregationKey::Merge(slot))))
        });
        leaves.chain(merges).max().map(|(_, Reverse(key))| key)
    }
}
